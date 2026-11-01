//! JSON exactly as the Python daemon reads and writes it.
//!
//! Signatures are computed over `json.dumps(payload, sort_keys=True,
//! separators=(',', ':'))` of whatever `json.loads` made of the request, so
//! this module reproduces both halves of Python's behaviour rather than
//! serde's: integers of any size kept exactly, floats printed as `repr(float)`,
//! `NaN`/`Infinity` accepted, duplicate keys resolved last-wins in the first
//! key's position, and `ensure_ascii` escaping down to DEL and surrogate pairs.
//!
//! One deliberate gap: Python strings may hold a lone surrogate (`"\ud800"`),
//! which a Rust `String` cannot. Such a document is refused as not JSON, so the
//! request gets the same malformed answer any unparseable body does.

use indexmap::IndexMap;

#[derive(Clone, Debug)]
pub enum Value {
    Null,
    Bool(bool),
    /// An integer, as Python's `repr(int)` prints it.
    Int(String),
    Float(f64),
    Str(String),
    Array(Vec<Value>),
    Object(Map),
}

pub type Map = IndexMap<String, Value>;

impl Value {
    pub fn str(s: impl Into<String>) -> Value {
        Value::Str(s.into())
    }
    pub fn int(n: i64) -> Value {
        Value::Int(n.to_string())
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_object(&self) -> Option<&Map> {
        match self {
            Value::Object(m) => Some(m),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
    /// Python `value == "text"`: only a str equals a str.
    pub fn is_str(&self, text: &str) -> bool {
        matches!(self, Value::Str(s) if s == text)
    }
    /// The number Python would compare this as (`True == 1`, `1.0 == 1`), if it is one.
    pub fn as_number(&self) -> Option<f64> {
        match self {
            Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            Value::Int(s) => s.parse::<f64>().ok(),
            Value::Float(f) => Some(*f),
            _ => None,
        }
    }
    /// Python `isinstance(value, int)`, which a bool also satisfies.
    pub fn is_python_int(&self) -> bool {
        matches!(self, Value::Int(_) | Value::Bool(_))
    }
}

/// Build an object from literal pairs, keeping their order.
pub fn object<const N: usize>(pairs: [(&str, Value); N]) -> Value {
    Value::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

// ---------------------------------------------------------------------------
// Parsing: json.loads
// ---------------------------------------------------------------------------

const MAX_DEPTH: usize = 512;

#[derive(Debug)]
pub struct ParseError;

/// `json.loads` on request bytes: UTF-8 (a UTF-8 BOM is skipped, as Python's
/// encoding detection does), JSON whitespace around one value, nothing after.
pub fn loads(bytes: &[u8]) -> Result<Value, ParseError> {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let text = std::str::from_utf8(bytes).map_err(|_| ParseError)?;
    loads_str(text)
}

pub fn loads_str(text: &str) -> Result<Value, ParseError> {
    let mut p = Parser { s: text.as_bytes(), i: 0, depth: 0 };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.i != p.s.len() {
        return Err(ParseError);
    }
    Ok(v)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    depth: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn starts(&self, lit: &str) -> bool {
        self.s[self.i..].starts_with(lit.as_bytes())
    }
    fn value(&mut self) -> Result<Value, ParseError> {
        let c = *self.s.get(self.i).ok_or(ParseError)?;
        match c {
            b'"' => Ok(Value::Str(self.string()?)),
            b'{' => self.nested(Self::object),
            b'[' => self.nested(Self::array),
            b'n' if self.starts("null") => { self.i += 4; Ok(Value::Null) }
            b't' if self.starts("true") => { self.i += 4; Ok(Value::Bool(true)) }
            b'f' if self.starts("false") => { self.i += 5; Ok(Value::Bool(false)) }
            b'N' if self.starts("NaN") => { self.i += 3; Ok(Value::Float(f64::NAN)) }
            b'I' if self.starts("Infinity") => { self.i += 8; Ok(Value::Float(f64::INFINITY)) }
            b'-' if self.starts("-Infinity") => { self.i += 9; Ok(Value::Float(f64::NEG_INFINITY)) }
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(ParseError),
        }
    }
    fn nested(&mut self, f: fn(&mut Self) -> Result<Value, ParseError>) -> Result<Value, ParseError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(ParseError);
        }
        let v = f(self);
        self.depth -= 1;
        v
    }
    fn object(&mut self) -> Result<Value, ParseError> {
        self.i += 1;
        let mut map = Map::new();
        self.ws();
        if self.s.get(self.i) == Some(&b'}') {
            self.i += 1;
            return Ok(Value::Object(map));
        }
        loop {
            if self.s.get(self.i) != Some(&b'"') {
                return Err(ParseError);
            }
            let key = self.string()?;
            self.ws();
            if self.s.get(self.i) != Some(&b':') {
                return Err(ParseError);
            }
            self.i += 1;
            self.ws();
            let v = self.value()?;
            // dict assignment: a repeated key keeps its first position, takes the last value.
            map.insert(key, v);
            self.ws();
            match self.s.get(self.i) {
                Some(b',') => { self.i += 1; self.ws(); }
                Some(b'}') => { self.i += 1; return Ok(Value::Object(map)); }
                _ => return Err(ParseError),
            }
        }
    }
    fn array(&mut self) -> Result<Value, ParseError> {
        self.i += 1;
        let mut items = Vec::new();
        self.ws();
        if self.s.get(self.i) == Some(&b']') {
            self.i += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value()?);
            self.ws();
            match self.s.get(self.i) {
                Some(b',') => { self.i += 1; self.ws(); }
                Some(b']') => { self.i += 1; return Ok(Value::Array(items)); }
                _ => return Err(ParseError),
            }
        }
    }
    fn digits(&mut self) -> usize {
        let start = self.i;
        while self.i < self.s.len() && self.s[self.i].is_ascii_digit() {
            self.i += 1;
        }
        self.i - start
    }
    /// `(-?(?:0|[1-9]\d*))(\.\d+)?([eE][-+]?\d+)?`, as Python's scanner matches it.
    fn number(&mut self) -> Result<Value, ParseError> {
        let start = self.i;
        if self.s[self.i] == b'-' {
            self.i += 1;
        }
        match self.s.get(self.i) {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => { self.digits(); }
            _ => return Err(ParseError),
        }
        let int_end = self.i;
        let mut is_float = false;
        if self.s.get(self.i) == Some(&b'.') && self.s.get(self.i + 1).is_some_and(u8::is_ascii_digit) {
            self.i += 1;
            self.digits();
            is_float = true;
        }
        if matches!(self.s.get(self.i), Some(b'e' | b'E')) {
            let save = self.i;
            self.i += 1;
            if matches!(self.s.get(self.i), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if self.digits() == 0 {
                self.i = save;
            } else {
                is_float = true;
            }
        }
        let text = std::str::from_utf8(&self.s[start..self.i]).map_err(|_| ParseError)?;
        if is_float {
            return text.parse::<f64>().map(Value::Float).map_err(|_| ParseError);
        }
        let digits = &self.s[start..int_end];
        // CPython refuses to convert an integer of more than 4300 digits.
        if digits.len() > 4301 {
            return Err(ParseError);
        }
        Ok(Value::Int(if text == "-0" { "0".into() } else { text.into() }))
    }
    fn hex4(&mut self) -> Result<u32, ParseError> {
        let h = self.s.get(self.i..self.i + 4).ok_or(ParseError)?;
        let h = std::str::from_utf8(h).map_err(|_| ParseError)?;
        if !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ParseError);
        }
        self.i += 4;
        u32::from_str_radix(h, 16).map_err(|_| ParseError)
    }
    fn string(&mut self) -> Result<String, ParseError> {
        self.i += 1;
        let mut out = String::new();
        loop {
            let start = self.i;
            while self.i < self.s.len() && !matches!(self.s[self.i], b'"' | b'\\') && self.s[self.i] >= 0x20 {
                self.i += 1;
            }
            out.push_str(std::str::from_utf8(&self.s[start..self.i]).map_err(|_| ParseError)?);
            match self.s.get(self.i) {
                Some(b'"') => { self.i += 1; return Ok(out); }
                Some(b'\\') => {
                    self.i += 1;
                    let c = *self.s.get(self.i).ok_or(ParseError)?;
                    self.i += 1;
                    match c {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let mut code = self.hex4()?;
                            if (0xd800..0xdc00).contains(&code) && self.starts("\\u") {
                                let save = self.i;
                                self.i += 2;
                                let low = self.hex4()?;
                                if (0xdc00..0xe000).contains(&low) {
                                    code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                                } else {
                                    self.i = save;
                                }
                            }
                            // A lone surrogate: Python keeps it, a Rust String cannot.
                            out.push(char::from_u32(code).ok_or(ParseError)?);
                        }
                        _ => return Err(ParseError),
                    }
                }
                // Python's strict scanner refuses raw control characters.
                _ => return Err(ParseError),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// `repr(float)`: the shortest round-tripping digits, in fixed notation from
/// 1e-4 up to 1e16 and in exponent notation (at least two exponent digits)
/// outside it, always with a `.0` when fixed and integral.
pub fn float_repr(x: f64) -> String {
    if x.is_nan() {
        return "NaN".into();
    }
    if x.is_infinite() {
        return if x > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    if x == 0.0 {
        return if x.is_sign_negative() { "-0.0".into() } else { "0.0".into() };
    }
    // Rust's shortest form has the right number of digits but, when several
    // strings of that length round-trip, not always the one Python picks: the
    // closest to x. Formatting x exactly to that many digits gives that one.
    let shortest = format!("{:e}", x);
    let ndigits = shortest.split_once('e').unwrap().0.chars().filter(char::is_ascii_digit).count();
    let sci = format!("{:.*e}", ndigits - 1, x);
    let (mantissa, exp) = sci.split_once('e').expect("LowerExp always has an exponent");
    let exp: i32 = exp.parse().expect("integer exponent");
    let (sign, mantissa) = match mantissa.strip_prefix('-') {
        Some(m) => ("-", m),
        None => ("", mantissa),
    };
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let decpt = exp + 1;
    let body = if decpt <= -4 || decpt > 16 {
        let (first, rest) = digits.split_at(1);
        let frac = if rest.is_empty() { String::new() } else { format!(".{rest}") };
        let esign = if exp < 0 { '-' } else { '+' };
        format!("{first}{frac}e{esign}{:02}", exp.abs())
    } else if decpt <= 0 {
        format!("0.{}{}", "0".repeat((-decpt) as usize), digits)
    } else if decpt as usize >= digits.len() {
        format!("{}{}.0", digits, "0".repeat(decpt as usize - digits.len()))
    } else {
        let (a, b) = digits.split_at(decpt as usize);
        format!("{a}.{b}")
    };
    format!("{sign}{body}")
}

fn escape_ascii(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            _ => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{:04x}", unit));
                }
            }
        }
    }
    out.push('"');
}

fn escape_utf8(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The bytes every signature covers:
/// `json.dumps(v, sort_keys=True, separators=(',', ':'))`.
pub fn canonical(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(s) => out.push_str(s),
        Value::Float(f) => out.push_str(&float_repr(*f)),
        Value::Str(s) => escape_ascii(s, out),
        Value::Array(items) => {
            out.push('[');
            for (n, item) in items.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Python sorts str keys by code point, which is UTF-8 byte order.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (n, key) in keys.into_iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                escape_ascii(key, out);
                out.push(':');
                write_canonical(&map[key], out);
            }
            out.push('}');
        }
    }
}

/// A response body as Starlette's JSONResponse renders it: insertion order,
/// UTF-8 kept, no whitespace, and no NaN or Infinity (`allow_nan=False`).
pub fn response(v: &Value) -> Option<String> {
    let mut out = String::new();
    write_response(v, &mut out).then_some(out)
}

fn write_response(v: &Value, out: &mut String) -> bool {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(s) => out.push_str(s),
        Value::Float(f) => {
            if !f.is_finite() {
                return false;
            }
            out.push_str(&float_repr(*f));
        }
        Value::Str(s) => escape_utf8(s, out),
        Value::Array(items) => {
            out.push('[');
            for (n, item) in items.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                if !write_response(item, out) {
                    return false;
                }
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (n, (key, item)) in map.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                escape_utf8(key, out);
                out.push(':');
                if !write_response(item, out) {
                    return false;
                }
            }
            out.push('}');
        }
    }
    true
}

/// `json.dumps(v, indent=2)`: how the identity and trust files are written.
pub fn indented(v: &Value) -> String {
    let mut out = String::new();
    write_indented(v, 0, &mut out);
    out
}

fn write_indented(v: &Value, level: usize, out: &mut String) {
    match v {
        Value::Object(map) if !map.is_empty() => {
            out.push_str("{\n");
            for (n, (key, item)) in map.iter().enumerate() {
                if n > 0 {
                    out.push_str(",\n");
                }
                out.push_str(&"  ".repeat(level + 1));
                escape_ascii(key, out);
                out.push_str(": ");
                write_indented(item, level + 1, out);
            }
            out.push('\n');
            out.push_str(&"  ".repeat(level));
            out.push('}');
        }
        Value::Array(items) if !items.is_empty() => {
            out.push_str("[\n");
            for (n, item) in items.iter().enumerate() {
                if n > 0 {
                    out.push_str(",\n");
                }
                out.push_str(&"  ".repeat(level + 1));
                write_indented(item, level + 1, out);
            }
            out.push('\n');
            out.push_str(&"  ".repeat(level));
            out.push(']');
        }
        other => write_canonical(other, out),
    }
}

// ---------------------------------------------------------------------------
// Python str helpers
// ---------------------------------------------------------------------------

/// `str.isspace()`: Unicode whitespace plus the four ASCII separators Python counts.
pub fn py_isspace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `str.strip()`.
pub fn py_strip(s: &str) -> &str {
    s.trim_matches(py_isspace)
}

/// `len(str)`: code points.
pub fn py_len(s: &str) -> usize {
    s.chars().count()
}

/// `s[:n]` on code points.
pub fn py_prefix(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((at, _)) => &s[..at],
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floats_print_as_python_repr() {
        let cases = [
            (1e16, "1e+16"), (1.5e16, "1.5e+16"), (1e-5, "1e-05"), (0.0001, "0.0001"),
            (123.0, "123.0"), (-0.0, "-0.0"), (1e301, "1e+301"), (2.5e-7, "2.5e-07"),
            (1234567890123456.0, "1234567890123456.0"), (0.1, "0.1"), (100.0, "100.0"),
            (5e-324, "5e-324"), (1.7976931348623157e308, "1.7976931348623157e+308"),
        ];
        for (x, want) in cases {
            assert_eq!(float_repr(x), want, "{x}");
        }
    }

    #[test]
    fn numbers_load_as_python_does() {
        let v = loads(b"[-0, 1E2, 1.0e0, 12345678901234567890123, NaN, -Infinity]").unwrap();
        assert_eq!(canonical(&v), "[0,100.0,1.0,12345678901234567890123,NaN,-Infinity]");
        assert!(loads(b"01").is_err());
        assert!(loads(b"1.").is_err());
        assert!(loads(b"[1,]").is_err());
        assert!(loads(b"{\"a\":1,}").is_err());
        assert!(loads(b"\"\\ud800\"").is_err());
        assert!(loads(b"\"a\nb\"").is_err());
    }

    #[test]
    fn repeated_keys_keep_the_first_position_and_the_last_value() {
        let v = loads(br#"{"b":1,"a":2,"b":3}"#).unwrap();
        assert_eq!(response(&v).unwrap(), r#"{"b":3,"a":2}"#);
    }

    #[test]
    fn canonical_escapes_like_ensure_ascii() {
        let v = loads("{\"b\":\"é\u{7f}🙂\u{2028}\",\"a\":[1,true,null]}".as_bytes()).unwrap();
        assert_eq!(canonical(&v), r#"{"a":[1,true,null],"b":"\u00e9\u007f\ud83d\ude42\u2028"}"#);
    }
}
