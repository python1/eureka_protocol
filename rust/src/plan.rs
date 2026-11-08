// SPDX-License-Identifier: AGPL-3.0-only
//! A room's plan for a seat to carry out: the JSON a Lead posts in an `eureka-plan` block, checked
//! against fixed limits and hashed in its canonical form. The hash is what the owner approves, so
//! Knights Circle and the daemon must compute it the same way; `vectors/plans-v1.json` is the
//! shared contract.
//!
//! The plan is untrusted text written by a room. Nothing here runs it: this module only decides
//! whether it is well formed and which files it names. Its `edit` patterns are relative paths
//! inside the seat's project, and the ones that could reach outside it, or into git's own
//! files, are refused.

use crate::crypto::{domain_separated_bytes, to_hex};
use crate::pyjson::{canonical, py_len, Value};
use sha2::{Digest, Sha256};

/// The signing domain of a plan's hash: tag, NUL, canonical plan.
pub const DOMAIN_PLAN: &[u8] = b"eureka/plan/v1";
pub const PLAN_VERSION: &str = "1";
pub const KEYS: [&str; 5] = ["edit", "eureka_plan", "project", "steps", "title"];
pub const MAX_TITLE_CHARS: usize = 120;
pub const MAX_STEPS: usize = 20;
pub const MAX_STEP_CHARS: usize = 1000;
pub const MAX_EDIT: usize = 30;
pub const MAX_PATTERN_CHARS: usize = 200;
pub const MAX_PROJECT_CHARS: usize = 32;
/// Of the canonical form, so both sides measure the same thing.
pub const MAX_PLAN_CHARS: usize = 8000;

/// A well-formed plan, with its hash.
#[derive(Clone, Debug)]
pub struct Plan {
    #[allow(dead_code)] // Kept with the plan it checked; the tests and the apply step read it.
    pub value: Value,
    pub title: String,
    pub project: String,
    pub steps: Vec<String>,
    pub edit: Vec<String>,
    /// SHA-256 of the domain-separated canonical plan, in lower-case hex.
    pub hash: String,
}

impl Plan {
    /// The plan's short code: what the owner compares on the card, the approval and the report.
    pub fn code(&self) -> &str {
        &self.hash[..8]
    }
}

/// Why a plan was refused: a stable code (the shared contract) and a sentence for people.
#[derive(Debug, PartialEq, Eq)]
pub struct PlanError {
    pub code: &'static str,
    pub detail: String,
}

fn refuse<T>(code: &'static str, detail: impl Into<String>) -> Result<T, PlanError> {
    Err(PlanError { code, detail: detail.into() })
}

/// SHA-256 over `eureka/plan/v1`, NUL and the canonical JSON.
pub fn plan_hash(value: &Value) -> String {
    to_hex(&Sha256::digest(domain_separated_bytes(DOMAIN_PLAN, value)))
}

/// Characters a plan may never hold: control characters (C0, DEL, C1), line and paragraph
/// separators, and the bidirectional controls that can make text read differently from what it
/// is. What the owner reads must be what was hashed.
pub fn hidden_char(c: char) -> bool {
    c.is_control() || matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{2028}' | '\u{2029}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

fn text(value: Option<&Value>, field: &str, code: &'static str, max: usize) -> Result<String, PlanError> {
    let Some(Value::Str(s)) = value else { return refuse(code, format!("{field} must be text")) };
    if s.trim().is_empty() {
        return refuse(code, format!("{field} is empty"));
    }
    if py_len(s) > max {
        return refuse(code, format!("{field} is longer than {max} characters"));
    }
    if s.chars().any(hidden_char) {
        return refuse("bad_text", format!("{field} holds a control or direction character"));
    }
    Ok(s.clone())
}

fn list<'a>(value: Option<&'a Value>, field: &str, code: &'static str, max: usize) -> Result<&'a [Value], PlanError> {
    match value {
        Some(Value::Array(items)) if !items.is_empty() && items.len() <= max => Ok(items),
        Some(Value::Array(_)) => refuse(code, format!("{field} must list 1 to {max} entries")),
        _ => refuse(code, format!("{field} must be a list")),
    }
}

/// A project's name as the owner gave it at setup: lower-case letters, digits, `-` and `_`.
pub fn valid_project_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_PROJECT_CHARS
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
}

/// Path segments a plan may not name in any letter case: git's own folder, and the files that
/// let a checkout run filters or fetch other repositories.
pub const GIT_NAMES: [&str; 3] = [".git", ".gitattributes", ".gitmodules"];

/// One `edit` entry: a relative path inside the project, `/`-separated, in which `*` and `?`
/// match within one segment and a `**` segment matches any number of segments. ASCII only.
pub fn check_pattern(pattern: &str) -> Result<(), String> {
    if pattern.is_empty() || pattern.len() > MAX_PATTERN_CHARS {
        return Err(format!("a pattern must be 1 to {MAX_PATTERN_CHARS} characters"));
    }
    if pattern.starts_with('/') || pattern.starts_with('~') {
        return Err("a pattern is relative to the project: no leading / or ~".into());
    }
    let allowed = |c: char| c.is_ascii_alphanumeric() || " ._-+@=,*?/".contains(c);
    if let Some(c) = pattern.chars().find(|&c| !allowed(c)) {
        return Err(format!("a pattern may not hold {c:?}"));
    }
    let mut literal = false;
    for segment in pattern.split('/') {
        if segment.is_empty() {
            return Err("a pattern may not have an empty segment (// or a trailing /)".into());
        }
        if segment == "." || segment == ".." {
            return Err("a pattern may not hold . or .. segments".into());
        }
        if segment.contains("**") && segment != "**" {
            return Err("** must be a whole segment".into());
        }
        if GIT_NAMES.iter().any(|g| segment.eq_ignore_ascii_case(g)) {
            return Err(format!("a pattern may not name {segment}"));
        }
        if segment.starts_with(' ') || segment.ends_with(' ') {
            return Err("a segment may not start or end with a space".into());
        }
        literal |= segment.chars().any(|c| c != '*' && c != '?');
    }
    if !literal {
        return Err("a pattern must name something: only wildcards would allow every file".into());
    }
    Ok(())
}

fn segment_matches(pattern: &[u8], name: &[u8]) -> bool {
    match pattern.split_first() {
        None => name.is_empty(),
        Some((b'*', rest)) => (0..=name.len()).any(|skip| segment_matches(rest, &name[skip..])),
        Some((b'?', rest)) => !name.is_empty() && segment_matches(rest, &name[1..]),
        Some((&c, rest)) => name.first() == Some(&c) && segment_matches(rest, &name[1..]),
    }
}

fn segments_match(pattern: &[&str], path: &[&str]) -> bool {
    match pattern.split_first() {
        None => path.is_empty(),
        // A trailing `**` is everything inside, not the folder itself (as in .gitignore).
        Some((&"**", [])) => !path.is_empty(),
        Some((&"**", rest)) => (0..=path.len()).any(|skip| segments_match(rest, &path[skip..])),
        Some((first, rest)) => {
            !path.is_empty() && segment_matches(first.as_bytes(), path[0].as_bytes()) && segments_match(rest, &path[1..])
        }
    }
}

/// Whether a relative, `/`-separated path is one an `edit` pattern allows. Case-sensitive.
pub fn pattern_matches(pattern: &str, path: &str) -> bool {
    let pattern: Vec<&str> = pattern.split('/').collect();
    let path: Vec<&str> = path.split('/').collect();
    segments_match(&pattern, &path)
}

impl Plan {
    /// Whether this plan allows a change to `path`.
    pub fn allows(&self, path: &str) -> bool {
        self.edit.iter().any(|p| pattern_matches(p, path))
    }

    /// Check a plan as parsed from its JSON. Unknown keys are refused, not ignored, so a plan
    /// can't carry anything the card doesn't show.
    pub fn from_value(value: &Value) -> Result<Plan, PlanError> {
        let Value::Object(map) = value else { return refuse("not_a_plan", "a plan is a JSON object") };
        if let Some(key) = map.keys().find(|k| !KEYS.contains(&k.as_str())) {
            return refuse("unknown_key", format!("a plan has no {key:?} field"));
        }
        if let Some(key) = KEYS.iter().find(|k| !map.contains_key(**k)) {
            return refuse("missing_key", format!("the plan has no {key:?} field"));
        }
        if !matches!(&map["eureka_plan"], Value::Int(n) if n == PLAN_VERSION) {
            return refuse("bad_version", "eureka_plan must be 1");
        }
        let title = text(map.get("title"), "title", "bad_title", MAX_TITLE_CHARS)?;
        let project = match &map["project"] {
            Value::Str(name) if valid_project_name(name) => name.clone(),
            _ => return refuse("bad_project", "project must be the project's name: lower-case letters, digits, - and _"),
        };
        let mut steps = Vec::new();
        for (n, step) in list(map.get("steps"), "steps", "bad_steps", MAX_STEPS)?.iter().enumerate() {
            steps.push(text(Some(step), &format!("step {}", n + 1), "bad_steps", MAX_STEP_CHARS)?);
        }
        let mut edit: Vec<String> = Vec::new();
        for entry in list(map.get("edit"), "edit", "bad_edit", MAX_EDIT)? {
            let Value::Str(pattern) = entry else { return refuse("bad_edit", "each edit entry must be text") };
            if let Err(why) = check_pattern(pattern) {
                return refuse("bad_edit", format!("{pattern:?}: {why}"));
            }
            if edit.contains(pattern) {
                return refuse("bad_edit", format!("{pattern:?} is listed twice"));
            }
            edit.push(pattern.clone());
        }
        if py_len(&canonical(value)) > MAX_PLAN_CHARS {
            return refuse("too_long", format!("the plan is longer than {MAX_PLAN_CHARS} characters"));
        }
        Ok(Plan { value: value.clone(), title, project, steps, edit, hash: plan_hash(value) })
    }

    /// Check a plan from its JSON text (the body of the `eureka-plan` block).
    #[cfg_attr(not(test), allow(dead_code))] // Plans arrive parsed; the shared vectors use the text.
    pub fn parse(json: &str) -> Result<Plan, PlanError> {
        match crate::pyjson::loads_str(json) {
            Ok(value) => Plan::from_value(&value),
            Err(_) => refuse("not_json", "the plan is not valid JSON"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"{"eureka_plan": 1, "title": "Add a dark-mode toggle", "project": "site",
        "steps": ["Add a .dark theme to src/theme.css", "Add a toggle to src/app.js that sets it"],
        "edit": ["src/theme.css", "src/app.js"]}"#;

    fn with(field: &str, json: &str) -> String {
        let mut value = crate::pyjson::loads_str(GOOD).unwrap();
        let Value::Object(map) = &mut value else { unreachable!() };
        map.insert(field.into(), crate::pyjson::loads_str(json).unwrap());
        canonical(&value)
    }

    fn code(json: &str) -> &'static str {
        Plan::parse(json).unwrap_err().code
    }

    #[test]
    fn a_good_plan_parses_and_its_hash_ignores_key_order_and_spacing() {
        let plan = Plan::parse(GOOD).unwrap();
        assert_eq!(plan.project, "site");
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.hash.len(), 64);
        assert_eq!(plan.code(), &plan.hash[..8]);
        let reordered = r#"{"edit":["src/theme.css","src/app.js"],"title":"Add a dark-mode toggle","steps":["Add a .dark theme to src/theme.css","Add a toggle to src/app.js that sets it"],"project":"site","eureka_plan":1}"#;
        assert_eq!(Plan::parse(reordered).unwrap().hash, plan.hash);
        // One changed byte is a different plan.
        assert_ne!(Plan::parse(&GOOD.replace("toggle\"", "toggles\"")).unwrap().hash, plan.hash);
        // The edit order is part of what was approved.
        assert_ne!(Plan::parse(&GOOD.replace(r#"["src/theme.css", "src/app.js"]"#, r#"["src/app.js", "src/theme.css"]"#)).unwrap().hash, plan.hash);
    }

    #[test]
    fn malformed_plans_are_refused_with_their_code() {
        assert_eq!(code("[1]"), "not_a_plan");
        assert_eq!(code("{"), "not_json");
        assert_eq!(code(&with("run", "\"rm -rf ~\"")), "unknown_key");
        assert_eq!(code(r#"{"eureka_plan":1,"title":"t","project":"p","steps":["s"]}"#), "missing_key");
        assert_eq!(code(&with("eureka_plan", "2")), "bad_version");
        assert_eq!(code(&with("eureka_plan", "true")), "bad_version");
        assert_eq!(code(&with("eureka_plan", "1.0")), "bad_version");
        assert_eq!(code(&with("eureka_plan", "\"1\"")), "bad_version");
        assert_eq!(code(&with("title", "\"  \"")), "bad_title");
        assert_eq!(code(&with("title", &format!("\"{}\"", "x".repeat(121)))), "bad_title");
        assert_eq!(code(&with("project", "\"../etc\"")), "bad_project");
        assert_eq!(code(&with("project", "\"/Users/me\"")), "bad_project");
        assert_eq!(code(&with("project", "\"Site\"")), "bad_project");
        assert_eq!(code(&with("steps", "[]")), "bad_steps");
        assert_eq!(code(&with("steps", "[1]")), "bad_steps");
        assert_eq!(code(&with("steps", &format!("[{}]", vec!["\"s\""; 21].join(",")))), "bad_steps");
        assert_eq!(code(&with("steps", &format!("[\"{}\"]", "x".repeat(1001)))), "bad_steps");
        assert_eq!(code(&with("edit", "[]")), "bad_edit");
        assert_eq!(code(&with("edit", r#"["a","a"]"#)), "bad_edit");
        assert_eq!(code(&with("steps", &format!("[{}]", vec![format!("\"{}\"", "x".repeat(999)); 9].join(",")))), "too_long");
    }

    #[test]
    fn hidden_characters_are_refused_anywhere_in_the_text() {
        for c in ["\\n", "\\t", "\\u0000", "\\u007f", "\\u0085", "\\u2028", "\\u202e", "\\u2066", "\\u200f"] {
            assert_eq!(code(&with("title", &format!("\"ok{c}ok\""))), "bad_text", "{c}");
            assert_eq!(code(&with("steps", &format!("[\"ok{c}ok\"]"))), "bad_text", "{c}");
        }
        // Other Unicode is fine, and is hashed escaped, as the canonical form does.
        assert!(Plan::parse(&with("title", "\"Caf\\u00e9 \\ud83d\\ude00\"")).is_ok());
    }

    #[test]
    fn patterns_that_could_leave_the_project_or_touch_git_are_refused() {
        for bad in [
            "/etc/passwd", "~/.ssh/config", "../x", "src/../../x", "./src", "src//a", "src/", "a\\b", "src/*.{js,css}",
            ".git/config", "src/.GIT/hooks/x", ".gitattributes", "sub/.gitmodules", "**", "*", "**/*", "?", "a**/b",
            "caf\u{e9}.txt", "a\nb", " src/a", "src/a ", "a:b", "$HOME/x", "a;b", "`x`", "'a'", "\"a\"", "[ab]",
        ] {
            assert!(check_pattern(bad).is_err(), "{bad:?}");
        }
        for good in ["src/app.js", "src/**/*.css", "docs/*.md", "README.md", "a b/c-d_e.f", ".github/workflows/ci.yml", ".gitignore", "**/test_*.py"] {
            assert!(check_pattern(good).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn patterns_match_paths_by_segment() {
        let cases = [
            ("src/app.js", "src/app.js", true),
            ("src/app.js", "src/app.jsx", false),
            ("src/*.js", "src/app.js", true),
            ("src/*.js", "src/lib/app.js", false),
            ("src/**/*.js", "src/app.js", true),
            ("src/**/*.js", "src/a/b/app.js", true),
            ("src/**", "src/a/b", true),
            ("src/**", "src", false),
            ("**/test_*.py", "test_a.py", true),
            ("**/test_*.py", "a/b/test_a.py", true),
            ("doc?.md", "docs.md", true),
            ("doc?.md", "doc.md", false),
            ("src/App.js", "src/app.js", false),
        ];
        for (pattern, path, expected) in cases {
            assert_eq!(pattern_matches(pattern, path), expected, "{pattern} {path}");
        }
        let plan = Plan::parse(GOOD).unwrap();
        assert!(plan.allows("src/app.js"));
        assert!(!plan.allows("src/other.js"));
    }
}
