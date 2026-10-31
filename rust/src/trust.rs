//! The trust file, read exactly as src/eureka_daemon/trust.py reads it.
//!
//! Versions 1-3, the same entry shapes per version, revocations applied
//! first, keys compared stripped and lowercased, grants keyed by public key.
//! A missing file is an empty allowlist that trusts nobody; a file that exists
//! and is wrong stops the daemon, with the same messages.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use indexmap::IndexMap;

use crate::crypto::{default_eureka_dir, expand_user, from_hex};
use crate::pyjson::{self, object, py_strip, Value};

pub const TRUST_PATH_ENV_VAR: &str = "EUREKA_TRUST_PATH";

/// Capabilities the Python daemon offers that this build does not run. A grant
/// for one of these loads (so an existing trust file keeps working) and is
/// refused at request time as not offered, which is how both daemons treat a
/// grant for something the node does not serve.
pub const PYTHON_ONLY_CAPABILITIES: &[&str] = &["web-retrieval"];

#[derive(Debug)]
pub struct TrustError(pub String);

impl std::fmt::Display for TrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub fn resolve_trust_path() -> PathBuf {
    match std::env::var(TRUST_PATH_ENV_VAR) {
        Ok(p) if !p.is_empty() => expand_user(&p),
        _ => default_eureka_dir().join("trust.json"),
    }
}

/// Python's `repr()` of a str, near enough for an error message.
fn r(s: &str) -> String {
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Int(_) => "int",
        Value::Float(_) => "float",
        Value::Str(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

fn normalise_public_key(v: &Value, context: &str) -> Result<String, TrustError> {
    let Value::Str(s) = v else {
        return Err(TrustError(format!("{context}: public key must be a string, got {}", type_name(v))));
    };
    let candidate = py_strip(s).to_lowercase();
    let n = pyjson::py_len(&candidate);
    if n != 64 {
        return Err(TrustError(format!("{context}: public key must be 64 hex characters, got {n}")));
    }
    if from_hex(&candidate).is_none() {
        return Err(TrustError(format!("{context}: public key is not valid hex")));
    }
    Ok(candidate)
}

fn normalise_capabilities(v: Option<&Value>, context: &str) -> Result<BTreeSet<String>, TrustError> {
    let items = match v {
        None | Some(Value::Null) => return Ok(BTreeSet::new()),
        Some(Value::Array(items)) => items,
        Some(other) => return Err(TrustError(format!("{context}: capabilities must be a list, got {}", type_name(other)))),
    };
    let mut granted = BTreeSet::new();
    for entry in items {
        match entry {
            Value::Str(s) if !py_strip(s).is_empty() => {
                granted.insert(py_strip(s).to_string());
            }
            other => {
                return Err(TrustError(format!(
                    "{context}: capability must be a non-empty string, got {}",
                    pyjson::response(other).unwrap_or_default()
                )))
            }
        }
    }
    Ok(granted)
}

#[derive(Default, Debug)]
pub struct TrustList {
    by_key: IndexMap<String, String>,
    grants: HashMap<String, BTreeSet<String>>,
    /// Each revoked key's record: its stripped reason and revoked_at, as Python keeps them.
    revoked: IndexMap<String, pyjson::Map>,
}

impl TrustList {
    /// What a key may ask for, matched stripped and lowercased.
    pub fn capabilities_for(&self, public_key: &str) -> BTreeSet<String> {
        self.grants.get(&py_strip(public_key).to_lowercase()).cloned().unwrap_or_default()
    }
    pub fn trusts(&self, public_key: &str) -> bool {
        self.by_key.contains_key(&py_strip(public_key).to_lowercase())
    }
    pub fn is_revoked(&self, public_key: &str) -> bool {
        self.revoked.contains_key(&py_strip(public_key).to_lowercase())
    }
    pub fn len(&self) -> usize {
        self.by_key.len()
    }
    pub fn revoked_count(&self) -> usize {
        self.revoked.len()
    }

    fn add(&mut self, name: &str, key: String, granted: BTreeSet<String>) -> Result<(), TrustError> {
        if name.is_empty() {
            return Err(TrustError("peer name must be a non-empty string, got ''".into()));
        }
        if self.revoked.contains_key(&key) {
            return Err(TrustError(format!("peer {}: public key is revoked", r(name))));
        }
        if let Some(existing) = self.by_key.get(&key) {
            if existing != name {
                return Err(TrustError(format!("duplicate public key: {} and {} share a key", r(existing), r(name))));
            }
        }
        self.by_key.insert(key.clone(), name.to_string());
        self.grants.insert(key, granted);
        Ok(())
    }

    fn apply_revocation(&mut self, entry: &Value) -> Result<(), TrustError> {
        let context = "revocation";
        let (key, record) = match entry {
            Value::Str(_) => (normalise_public_key(entry, context)?, pyjson::Map::new()),
            Value::Object(map) => {
                let mut unknown: Vec<&str> = map.keys().map(String::as_str).filter(|k| !["public_key", "reason", "revoked_at"].contains(k)).collect();
                unknown.sort();
                if !unknown.is_empty() {
                    return Err(TrustError(format!("{context}: revocation has unexpected field(s) {}", unknown.join(", "))));
                }
                let key = map.get("public_key").ok_or_else(|| TrustError(format!("{context}: revocation is missing 'public_key'")))?;
                let key = normalise_public_key(key, context)?;
                let mut record = pyjson::Map::new();
                for field in ["reason", "revoked_at"] {
                    match map.get(field) {
                        None | Some(Value::Null) => {}
                        Some(Value::Str(s)) if !py_strip(s).is_empty() => {
                            record.insert(field.to_string(), Value::str(py_strip(s)));
                        }
                        Some(other) => {
                            return Err(TrustError(format!(
                                "{context}: revocation {field} must be a non-empty string, got {}",
                                pyjson::response(other).unwrap_or_default()
                            )))
                        }
                    }
                }
                (key, record)
            }
            other => {
                return Err(TrustError(format!(
                    "{context}: revocation must be a public key string or an object with 'public_key', got {}",
                    type_name(other)
                )))
            }
        };
        self.by_key.shift_remove(&key);
        self.grants.remove(&key);
        self.revoked.insert(key, record);
        Ok(())
    }

    /// `TrustList.add(name, public_key_hex, capabilities)`, for the `trust add` command.
    pub fn add_peer(&mut self, name: &str, public_key: &str, capabilities: &[String]) -> Result<(), TrustError> {
        let context = format!("peer {}", r(name));
        let key = normalise_public_key(&Value::str(public_key), &context)?;
        let caps = Value::Array(capabilities.iter().map(|c| Value::str(c.as_str())).collect());
        let granted = normalise_capabilities(Some(&caps), &context)?;
        self.add(name, key, granted)
    }

    /// `TrustList.to_document()`: always the current version, with a revocation list even when empty.
    pub fn to_document(&self) -> Value {
        let peers = self
            .by_key
            .iter()
            .map(|(key, name)| {
                let caps = self.grants.get(key).map(|g| g.iter().map(|c| Value::str(c.as_str())).collect()).unwrap_or_default();
                (name.clone(), object([("public_key", Value::str(key.as_str())), ("capabilities", Value::Array(caps))]))
            })
            .collect();
        let revoked = self
            .revoked
            .iter()
            .map(|(key, record)| {
                let mut entry = record.clone();
                entry.insert("public_key".into(), Value::str(key.as_str()));
                Value::Object(entry)
            })
            .collect();
        object([
            ("version", Value::int(3)),
            ("algorithm", Value::str("ed25519")),
            ("peers", Value::Object(peers)),
            ("revoked", Value::Array(revoked)),
        ])
    }

    /// Write the file as `json.dumps(to_document(), indent=2) + "\n"`, owner-only.
    pub fn save(&self, target: &Path) -> std::io::Result<()> {
        crate::crypto::write_private_file(target, (pyjson::indented(&self.to_document()) + "\n").as_bytes())
    }

    pub fn names(&self) -> Vec<(String, String, Vec<String>)> {
        self.by_key
            .iter()
            .map(|(key, name)| (name.clone(), key.clone(), self.grants.get(key).map(|g| g.iter().cloned().collect()).unwrap_or_default()))
            .collect()
    }

    /// `TrustList.load_or_empty(path, advertised=...)`.
    pub fn load_or_empty(target: &Path, advertised: &[String]) -> Result<(TrustList, Vec<String>), TrustError> {
        if !target.exists() {
            return Ok((TrustList::default(), Vec::new()));
        }
        TrustList::load(target, advertised)
    }

    /// Load and check a trust file. Also returns warnings for grants this build
    /// recognises but does not serve.
    pub fn load(target: &Path, advertised: &[String]) -> Result<(TrustList, Vec<String>), TrustError> {
        let t = target.display();
        let raw = std::fs::read(target).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => TrustError(format!("no trust file at {t}")),
            _ => TrustError(format!("cannot read trust file {t}: {e}")),
        })?;
        let document = pyjson::loads(&raw).map_err(|_| TrustError(format!("trust file {t} is not valid JSON")))?;
        let Value::Object(doc) = document else {
            return Err(TrustError(format!("trust file {t} must contain a JSON object")));
        };
        let version = doc.get("version");
        let version_number = version.and_then(Value::as_number).filter(|n| [1.0, 2.0, 3.0].contains(n));
        let Some(version) = version_number else {
            let shown = version.and_then(pyjson::response).unwrap_or_else(|| "None".into());
            return Err(TrustError(format!("trust file {t} has unsupported version {shown}")));
        };
        if !doc.get("algorithm").is_some_and(|v| v.is_str("ed25519")) {
            return Err(TrustError(format!("trust file {t} has unsupported algorithm")));
        }
        let Some(Value::Object(peers)) = doc.get("peers") else {
            return Err(TrustError(format!("trust file {t} must have a 'peers' object mapping name to public key hex")));
        };
        if doc.contains_key("revoked") && version < 3.0 {
            return Err(TrustError(format!(
                "trust file {t} is version {}, which cannot express revocations; set version to 3",
                version as i64
            )));
        }
        let revoked = match doc.get("revoked") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => items.clone(),
            Some(_) => return Err(TrustError(format!("trust file {t} must have a 'revoked' list of public keys"))),
        };
        let offered: BTreeSet<&str> = advertised.iter().map(|s| py_strip(s)).filter(|s| !s.is_empty()).collect();

        let mut list = TrustList::default();
        let mut warnings = Vec::new();
        for entry in &revoked {
            list.apply_revocation(entry).map_err(|e| TrustError(format!("trust file {t}: {e}")))?;
        }
        for (name, entry) in peers {
            let wrap = |e: TrustError| TrustError(format!("trust file {t}: {e}"));
            let context = format!("peer {}", r(name));
            let (key, caps) = if version == 1.0 {
                if matches!(entry, Value::Object(_)) {
                    return Err(wrap(TrustError(format!(
                        "{context}: v1 entries are a public key string; set version to 3 to grant capabilities"
                    ))));
                }
                (entry, None)
            } else {
                let Value::Object(fields) = entry else {
                    return Err(wrap(TrustError(format!(
                        "{context}: v3 entries must be an object with 'public_key', got {}",
                        type_name(entry)
                    ))));
                };
                let mut unknown: Vec<&str> = fields.keys().map(String::as_str).filter(|k| !["public_key", "capabilities"].contains(k)).collect();
                unknown.sort();
                if !unknown.is_empty() {
                    return Err(wrap(TrustError(format!("{context}: unexpected field(s) {}", unknown.join(", ")))));
                }
                let key = fields.get("public_key").ok_or_else(|| wrap(TrustError(format!("{context}: missing 'public_key'"))))?;
                (key, fields.get("capabilities"))
            };
            let granted = normalise_capabilities(caps, &context).map_err(wrap)?;
            let mut unadvertised = Vec::new();
            for capability in &granted {
                if offered.contains(capability.as_str()) {
                    continue;
                }
                if PYTHON_ONLY_CAPABILITIES.contains(&capability.as_str()) {
                    warnings.push(format!(
                        "peer {}: grant {} is not served by this build and will be refused",
                        r(name),
                        r(capability)
                    ));
                } else {
                    unadvertised.push(r(capability));
                }
            }
            if !unadvertised.is_empty() {
                return Err(wrap(TrustError(format!(
                    "{context}: granted capability {} that this node does not advertise",
                    unadvertised.join(", ")
                ))));
            }
            let key = normalise_public_key(key, &context).map_err(wrap)?;
            list.add(name, key, granted).map_err(wrap)?;
        }
        Ok((list, warnings))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(text: &str, advertised: &[&str]) -> Result<TrustList, TrustError> {
        let dir = std::env::temp_dir().join(format!("eureka-trust-{}", crate::crypto::token_hex16()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trust.json");
        std::fs::write(&path, text).unwrap();
        let advertised: Vec<String> = advertised.iter().map(|s| s.to_string()).collect();
        let out = TrustList::load(&path, &advertised).map(|(l, _)| l);
        std::fs::remove_dir_all(&dir).unwrap();
        out
    }

    const A: &str = "aa00000000000000000000000000000000000000000000000000000000000000";
    const B: &str = "bb00000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn versions_and_shapes() {
        let v1 = load(&format!(r#"{{"version":1,"algorithm":"ed25519","peers":{{"x":"{A}"}}}}"#), &[]).unwrap();
        assert!(v1.trusts(A) && v1.capabilities_for(A).is_empty());
        let v3 = load(&format!(r#"{{"version":3,"algorithm":"ed25519","peers":{{"x":{{"public_key":" {} ","capabilities":["room-turn"]}}}},"revoked":["{B}"]}}"#, A.to_uppercase()), &["room-turn"]).unwrap();
        assert!(v3.trusts(A) && v3.capabilities_for(A).contains("room-turn") && v3.is_revoked(B) && !v3.trusts(B));
        assert!(load(&format!(r#"{{"version":2,"algorithm":"ed25519","peers":{{}},"revoked":[]}}"#), &[]).is_err());
        assert!(load(&format!(r#"{{"version":1,"algorithm":"ed25519","peers":{{"x":{{"public_key":"{A}"}}}}}}"#), &[]).is_err());
        assert!(load(r#"{"version":4,"algorithm":"ed25519","peers":{}}"#, &[]).is_err());
        assert!(load(r#"{"version":true,"algorithm":"ed25519","peers":{}}"#, &[]).is_ok(), "True == 1 in Python");
    }

    #[test]
    fn grants_must_be_offered_except_python_only_ones() {
        let file = |cap: &str| format!(r#"{{"version":3,"algorithm":"ed25519","peers":{{"x":{{"public_key":"{A}","capabilities":["{cap}"]}}}}}}"#);
        assert!(load(&file("code-exec"), &["room-turn"]).is_err());
        assert!(load(&file("inference"), &["room-turn"]).is_err());
        assert!(load(&file("web-retrieval"), &["room-turn"]).is_ok());
    }

    #[test]
    fn a_revoked_key_cannot_also_be_trusted() {
        let text = format!(r#"{{"version":3,"algorithm":"ed25519","peers":{{"x":{{"public_key":"{A}"}}}},"revoked":[{{"public_key":"{A}","reason":"lost"}}]}}"#);
        assert!(load(&text, &[]).unwrap_err().0.contains("revoked"));
    }
}
