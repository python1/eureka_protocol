// SPDX-License-Identifier: AGPL-3.0-only
//! Identity, signing domains and Ed25519, matching src/eureka_daemon/crypto.py.
//!
//! The identity file is the Python daemon's: same JSON document, same 0600
//! rule, same location and $EUREKA_IDENTITY_PATH, so either daemon can be
//! started on the other's key. Every signature is over `tag || 0x00 ||
//! canonical JSON`, and verification decodes keys and signatures the way
//! Python's `bytes.fromhex` and strict `b64decode` do, so a request one daemon
//! accepts the other accepts too.

use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::pyjson::{self, object, Value};

pub const IDENTITY_PATH_ENV_VAR: &str = "EUREKA_IDENTITY_PATH";

pub const DOMAIN_HANDSHAKE_OFFER: &[u8] = b"eureka/handshake/offer/v1";
pub const DOMAIN_HANDSHAKE: &[u8] = b"eureka/handshake/v1";
pub const DOMAIN_HANDSHAKE_CONFIRM: &[u8] = b"eureka/handshake/confirm/v1";
pub const DOMAIN_AUDIT_LOG: &[u8] = b"eureka/audit-log/v1";
pub const DOMAIN_DISCOVERY_QUERY: &[u8] = b"eureka/discovery/query/v1";
pub const DOMAIN_READ_QUERY: &[u8] = b"eureka/read/query/v1";
pub const DOMAIN_ASSIGN_QUERY: &[u8] = b"eureka/assign/query/v1";
pub const DOMAIN_ASSIGN_RESULT: &[u8] = b"eureka/assign/result/v1";

/// The exact bytes that get signed: tag, NUL, canonical payload.
pub fn domain_separated_bytes(domain: &[u8], payload: &Value) -> Vec<u8> {
    let mut out = domain.to_vec();
    out.push(0);
    out.extend_from_slice(pyjson::canonical(payload).as_bytes());
    out
}

/// `bytes.fromhex`: pairs of hex digits, ASCII whitespace allowed between pairs.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    let space = |c: u8| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
    loop {
        while i < b.len() && space(b[i]) {
            i += 1;
        }
        if i >= b.len() {
            return Some(out);
        }
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (*b.get(i + 1)? as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (k, b)| n | (*b as u32) << (16 - 8 * k));
        for k in 0..4 {
            if k <= chunk.len() {
                out.push(B64[(n >> (18 - 6 * k) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// `base64.b64decode(s, validate=True)`, i.e. CPython's `a2b_base64` in strict
/// mode: the standard alphabet only, padding only at the end and only as much
/// as the final quantum needs, nothing after it.
pub fn b64decode_strict(s: &str) -> Option<Vec<u8>> {
    if !s.is_ascii() {
        return None;
    }
    let data = s.as_bytes();
    let mut out = Vec::with_capacity(data.len() * 3 / 4);
    let (mut quad_pos, mut leftchar, mut pads) = (0u8, 0u32, 0u8);
    let mut padding_started = false;
    for (i, &c) in data.iter().enumerate() {
        if c == b'=' {
            padding_started = true;
            if quad_pos == 0 {
                return None;
            }
            pads += 1;
            if quad_pos >= 2 && quad_pos + pads >= 4 {
                return if i + 1 < data.len() { None } else { Some(out) };
            }
            continue;
        }
        let v = B64.iter().position(|&a| a == c)? as u32;
        if padding_started {
            return None;
        }
        pads = 0;
        match quad_pos {
            0 => { quad_pos = 1; leftchar = v; }
            1 => { quad_pos = 2; out.push(((leftchar << 2) | (v >> 4)) as u8); leftchar = v & 0x0f; }
            2 => { quad_pos = 3; out.push(((leftchar << 4) | (v >> 2)) as u8); leftchar = v & 0x03; }
            _ => { quad_pos = 0; out.push(((leftchar << 6) | v) as u8); leftchar = 0; }
        }
    }
    if quad_pos != 0 {
        return None;
    }
    Some(out)
}

/// `verify_signature`: False for a bad signature, an unusable key or bad base64.
pub fn verify_bytes(public_key_hex: &str, signature_base64: &str, data: &[u8]) -> bool {
    let Some(key) = from_hex(public_key_hex) else { return false };
    let Ok(key) = <[u8; 32]>::try_from(key.as_slice()) else { return false };
    let Ok(key) = VerifyingKey::from_bytes(&key) else { return false };
    let Some(sig) = b64decode_strict(signature_base64) else { return false };
    let Ok(sig) = ed25519_dalek::Signature::from_slice(&sig) else { return false };
    // Cofactorless verification that refuses a non-canonical S, which is what
    // OpenSSL (behind Python's `cryptography`) does too.
    key.verify(data, &sig).is_ok()
}

pub fn verify_json(public_key_hex: &str, signature_base64: &str, payload: &Value, domain: &[u8]) -> bool {
    verify_bytes(public_key_hex, signature_base64, &domain_separated_bytes(domain, payload))
}

pub fn node_id_for(public_key: &[u8]) -> String {
    format!("node_{}", &to_hex(&Sha256::digest(public_key))[..8])
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out).expect("the operating system's random source failed");
    out
}

/// `secrets.token_hex(16)`.
pub fn token_hex16() -> String {
    to_hex(&random_bytes::<16>())
}

/// `str(uuid.uuid4())`.
pub fn uuid4() -> String {
    let mut b = random_bytes::<16>();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = to_hex(&b);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

#[derive(Debug)]
pub struct IdentityError(pub String);

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub struct Identity {
    key: SigningKey,
    pub public_key_hex: String,
    pub node_id: String,
}

/// `Path.expanduser()` for the two forms anyone writes: `~` and `~/...`.
pub fn expand_user(raw: &str) -> PathBuf {
    #[cfg(windows)]
    let rest = raw.strip_prefix("~/").or_else(|| raw.strip_prefix("~\\"));
    #[cfg(not(windows))]
    let rest = raw.strip_prefix("~/");
    if raw == "~" {
        if let Some(h) = home_dir() {
            return h;
        }
    } else if let Some(rest) = rest {
        if let Some(h) = home_dir() {
            return h.join(rest);
        }
    }
    PathBuf::from(raw)
}

#[cfg(not(windows))]
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// As Python's `expanduser` on Windows: `%USERPROFILE%`, then `%HOMEDRIVE%%HOMEPATH%`.
#[cfg(windows)]
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE").filter(|v| !v.is_empty()).map(PathBuf::from).or_else(|| {
        let mut home = std::env::var_os("HOMEDRIVE")?;
        home.push(std::env::var_os("HOMEPATH")?);
        Some(PathBuf::from(home))
    })
}

pub fn default_eureka_dir() -> PathBuf {
    expand_user("~").join(".eureka")
}

/// Explicit path, then $EUREKA_IDENTITY_PATH, then ~/.eureka/identity.key.
pub fn resolve_identity_path() -> PathBuf {
    match std::env::var(IDENTITY_PATH_ENV_VAR) {
        Ok(p) if !p.is_empty() => expand_user(&p),
        _ => default_eureka_dir().join("identity.key"),
    }
}

impl Identity {
    fn from_seed(seed: [u8; 32]) -> Identity {
        let key = SigningKey::from_bytes(&seed);
        let public = key.verifying_key().to_bytes();
        Identity { key, public_key_hex: to_hex(&public), node_id: node_id_for(&public) }
    }

    /// Load the identity, creating it on first run. An existing key is always loaded, never replaced.
    pub fn load_or_create(target: &Path) -> Result<Identity, IdentityError> {
        if target.exists() {
            return Identity::load(target);
        }
        let identity = Identity::from_seed(random_bytes::<32>());
        identity.save(target)?;
        Ok(identity)
    }

    pub fn load(target: &Path) -> Result<Identity, IdentityError> {
        let shown = target.display();
        let raw = fs::read_to_string(target).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => IdentityError(format!("no identity file at {shown}")),
            _ => IdentityError(format!("cannot read identity file {shown}: {e}")),
        })?;
        if let Some(problem) = private_file_problem(target).map_err(|e| IdentityError(e.to_string()))? {
            return Err(IdentityError(format!("identity file {shown} {problem}")));
        }
        let document = pyjson::loads_str(&raw).map_err(|_| IdentityError(format!("identity file {shown} is not valid JSON")))?;
        let doc = document.as_object().ok_or_else(|| IdentityError(format!("identity file {shown} is not valid JSON")))?;
        if doc.get("version").and_then(Value::as_number) != Some(1.0) {
            return Err(IdentityError(format!("identity file {shown} has unsupported version")));
        }
        if !doc.get("algorithm").is_some_and(|v| v.is_str("ed25519")) {
            return Err(IdentityError(format!("identity file {shown} has unsupported algorithm")));
        }
        let private = doc
            .get("private_key_hex")
            .and_then(Value::as_str)
            .ok_or_else(|| IdentityError(format!("identity file {shown} has no private_key_hex")))?;
        let seed = from_hex(private)
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .ok_or_else(|| IdentityError(format!("identity file {shown} does not contain a usable key")))?;
        Ok(Identity::from_seed(seed))
    }

    fn save(&self, target: &Path) -> Result<(), IdentityError> {
        let document = object([
            ("version", Value::int(1)),
            ("algorithm", Value::str("ed25519")),
            ("private_key_hex", Value::str(to_hex(&self.key.to_bytes()))),
            ("public_key_hex", Value::str(self.public_key_hex.clone())),
            ("node_id", Value::str(self.node_id.clone())),
            ("created", Value::str(crate::isotime::now_iso())),
        ]);
        write_private_file(target, format!("{}\n", pyjson::indented(&document)).as_bytes())
            .map_err(|e| IdentityError(format!("cannot write identity file {}: {e}", target.display())))
    }

    /// The forms of the private key a reply must never contain.
    pub fn secret_forms(&self) -> Vec<String> {
        let seed = self.key.to_bytes();
        vec![to_hex(&seed), b64encode(&seed)]
    }

    pub fn sign(&self, domain: &[u8], payload: &Value) -> String {
        b64encode(&self.key.sign(&domain_separated_bytes(domain, payload)).to_bytes())
    }
}

/// Why a secret file is not private to this user, if it is not: read by the caller at load, so a
/// key other accounts can read is refused rather than used.
#[cfg(unix)]
pub fn private_file_problem(target: &Path) -> std::io::Result<Option<String>> {
    let mode = fs::metadata(target)?.permissions().mode() & 0o7777;
    Ok((mode & 0o077 != 0).then(|| format!("is group/world accessible (mode {mode:04o}); expected 0600")))
}

#[cfg(windows)]
pub fn private_file_problem(target: &Path) -> std::io::Result<Option<String>> {
    crate::winsec::private_file_problem(target)
}

/// A new directory for secrets, closed to other users: 0700, or a private access list on Windows.
#[cfg(unix)]
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)
}

#[cfg(windows)]
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    crate::winsec::make_dir_private(dir)
}

/// A new, empty file for secrets, closed to other users before anything is written to it.
#[cfg(unix)]
fn create_private_file(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
}

#[cfg(windows)]
fn create_private_file(path: &Path) -> std::io::Result<fs::File> {
    let file = fs::OpenOptions::new().write(true).create_new(true).open(path)?;
    crate::winsec::make_file_private(path)?;
    Ok(file)
}

/// Write secret bytes atomically in a file only this user can read (0600, or a private access
/// list on Windows), creating the directory the same way.
pub fn write_private_file(target: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = target.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    if !dir.exists() {
        create_private_dir(dir)?;
    }
    let temp = dir.join(format!(".identity-{}.tmp", token_hex16()));
    let result = (|| {
        let mut file = create_private_file(&temp)?;
        file.write_all(data)?;
        file.sync_all()?;
        // Windows cannot be relied on to rename a file that is still open.
        drop(file);
        fs::rename(&temp, target)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}


#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("eureka-crypto-{}", token_hex16()))
    }

    #[test]
    fn a_saved_identity_is_private_and_loads_as_the_same_node() {
        let dir = temp_dir();
        let path = dir.join("nested").join("identity.key");
        let made = Identity::load_or_create(&path).unwrap();
        assert_eq!(private_file_problem(&path).unwrap(), None);
        assert_eq!(Identity::load(&path).unwrap().node_id, made.node_id);
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn an_identity_other_accounts_can_read_is_refused() {
        let dir = temp_dir();
        let path = dir.join("identity.key");
        Identity::load_or_create(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let refused = Identity::load(&path).err().unwrap().to_string();
        assert!(refused.contains("group/world accessible (mode 0644); expected 0600"), "{refused}");
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(windows)]
    #[test]
    fn an_identity_other_accounts_can_read_is_refused() {
        let dir = temp_dir();
        let path = dir.join("identity.key");
        Identity::load_or_create(&path).unwrap();
        // S-1-1-0 is Everyone.
        let granted = std::process::Command::new("icacls").arg(&path).args(["/grant", "*S-1-1-0:R"]).output().unwrap();
        assert!(granted.status.success(), "{granted:?}");
        let refused = Identity::load(&path).err().unwrap().to_string();
        assert!(refused.contains("S-1-1-0"), "{refused}");
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(windows)]
    #[test]
    fn a_new_secret_directory_is_private_too() {
        let dir = temp_dir();
        let path = dir.join("identity.key");
        Identity::load_or_create(&path).unwrap();
        let shown = std::process::Command::new("icacls").arg(&dir).output().unwrap();
        let shown = String::from_utf8_lossy(&shown.stdout).to_string();
        assert!(!shown.contains("BUILTIN\\Users"), "{shown}");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn base64_matches_python_strict_decoding() {
        assert_eq!(b64decode_strict("AA==").unwrap(), vec![0]);
        assert_eq!(b64decode_strict("AAA=").unwrap(), vec![0, 0]);
        assert_eq!(b64decode_strict("AR==").unwrap(), vec![1]);
        assert_eq!(b64decode_strict("").unwrap(), Vec::<u8>::new());
        for bad in ["AA", "AAAA=", "AA=A", "A===", "AAAA==", "====", "AA!=", "AAAA AAAA"] {
            assert!(b64decode_strict(bad).is_none(), "{bad}");
        }
        assert_eq!(b64encode(b"\x00\x01\x02\x03"), "AAECAw==");
    }

    #[test]
    fn hex_matches_bytes_fromhex() {
        assert_eq!(from_hex("0a FF\t10").unwrap(), vec![10, 255, 16]);
        assert!(from_hex("0 a").is_none());
        assert!(from_hex("abc").is_none());
    }
}
