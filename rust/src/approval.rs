// SPDX-License-Identifier: AGPL-3.0-only
//! The owner's approval of a plan: a passkey (WebAuthn, ES256) assertion over the exact approval,
//! made with Touch ID in Knights Circle and checked here against the one passkey the owner pinned
//! at the seat's own terminal (`eureka-daemon approver add`). The room key that carries the
//! request proves nothing on its own: Knights Circle signs every turn with it automatically.
//!
//! An approval is accepted only if all of these hold: it is signed by the pinned credential, for
//! the pinned origin and relying party, with the user present and verified; its challenge is the
//! hash of this approval; it is for this seat, this room key, this room and this plan (or, to
//! apply, this run, diff and base commit); it is in its time window, at most 10 minutes long; and
//! its id has never been used. The id is written to disk before anything runs, so a restart
//! doesn't make an approval usable again. `vectors/plans-v1.json` is the shared contract.

use crate::crypto::{self, domain_separated_bytes, to_hex};
use crate::pyjson::{self, object, Value};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const DOMAIN_APPROVAL: &[u8] = b"eureka/plan/approval/v1";
pub const MAX_LIFETIME_SECONDS: i64 = 600;
/// How far ahead of the seat's clock an approval may say it was issued.
pub const CLOCK_SKEW_SECONDS: i64 = 60;
pub const DEFAULT_ORIGIN: &str = "https://knights-circle.vercel.app";
pub const APPROVER_FILE: &str = "approver.json";
pub const STORE_FILE: &str = "approvals.json";
/// Used approvals kept at once; past this, approvals are refused until old ones expire.
pub const MAX_STORED: usize = 10_000;

pub const REASON_BAD_APPROVAL: &str = "bad_approval";
pub const REASON_EXPIRED: &str = "expired";
pub const REASON_REPLAYED: &str = "replayed";
pub const REASON_PLAN_MISMATCH: &str = "plan_mismatch";
pub const REASON_NO_APPROVER: &str = "no_approver";

const RUN_KEYS: [&str; 8] = ["approval_id", "expires_at", "issued_at", "kind", "plan_hash", "requester_id", "room_id", "seat_id"];
const APPLY_KEYS: [&str; 3] = ["base_commit", "diff_hash", "run_id"];
/// The DER SubjectPublicKeyInfo header of an uncompressed P-256 key, as a browser's
/// `getPublicKey()` returns it: id-ecPublicKey, prime256v1, a 66-byte bit string.
pub(crate) const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
    0x07, 0x03, 0x42, 0x00,
];
const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;

/// Why an approval was refused: a reason the room may see, and a detail for the seat's log.
#[derive(Debug, PartialEq, Eq)]
pub struct Refusal {
    pub reason: &'static str,
    pub detail: String,
}

fn refuse<T>(reason: &'static str, detail: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal { reason, detail: detail.into() })
}

// ---------------------------------------------------------------------------
// base64url, as WebAuthn writes it: no padding.

pub fn b64url_encode(data: &[u8]) -> String {
    crypto::b64encode(data).trim_end_matches('=').replace('+', "-").replace('/', "_")
}

pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    if s.contains(['+', '/', '=']) || s.len() % 4 == 1 {
        return None;
    }
    let mut standard = s.replace('-', "+").replace('_', "/");
    while standard.len() % 4 != 0 {
        standard.push('=');
    }
    crypto::b64decode_strict(&standard)
}

// ---------------------------------------------------------------------------
// The pinned approver

/// The owner's passkey, pinned at the seat's terminal. One per seat.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approver {
    pub credential_id: Vec<u8>,
    /// The DER SubjectPublicKeyInfo, as Knights Circle shows it.
    pub public_key: Vec<u8>,
    pub origin: String,
    pub rp_id: String,
}

/// An origin approvals may come from: `https://host`, or `http://localhost:PORT` and
/// `http://127.0.0.1:PORT` for a copy of Knights Circle run locally. Returns its host, the
/// relying party id.
pub fn origin_host(origin: &str) -> Option<String> {
    let host_ok = |h: &str| {
        !h.is_empty() && h.len() <= 253 && !h.starts_with(['.', '-']) && !h.ends_with('.')
            && h.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    };
    if let Some(host) = origin.strip_prefix("https://") {
        return host_ok(host).then(|| host.to_string());
    }
    let rest = origin.strip_prefix("http://")?;
    let (host, port) = rest.split_once(':')?;
    let port_ok = !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit()) && port.parse::<u16>().is_ok_and(|p| p > 0);
    (["localhost", "127.0.0.1"].contains(&host) && port_ok).then(|| host.to_string())
}

impl Approver {
    /// From what Knights Circle shows when it creates the passkey: the credential id and the
    /// public key, both base64url.
    pub fn new(credential_id: &str, public_key: &str, origin: &str) -> Result<Approver, String> {
        let credential_id = b64url_decode(credential_id.trim())
            .filter(|id| !id.is_empty() && id.len() <= 1023)
            .ok_or("the credential id is not base64url (copy it from Knights Circle)")?;
        let public_key = b64url_decode(public_key.trim()).ok_or("the public key is not base64url (copy it from Knights Circle)")?;
        verifying_key(&public_key).ok_or("the public key is not a P-256 passkey key")?;
        let rp_id = origin_host(origin).ok_or_else(|| format!("{origin:?} is not an https:// origin (or http://localhost:PORT)"))?;
        Ok(Approver { credential_id, public_key, origin: origin.to_string(), rp_id })
    }

    /// What the owner compares with the key Knights Circle shows: the first 16 hex digits of the
    /// public key's SHA-256, in groups of four.
    pub fn fingerprint(&self) -> String {
        let hex = to_hex(&Sha256::digest(&self.public_key));
        hex.as_bytes()[..16].chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(" ")
    }

    pub fn to_document(&self) -> Value {
        object([
            ("version", Value::int(1)),
            ("credential_id", Value::str(b64url_encode(&self.credential_id))),
            ("public_key", Value::str(b64url_encode(&self.public_key))),
            ("origin", Value::str(self.origin.as_str())),
        ])
    }

    pub fn from_document(doc: &Value) -> Result<Approver, String> {
        let field = |k: &str| doc.as_object().and_then(|m| m.get(k)).and_then(Value::as_str).ok_or(format!("the approver file has no {k}"));
        if !matches!(doc.as_object().and_then(|m| m.get("version")), Some(Value::Int(v)) if v == "1") {
            return Err("the approver file is not version 1".into());
        }
        Approver::new(field("credential_id")?, field("public_key")?, field("origin")?)
    }

    pub fn path(seat_dir: &Path) -> PathBuf {
        seat_dir.join(APPROVER_FILE)
    }

    /// The seat's pinned approver, if it has one.
    pub fn load(seat_dir: &Path) -> Result<Option<Approver>, String> {
        let path = Approver::path(seat_dir);
        let raw = match std::fs::read(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        let doc = pyjson::loads(&raw).map_err(|_| format!("{} is not valid JSON", path.display()))?;
        Approver::from_document(&doc).map(Some).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn save(&self, seat_dir: &Path) -> std::io::Result<()> {
        crypto::write_private_file(&Approver::path(seat_dir), (pyjson::indented(&self.to_document()) + "\n").as_bytes())
    }
}

fn verifying_key(spki: &[u8]) -> Option<VerifyingKey> {
    let point = spki.strip_prefix(&P256_SPKI_PREFIX[..])?;
    (point.len() == 65 && point[0] == 0x04).then_some(())?;
    VerifyingKey::from_sec1_bytes(point).ok()
}

// ---------------------------------------------------------------------------
// The approval

/// The fields an approval is signed over. A run approval has `kind: "run"`; an apply approval
/// has `kind: "apply"` and also names the run, its diff and the commit it was made from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approval {
    pub kind: String,
    pub plan_hash: String,
    pub seat_id: String,
    pub requester_id: String,
    pub room_id: String,
    pub approval_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub apply: Option<ApplyTarget>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyTarget {
    pub run_id: String,
    pub diff_hash: String,
    pub base_commit: String,
}

fn is_hex(s: &str, lengths: &[usize]) -> bool {
    lengths.contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_node_id(s: &str) -> bool {
    s.strip_prefix("node_").is_some_and(|h| is_hex(h, &[8]))
}

impl Approval {
    pub fn from_value(value: &Value) -> Result<Approval, String> {
        let Value::Object(map) = value else { return Err("an approval is an object".into()) };
        let apply = map.get("kind").is_some_and(|k| k.is_str("apply"));
        let expected: Vec<&str> = RUN_KEYS.iter().chain(if apply { &APPLY_KEYS[..] } else { &[] }).copied().collect();
        if map.len() != expected.len() || !expected.iter().all(|k| map.contains_key(*k)) {
            return Err(format!("an approval has exactly the fields {}", expected.join(", ")));
        }
        let s = |k: &str| map[k].as_str().map(str::to_string).ok_or(format!("{k} must be text"));
        let n = |k: &str| match &map[k] {
            Value::Int(v) => v.parse::<i64>().map_err(|_| format!("{k} is out of range")),
            _ => Err(format!("{k} must be a whole number of seconds")),
        };
        let approval = Approval {
            kind: s("kind")?,
            plan_hash: s("plan_hash")?,
            seat_id: s("seat_id")?,
            requester_id: s("requester_id")?,
            room_id: s("room_id")?,
            approval_id: s("approval_id")?,
            issued_at: n("issued_at")?,
            expires_at: n("expires_at")?,
            apply: if apply { Some(ApplyTarget { run_id: s("run_id")?, diff_hash: s("diff_hash")?, base_commit: s("base_commit")? }) } else { None },
        };
        if approval.kind != "run" && approval.kind != "apply" {
            return Err("kind must be run or apply".into());
        }
        if !is_hex(&approval.plan_hash, &[64]) {
            return Err("plan_hash must be 64 lower-case hex digits".into());
        }
        if !is_node_id(&approval.seat_id) || !is_node_id(&approval.requester_id) {
            return Err("seat_id and requester_id must be node ids".into());
        }
        let room_ok = (1..=64).contains(&approval.room_id.len()) && approval.room_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !room_ok {
            return Err("room_id must be 1 to 64 letters, digits and -".into());
        }
        if !is_hex(&approval.approval_id, &[32]) {
            return Err("approval_id must be 32 lower-case hex digits".into());
        }
        let lifetime = approval.expires_at - approval.issued_at;
        if approval.issued_at <= 0 || !(1..=MAX_LIFETIME_SECONDS).contains(&lifetime) {
            return Err(format!("an approval lasts 1 to {MAX_LIFETIME_SECONDS} seconds"));
        }
        if let Some(target) = &approval.apply {
            if !is_hex(&target.run_id, &[32]) || !is_hex(&target.diff_hash, &[64]) || !is_hex(&target.base_commit, &[40, 64]) {
                return Err("run_id, diff_hash and base_commit must be lower-case hex".into());
            }
        }
        Ok(approval)
    }
}

/// The WebAuthn challenge for an approval: SHA-256 of `eureka/plan/approval/v1`, NUL and the
/// canonical approval.
pub fn challenge(approval: &Value) -> [u8; 32] {
    Sha256::digest(domain_separated_bytes(DOMAIN_APPROVAL, approval)).into()
}

/// What the request must match, from the daemon's own state, never from the approval itself.
#[derive(Clone, Debug)]
pub struct Expected<'a> {
    pub seat_id: &'a str,
    pub requester_id: &'a str,
    pub room_id: &'a str,
    pub plan_hash: &'a str,
    /// For an apply: the run, diff and base commit the daemon holds for that run.
    pub apply: Option<&'a ApplyTarget>,
}

/// An approval that passed every check but the one-time store.
#[derive(Debug)]
pub struct Checked {
    pub approval: Approval,
    pub sign_count: u32,
}

/// Check a passkey assertion over an approval. `assertion` holds base64url `credential_id`,
/// `authenticator_data`, `client_data_json` and `signature` (DER), as the browser returns them.
pub fn check(approver: &Approver, approval: &Value, assertion: &Value, expected: &Expected, now: i64) -> Result<Checked, Refusal> {
    let parsed = Approval::from_value(approval).or_else(|why| refuse(REASON_BAD_APPROVAL, why))?;
    let field = |k: &str| {
        assertion.as_object().and_then(|m| m.get(k)).and_then(Value::as_str).and_then(b64url_decode)
            .ok_or_else(|| Refusal { reason: REASON_BAD_APPROVAL, detail: format!("the assertion has no base64url {k}") })
    };
    if field("credential_id")? != approver.credential_id {
        return refuse(REASON_BAD_APPROVAL, "signed by a passkey this seat hasn't pinned");
    }
    let (auth_data, client_data, signature) = (field("authenticator_data")?, field("client_data_json")?, field("signature")?);

    let client = pyjson::loads(&client_data).ok().and_then(|v| v.as_object().cloned())
        .ok_or_else(|| Refusal { reason: REASON_BAD_APPROVAL, detail: "clientDataJSON is not a JSON object".into() })?;
    if !client.get("type").is_some_and(|t| t.is_str("webauthn.get")) {
        return refuse(REASON_BAD_APPROVAL, "not a WebAuthn assertion");
    }
    if !client.get("challenge").is_some_and(|c| c.is_str(&b64url_encode(&challenge(approval)))) {
        return refuse(REASON_BAD_APPROVAL, "the passkey signed a different approval");
    }
    if !client.get("origin").is_some_and(|o| o.is_str(&approver.origin)) {
        return refuse(REASON_BAD_APPROVAL, "signed on a site other than the pinned origin");
    }
    if client.get("crossOrigin").is_some_and(|c| !matches!(c, Value::Bool(false))) || client.contains_key("topOrigin") {
        return refuse(REASON_BAD_APPROVAL, "signed inside another site's frame");
    }

    if auth_data.len() < 37 || auth_data[..32] != Sha256::digest(approver.rp_id.as_bytes())[..] {
        return refuse(REASON_BAD_APPROVAL, "signed for a different relying party");
    }
    let flags = auth_data[32];
    if flags & FLAG_USER_PRESENT == 0 || flags & FLAG_USER_VERIFIED == 0 {
        return refuse(REASON_BAD_APPROVAL, "the passkey didn't verify the user (Touch ID or the device passcode)");
    }
    let sign_count = u32::from_be_bytes(auth_data[33..37].try_into().unwrap());

    let key = verifying_key(&approver.public_key).ok_or_else(|| Refusal { reason: REASON_BAD_APPROVAL, detail: "the pinned key is unusable".into() })?;
    let signature = Signature::from_der(&signature).or_else(|_| refuse(REASON_BAD_APPROVAL, "the signature is not DER ECDSA"))?;
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data));
    if key.verify(&signed, &signature).is_err() {
        return refuse(REASON_BAD_APPROVAL, "the signature doesn't verify with the pinned passkey");
    }

    // Signed by the owner. Now: is it for this, here, now?
    if parsed.seat_id != expected.seat_id || parsed.requester_id != expected.requester_id || parsed.room_id != expected.room_id {
        return refuse(REASON_BAD_APPROVAL, "approved for another seat, room key or room");
    }
    if parsed.kind != if expected.apply.is_some() { "apply" } else { "run" } {
        return refuse(REASON_BAD_APPROVAL, format!("a {} approval can't be used here", parsed.kind));
    }
    if parsed.plan_hash != expected.plan_hash || parsed.apply.as_ref() != expected.apply {
        return refuse(REASON_PLAN_MISMATCH, "the plan (or diff) is not the one approved");
    }
    if now + CLOCK_SKEW_SECONDS < parsed.issued_at {
        return refuse(REASON_BAD_APPROVAL, "issued in the future: check this computer's clock");
    }
    if now > parsed.expires_at {
        return refuse(REASON_EXPIRED, "the approval has expired");
    }
    Ok(Checked { approval: parsed, sign_count })
}

// ---------------------------------------------------------------------------
// The one-time store

/// Approval ids already used, kept until they expire, and the passkey's last signature counter.
/// A file in the seat's folder, written in full (atomically, fsynced) before a run starts.
pub struct ApprovalStore {
    path: PathBuf,
}

impl ApprovalStore {
    pub fn new(seat_dir: &Path) -> ApprovalStore {
        ApprovalStore { path: seat_dir.join(STORE_FILE) }
    }

    fn read(&self) -> Result<(pyjson::Map, u32), Refusal> {
        let broken = |why: String| Refusal { reason: REASON_BAD_APPROVAL, detail: format!("{}: {why}; approvals are refused until it is fixed", self.path.display()) };
        let raw = match std::fs::read(&self.path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((pyjson::Map::new(), 0)),
            Err(e) => return Err(broken(e.to_string())),
        };
        let doc = pyjson::loads(&raw).ok().and_then(|v| v.as_object().cloned()).ok_or_else(|| broken("not a JSON object".into()))?;
        let used = doc.get("used").and_then(Value::as_object).cloned().ok_or_else(|| broken("no used list".into()))?;
        let count = match doc.get("sign_count") {
            Some(Value::Int(n)) => n.parse::<u32>().map_err(|_| broken("a bad sign_count".into()))?,
            _ => return Err(broken("no sign_count".into())),
        };
        Ok((used, count))
    }

    /// Mark an approval used, or refuse it if it was. Fails closed: if the store can't be read
    /// or written, the approval is refused.
    pub fn consume(&self, checked: &Checked, now: i64) -> Result<(), Refusal> {
        let (mut used, last_count) = self.read()?;
        let id = &checked.approval.approval_id;
        if used.contains_key(id) {
            return refuse(REASON_REPLAYED, "this approval was already used");
        }
        // A counter that stays 0 is normal for synced passkeys; one that moves must only go up.
        if (checked.sign_count != 0 || last_count != 0) && checked.sign_count <= last_count {
            return refuse(REASON_BAD_APPROVAL, "the passkey's signature counter went backwards: it may have been cloned");
        }
        used.retain(|_, expires| matches!(expires, Value::Int(e) if e.parse::<i64>().is_ok_and(|e| e >= now)));
        if used.len() >= MAX_STORED {
            return refuse(REASON_BAD_APPROVAL, "too many approvals in the last 10 minutes");
        }
        used.insert(id.clone(), Value::int(checked.approval.expires_at));
        let doc = object([("version", Value::int(1)), ("sign_count", Value::int(checked.sign_count.into())), ("used", Value::Object(used))]);
        crypto::write_private_file(&self.path, (pyjson::canonical(&doc) + "\n").as_bytes())
            .or_else(|e| refuse(REASON_BAD_APPROVAL, format!("cannot record the approval in {}: {e}", self.path.display())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;

    const NOW: i64 = 1_800_000_000;
    const SEAT: &str = "node_0123abcd";
    const ROOM_KEY: &str = "node_89abcdef";
    const ROOM: &str = "7d3c1f2e-0000-4000-8000-000000000001";
    const PLAN: &str = "3f9a000000000000000000000000000000000000000000000000000000000000";

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&Sha256::digest(b"approval unit tests -- never trust this key")).unwrap()
    }

    fn approver() -> Approver {
        let mut spki = P256_SPKI_PREFIX.to_vec();
        spki.extend_from_slice(signing_key().verifying_key().to_encoded_point(false).as_bytes());
        Approver::new(&b64url_encode(b"credential-1"), &b64url_encode(&spki), DEFAULT_ORIGIN).unwrap()
    }

    fn approval(id: &str) -> Value {
        pyjson::loads_str(&format!(
            r#"{{"kind":"run","plan_hash":"{PLAN}","seat_id":"{SEAT}","requester_id":"{ROOM_KEY}","room_id":"{ROOM}","approval_id":"{id}","issued_at":{},"expires_at":{}}}"#,
            NOW - 5,
            NOW + 595
        ))
        .unwrap()
    }

    struct Assertion {
        challenge: String,
        origin: String,
        kind: &'static str,
        cross_origin: &'static str,
        rp_id: String,
        flags: u8,
        count: u32,
    }

    fn assertion_for(approval: &Value) -> Assertion {
        Assertion {
            challenge: b64url_encode(&challenge(approval)),
            origin: DEFAULT_ORIGIN.into(),
            kind: "webauthn.get",
            cross_origin: "false",
            rp_id: "knights-circle.vercel.app".into(),
            flags: FLAG_USER_PRESENT | FLAG_USER_VERIFIED,
            count: 0,
        }
    }

    impl Assertion {
        fn sign(&self) -> Value {
            let client = format!(r#"{{"type":"{}","challenge":"{}","origin":"{}","crossOrigin":{}}}"#, self.kind, self.challenge, self.origin, self.cross_origin);
            let mut auth = Sha256::digest(self.rp_id.as_bytes()).to_vec();
            auth.push(self.flags);
            auth.extend_from_slice(&self.count.to_be_bytes());
            let mut signed = auth.clone();
            signed.extend_from_slice(&Sha256::digest(client.as_bytes()));
            let signature: Signature = signing_key().sign(&signed);
            object([
                ("credential_id", Value::str(b64url_encode(b"credential-1"))),
                ("authenticator_data", Value::str(b64url_encode(&auth))),
                ("client_data_json", Value::str(b64url_encode(client.as_bytes()))),
                ("signature", Value::str(b64url_encode(signature.to_der().as_bytes()))),
            ])
        }
    }

    fn expected() -> Expected<'static> {
        Expected { seat_id: SEAT, requester_id: ROOM_KEY, room_id: ROOM, plan_hash: PLAN, apply: None }
    }

    fn reason(approval: &Value, assertion: &Value, expected: &Expected, now: i64) -> &'static str {
        check(&approver(), approval, assertion, expected, now).map(|_| "ok").unwrap_or_else(|r| r.reason)
    }

    const ID: &str = "00112233445566778899aabbccddeeff";

    #[test]
    fn a_good_approval_passes_once_and_is_refused_after() {
        let a = approval(ID);
        let checked = check(&approver(), &a, &assertion_for(&a).sign(), &expected(), NOW).unwrap();
        let dir = std::env::temp_dir().join(format!("eureka-approvals-{}", crypto::token_hex16()));
        let store = ApprovalStore::new(&dir);
        store.consume(&checked, NOW).unwrap();
        assert_eq!(store.consume(&checked, NOW).unwrap_err().reason, REASON_REPLAYED);
        // A new store reads the same file: a restart doesn't forget.
        assert_eq!(ApprovalStore::new(&dir).consume(&checked, NOW).unwrap_err().reason, REASON_REPLAYED);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn every_part_of_the_assertion_is_checked() {
        let a = approval(ID);
        let base = || assertion_for(&a);
        let mut s = base();
        s.origin = "https://evil.example".into();
        assert_eq!(reason(&a, &s.sign(), &expected(), NOW), REASON_BAD_APPROVAL);
        let mut s = base();
        s.rp_id = "evil.example".into();
        assert_eq!(reason(&a, &s.sign(), &expected(), NOW), REASON_BAD_APPROVAL);
        let mut s = base();
        s.flags = FLAG_USER_PRESENT;
        assert_eq!(reason(&a, &s.sign(), &expected(), NOW), REASON_BAD_APPROVAL);
        let mut s = base();
        s.kind = "webauthn.create";
        assert_eq!(reason(&a, &s.sign(), &expected(), NOW), REASON_BAD_APPROVAL);
        let mut s = base();
        s.cross_origin = "true";
        assert_eq!(reason(&a, &s.sign(), &expected(), NOW), REASON_BAD_APPROVAL);
        // Signed for another approval.
        let other = approval("ffeeddccbbaa99887766554433221100");
        assert_eq!(reason(&a, &assertion_for(&other).sign(), &expected(), NOW), REASON_BAD_APPROVAL);
        // A signature from another key.
        let replaced = |field: &str, value: String| {
            let Value::Object(mut m) = base().sign() else { unreachable!() };
            m.insert(field.into(), Value::str(value));
            reason(&a, &Value::Object(m), &expected(), NOW)
        };
        let wrong: Signature = SigningKey::from_bytes(&Sha256::digest(b"another key")).unwrap().sign(b"x");
        assert_eq!(replaced("signature", b64url_encode(wrong.to_der().as_bytes())), REASON_BAD_APPROVAL);
        assert_eq!(replaced("signature", "not-der".into()), REASON_BAD_APPROVAL);
        // Another passkey's credential id.
        assert_eq!(replaced("credential_id", b64url_encode(b"credential-2")), REASON_BAD_APPROVAL);
    }

    #[test]
    fn the_approval_is_bound_to_this_seat_room_plan_and_time() {
        let a = approval(ID);
        let signed = assertion_for(&a).sign();
        assert_eq!(reason(&a, &signed, &expected(), NOW), "ok");
        assert_eq!(reason(&a, &signed, &Expected { seat_id: "node_ffffffff", ..expected() }, NOW), REASON_BAD_APPROVAL);
        assert_eq!(reason(&a, &signed, &Expected { requester_id: "node_ffffffff", ..expected() }, NOW), REASON_BAD_APPROVAL);
        assert_eq!(reason(&a, &signed, &Expected { room_id: "another-room", ..expected() }, NOW), REASON_BAD_APPROVAL);
        let other_plan = "4".repeat(64);
        assert_eq!(reason(&a, &signed, &Expected { plan_hash: &other_plan, ..expected() }, NOW), REASON_PLAN_MISMATCH);
        let target = ApplyTarget { run_id: "a".repeat(32), diff_hash: "b".repeat(64), base_commit: "c".repeat(40) };
        assert_eq!(reason(&a, &signed, &Expected { apply: Some(&target), ..expected() }, NOW), REASON_BAD_APPROVAL);
        assert_eq!(reason(&a, &signed, &expected(), NOW + 596), REASON_EXPIRED);
        assert_eq!(reason(&a, &signed, &expected(), NOW - 70), REASON_BAD_APPROVAL);
        // Changing the approval after it was signed changes its challenge.
        let Value::Object(mut m) = a.clone() else { unreachable!() };
        m.insert("expires_at".into(), Value::int(NOW + 600));
        assert_eq!(reason(&Value::Object(m), &signed, &expected(), NOW), REASON_BAD_APPROVAL);
    }

    #[test]
    fn malformed_approvals_are_refused() {
        let base = approval(ID);
        for (field, json) in [
            ("kind", "\"delete\""),
            ("plan_hash", "\"3F9A\""),
            ("seat_id", "\"me\""),
            ("approval_id", "\"short\""),
            ("room_id", "\"a/b\""),
            ("expires_at", &(NOW + 1000).to_string()),
            ("expires_at", &(NOW - 10).to_string()),
            ("issued_at", "\"now\""),
            ("extra", "1"),
        ] {
            let Value::Object(mut m) = base.clone() else { unreachable!() };
            m.insert(field.into(), pyjson::loads_str(json).unwrap());
            assert!(Approval::from_value(&Value::Object(m)).is_err(), "{field} {json}");
        }
        let Value::Object(mut m) = base.clone() else { unreachable!() };
        m.insert("kind".into(), Value::str("apply"));
        assert!(Approval::from_value(&Value::Object(m)).is_err(), "an apply needs its run, diff and commit");
    }

    #[test]
    fn a_moving_signature_counter_must_only_go_up() {
        let dir = std::env::temp_dir().join(format!("eureka-approvals-{}", crypto::token_hex16()));
        let store = ApprovalStore::new(&dir);
        let consume = |id: &str, count: u32| {
            let a = approval(id);
            let mut s = assertion_for(&a);
            s.count = count;
            let checked = check(&approver(), &a, &s.sign(), &expected(), NOW).unwrap();
            store.consume(&checked, NOW).map_err(|r| r.reason)
        };
        assert_eq!(consume(&"1".repeat(32), 5), Ok(()));
        assert_eq!(consume(&"2".repeat(32), 5), Err(REASON_BAD_APPROVAL));
        assert_eq!(consume(&"3".repeat(32), 6), Ok(()));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_approver_is_checked_and_round_trips() {
        let a = approver();
        assert_eq!(a.rp_id, "knights-circle.vercel.app");
        assert_eq!(Approver::from_document(&a.to_document()).unwrap(), a);
        assert_eq!(a.fingerprint().len(), 19);
        let key = b64url_encode(&a.public_key);
        assert!(Approver::new("", &key, DEFAULT_ORIGIN).is_err());
        assert!(Approver::new("abc+", &key, DEFAULT_ORIGIN).is_err());
        assert!(Approver::new("YWJj", &b64url_encode(&a.public_key[1..]), DEFAULT_ORIGIN).is_err());
        for origin in ["http://knights-circle.vercel.app", "https://a.example/path", "https://A.example", "https://a.example:8443", "http://localhost", "http://evil.example:80", "javascript:x"] {
            assert!(Approver::new("YWJj", &key, origin).is_err(), "{origin}");
        }
        assert!(Approver::new("YWJj", &key, "http://localhost:8000").is_ok());
        assert_eq!(b64url_decode(&b64url_encode(b"\xfb\xff")), Some(b"\xfb\xff".to_vec()));
    }
}
