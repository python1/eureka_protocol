// SPDX-License-Identifier: AGPL-3.0-only
//! The shared contract: vectors/signatures-v1.json, which every implementation
//! must reproduce byte for byte. Read from the repository, never copied.

use crate::crypto::{self, to_hex};
use crate::pyjson::{self, Value};

const DOMAINS: [(&str, &[u8]); 6] = [
    ("handshake_offer", crypto::DOMAIN_HANDSHAKE_OFFER),
    ("handshake", crypto::DOMAIN_HANDSHAKE),
    ("handshake_confirm", crypto::DOMAIN_HANDSHAKE_CONFIRM),
    ("read_query", crypto::DOMAIN_READ_QUERY),
    ("assign_query", crypto::DOMAIN_ASSIGN_QUERY),
    ("assign_result", crypto::DOMAIN_ASSIGN_RESULT),
];

fn load() -> pyjson::Map {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/signatures-v1.json");
    let raw = std::fs::read(path).expect("vectors/signatures-v1.json");
    match pyjson::loads(&raw).expect("valid JSON") {
        Value::Object(m) => m,
        _ => panic!("vectors file is an object"),
    }
}

#[test]
fn all_30_vectors_match_byte_for_byte_and_verify() {
    let doc = load();
    let public_key = doc["public_key"].as_str().unwrap();
    let vectors = doc["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 30);
    for v in vectors {
        let v = v.as_object().unwrap();
        let name = v["domain"].as_str().unwrap();
        let (_, domain) = DOMAINS.iter().find(|(n, _)| *n == name).expect("known domain");
        assert_eq!(v["domain_tag"].as_str().unwrap().as_bytes(), *domain);
        let signed = crypto::domain_separated_bytes(domain, &v["payload"]);
        assert_eq!(to_hex(&signed), v["signed_bytes_hex"].as_str().unwrap(), "{name}");
        let signature = v["signature"].as_str().unwrap();
        assert!(crypto::verify_json(public_key, signature, &v["payload"], domain), "{name}");
        // Bound to its domain and to its payload.
        assert!(!crypto::verify_json(public_key, signature, &v["payload"], crypto::DOMAIN_AUDIT_LOG));
        let mut altered = v["payload"].as_object().unwrap().clone();
        altered.insert("extra".into(), Value::int(1));
        assert!(!crypto::verify_json(public_key, signature, &Value::Object(altered), domain));
    }
    let key = crypto::from_hex(public_key).unwrap();
    assert_eq!(crypto::node_id_for(&key), doc["node_id"].as_str().unwrap());
}

#[test]
fn signing_with_the_published_test_seed_reproduces_every_signature() {
    // vectors/make_signature_vectors.py: SEED = sha256(b"eureka signature test vectors v1 -- never trust this key").
    use ed25519_dalek::Signer;
    use sha2::Digest;
    let seed: [u8; 32] = sha2::Sha256::digest(b"eureka signature test vectors v1 -- never trust this key").into();
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    for v in load()["vectors"].as_array().unwrap() {
        let v = v.as_object().unwrap();
        let (_, domain) = DOMAINS.iter().find(|(n, _)| *n == v["domain"].as_str().unwrap()).unwrap();
        let signature = crypto::b64encode(&key.sign(&crypto::domain_separated_bytes(domain, &v["payload"])).to_bytes());
        assert_eq!(signature, v["signature"].as_str().unwrap());
    }
}

// ---------------------------------------------------------------------------
// vectors/plans-v1.json: plan hashes and passkey approvals (vectors/make_plan_vectors.py).

fn at<'a>(v: &'a Value, k: &str) -> &'a Value {
    &v.as_object().unwrap_or_else(|| panic!("{k}: not an object"))[k]
}

fn load_plans() -> pyjson::Map {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/plans-v1.json");
    match pyjson::loads(&std::fs::read(path).expect("vectors/plans-v1.json")).expect("valid JSON") {
        Value::Object(m) => m,
        _ => panic!("vectors file is an object"),
    }
}

#[test]
fn every_plan_vector_hashes_and_refuses_as_listed() {
    use crate::plan::{pattern_matches, Plan, DOMAIN_PLAN};
    let doc = load_plans();
    assert_eq!(at(&doc["domains"], "plan").as_str().unwrap().as_bytes(), DOMAIN_PLAN);
    for v in doc["plans"].as_array().unwrap() {
        let name = at(v, "name").as_str().unwrap();
        let plan = Plan::parse(at(v, "plan_json").as_str().unwrap()).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(pyjson::canonical(&plan.value), at(v, "canonical").as_str().unwrap(), "{name}");
        assert_eq!(to_hex(&crypto::domain_separated_bytes(DOMAIN_PLAN, &plan.value)), at(v, "signed_bytes_hex").as_str().unwrap(), "{name}");
        assert_eq!(plan.hash, at(v, "plan_hash").as_str().unwrap(), "{name}");
    }
    let invalid = doc["invalid_plans"].as_array().unwrap();
    assert!(invalid.len() >= 25);
    for v in invalid {
        let name = at(v, "name").as_str().unwrap();
        let refused = Plan::parse(at(v, "plan_json").as_str().unwrap()).map(|_| "accepted").unwrap_or_else(|e| e.code);
        assert_eq!(refused, at(v, "code").as_str().unwrap(), "{name}");
    }
    for case in doc["pattern_matches"].as_array().unwrap() {
        let c = case.as_array().unwrap();
        let (pattern, path) = (c[0].as_str().unwrap(), c[1].as_str().unwrap());
        assert_eq!(pattern_matches(pattern, path), matches!(c[2], Value::Bool(true)), "{pattern} {path}");
    }
}

#[test]
fn every_approval_vector_gives_its_listed_result() {
    use crate::approval::{b64url_encode, challenge, check, ApplyTarget, Approver, Expected, DOMAIN_APPROVAL};
    let doc = load_plans();
    assert_eq!(at(&doc["domains"], "approval").as_str().unwrap().as_bytes(), DOMAIN_APPROVAL);
    let a = &doc["approver"];
    let s = |v: &Value, k: &str| at(v, k).as_str().unwrap().to_string();
    let approver = Approver::new(&s(a, "credential_id"), &s(a, "public_key"), &s(a, "origin")).unwrap();
    assert_eq!(approver.rp_id, s(a, "rp_id"));
    assert_eq!(approver.fingerprint(), s(a, "fingerprint"));
    let vectors = doc["approvals"].as_array().unwrap();
    assert!(vectors.len() >= 16);
    for v in vectors {
        let name = at(v, "name").as_str().unwrap();
        assert_eq!(b64url_encode(&challenge(&at(v, "approval"))), s(v, "challenge"), "{name}");
        let e = &at(v, "expected");
        let target = e.as_object().unwrap().get("apply").map(|t| ApplyTarget { run_id: s(t, "run_id"), diff_hash: s(t, "diff_hash"), base_commit: s(t, "base_commit") });
        let (seat, requester, room, plan) = (s(e, "seat_id"), s(e, "requester_id"), s(e, "room_id"), s(e, "plan_hash"));
        let expected = Expected { seat_id: &seat, requester_id: &requester, room_id: &room, plan_hash: &plan, apply: target.as_ref() };
        let now: i64 = match &at(v, "now") { Value::Int(n) => n.parse().unwrap(), _ => panic!("now") };
        let result = check(&approver, &at(v, "approval"), &at(v, "assertion"), &expected, now).map(|_| "ok").unwrap_or_else(|r| r.reason);
        assert_eq!(result, at(v, "result").as_str().unwrap(), "{name}");
    }
}
