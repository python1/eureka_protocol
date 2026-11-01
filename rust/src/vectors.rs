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
