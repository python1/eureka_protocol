//! The protocol: the three-message handshake, the signed-request gate, assign,
//! the authenticated reads and the audit log.
//!
//! A line-for-line port of node.py, signed_request.py, assign.py, reads.py and
//! the responder half of discovery.py. The checks run in the same order and
//! refuse with the same reasons, the replay tables are bounded and pruned the
//! same way, and every answer has the same fields, because the peers on the
//! other end -- Knights Circle's browser client and the Python client -- were
//! written against those exact shapes.

use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use indexmap::IndexMap;

use crate::crypto::{self, Identity};
use crate::handlers::HandlerResult;
use crate::isotime;
use crate::pyjson::{object, py_len, py_strip, Map, Value};
use crate::trust::TrustList;

pub const HANDSHAKE_FRESHNESS_SECONDS: f64 = 30.0;
pub const MAX_PENDING_CHALLENGES: usize = 1024;
pub const MAX_SEEN_NONCES: usize = 4096;

pub const PROTOCOL: &str = "eureka/1.0";
const CHALLENGE_EVENT: &str = "handshake_challenge";
const CHALLENGE_STRING_FIELDS: [&str; 4] = ["nonce", "timestamp", "initiator_id", "peer_id"];

pub const REASON_OK: &str = "authenticated";
pub const REASON_UNKNOWN_NONCE: &str = "unknown_nonce";
pub const REASON_REPLAYED_NONCE: &str = "replayed_nonce";
pub const REASON_MALFORMED: &str = "malformed_response";
pub const REASON_STALE: &str = "stale_timestamp";
pub const REASON_BAD_SIGNATURE: &str = "signature_verification_failed";
pub const REASON_CHALLENGE_MISMATCH: &str = "challenge_mismatch";
pub const REASON_WRONG_PEER: &str = "unexpected_responder";
pub const REASON_UNTRUSTED_KEY: &str = "untrusted_key";
pub const REASON_REVOKED_KEY: &str = "revoked_key";
pub const REASON_NOT_AUTHENTICATED: &str = "not_authenticated";
pub const REASON_NOT_PERMITTED: &str = "capability_not_granted";

pub const ASSIGN_EVENT: &str = "assign_query";
pub const PEERS_EVENT: &str = "peers_query";
pub const LOGS_EVENT: &str = "logs_query";
pub const MANIFEST_EVENT: &str = "manifest_query";
pub const DISCOVERY_EVENT: &str = "discovery_query";

const MAX_NONCE_LENGTH: usize = 128;
const MAX_TASK_NAME_LENGTH: usize = 256;
const MAX_CAPABILITY_LENGTH: usize = 256;
const MAX_QUERY_KEYS: usize = 128;

/// An instant, in microseconds since the epoch.
type Instant = i128;

#[allow(dead_code)] // Kept as node.py keeps them; nothing reads them yet.
pub struct PeerRecord {
    pub public_key: String,
    pub last_seen: f64,
    pub capabilities: Vec<String>,
}

pub struct Node {
    pub identity: Identity,
    pub node_id: String,
    /// What this node offers: exactly the registered handlers, sorted.
    pub capabilities: Vec<String>,
    pub trust: TrustList,
    pub session_id: String,
    pub freshness_seconds: f64,
    pub max_pending_challenges: usize,
    pub max_seen_nonces: usize,
    pub peers: IndexMap<String, PeerRecord>,
    pub pending_challenges: IndexMap<String, Map>,
    pub pending_peers: IndexMap<String, (String, String)>,
    pub seen_nonces: IndexMap<String, Instant>,
    pub seen_assign_nonces: IndexMap<String, Instant>,
    pub event_log: Vec<Value>,
}

/// `normalise_key`: canonical lowercase hex, or None.
pub fn normalise_key(v: Option<&Value>) -> Option<String> {
    let s = v?.as_str()?;
    let candidate = py_strip(s).to_lowercase();
    if py_len(&candidate) != 64 || crypto::from_hex(&candidate).is_none() {
        return None;
    }
    Some(candidate)
}

fn unix_time() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn str_or_null(s: Option<&str>) -> Value {
    s.map(Value::str).unwrap_or(Value::Null)
}

/// What answer_assign decided before any handler runs.
pub enum AssignDecision {
    Refused(Value),
    Dispatch { capability: String, task_name: String, nonce: String, peer_id: String, payload: Value },
}

impl Node {
    pub fn new(identity: Identity, capabilities: Vec<String>, trust: TrustList) -> Node {
        let node_id = identity.node_id.clone();
        Node {
            identity,
            node_id,
            capabilities,
            trust,
            session_id: format!("urn:uuid:{}", crypto::uuid4()),
            freshness_seconds: HANDSHAKE_FRESHNESS_SECONDS,
            max_pending_challenges: MAX_PENDING_CHALLENGES,
            max_seen_nonces: MAX_SEEN_NONCES,
            peers: IndexMap::new(),
            pending_challenges: IndexMap::new(),
            pending_peers: IndexMap::new(),
            seen_nonces: IndexMap::new(),
            seen_assign_nonces: IndexMap::new(),
            event_log: Vec::new(),
        }
    }

    fn log(&self, message: &str) {
        println!("[NODE {}] {}", self.node_id, message);
    }

    // -- Handshake state ----------------------------------------------------

    fn create_challenge(&mut self, peer_id: &str) -> Map {
        let challenge: Map = [
            ("protocol", Value::str(PROTOCOL)),
            ("event", Value::str(CHALLENGE_EVENT)),
            ("initiator_id", Value::str(self.node_id.clone())),
            ("peer_id", Value::str(peer_id)),
            ("nonce", Value::str(crypto::token_hex16())),
            ("timestamp", Value::str(isotime::now_iso())),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        let nonce = challenge["nonce"].as_str().unwrap().to_string();
        self.pending_challenges.insert(nonce, challenge.clone());
        self.prune_expired(None);
        self.log(&format!("Challenge issued to {peer_id}"));
        challenge
    }

    /// `validate_challenge`: exactly the six fields, the right protocol and event, four non-empty strings.
    fn valid_challenge(challenge: Option<&Value>) -> Option<&Map> {
        let map = challenge?.as_object()?;
        let required = ["protocol", "event", "nonce", "timestamp", "initiator_id", "peer_id"];
        if map.len() != required.len() || !required.iter().all(|k| map.contains_key(*k)) {
            return None;
        }
        if !map["protocol"].is_str(PROTOCOL) || !map["event"].is_str(CHALLENGE_EVENT) {
            return None;
        }
        CHALLENGE_STRING_FIELDS
            .iter()
            .all(|f| matches!(&map[*f], Value::Str(s) if !s.is_empty()))
            .then_some(map)
    }

    fn drop_pending(&mut self, nonce: &str) {
        self.pending_challenges.shift_remove(nonce);
        self.pending_peers.shift_remove(nonce);
    }

    fn evict_oldest<V>(table: &mut IndexMap<String, V>, limit: usize) {
        while table.len() > limit {
            table.shift_remove_index(0);
        }
    }

    /// Drop handshake and assign state past the freshness window, then enforce the caps.
    pub fn prune_expired(&mut self, now: Option<Instant>) {
        let now = now.unwrap_or_else(isotime::now_micros);
        let cutoff = now - (self.freshness_seconds * 1e6) as Instant;
        while let Some((nonce, challenge)) = self.pending_challenges.first() {
            let issued = challenge.get("timestamp").and_then(Value::as_str).and_then(isotime::parse_fromisoformat);
            if issued.is_some_and(|t| t >= cutoff) {
                break;
            }
            let nonce = nonce.clone();
            self.drop_pending(&nonce);
        }
        for table in [&mut self.seen_nonces, &mut self.seen_assign_nonces] {
            while table.first().is_some_and(|(_, t)| *t < cutoff) {
                table.shift_remove_index(0);
            }
        }
        while self.pending_challenges.len() > self.max_pending_challenges {
            let nonce = self.pending_challenges.first().unwrap().0.clone();
            self.drop_pending(&nonce);
        }
        Self::evict_oldest(&mut self.seen_nonces, self.max_seen_nonces);
        Self::evict_oldest(&mut self.seen_assign_nonces, self.max_seen_nonces);
    }

    fn handshake_result(&self, authenticated: bool, reason: &str, peer_id: Value) -> Value {
        object([
            ("event", Value::str(if authenticated { "handshake_established" } else { "handshake_rejected" })),
            ("authenticated", Value::Bool(authenticated)),
            ("reason", Value::str(reason)),
            ("session_id", Value::str(self.session_id.clone())),
            ("peer_id", peer_id),
            ("auth_type", Value::str("Ed25519")),
            ("timestamp", Value::str(isotime::now_iso())),
        ])
    }

    fn age(timestamp: Option<&Value>) -> Option<f64> {
        isotime::age_seconds(timestamp?.as_str()?)
    }

    /// Responder side of message 1: check the offer, then answer with message 2 and a counter-challenge.
    pub fn answer_handshake_offer(&mut self, offer: &Value) -> Value {
        let Some(offer) = offer.as_object() else {
            return self.handshake_result(false, REASON_MALFORMED, Value::Null);
        };
        let Some(challenge) = Self::valid_challenge(offer.get("challenge")) else {
            return self.handshake_result(false, REASON_MALFORMED, Value::Null);
        };
        let challenge = challenge.clone();
        let nonce = challenge["nonce"].as_str().unwrap().to_string();
        let peer_id = offer.get("initiator_id").cloned().unwrap_or(Value::Null);

        if self.seen_nonces.contains_key(&nonce) {
            return self.handshake_result(false, REASON_REPLAYED_NONCE, peer_id);
        }
        let Some(age) = Self::age(challenge.get("timestamp")) else {
            return self.handshake_result(false, REASON_MALFORMED, peer_id);
        };
        if age.abs() > self.freshness_seconds {
            return self.handshake_result(false, REASON_STALE, peer_id);
        }
        let (Some(Value::Str(signature)), Some(Value::Str(public_key))) = (offer.get("signature"), offer.get("public_key")) else {
            return self.handshake_result(false, REASON_MALFORMED, peer_id);
        };
        let challenge_value = Value::Object(challenge.clone());
        if !crypto::verify_json(public_key, signature, &challenge_value, crypto::DOMAIN_HANDSHAKE_OFFER) {
            return self.handshake_result(false, REASON_BAD_SIGNATURE, peer_id);
        }
        let initiator = challenge["initiator_id"].as_str().unwrap().to_string();
        if !peer_id.is_str(&initiator) {
            return self.handshake_result(false, REASON_WRONG_PEER, peer_id);
        }
        if self.trust.is_revoked(public_key) {
            self.log("Rejected offer: revoked key");
            return self.handshake_result(false, REASON_REVOKED_KEY, peer_id);
        }
        if !self.trust.trusts(public_key) {
            self.log("Rejected offer: untrusted key");
            return self.handshake_result(false, REASON_UNTRUSTED_KEY, peer_id);
        }

        self.seen_nonces.insert(nonce, isotime::now_micros());
        let counter = self.create_challenge(&initiator);
        let counter_nonce = counter["nonce"].as_str().unwrap().to_string();
        self.pending_peers.insert(counter_nonce, (initiator, public_key.clone()));

        object([
            ("event", Value::str("handshake_response")),
            ("responder_id", Value::str(self.node_id.clone())),
            ("signature", Value::str(self.identity.sign(crypto::DOMAIN_HANDSHAKE, &challenge_value))),
            ("challenge", challenge_value),
            ("public_key", Value::str(self.identity.public_key_hex.clone())),
            ("counter_challenge", Value::Object(counter)),
        ])
        .reordered(&["event", "responder_id", "challenge", "signature", "public_key", "counter_challenge"])
    }

    /// The ordered check sequence over message 3. Ok((nonce, public_key, peer_id)) or Err((rejection, nonce)).
    fn verify_confirmation(&self, reply: &Value) -> Result<(String, String, String), (Value, Option<String>)> {
        let malformed = |peer: Value| self.handshake_result(false, REASON_MALFORMED, peer);
        let reply = reply.as_object().ok_or_else(|| (malformed(Value::Null), None))?;
        let challenge = reply.get("challenge").and_then(Value::as_object).ok_or_else(|| (malformed(Value::Null), None))?;
        let nonce = challenge.get("nonce").and_then(Value::as_str).ok_or_else(|| (malformed(Value::Null), None))?.to_string();
        if self.seen_nonces.contains_key(&nonce) {
            self.log("Rejected handshake: nonce already used");
            return Err((self.handshake_result(false, REASON_REPLAYED_NONCE, Value::Null), Some(nonce)));
        }
        let Some(pending) = self.pending_challenges.get(&nonce) else {
            return Err((self.handshake_result(false, REASON_UNKNOWN_NONCE, Value::Null), Some(nonce)));
        };
        let peer_id = pending.get("peer_id").and_then(Value::as_str).unwrap_or_default().to_string();
        let peer = || Value::str(peer_id.clone());
        let fail = |reason: &str| Err((self.handshake_result(false, reason, peer()), Some(nonce.clone())));

        let Some(age) = Self::age(challenge.get("timestamp")) else { return fail(REASON_MALFORMED) };
        if age.abs() > self.freshness_seconds {
            self.log(&format!("Rejected handshake: challenge {age:.1}s old"));
            return fail(REASON_STALE);
        }
        let (Some(Value::Str(signature)), Some(Value::Str(public_key))) = (reply.get("signature"), reply.get("public_key")) else {
            return fail(REASON_MALFORMED);
        };
        if !crypto::verify_json(public_key, signature, &Value::Object(challenge.clone()), crypto::DOMAIN_HANDSHAKE_CONFIRM) {
            self.log("Rejected handshake: bad signature");
            return fail(REASON_BAD_SIGNATURE);
        }
        // Python dict equality against our own copy, whose values are all strings.
        let same = challenge.len() == pending.len()
            && pending.iter().all(|(k, v)| challenge.get(k).is_some_and(|c| c.is_str(v.as_str().unwrap_or_default())));
        if !same {
            return fail(REASON_CHALLENGE_MISMATCH);
        }
        if !reply.get("initiator_id").is_some_and(|v| v.is_str(&peer_id)) {
            return fail(REASON_WRONG_PEER);
        }
        if self.trust.is_revoked(public_key) {
            self.log("Rejected handshake: revoked key");
            return fail(REASON_REVOKED_KEY);
        }
        if !self.trust.trusts(public_key) {
            self.log("Rejected handshake: untrusted key");
            return fail(REASON_UNTRUSTED_KEY);
        }
        Ok((nonce, public_key.clone(), peer_id))
    }

    /// Responder side of message 3: verify it and record the initiator.
    pub fn complete_mutual_handshake(&mut self, confirmation: &Value) -> Value {
        let result = match self.verify_confirmation(confirmation) {
            Err((rejection, nonce)) => {
                if let Some(nonce) = nonce {
                    self.drop_pending(&nonce);
                }
                rejection
            }
            Ok((nonce, public_key, peer_id)) => {
                let provisional = self.pending_peers.get(&nonce).map(|(_, key)| key.clone());
                if provisional.is_some_and(|key| key != public_key) {
                    self.drop_pending(&nonce);
                    self.handshake_result(false, REASON_WRONG_PEER, Value::str(peer_id))
                } else {
                    self.seen_nonces.insert(nonce.clone(), isotime::now_micros());
                    self.drop_pending(&nonce);
                    let capabilities = self.trust.capabilities_for(&public_key).into_iter().collect();
                    self.peers.insert(peer_id.clone(), PeerRecord { public_key, last_seen: unix_time(), capabilities });
                    self.log(&format!("Handshake established with {peer_id}"));
                    self.handshake_result(true, REASON_OK, Value::str(peer_id))
                }
            }
        };
        self.prune_expired(None);
        result
    }

    // -- The signed-request gate -------------------------------------------

    /// `signed_request.verify`. Ok((public_key, requester_id)) or the refusal reason.
    fn verify_request(
        &self,
        document: &Value,
        event: &str,
        domain: &[u8],
        extra_keys: &[&str],
        valid_body: Option<&dyn Fn(&Map) -> bool>,
    ) -> Result<(String, String), &'static str> {
        let doc = document.as_object().ok_or(REASON_MALFORMED)?;
        let query = doc.get("query").and_then(Value::as_object);
        let public_key = normalise_key(doc.get("public_key"));
        let signature = doc.get("signature").and_then(Value::as_str);
        let (Some(query), Some(public_key), Some(signature)) = (query, public_key, signature) else {
            return Err(REASON_MALFORMED);
        };
        let base = ["protocol", "event", "requester_id", "timestamp"];
        let required: BTreeSet<&str> = base.iter().chain(extra_keys).copied().collect();
        let present: BTreeSet<&str> = query.keys().map(String::as_str).collect();
        if present != required {
            return Err(REASON_MALFORMED);
        }
        if !query["protocol"].is_str(PROTOCOL) || !query["event"].is_str(event) {
            return Err(REASON_MALFORMED);
        }
        let requester_id = match &query["requester_id"] {
            Value::Str(s) if !s.is_empty() => s.clone(),
            _ => return Err(REASON_MALFORMED),
        };
        if !doc.get("requester_id").is_some_and(|v| v.is_str(&requester_id)) {
            return Err(REASON_MALFORMED);
        }
        if let Some(valid) = valid_body {
            if !valid(query) {
                return Err(REASON_MALFORMED);
            }
        }
        if !crypto::verify_json(&public_key, signature, &Value::Object(query.clone()), domain) {
            return Err(REASON_BAD_SIGNATURE);
        }
        let age = Self::age(query.get("timestamp")).ok_or(REASON_MALFORMED)?;
        if age.abs() > self.freshness_seconds {
            return Err(REASON_STALE);
        }
        if self.trust.is_revoked(&public_key) {
            return Err(REASON_REVOKED_KEY);
        }
        if !self.trust.trusts(&public_key) {
            return Err(REASON_UNTRUSTED_KEY);
        }
        match self.peers.get(&requester_id) {
            Some(record) if normalise_key(Some(&Value::str(record.public_key.clone()))).as_deref() == Some(public_key.as_str()) => {}
            _ => return Err(REASON_NOT_AUTHENTICATED),
        }
        Ok((public_key, requester_id))
    }

    /// Both gates: the trust file grants it and this node offers it.
    fn is_permitted(&self, peer_id: &str, capability: &str) -> bool {
        let capability = py_strip(capability);
        if capability.is_empty() {
            return false;
        }
        let Some(record) = self.peers.get(peer_id) else { return false };
        self.trust.capabilities_for(&record.public_key).contains(capability) && self.capabilities.iter().any(|c| c == capability)
    }

    // -- Assign --------------------------------------------------------------

    pub fn assign_rejected(reason: &str) -> Value {
        object([("event", Value::str("assign_rejected")), ("reason", Value::str(reason)), ("result", Value::Object(Map::new()))])
    }

    /// Authenticate, then check replay, then authorize. Dispatch happens outside the lock.
    pub fn decide_assign(&mut self, document: &Value) -> AssignDecision {
        let valid = |q: &Map| {
            let nonce_ok = matches!(q.get("nonce"), Some(Value::Str(n)) if (1..=MAX_NONCE_LENGTH).contains(&py_len(n)));
            let cap_ok = matches!(q.get("capability"), Some(Value::Str(c)) if (1..=MAX_CAPABILITY_LENGTH).contains(&py_len(py_strip(c))));
            let name_ok = matches!(q.get("task_name"), Some(Value::Str(t)) if (1..=MAX_TASK_NAME_LENGTH).contains(&py_len(py_strip(t))));
            nonce_ok && cap_ok && name_ok && matches!(q.get("payload"), Some(Value::Object(_)))
        };
        let extra = ["nonce", "capability", "task_name", "payload"];
        let (_, peer_id) = match self.verify_request(document, ASSIGN_EVENT, crypto::DOMAIN_ASSIGN_QUERY, &extra, Some(&valid)) {
            Ok(ok) => ok,
            Err(reason) => return AssignDecision::Refused(Self::assign_rejected(reason)),
        };
        let query = document.as_object().unwrap()["query"].as_object().unwrap();
        let nonce = query["nonce"].as_str().unwrap().to_string();
        let task_name = py_strip(query["task_name"].as_str().unwrap()).to_string();
        let capability = py_strip(query["capability"].as_str().unwrap()).to_string();

        self.prune_expired(None);
        if self.seen_assign_nonces.contains_key(&nonce) {
            self.log_refusal(&task_name, REASON_REPLAYED_NONCE, &peer_id, &capability);
            return AssignDecision::Refused(Self::assign_rejected(REASON_REPLAYED_NONCE));
        }
        self.seen_assign_nonces.insert(nonce.clone(), isotime::now_micros());
        Self::evict_oldest(&mut self.seen_assign_nonces, self.max_seen_nonces);

        if !self.is_permitted(&peer_id, &capability) {
            self.log_refusal(&task_name, REASON_NOT_PERMITTED, &peer_id, &capability);
            return AssignDecision::Refused(Self::assign_rejected(REASON_NOT_PERMITTED));
        }
        self.log(&format!("Dispatching task: {task_name} ({capability})"));
        AssignDecision::Dispatch { capability, task_name, nonce, peer_id, payload: query["payload"].clone() }
    }

    /// The signed answer to a request that ran, whatever the handler made of it.
    pub fn finish_assign(&mut self, capability: &str, task_name: &str, nonce: &str, peer_id: &str, outcome: HandlerResult) -> Value {
        let result = object([
            ("protocol", Value::str(PROTOCOL)),
            ("event", Value::str("assign_result")),
            ("task_id", Value::str(crypto::uuid4())),
            ("status", Value::str(outcome.status)),
            ("reason", Value::str(outcome.reason.clone())),
            ("capability", Value::str(capability)),
            ("task_name", Value::str(task_name)),
            ("responder_id", Value::str(self.node_id.clone())),
            ("requester_id", Value::str(peer_id)),
            ("nonce", Value::str(nonce)),
            ("output", outcome.output),
            ("timestamp", Value::str(isotime::now_iso())),
        ]);
        self.log_event(task_name, outcome.status, Some(&outcome.reason), Some(peer_id), Some(capability));
        let signature = self.identity.sign(crypto::DOMAIN_ASSIGN_RESULT, &result);
        object([
            ("event", Value::str("assign_answer")),
            ("responder_id", Value::str(self.node_id.clone())),
            ("reason", Value::str(REASON_OK)),
            ("result", result),
            ("result_signature", Value::str(signature)),
        ])
    }

    fn log_refusal(&mut self, task_name: &str, reason: &str, peer_id: &str, capability: &str) {
        self.log_event(task_name, "refused", Some(reason), Some(peer_id), Some(capability));
    }

    /// A signed audit entry naming who asked, which capability and what came of it -- never the work itself.
    fn log_event(&mut self, task_name: &str, status: &str, reason: Option<&str>, peer: Option<&str>, capability: Option<&str>) {
        let outcome = if status == "completed" { status } else { reason.filter(|r| !r.is_empty()).unwrap_or(status) };
        let entry = object([
            ("protocol", Value::str(PROTOCOL)),
            ("event", Value::str("task_execution_complete")),
            ("session_id", Value::str(self.session_id.clone())),
            ("timestamp", Value::str(isotime::now_iso())),
            ("initiator_node", Value::str(self.node_id.clone())),
            ("peer", str_or_null(peer)),
            ("capability", str_or_null(capability)),
            ("task_summary", Value::str(task_name)),
            ("result", Value::str(status)),
            ("outcome", Value::str(outcome)),
        ]);
        let signature = self.identity.sign(crypto::DOMAIN_AUDIT_LOG, &entry);
        self.event_log.push(object([("payload", entry), ("signature", Value::str(signature)), ("auth_type", Value::str("Ed25519"))]));
        self.log(&format!("EUREKA-LOG generated for task {task_name}"));
    }

    // -- Authenticated reads and discovery ------------------------------------

    pub fn read_rejected(event: &str, reason: &str) -> Value {
        let (field, empty) = match event {
            PEERS_EVENT => ("peers", Value::Object(Map::new())),
            LOGS_EVENT => ("logs", Value::Array(Vec::new())),
            MANIFEST_EVENT => ("manifest", Value::Object(Map::new())),
            _ => ("result", Value::Object(Map::new())),
        };
        object([("event", Value::str("read_rejected")), ("reason", Value::str(reason)), (field, empty)])
    }

    pub fn discovery_rejected(reason: &str) -> Value {
        object([("event", Value::str("discovery_rejected")), ("reason", Value::str(reason)), ("addresses", Value::Object(Map::new()))])
    }

    fn keys_body(q: &Map) -> bool {
        matches!(q.get("keys"), Some(Value::Array(k)) if k.len() <= MAX_QUERY_KEYS)
    }

    pub fn answer_read(&self, event: &str, document: &Value) -> Value {
        let peers = event == PEERS_EVENT;
        let extra: &[&str] = if peers { &["keys"] } else { &[] };
        let body: Option<&dyn Fn(&Map) -> bool> = if peers { Some(&Self::keys_body) } else { None };
        let (_, peer_id) = match self.verify_request(document, event, crypto::DOMAIN_READ_QUERY, extra, body) {
            Ok(ok) => ok,
            Err(reason) => return Self::read_rejected(event, reason),
        };
        let head = |name: &str, value: Value| {
            object([
                ("event", Value::str(name)),
                ("responder_id", Value::str(self.node_id.clone())),
                ("reason", Value::str(REASON_OK)),
                (if name == "peers_answer" { "peers" } else if name == "logs_answer" { "logs" } else { "manifest" }, value),
            ])
        };
        match event {
            PEERS_EVENT => {
                let query = document.as_object().unwrap()["query"].as_object().unwrap();
                let wanted: BTreeSet<String> = query["keys"].as_array().unwrap().iter().filter_map(|k| normalise_key(Some(k))).collect();
                let mut disclosed = Map::new();
                for (peer_id, record) in &self.peers {
                    let Some(key) = normalise_key(Some(&Value::str(record.public_key.clone()))) else { continue };
                    if !wanted.contains(&key) || self.trust.is_revoked(&key) || !self.trust.trusts(&key) {
                        continue;
                    }
                    disclosed.insert(key, object([("peer_id", Value::str(peer_id.clone())), ("status", Value::str("authenticated"))]));
                }
                head("peers_answer", Value::Object(disclosed))
            }
            LOGS_EVENT => {
                let entitled = self
                    .event_log
                    .iter()
                    .filter(|e| e.as_object().and_then(|m| m.get("payload")).and_then(Value::as_object).is_some_and(|p| p.get("peer").is_some_and(|v| v.is_str(&peer_id))))
                    .cloned()
                    .collect();
                head("logs_answer", Value::Array(entitled))
            }
            _ => head(
                "manifest_answer",
                object([
                    ("node_id", Value::str(self.node_id.clone())),
                    ("runtime", Value::str("eureka-daemon")),
                    ("capabilities", Value::Array(self.capabilities.iter().map(Value::str).collect())),
                ]),
            ),
        }
    }

    /// Discovery, responder side. This daemon never learns addresses (only a
    /// client does), so an authenticated caller always hears "none known" --
    /// exactly what the Python daemon answers.
    pub fn answer_discovery(&self, document: &Value) -> Value {
        match self.verify_request(document, DISCOVERY_EVENT, crypto::DOMAIN_DISCOVERY_QUERY, &["keys"], Some(&Self::keys_body)) {
            Err(reason) => Self::discovery_rejected(reason),
            Ok(_) => object([
                ("event", Value::str("discovery_answer")),
                ("responder_id", Value::str(self.node_id.clone())),
                ("reason", Value::str(REASON_OK)),
                ("addresses", Value::Object(Map::new())),
            ]),
        }
    }
}

trait Reorder {
    fn reordered(self, order: &[&str]) -> Value;
}

impl Reorder for Value {
    /// Put an object's keys in the order the Python daemon emits them.
    fn reordered(self, order: &[&str]) -> Value {
        let Value::Object(mut map) = self else { return self };
        let mut out = Map::new();
        for key in order {
            if let Some(v) = map.shift_remove(*key) {
                out.insert(key.to_string(), v);
            }
        }
        out.extend(map);
        Value::Object(out)
    }
}
