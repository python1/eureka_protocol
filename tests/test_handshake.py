"""
Acceptance tests for the Eureka Protocol Ed25519 handshake (Objective 2).

pytest-asyncio is not installed in eureka_venv and the task forbids new
dependencies, so the async entry points are driven through asyncio.run()
via the run() helper below.
"""
import asyncio
import base64
import json
import time
from datetime import datetime, timedelta, timezone

import pytest

from eureka_protocol.src.eureka_daemon.crypto import (
    DOMAIN_AUDIT_LOG,
    DOMAIN_HANDSHAKE,
    EurekaCrypto,
    canonical_json_bytes,
    domain_separated_bytes,
)
from eureka_protocol.src.eureka_daemon.node import (
    EurekaNode,
    InvalidChallengeError,
    MAX_PENDING_CHALLENGES,
    REASON_BAD_SIGNATURE,
    REASON_MALFORMED,
    REASON_OK,
    REASON_REPLAYED_NONCE,
    REASON_STALE,
    REASON_UNKNOWN_NONCE,
)


def run(coro):
    """Drive a coroutine to completion without pytest-asyncio."""
    return asyncio.run(coro)


def make_node(node_id, **kwargs):
    return EurekaNode(
        node_id=node_id,
        crypto_engine=EurekaCrypto(),
        capabilities=["code-exec"],
        **kwargs,
    )


def trust(node, *peers, mutual=True):
    """
    Provision `node` to trust each peer's public key, and by default each peer
    to trust `node` back.

    The handshake is mutual, so a successful exchange needs trust in both
    directions: the responder checks the initiator's key at message 1 and the
    initiator checks the responder's at message 2. Pass mutual=False to
    provision only one direction, which is how the asymmetric-trust tests set
    themselves up. This is a provisioning action, never something the
    handshake does on its own.
    """
    for peer in peers:
        node.trust_list.add(peer.node_id, peer.crypto.get_public_key_hex())
        if mutual:
            peer.trust_list.add(node.node_id, node.crypto.get_public_key_hex())
    return node


@pytest.fixture
def responder():
    return make_node("node_responder")


@pytest.fixture
def initiator(responder):
    # Trusts the responder, so these tests exercise the handshake rather than
    # tripping over the allowlist. Tests about the allowlist itself live in
    # test_trust.py and build their own nodes.
    return trust(make_node("node_initiator"), responder)


def authenticated_peers(node):
    """Peer ids this node currently regards as authenticated."""
    return {
        pid for pid, info in node.peers.items()
        if info.get("status") == "authenticated"
    }


def stale_timestamp(seconds_ago):
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()


def age_challenge(node, challenge, seconds_ago):
    """
    Simulate a challenge that was genuinely issued `seconds_ago`.

    The timestamp is moved on both copies -- the one travelling on the wire
    and the issuer's pending record -- because a real aged challenge is old
    on both sides. Ageing only the wire copy would instead trip the
    tamper-detection check and never reach the freshness check.
    """
    timestamp = stale_timestamp(seconds_ago)
    challenge["timestamp"] = timestamp
    node.pending_challenges[challenge["nonce"]]["timestamp"] = timestamp
    return challenge


# ---------------------------------------------------------------------------
# 1. Round trip
# ---------------------------------------------------------------------------

def test_round_trip_authenticates_peer(initiator, responder):
    result = run(initiator.handshake(responder))

    assert result["authenticated"] is True
    assert result["reason"] == REASON_OK
    assert result["event"] == "handshake_established"

    assert responder.node_id in authenticated_peers(initiator)
    recorded = initiator.peers[responder.node_id]
    assert recorded["status"] == "authenticated"
    # The key recorded is the one that actually produced the signature.
    assert recorded["public_key"] == responder.crypto.get_public_key_hex()


def test_round_trip_uses_two_messages(initiator, responder):
    """The challenge really crosses the wire and really gets signed."""
    challenge = initiator.create_challenge(responder.node_id)
    assert challenge["nonce"]
    assert challenge["peer_id"] == responder.node_id

    response = responder.answer_challenge(challenge)
    assert response["public_key"] == responder.crypto.get_public_key_hex()
    # The signature verifies against the challenge that was sent, in the
    # handshake domain it was minted for.
    assert EurekaCrypto.verify_handshake(
        response["public_key"], response["signature"], challenge
    ) is True

    result = run(initiator.complete_handshake(response))
    assert result["authenticated"] is True


# ---------------------------------------------------------------------------
# 2. Tampered payload
# ---------------------------------------------------------------------------

def test_tampered_payload_rejected(initiator, responder):
    challenge = initiator.create_challenge(responder.node_id)
    response = responder.answer_challenge(challenge)

    # Alter the payload after it was signed.
    response["challenge"]["initiator_id"] = "node_attacker"

    result = run(initiator.complete_handshake(response))

    assert result["authenticated"] is False
    assert result["reason"] == REASON_BAD_SIGNATURE
    assert authenticated_peers(initiator) == set()


# ---------------------------------------------------------------------------
# 3. Wrong-key signature
# ---------------------------------------------------------------------------

def test_wrong_key_signature_rejected(initiator, responder):
    """An impostor signs the challenge but claims the real peer's key."""
    attacker = make_node("node_attacker")
    challenge = initiator.create_challenge(responder.node_id)

    forged = attacker.answer_challenge(challenge)
    forged["responder_id"] = responder.node_id
    forged["public_key"] = responder.crypto.get_public_key_hex()

    result = run(initiator.complete_handshake(forged))

    assert result["authenticated"] is False
    assert result["reason"] == REASON_BAD_SIGNATURE
    assert authenticated_peers(initiator) == set()


# ---------------------------------------------------------------------------
# 4. Malformed base64 signature
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_signature", [
    "!!!!not base64!!!!",
    "abc",              # incorrect padding
    "",                 # empty
    "@@@@",             # non-alphabet, would silently decode to b"" without validate=True
])
def test_malformed_base64_signature_rejected(initiator, responder, bad_signature):
    challenge = initiator.create_challenge(responder.node_id)
    response = responder.answer_challenge(challenge)
    response["signature"] = bad_signature

    result = run(initiator.complete_handshake(response))

    assert result["authenticated"] is False
    assert result["reason"] == REASON_BAD_SIGNATURE
    assert authenticated_peers(initiator) == set()


def test_verify_signature_returns_false_for_malformed_inputs():
    crypto = EurekaCrypto()
    data = b"payload"
    good_sig = crypto.sign_data(data)
    pub = crypto.get_public_key_hex()

    assert EurekaCrypto.verify_signature(pub, good_sig, data) is True
    assert EurekaCrypto.verify_signature(pub, "!!!!", data) is False
    assert EurekaCrypto.verify_signature(pub, "abc", data) is False
    # Unparseable / wrong-length public key is an encoding failure, not a crash.
    assert EurekaCrypto.verify_signature("zzzz", good_sig, data) is False
    assert EurekaCrypto.verify_signature("aabb", good_sig, data) is False


def test_unexpected_errors_propagate():
    """
    Requirement 6: only InvalidSignature and encoding errors are swallowed.
    A wrongly typed signature is a caller bug and must not be silently
    downgraded to 'not authenticated'.
    """
    crypto = EurekaCrypto()
    with pytest.raises(TypeError):
        EurekaCrypto.verify_signature(crypto.get_public_key_hex(), None, b"data")


# ---------------------------------------------------------------------------
# 5. Stale timestamp
# ---------------------------------------------------------------------------

def test_stale_timestamp_rejected(initiator, responder):
    challenge = initiator.create_challenge(responder.node_id)
    # The challenge sat on the wire far longer than the 30s default window.
    age_challenge(initiator, challenge, 120)
    response = responder.answer_challenge(challenge)  # signature is valid

    result = run(initiator.complete_handshake(response))

    assert result["authenticated"] is False
    assert result["reason"] == REASON_STALE
    assert authenticated_peers(initiator) == set()


def test_freshness_window_is_configurable():
    strict = make_node("node_strict", freshness_seconds=5)
    lenient = make_node("node_lenient", freshness_seconds=300)
    peer = make_node("node_peer")
    trust(strict, peer)
    trust(lenient, peer)

    for node in (strict, lenient):
        challenge = node.create_challenge(peer.node_id)
        age_challenge(node, challenge, 60)
        response = peer.answer_challenge(challenge)
        result = run(node.complete_handshake(response))
        if node is strict:
            assert result["authenticated"] is False
            assert result["reason"] == REASON_STALE
        else:
            assert result["authenticated"] is True


def test_default_freshness_window_is_30_seconds(initiator):
    assert initiator.freshness_seconds == 30.0


def test_malformed_timestamp_rejected(initiator, responder):
    challenge = initiator.create_challenge(responder.node_id)
    challenge["timestamp"] = "not-a-timestamp"
    response = responder.answer_challenge(challenge)

    result = run(initiator.complete_handshake(response))

    assert result["authenticated"] is False
    assert result["reason"] == REASON_MALFORMED
    assert authenticated_peers(initiator) == set()


# ---------------------------------------------------------------------------
# 6. Replayed nonce
# ---------------------------------------------------------------------------

def test_replayed_nonce_rejected(initiator, responder):
    challenge = initiator.create_challenge(responder.node_id)
    response = responder.answer_challenge(challenge)

    first = run(initiator.complete_handshake(response))
    assert first["authenticated"] is True

    # Capture and replay the identical, perfectly valid response.
    second = run(initiator.complete_handshake(response))

    assert second["authenticated"] is False
    assert second["reason"] == REASON_REPLAYED_NONCE


def test_unknown_nonce_rejected(initiator, responder):
    """A challenge this node never issued cannot authenticate anyone."""
    rogue = make_node("node_rogue")
    challenge = rogue.create_challenge(responder.node_id)
    response = responder.answer_challenge(challenge)

    result = run(initiator.complete_handshake(response))

    assert result["authenticated"] is False
    assert result["reason"] == REASON_UNKNOWN_NONCE
    assert authenticated_peers(initiator) == set()


def test_nonces_are_unique_per_challenge(initiator, responder):
    nonces = {initiator.create_challenge(responder.node_id)["nonce"]
              for _ in range(50)}
    assert len(nonces) == 50


# ---------------------------------------------------------------------------
# 7. An unauthenticated peer never appears in node.peers as authenticated
# ---------------------------------------------------------------------------

def _rejection_scenarios(initiator, responder):
    """(label, response) pairs, each of which must be rejected."""
    attacker = make_node("node_attacker")
    scenarios = []

    c = initiator.create_challenge(responder.node_id)
    r = responder.answer_challenge(c)
    r["challenge"]["peer_id"] = "node_somebody_else"
    scenarios.append(("tampered", r))

    c = initiator.create_challenge(responder.node_id)
    r = attacker.answer_challenge(c)
    r["responder_id"] = responder.node_id
    r["public_key"] = responder.crypto.get_public_key_hex()
    scenarios.append(("wrong_key", r))

    c = initiator.create_challenge(responder.node_id)
    r = responder.answer_challenge(c)
    r["signature"] = "!!!!"
    scenarios.append(("malformed_signature", r))

    c = age_challenge(initiator, initiator.create_challenge(responder.node_id), 300)
    scenarios.append(("stale", responder.answer_challenge(c)))

    c = initiator.create_challenge(responder.node_id)
    r = responder.answer_challenge(c)
    del r["signature"]
    scenarios.append(("missing_signature", r))

    c = initiator.create_challenge(responder.node_id)
    r = responder.answer_challenge(c)
    r["public_key"] = attacker.crypto.get_public_key_hex()
    scenarios.append(("swapped_public_key", r))

    # A third party relaying a legitimately signed challenge as its own.
    c = initiator.create_challenge(responder.node_id)
    r = responder.answer_challenge(c)
    r["responder_id"] = "node_attacker"
    scenarios.append(("impersonated_responder", r))

    return scenarios


def test_no_rejected_peer_is_ever_recorded_authenticated(initiator, responder):
    for label, response in _rejection_scenarios(initiator, responder):
        result = run(initiator.complete_handshake(response))
        assert result["authenticated"] is False, f"{label} was accepted"
        assert authenticated_peers(initiator) == set(), (
            f"{label} left an authenticated peer behind: {initiator.peers}"
        )

    # Nothing at all was written into the peer registry.
    assert initiator.peers == {}


def test_failed_handshake_does_not_block_later_success(initiator, responder):
    bad = initiator.create_challenge(responder.node_id)
    bad_response = responder.answer_challenge(bad)
    bad_response["signature"] = "!!!!"
    assert run(initiator.complete_handshake(bad_response))["authenticated"] is False
    assert authenticated_peers(initiator) == set()

    assert run(initiator.handshake(responder))["authenticated"] is True
    assert responder.node_id in authenticated_peers(initiator)


# ---------------------------------------------------------------------------
# Requirements 3 and 5: send-time timestamps, canonical serialization
# ---------------------------------------------------------------------------

def test_timestamp_is_generated_at_send_time(initiator, responder):
    constructed_at = datetime.now(timezone.utc)
    time.sleep(0.01)
    first = initiator.create_challenge(responder.node_id)
    time.sleep(0.01)
    second = initiator.create_challenge(responder.node_id)

    t1 = datetime.fromisoformat(first["timestamp"])
    t2 = datetime.fromisoformat(second["timestamp"])

    # Not frozen at construction, and not shared between challenges.
    assert t1 > constructed_at
    assert t2 > t1


def test_sign_json_uses_canonical_separators():
    payload = {"b": 1, "a": ["x", "y"], "nested": {"z": 0, "y": 1}}
    encoded = canonical_json_bytes(payload).decode()

    assert ", " not in encoded and ": " not in encoded
    assert encoded == json.dumps(payload, sort_keys=True, separators=(",", ":"))


def test_signature_is_independent_of_key_order():
    crypto = EurekaCrypto()
    a = {"alpha": 1, "beta": {"x": 1, "y": 2}}
    b = {"beta": {"y": 2, "x": 1}, "alpha": 1}

    assert crypto.sign_json(a, DOMAIN_HANDSHAKE) == crypto.sign_json(b, DOMAIN_HANDSHAKE)
    assert EurekaCrypto.verify_json(
        crypto.get_public_key_hex(), crypto.sign_json(a, DOMAIN_HANDSHAKE), b,
        DOMAIN_HANDSHAKE,
    ) is True


def test_sign_json_round_trips_through_the_wire():
    """A payload serialized, transmitted and reparsed still verifies."""
    crypto = EurekaCrypto()
    payload = {"nonce": "abc123", "timestamp": "2026-08-23T00:00:00+00:00"}
    signature = crypto.sign_json(payload, DOMAIN_HANDSHAKE)

    reparsed = json.loads(json.dumps(payload))
    assert EurekaCrypto.verify_json(
        crypto.get_public_key_hex(), signature, reparsed, DOMAIN_HANDSHAKE
    ) is True


# ===========================================================================
# Hardening: signing oracle (Problem 1)
# ===========================================================================

class SigningSpy:
    """
    Wraps a real EurekaCrypto and records every signing call.

    Used to prove answer_challenge signs *nothing* when it rejects a payload:
    asserting only that it raised would not rule out a signature having been
    minted first.
    """

    def __init__(self, inner):
        self._inner = inner
        self.calls = []

    def sign_handshake(self, payload):
        self.calls.append(("sign_handshake", payload))
        return self._inner.sign_handshake(payload)

    def sign_audit_log(self, payload):
        self.calls.append(("sign_audit_log", payload))
        return self._inner.sign_audit_log(payload)

    def sign_json(self, payload, *args, **kwargs):
        self.calls.append(("sign_json", payload))
        return self._inner.sign_json(payload, *args, **kwargs)

    def sign_data(self, data):
        self.calls.append(("sign_data", data))
        return self._inner.sign_data(data)

    def get_public_key_hex(self):
        return self._inner.get_public_key_hex()


def spying_node(node_id="node_spied"):
    node = make_node(node_id)
    node.crypto = SigningSpy(node.crypto)
    return node


def log_shaped_payload():
    """A payload shaped like an entry produced by the node's audit log layer."""
    return {
        "protocol": "eureka/1.0",
        "event": "task_execution_complete",
        "session_id": "urn:uuid:00000000-0000-0000-0000-000000000000",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "initiator_node": "node_attacker",
        "task_summary": "transfer_everything",
        "result": "completed",
    }


def test_answer_challenge_refuses_log_shaped_payload_and_signs_nothing():
    node = spying_node()

    with pytest.raises(InvalidChallengeError) as excinfo:
        node.answer_challenge(log_shaped_payload())

    # The oracle is closed: the private key was never touched.
    assert node.crypto.calls == []
    assert excinfo.value.reason in {"missing_fields", "unexpected_fields"}


def test_answer_challenge_refuses_task_shaped_payload_and_signs_nothing():
    node = spying_node()
    task = {"task_name": "compute_pi_digit", "payload": {"digits": 100}}

    with pytest.raises(InvalidChallengeError):
        node.answer_challenge(task)

    assert node.crypto.calls == []


@pytest.mark.parametrize("mutate, expected_reason", [
    (lambda c: c.pop("protocol"), "missing_fields"),
    (lambda c: c.update(protocol="eureka/2.0"), "wrong_protocol"),
    (lambda c: c.update(protocol=None), "wrong_protocol"),
    (lambda c: c.update(protocol=""), "wrong_protocol"),
    (lambda c: c.update(event="task_execution_complete"), "wrong_event"),
    (lambda c: c.pop("event"), "missing_fields"),
])
def test_answer_challenge_refuses_wrong_or_missing_protocol_field(
    initiator, mutate, expected_reason
):
    node = spying_node()
    challenge = initiator.create_challenge(node.node_id)
    mutate(challenge)

    with pytest.raises(InvalidChallengeError) as excinfo:
        node.answer_challenge(challenge)

    assert excinfo.value.reason == expected_reason
    assert node.crypto.calls == []


@pytest.mark.parametrize("extra", [
    {"task_summary": "exfiltrate"},
    {"result": "completed"},
    {"session_id": "urn:uuid:deadbeef"},
    {"harmless_looking": 1},
])
def test_answer_challenge_refuses_unexpected_extra_keys(initiator, extra):
    node = spying_node()
    challenge = initiator.create_challenge(node.node_id)
    challenge.update(extra)

    with pytest.raises(InvalidChallengeError) as excinfo:
        node.answer_challenge(challenge)

    assert excinfo.value.reason == "unexpected_fields"
    assert node.crypto.calls == []


@pytest.mark.parametrize("field", ["nonce", "timestamp", "initiator_id", "peer_id"])
def test_answer_challenge_refuses_missing_or_mistyped_required_fields(initiator, field):
    node = spying_node()

    missing = initiator.create_challenge(node.node_id)
    missing.pop(field)
    with pytest.raises(InvalidChallengeError) as excinfo:
        node.answer_challenge(missing)
    assert excinfo.value.reason == "missing_fields"

    mistyped = initiator.create_challenge(node.node_id)
    mistyped[field] = 12345
    with pytest.raises(InvalidChallengeError) as excinfo:
        node.answer_challenge(mistyped)
    assert excinfo.value.reason == "bad_field_type"

    assert node.crypto.calls == []


def test_answer_challenge_still_signs_a_well_formed_challenge(initiator):
    node = spying_node()
    challenge = initiator.create_challenge(node.node_id)

    response = node.answer_challenge(challenge)

    # Exactly one signing call, and it went through the handshake domain.
    # (Inner delegation happens on the wrapped object, so it is not recorded.)
    assert [c[0] for c in node.crypto.calls] == ["sign_handshake"]
    assert EurekaCrypto.verify_handshake(
        response["public_key"], response["signature"], challenge
    ) is True


# ===========================================================================
# Hardening: domain separation (Problem 1b/1c)
# ===========================================================================

def test_handshake_signature_does_not_verify_as_log_signature():
    crypto = EurekaCrypto()
    pub = crypto.get_public_key_hex()
    payload = {"protocol": "eureka/1.0", "event": "handshake_challenge"}

    handshake_sig = crypto.sign_handshake(payload)
    log_sig = crypto.sign_audit_log(payload)

    # Each verifies in its own domain...
    assert EurekaCrypto.verify_handshake(pub, handshake_sig, payload) is True
    assert EurekaCrypto.verify_audit_log(pub, log_sig, payload) is True

    # ...and in neither of the others.
    assert EurekaCrypto.verify_audit_log(pub, handshake_sig, payload) is False
    assert EurekaCrypto.verify_handshake(pub, log_sig, payload) is False

    # Same key, same payload, different bytes signed.
    assert handshake_sig != log_sig


def test_domain_tag_is_part_of_the_signed_bytes():
    payload = {"a": 1}
    handshake_bytes = domain_separated_bytes(DOMAIN_HANDSHAKE, payload)
    log_bytes = domain_separated_bytes(DOMAIN_AUDIT_LOG, payload)

    assert handshake_bytes.startswith(DOMAIN_HANDSHAKE)
    assert log_bytes.startswith(DOMAIN_AUDIT_LOG)
    assert handshake_bytes != log_bytes
    # The canonical payload is still in there, behind the tag separator.
    assert handshake_bytes.endswith(canonical_json_bytes(payload))


def test_real_audit_log_signature_cannot_be_used_as_a_handshake(initiator, responder):
    """End to end: a genuine log signature is unusable in the handshake path."""
    run(responder.assign({"task_name": "any_task", "payload": {}}))
    signed_log = responder.event_log[-1]

    challenge = initiator.create_challenge(responder.node_id)
    forged = {
        "event": "handshake_response",
        "responder_id": responder.node_id,
        "challenge": challenge,
        "signature": signed_log["signature"],
        "public_key": responder.crypto.get_public_key_hex(),
    }

    result = run(initiator.complete_handshake(forged))

    assert result["authenticated"] is False
    assert result["reason"] == REASON_BAD_SIGNATURE
    assert authenticated_peers(initiator) == set()


def test_handshake_signature_cannot_be_used_as_a_log_signature(initiator, responder):
    """The inverse: a handshake signature does not authenticate a log entry."""
    challenge = initiator.create_challenge(responder.node_id)
    response = responder.answer_challenge(challenge)

    assert EurekaCrypto.verify_audit_log(
        response["public_key"], response["signature"], challenge
    ) is False


def test_audit_log_entries_verify_in_the_audit_domain(responder):
    run(responder.assign({"task_name": "any_task", "payload": {}}))
    entry = responder.event_log[-1]
    pub = responder.crypto.get_public_key_hex()

    assert EurekaCrypto.verify_audit_log(pub, entry["signature"], entry["payload"]) is True
    assert EurekaCrypto.verify_handshake(pub, entry["signature"], entry["payload"]) is False


# ===========================================================================
# Hardening: bounded state (Problem 2)
# ===========================================================================

def test_ten_thousand_unanswered_challenges_leave_pending_bounded():
    """
    The flood is the attack in Problem 2: request challenges, never answer.
    Every one of these is inside the freshness window, so age-based pruning
    alone would not bound anything -- the cap is what holds the line.
    """
    node = make_node("node_flooded")

    for i in range(10_000):
        node.create_challenge(f"peer_{i}")

    assert len(node.pending_challenges) <= MAX_PENDING_CHALLENGES
    # Bounded, and the survivors are the most recent ones.
    assert len(node.pending_challenges) == MAX_PENDING_CHALLENGES
    last_nonce = list(node.pending_challenges)[-1]
    assert node.pending_challenges[last_nonce]["peer_id"] == "peer_9999"


def test_pending_cap_is_configurable():
    node = make_node("node_small", max_pending_challenges=16)
    for i in range(500):
        node.create_challenge(f"peer_{i}")
    assert len(node.pending_challenges) == 16


def test_expired_pending_challenges_are_pruned_by_age():
    node = make_node("node_ager")
    for i in range(5):
        node.create_challenge(f"peer_{i}")
    assert len(node.pending_challenges) == 5

    # Deterministic: drive the clock forward instead of sleeping.
    future = datetime.now(timezone.utc) + timedelta(seconds=120)
    counts = node.prune_expired(now=future)

    assert node.pending_challenges == {}
    assert counts["pending_expired"] == 5


def test_nonce_older_than_the_window_is_pruned_from_seen_nonces(initiator, responder):
    challenge = initiator.create_challenge(responder.node_id)
    response = responder.answer_challenge(challenge)
    assert run(initiator.complete_handshake(response))["authenticated"] is True

    nonce = challenge["nonce"]
    assert nonce in initiator.seen_nonces

    # Past the freshness window the nonce can no longer authenticate anything,
    # so retaining it buys nothing.
    future = datetime.now(timezone.utc) + timedelta(seconds=120)
    counts = initiator.prune_expired(now=future)

    assert nonce not in initiator.seen_nonces
    assert counts["nonces_expired"] == 1


def test_replay_protection_holds_inside_the_window(initiator, responder):
    """Pruning must not open a replay hole for a nonce still in the window."""
    challenge = initiator.create_challenge(responder.node_id)
    response = responder.answer_challenge(challenge)
    assert run(initiator.complete_handshake(response))["authenticated"] is True

    # A prune at "now" is well inside the 30s window: the nonce must survive.
    initiator.prune_expired()
    assert challenge["nonce"] in initiator.seen_nonces

    replayed = run(initiator.complete_handshake(response))
    assert replayed["authenticated"] is False
    assert replayed["reason"] == REASON_REPLAYED_NONCE


def test_pruned_nonce_still_cannot_be_replayed(initiator, responder):
    """
    Once pruned the precise reason changes, but the replay is still refused:
    the challenge is stale and was removed from pending when it was spent.
    """
    challenge = initiator.create_challenge(responder.node_id)
    response = responder.answer_challenge(challenge)
    assert run(initiator.complete_handshake(response))["authenticated"] is True

    initiator.prune_expired(now=datetime.now(timezone.utc) + timedelta(seconds=120))
    assert challenge["nonce"] not in initiator.seen_nonces

    # The peer stays authenticated from the legitimate handshake above; what
    # matters is that the replay is refused and changes nothing.
    before = json.dumps(initiator.peers, sort_keys=True, default=str)
    replayed = run(initiator.complete_handshake(response))

    assert replayed["authenticated"] is False
    assert replayed["reason"] == REASON_UNKNOWN_NONCE
    assert json.dumps(initiator.peers, sort_keys=True, default=str) == before


def test_seen_nonces_are_capped():
    node = make_node("node_many", max_seen_nonces=32)
    peer = make_node("node_peer")
    trust(node, peer)

    for _ in range(200):
        challenge = node.create_challenge(peer.node_id)
        assert run(node.complete_handshake(peer.answer_challenge(challenge)))[
            "authenticated"
        ] is True

    assert len(node.seen_nonces) <= 32


def test_pruning_is_deterministic_and_needs_no_threads():
    """Same inputs, same clock, same result -- twice."""
    def build():
        node = make_node("node_det")
        for i in range(10):
            node.create_challenge(f"peer_{i}")
        return node

    at = datetime.now(timezone.utc) + timedelta(seconds=120)
    first, second = build().prune_expired(now=at), build().prune_expired(now=at)
    assert first == second == {
        "pending_expired": 10,
        "pending_evicted": 0,
        "nonces_expired": 0,
        "nonces_evicted": 0,
    }


def test_handshake_still_works_after_heavy_pruning(initiator, responder):
    """A flood must not break the next legitimate handshake."""
    for i in range(3000):
        initiator.create_challenge(f"peer_{i}")

    assert run(initiator.handshake(responder))["authenticated"] is True
    assert responder.node_id in authenticated_peers(initiator)


def test_signing_domain_is_a_required_parameter():
    """
    There is no untagged signature in this protocol. A default domain would
    let a caller mint one in whichever context happened to be the default,
    which is the oracle this hardening exists to close.
    """
    crypto = EurekaCrypto()

    with pytest.raises(TypeError):
        crypto.sign_json({"a": 1})

    with pytest.raises(TypeError):
        EurekaCrypto.verify_json(crypto.get_public_key_hex(), "AA==", {"a": 1})

    # The tagged form is unaffected.
    signature = crypto.sign_json({"a": 1}, DOMAIN_HANDSHAKE)
    assert EurekaCrypto.verify_json(
        crypto.get_public_key_hex(), signature, {"a": 1}, DOMAIN_HANDSHAKE
    ) is True
