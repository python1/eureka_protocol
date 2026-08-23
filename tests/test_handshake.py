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
    EurekaCrypto,
    canonical_json_bytes,
)
from eureka_protocol.src.eureka_daemon.node import (
    EurekaNode,
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


@pytest.fixture
def initiator():
    return make_node("node_initiator")


@pytest.fixture
def responder():
    return make_node("node_responder")


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
    # The signature verifies against the challenge that was sent.
    assert EurekaCrypto.verify_json(
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

    assert crypto.sign_json(a) == crypto.sign_json(b)
    assert EurekaCrypto.verify_json(
        crypto.get_public_key_hex(), crypto.sign_json(a), b
    ) is True


def test_sign_json_round_trips_through_the_wire():
    """A payload serialized, transmitted and reparsed still verifies."""
    crypto = EurekaCrypto()
    payload = {"nonce": "abc123", "timestamp": "2026-08-23T00:00:00+00:00"}
    signature = crypto.sign_json(payload)

    reparsed = json.loads(json.dumps(payload))
    assert EurekaCrypto.verify_json(
        crypto.get_public_key_hex(), signature, reparsed
    ) is True
