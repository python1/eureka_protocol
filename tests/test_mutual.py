"""
Tests for the three-message mutually authenticating handshake.

The property under test: both sides end the exchange knowing who the other
is. The initiator proves key possession in message 3 against a challenge the
responder minted, so a responder can decide whose tasks it is willing to run
later instead of having signed for an anonymous caller.
"""
import asyncio

import pytest

from eureka_protocol.src.eureka_daemon.crypto import (
    DOMAIN_HANDSHAKE,
    DOMAIN_HANDSHAKE_CONFIRM,
    DOMAIN_HANDSHAKE_OFFER,
    EurekaCrypto,
)
from eureka_protocol.src.eureka_daemon.node import (
    MAX_PENDING_CHALLENGES,
    EurekaNode,
    InvalidChallengeError,
    REASON_BAD_SIGNATURE,
    REASON_CHALLENGE_MISMATCH,
    REASON_MALFORMED,
    REASON_REPLAYED_NONCE,
    REASON_STALE,
    REASON_UNKNOWN_NONCE,
    REASON_UNTRUSTED_KEY,
    REASON_WRONG_PEER,
)


def run(coro):
    return asyncio.run(coro)


def make_node(node_id, **kwargs):
    return EurekaNode(
        node_id=node_id,
        crypto_engine=EurekaCrypto(),
        capabilities=["code-exec"],
        **kwargs,
    )


def trust_both_ways(a, b):
    a.trust_list.add(b.node_id, b.crypto.get_public_key_hex())
    b.trust_list.add(a.node_id, a.crypto.get_public_key_hex())


def trust_one_way(truster, trusted):
    truster.trust_list.add(trusted.node_id, trusted.crypto.get_public_key_hex())


@pytest.fixture
def pair():
    """An initiator and responder that trust each other."""
    initiator = make_node("node_initiator")
    responder = make_node("node_responder")
    trust_both_ways(initiator, responder)
    return initiator, responder


def authenticated_peers(node):
    return {
        pid for pid, info in node.peers.items()
        if info.get("status") == "authenticated"
    }


def drive(initiator, responder):
    """Run the three messages by hand, returning every intermediate."""
    offer = initiator.create_handshake_offer(responder.node_id)
    message_two = responder.answer_handshake_offer(offer)
    mine = run(initiator.complete_handshake(message_two))
    confirmation = initiator.confirm_handshake(message_two)
    theirs = run(responder.complete_mutual_handshake(confirmation))
    return offer, message_two, confirmation, mine, theirs


# ---------------------------------------------------------------------------
# Full round trip
# ---------------------------------------------------------------------------

def test_three_message_round_trip_authenticates_both_sides(pair):
    initiator, responder = pair

    result = run(initiator.handshake(responder))

    assert result["authenticated"] is True
    assert result["mutual"] is True

    # BOTH directions recorded.
    assert responder.node_id in authenticated_peers(initiator)
    assert initiator.node_id in authenticated_peers(responder)

    # Each side recorded the key that actually signed for the other.
    assert initiator.peers[responder.node_id]["public_key"] == \
        responder.crypto.get_public_key_hex()
    assert responder.peers[initiator.node_id]["public_key"] == \
        initiator.crypto.get_public_key_hex()


def test_the_exchange_really_is_three_messages(pair):
    initiator, responder = pair
    offer, message_two, confirmation, mine, theirs = drive(initiator, responder)

    assert offer["event"] == "handshake_offer"
    assert message_two["event"] == "handshake_response"
    assert confirmation["event"] == "handshake_confirm"

    # Message 1 carries the initiator's key and a signature over its challenge.
    assert offer["public_key"] == initiator.crypto.get_public_key_hex()
    assert EurekaCrypto.verify_handshake_offer(
        offer["public_key"], offer["signature"], offer["challenge"]
    ) is True

    # Message 2 answers that challenge and adds a fresh one of its own.
    assert message_two["challenge"] == offer["challenge"]
    assert message_two["counter_challenge"]["nonce"] != offer["challenge"]["nonce"]

    # Message 3 signs the responder's challenge, not the initiator's.
    assert confirmation["challenge"] == message_two["counter_challenge"]
    assert EurekaCrypto.verify_handshake_confirm(
        confirmation["public_key"], confirmation["signature"],
        confirmation["challenge"],
    ) is True

    assert mine["authenticated"] is True
    assert theirs["authenticated"] is True


def test_responder_challenge_is_fresh_each_exchange(pair):
    initiator, responder = pair
    nonces = set()
    for _ in range(5):
        offer = initiator.create_handshake_offer(responder.node_id)
        message_two = responder.answer_handshake_offer(offer)
        nonces.add(message_two["counter_challenge"]["nonce"])
    assert len(nonces) == 5


# ---------------------------------------------------------------------------
# Trust, in both directions
# ---------------------------------------------------------------------------

def test_responder_rejects_an_untrusted_initiator():
    initiator = make_node("node_initiator")
    responder = make_node("node_responder")
    # The initiator trusts the responder; the responder trusts nobody.
    trust_one_way(initiator, responder)

    result = run(initiator.handshake(responder))

    assert result["authenticated"] is False
    assert result["reason"] == REASON_UNTRUSTED_KEY
    assert responder.peers == {}
    assert responder.pending_peers == {}


def test_asymmetric_trust_leaves_neither_side_authenticated():
    """A trusts B, B does not trust A: nobody ends up authenticated."""
    a = make_node("node_a")
    b = make_node("node_b")
    trust_one_way(a, b)

    result = run(a.handshake(b))

    assert result["authenticated"] is False
    assert authenticated_peers(a) == set()
    assert authenticated_peers(b) == set()
    assert a.peers == {}
    assert b.peers == {}


def test_responder_refuses_before_minting_a_counter_challenge():
    """An untrusted initiator gets no challenge to answer."""
    initiator = make_node("node_initiator")
    responder = make_node("node_responder")
    trust_one_way(initiator, responder)

    offer = initiator.create_handshake_offer(responder.node_id)
    rejection = responder.answer_handshake_offer(offer)

    assert rejection["authenticated"] is False
    assert rejection["reason"] == REASON_UNTRUSTED_KEY
    assert "counter_challenge" not in rejection
    assert responder.pending_challenges == {}
    assert responder.pending_peers == {}


def test_initiator_rejects_an_untrusted_responder():
    initiator = make_node("node_initiator")
    responder = make_node("node_responder")
    # Only the responder trusts: the initiator has an empty allowlist.
    trust_one_way(responder, initiator)

    result = run(initiator.handshake(responder))

    assert result["authenticated"] is False
    assert result["reason"] == REASON_UNTRUSTED_KEY
    assert initiator.peers == {}
    # The responder saw message 1 but never got a verifiable message 3.
    assert responder.peers == {}


# ---------------------------------------------------------------------------
# Domain separation between the three positions
# ---------------------------------------------------------------------------

def test_the_three_message_domains_are_distinct():
    assert len({DOMAIN_HANDSHAKE_OFFER, DOMAIN_HANDSHAKE,
                DOMAIN_HANDSHAKE_CONFIRM}) == 3


def test_a_signature_does_not_verify_in_another_position():
    crypto = EurekaCrypto()
    pub = crypto.get_public_key_hex()
    payload = {"protocol": "eureka/1.0", "event": "handshake_challenge"}

    offer_sig = crypto.sign_handshake_offer(payload)
    reply_sig = crypto.sign_handshake(payload)
    confirm_sig = crypto.sign_handshake_confirm(payload)

    assert len({offer_sig, reply_sig, confirm_sig}) == 3

    assert EurekaCrypto.verify_handshake_offer(pub, offer_sig, payload) is True
    assert EurekaCrypto.verify_handshake(pub, reply_sig, payload) is True
    assert EurekaCrypto.verify_handshake_confirm(pub, confirm_sig, payload) is True

    # Every cross-position combination fails.
    assert EurekaCrypto.verify_handshake(pub, offer_sig, payload) is False
    assert EurekaCrypto.verify_handshake_confirm(pub, offer_sig, payload) is False
    assert EurekaCrypto.verify_handshake_offer(pub, reply_sig, payload) is False
    assert EurekaCrypto.verify_handshake_confirm(pub, reply_sig, payload) is False
    assert EurekaCrypto.verify_handshake_offer(pub, confirm_sig, payload) is False
    assert EurekaCrypto.verify_handshake(pub, confirm_sig, payload) is False


def test_message_three_signature_replayed_as_message_one_is_rejected(pair):
    """A harvested confirm signature must not open a new exchange."""
    initiator, responder = pair
    _, _, confirmation, _, _ = drive(initiator, responder)

    victim = make_node("node_victim")
    trust_one_way(victim, initiator)

    forged_offer = {
        "event": "handshake_offer",
        "initiator_id": initiator.node_id,
        "challenge": confirmation["challenge"],
        "public_key": confirmation["public_key"],
        # Signature harvested from message 3, presented in the message 1 slot.
        "signature": confirmation["signature"],
    }

    rejection = victim.answer_handshake_offer(forged_offer)

    assert rejection["authenticated"] is False
    assert rejection["reason"] == REASON_BAD_SIGNATURE
    assert victim.peers == {}


def test_message_one_signature_replayed_as_message_three_is_rejected(pair):
    """And the inverse: an offer signature cannot confirm an exchange."""
    initiator, responder = pair
    offer = initiator.create_handshake_offer(responder.node_id)
    message_two = responder.answer_handshake_offer(offer)

    forged_confirm = {
        "event": "handshake_confirm",
        "initiator_id": initiator.node_id,
        "challenge": message_two["counter_challenge"],
        "public_key": initiator.crypto.get_public_key_hex(),
        # Signature from message 1, presented in the message 3 slot.
        "signature": offer["signature"],
    }

    result = run(responder.complete_mutual_handshake(forged_confirm))

    assert result["authenticated"] is False
    assert result["reason"] == REASON_BAD_SIGNATURE
    assert responder.peers == {}


def test_message_two_signature_cannot_confirm(pair):
    initiator, responder = pair
    offer = initiator.create_handshake_offer(responder.node_id)
    message_two = responder.answer_handshake_offer(offer)

    forged_confirm = {
        "event": "handshake_confirm",
        "initiator_id": initiator.node_id,
        "challenge": message_two["counter_challenge"],
        "public_key": initiator.crypto.get_public_key_hex(),
        "signature": initiator.crypto.sign_handshake(
            message_two["counter_challenge"]
        ),
    }

    result = run(responder.complete_mutual_handshake(forged_confirm))

    assert result["reason"] == REASON_BAD_SIGNATURE


# ---------------------------------------------------------------------------
# Responder-side rejection scenarios: the same checks, from the other side
# ---------------------------------------------------------------------------

def test_responder_rejects_a_tampered_confirmation(pair):
    initiator, responder = pair
    offer = initiator.create_handshake_offer(responder.node_id)
    message_two = responder.answer_handshake_offer(offer)
    confirmation = initiator.confirm_handshake(message_two)

    confirmation["challenge"]["initiator_id"] = "node_attacker"

    result = run(responder.complete_mutual_handshake(confirmation))

    assert result["reason"] == REASON_BAD_SIGNATURE
    assert responder.peers == {}


def test_responder_rejects_a_wrong_key_confirmation(pair):
    initiator, responder = pair
    attacker = make_node("node_attacker")
    trust_one_way(responder, attacker)

    offer = initiator.create_handshake_offer(responder.node_id)
    message_two = responder.answer_handshake_offer(offer)

    # The attacker signs, but claims to be the initiator.
    forged = attacker.confirm_handshake(message_two)
    forged["initiator_id"] = initiator.node_id
    forged["public_key"] = initiator.crypto.get_public_key_hex()

    result = run(responder.complete_mutual_handshake(forged))

    assert result["reason"] == REASON_BAD_SIGNATURE
    assert responder.peers == {}


def test_responder_rejects_a_key_swap_between_message_one_and_three(pair):
    """
    Open with one trusted identity, prove a different one: refused.

    Both keys are trusted here, so only the binding between message 1 and
    message 3 can catch this.
    """
    initiator, responder = pair
    other = make_node("node_other")
    trust_both_ways(other, responder)

    offer = initiator.create_handshake_offer(responder.node_id)
    message_two = responder.answer_handshake_offer(offer)

    # `other` legitimately signs the counter-challenge with its own trusted
    # key, but the exchange was opened by `initiator`.
    swapped = other.confirm_handshake(message_two)
    swapped["initiator_id"] = initiator.node_id

    result = run(responder.complete_mutual_handshake(swapped))

    # The signature is genuine and the key is trusted, so only the message
    # 1 <-> message 3 key binding can reject this.
    assert result["authenticated"] is False
    assert result["reason"] == REASON_WRONG_PEER
    assert responder.peers == {}
    assert other.node_id not in responder.peers


@pytest.mark.parametrize("bad_signature", ["!!!!", "abc", "", "@@@@"])
def test_responder_rejects_malformed_confirmation_signatures(pair, bad_signature):
    initiator, responder = pair
    offer = initiator.create_handshake_offer(responder.node_id)
    message_two = responder.answer_handshake_offer(offer)
    confirmation = initiator.confirm_handshake(message_two)
    confirmation["signature"] = bad_signature

    result = run(responder.complete_mutual_handshake(confirmation))

    assert result["reason"] == REASON_BAD_SIGNATURE
    assert responder.peers == {}


def test_responder_rejects_an_unknown_nonce(pair):
    initiator, responder = pair
    stranger = make_node("node_stranger")
    trust_both_ways(stranger, responder)

    # A counter-challenge minted by somebody else entirely.
    rogue_challenge = stranger.create_challenge(initiator.node_id)
    confirmation = initiator.confirm_handshake(
        {"counter_challenge": rogue_challenge}
    )

    result = run(responder.complete_mutual_handshake(confirmation))

    assert result["reason"] == REASON_UNKNOWN_NONCE
    assert responder.peers == {}


def test_responder_rejects_a_replayed_confirmation(pair):
    initiator, responder = pair
    offer = initiator.create_handshake_offer(responder.node_id)
    message_two = responder.answer_handshake_offer(offer)
    confirmation = initiator.confirm_handshake(message_two)

    first = run(responder.complete_mutual_handshake(confirmation))
    assert first["authenticated"] is True

    second = run(responder.complete_mutual_handshake(confirmation))

    assert second["authenticated"] is False
    assert second["reason"] == REASON_REPLAYED_NONCE


def test_responder_rejects_a_stale_confirmation(pair):
    from datetime import datetime, timedelta, timezone

    initiator, responder = pair
    offer = initiator.create_handshake_offer(responder.node_id)
    message_two = responder.answer_handshake_offer(offer)

    counter = message_two["counter_challenge"]
    stale = (datetime.now(timezone.utc) - timedelta(seconds=300)).isoformat()
    counter["timestamp"] = stale
    responder.pending_challenges[counter["nonce"]]["timestamp"] = stale

    confirmation = initiator.confirm_handshake(message_two)
    result = run(responder.complete_mutual_handshake(confirmation))

    assert result["reason"] == REASON_STALE
    assert responder.peers == {}


def test_responder_rejects_a_confirmation_from_the_wrong_peer(pair):
    initiator, responder = pair
    offer = initiator.create_handshake_offer(responder.node_id)
    message_two = responder.answer_handshake_offer(offer)
    confirmation = initiator.confirm_handshake(message_two)
    confirmation["initiator_id"] = "node_somebody_else"

    result = run(responder.complete_mutual_handshake(confirmation))

    assert result["reason"] == REASON_WRONG_PEER
    assert responder.peers == {}


@pytest.mark.parametrize("mutate, expected", [
    (lambda o: o.update(signature=12345), REASON_MALFORMED),
    (lambda o: o.update(public_key=None), REASON_MALFORMED),
    (lambda o: o.pop("challenge"), REASON_MALFORMED),
    (lambda o: o.update(challenge={"not": "a challenge"}), REASON_MALFORMED),
    (lambda o: o.update(initiator_id="node_someone_else"), REASON_WRONG_PEER),
])
def test_responder_rejects_malformed_offers(pair, mutate, expected):
    initiator, responder = pair
    offer = initiator.create_handshake_offer(responder.node_id)
    mutate(offer)

    rejection = responder.answer_handshake_offer(offer)

    assert rejection["authenticated"] is False
    assert rejection["reason"] == expected
    assert responder.peers == {}


def test_responder_rejects_a_replayed_offer(pair):
    initiator, responder = pair
    offer = initiator.create_handshake_offer(responder.node_id)

    assert responder.answer_handshake_offer(offer)["event"] == "handshake_response"
    replayed = responder.answer_handshake_offer(offer)

    assert replayed["authenticated"] is False
    assert replayed["reason"] == REASON_REPLAYED_NONCE


def test_confirm_handshake_refuses_to_sign_a_non_challenge(pair):
    """The signing-oracle gate applies to message 3 as well."""
    initiator, _ = pair

    with pytest.raises(InvalidChallengeError):
        initiator.confirm_handshake({"counter_challenge": {"task": "anything"}})

    with pytest.raises(InvalidChallengeError):
        initiator.confirm_handshake({})


# ---------------------------------------------------------------------------
# Bounded responder state
# ---------------------------------------------------------------------------

def test_responder_state_is_bounded_under_abandoned_exchanges():
    """
    10000 initiators send message 1 and never send message 3.

    Every one of these is inside the freshness window, so age pruning alone
    would not bound anything -- the caps carry it, and the provisional peer
    table is capped with them rather than separately.
    """
    responder = make_node("node_responder")
    initiators = [make_node(f"node_init_{i}") for i in range(20)]
    for node in initiators:
        trust_both_ways(node, responder)

    for i in range(10_000):
        offer = initiators[i % len(initiators)].create_handshake_offer(
            responder.node_id
        )
        message = responder.answer_handshake_offer(offer)
        assert message["event"] == "handshake_response"

    assert len(responder.pending_challenges) <= MAX_PENDING_CHALLENGES
    assert len(responder.pending_peers) <= MAX_PENDING_CHALLENGES
    # The provisional table never outgrows the challenges it hangs off.
    assert set(responder.pending_peers) <= set(responder.pending_challenges)
    assert responder.peers == {}


def test_provisional_peers_are_dropped_with_their_challenges(pair):
    initiator, responder = pair
    for _ in range(5):
        offer = initiator.create_handshake_offer(responder.node_id)
        responder.answer_handshake_offer(offer)

    assert len(responder.pending_peers) == 5

    from datetime import datetime, timedelta, timezone
    responder.prune_expired(
        now=datetime.now(timezone.utc) + timedelta(seconds=300)
    )

    assert responder.pending_challenges == {}
    assert responder.pending_peers == {}


def test_abandoning_after_message_two_leaves_no_authenticated_peer(pair):
    initiator, responder = pair

    offer = initiator.create_handshake_offer(responder.node_id)
    message_two = responder.answer_handshake_offer(offer)
    mine = run(initiator.complete_handshake(message_two))

    # The initiator verified the responder and stops there.
    assert mine["authenticated"] is True
    assert responder.node_id in authenticated_peers(initiator)

    # The responder has provisional state only -- nobody is authenticated.
    assert responder.peers == {}
    assert authenticated_peers(responder) == set()
    assert len(responder.pending_peers) == 1


def test_failed_confirmation_discards_the_provisional_peer(pair):
    initiator, responder = pair
    offer = initiator.create_handshake_offer(responder.node_id)
    message_two = responder.answer_handshake_offer(offer)
    confirmation = initiator.confirm_handshake(message_two)
    confirmation["signature"] = "!!!!"

    nonce = message_two["counter_challenge"]["nonce"]
    assert nonce in responder.pending_peers

    result = run(responder.complete_mutual_handshake(confirmation))

    assert result["authenticated"] is False
    assert responder.peers == {}
    # Discarded, not left behind for a second attempt.
    assert nonce not in responder.pending_peers
    assert nonce not in responder.pending_challenges


def test_a_failed_exchange_does_not_block_a_later_one(pair):
    initiator, responder = pair

    offer = initiator.create_handshake_offer(responder.node_id)
    message_two = responder.answer_handshake_offer(offer)
    broken = initiator.confirm_handshake(message_two)
    broken["signature"] = "!!!!"
    assert run(responder.complete_mutual_handshake(broken))["authenticated"] is False

    result = run(initiator.handshake(responder))

    assert result["authenticated"] is True
    assert initiator.node_id in authenticated_peers(responder)
