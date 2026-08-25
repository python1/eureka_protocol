"""
Key revocation and rotation.

Trust can be withdrawn. A revoked key is one this node refuses forever, and
the point of recording it separately from the allowlist is that *removing* a
peer and *revoking* one are different acts: a removed key comes back the
moment someone restores an old trust file from a backup, while a revoked key
stays refused and says why.

Rotation is the same machinery from the other side -- the peer's new key is
trusted and the old one is revoked, in one step, so there is never a window
in which both keys work.
"""
import asyncio
import json

import pytest

from eureka_protocol.src.eureka_daemon.crypto import EurekaCrypto
from eureka_protocol.src.eureka_daemon.node import (
    EurekaNode,
    REASON_REVOKED_KEY,
    REASON_UNTRUSTED_KEY,
)
from eureka_protocol.src.eureka_daemon.trust import (
    TRUST_ALGORITHM,
    TRUST_FILE_VERSION,
    TRUST_FILE_VERSION_CAPABILITIES,
    TRUST_FILE_VERSION_LEGACY,
    TrustError,
    TrustList,
)


def run(coro):
    return asyncio.run(coro)


def make_node(node_id, capabilities=("code-exec", "web-retrieval"), **kwargs):
    return EurekaNode(
        node_id=node_id,
        crypto_engine=EurekaCrypto(),
        capabilities=list(capabilities),
        **kwargs,
    )


def some_key():
    return EurekaCrypto().get_public_key_hex()


def write_trust(path, peers=None, revoked=None, version=TRUST_FILE_VERSION,
                algorithm=TRUST_ALGORITHM):
    """
    Write a trust file. `peers` maps name -> key hex or a full entry object.

    `revoked` is omitted from the document entirely when None, so tests can
    tell "no revocation list" apart from "an empty one".
    """
    entries = {
        name: (value if isinstance(value, dict) else {"public_key": value})
        for name, value in (peers or {}).items()
    }
    document = {"version": version, "algorithm": algorithm, "peers": entries}
    if revoked is not None:
        document["revoked"] = revoked
    path.write_text(json.dumps(document))
    return path


# ---------------------------------------------------------------------------
# A revoked key is not trusted, whatever else the file says
# ---------------------------------------------------------------------------

def test_revoking_removes_the_key_from_the_allowlist():
    key = some_key()
    trust = TrustList({"alice": key})
    assert trust.trusts(key)

    trust.revoke(key, reason="laptop stolen")

    assert not trust.trusts(key)
    assert trust.is_revoked(key)
    assert len(trust) == 0


def test_revoking_strips_the_grants_too():
    key = some_key()
    trust = TrustList({"alice": key}, {"alice": ["code-exec"]})

    trust.revoke(key)

    assert trust.capabilities_for(key) == frozenset()
    assert trust.grants(key, "code-exec") is False


def test_revoked_key_cannot_be_added_back():
    key = some_key()
    trust = TrustList()
    trust.revoke(key, reason="compromised")

    with pytest.raises(TrustError, match="revoked"):
        trust.add("alice", key)


def test_revoked_key_cannot_be_added_back_under_a_different_name():
    """Renaming a compromised key does not launder it."""
    key = some_key()
    trust = TrustList({"alice": key})
    trust.revoke(key)

    with pytest.raises(TrustError, match="revoked"):
        trust.add("alice-new-laptop", key)


def test_revoking_a_key_that_was_never_trusted_is_recorded():
    """
    Pre-emptive revocation is a real operation: it is how an operator makes
    sure a key they were offered can never be provisioned by mistake later.
    """
    key = some_key()
    trust = TrustList()

    assert trust.revoke(key, reason="never trust this") is None

    assert trust.is_revoked(key)
    with pytest.raises(TrustError, match="revoked"):
        trust.add("someone", key)


def test_revocation_returns_the_label_it_withdrew():
    key = some_key()
    trust = TrustList({"alice": key})
    assert trust.revoke(key) == "alice"


def test_revoking_one_key_leaves_the_others_alone():
    alice, bob = some_key(), some_key()
    trust = TrustList({"alice": alice, "bob": bob}, {"bob": ["code-exec"]})

    trust.revoke(alice)

    assert trust.trusts(bob)
    assert trust.grants(bob, "code-exec") is True
    assert not trust.is_revoked(bob)


def test_revocation_records_the_reason_and_a_timestamp():
    key = some_key()
    trust = TrustList()
    trust.revoke(key, reason="key exposed in a backup")

    record = trust.revocation_for(key)
    assert record["reason"] == "key exposed in a backup"
    # Stamped automatically: a revocation with no date is hard to audit.
    assert record["revoked_at"]


def test_revocation_record_is_a_copy():
    """A caller cannot reach in and edit the audit trail by accident."""
    key = some_key()
    trust = TrustList()
    trust.revoke(key, reason="original")

    trust.revocation_for(key)["reason"] = "tampered"

    assert trust.revocation_for(key)["reason"] == "original"


def test_revocation_for_a_live_key_is_none():
    key = some_key()
    trust = TrustList({"alice": key})
    assert trust.revocation_for(key) is None


@pytest.mark.parametrize("value", [None, 42, b"bytes", ["list"]])
def test_is_revoked_says_no_to_non_strings(value):
    trust = TrustList()
    assert trust.is_revoked(value) is False
    assert trust.revocation_for(value) is None


def test_revocation_matching_ignores_case_and_whitespace():
    key = some_key()
    trust = TrustList()
    trust.revoke(key.upper())

    assert trust.is_revoked(f"  {key}  ")
    with pytest.raises(TrustError, match="revoked"):
        trust.add("alice", key)


# ---------------------------------------------------------------------------
# Loading revocations from a trust file
# ---------------------------------------------------------------------------

def test_revoked_key_in_the_file_is_refused(tmp_path):
    dead, live = some_key(), some_key()
    path = write_trust(tmp_path / "trust.json",
                       peers={"bob": live}, revoked=[{"public_key": dead}])

    trust = TrustList.load(path)

    assert trust.is_revoked(dead)
    assert not trust.trusts(dead)
    assert trust.trusts(live)


def test_bare_key_strings_are_accepted_in_the_revoked_list(tmp_path):
    dead = some_key()
    path = write_trust(tmp_path / "trust.json", revoked=[dead])

    assert TrustList.load(path).is_revoked(dead)


def test_revocation_metadata_survives_the_load(tmp_path):
    dead = some_key()
    path = write_trust(tmp_path / "trust.json", revoked=[{
        "public_key": dead,
        "reason": "stolen laptop",
        "revoked_at": "2026-08-24T00:00:00+00:00",
    }])

    record = TrustList.load(path).revocation_for(dead)

    assert record == {"reason": "stolen laptop",
                      "revoked_at": "2026-08-24T00:00:00+00:00"}


def test_a_key_that_is_both_trusted_and_revoked_is_a_load_error(tmp_path):
    """
    The file contradicts itself. Rather than picking a winner, refuse: the
    operator meant one of these and there is no way to tell which.
    """
    key = some_key()
    path = write_trust(tmp_path / "trust.json",
                       peers={"alice": key}, revoked=[{"public_key": key}])

    with pytest.raises(TrustError, match="revoked"):
        TrustList.load(path)


def test_revocation_wins_regardless_of_entry_order(tmp_path):
    """Same contradiction, written the other way round in the document."""
    key = some_key()
    path = tmp_path / "trust.json"
    path.write_text(json.dumps({
        "version": TRUST_FILE_VERSION,
        "algorithm": TRUST_ALGORITHM,
        "revoked": [{"public_key": key}],
        "peers": {"alice": {"public_key": key}},
    }))

    with pytest.raises(TrustError, match="revoked"):
        TrustList.load(path)


@pytest.mark.parametrize("version", [
    TRUST_FILE_VERSION_LEGACY, TRUST_FILE_VERSION_CAPABILITIES,
])
def test_revocations_in_an_older_file_are_an_error(tmp_path, version):
    """
    The single most dangerous failure this format can have: a revocation list
    that is present, looks effective, and does nothing. Every other
    back-compatibility rule drops something and fails closed; dropping a
    revocation fails open.
    """
    dead = some_key()
    path = tmp_path / "trust.json"
    peers = ({"bob": some_key()} if version == TRUST_FILE_VERSION_LEGACY
             else {"bob": {"public_key": some_key()}})
    path.write_text(json.dumps({
        "version": version, "algorithm": TRUST_ALGORITHM,
        "peers": peers, "revoked": [dead],
    }))

    with pytest.raises(TrustError, match="cannot.*express revocations"):
        TrustList.load(path)


def test_an_empty_revocation_list_in_an_older_file_is_still_an_error(tmp_path):
    """The field does not belong to that version at all, empty or not."""
    path = tmp_path / "trust.json"
    path.write_text(json.dumps({
        "version": TRUST_FILE_VERSION_CAPABILITIES,
        "algorithm": TRUST_ALGORITHM, "peers": {}, "revoked": [],
    }))

    with pytest.raises(TrustError, match="cannot.*express revocations"):
        TrustList.load(path)


def test_a_null_revocation_field_in_an_older_file_is_still_an_error(tmp_path):
    """`"revoked": null` is the field being present, not absent."""
    path = tmp_path / "trust.json"
    path.write_text(json.dumps({
        "version": TRUST_FILE_VERSION_CAPABILITIES,
        "algorithm": TRUST_ALGORITHM, "peers": {}, "revoked": None,
    }))

    with pytest.raises(TrustError, match="cannot.*express revocations"):
        TrustList.load(path)


def test_a_current_file_without_a_revoked_list_loads(tmp_path):
    """Absent is fine -- it means nothing has been revoked."""
    key = some_key()
    path = write_trust(tmp_path / "trust.json", peers={"alice": key})

    trust = TrustList.load(path)

    assert trust.trusts(key)
    assert list(trust.revocations()) == []


@pytest.mark.parametrize("revoked, match", [
    ("deadbeef", "must have a 'revoked' list"),
    ({"alice": "key"}, "must have a 'revoked' list"),
    (42, "must have a 'revoked' list"),
    ([{"reason": "no key here"}], "missing 'public_key'"),
    ([{"public_kye": "x" * 64}], "unexpected field"),
    ([{"public_key": "x" * 64, "note": "typo'd field"}], "unexpected field"),
    ([{"public_key": "not-hex"}], "64 hex characters"),
    ([{"public_key": "zz" + "0" * 62}], "not valid hex"),
    ([{"public_key": 42}], "must be a string"),
    ([42], "must be a public key string or an object"),
    ([None], "must be a public key string or an object"),
    ([{"public_key": "0" * 64, "reason": ""}], "non-empty string"),
    ([{"public_key": "0" * 64, "reason": 42}], "non-empty string"),
    ([{"public_key": "0" * 64, "revoked_at": "  "}], "non-empty string"),
])
def test_malformed_revocations_are_rejected(tmp_path, revoked, match):
    path = write_trust(tmp_path / "trust.json", revoked=revoked)
    with pytest.raises(TrustError, match=match):
        TrustList.load(path)


def test_a_malformed_revocation_does_not_load_a_partial_list(tmp_path):
    """A file that fails to load must not leave a half-applied allowlist."""
    path = write_trust(tmp_path / "trust.json",
                       peers={"alice": some_key()},
                       revoked=[{"public_key": "nonsense"}])

    with pytest.raises(TrustError):
        TrustList.load(path)


def test_revocations_round_trip_through_to_document(tmp_path):
    live, dead = some_key(), some_key()
    trust = TrustList({"alice": live}, {"alice": ["code-exec"]})
    trust.revoke(dead, reason="rotated out")

    path = tmp_path / "trust.json"
    path.write_text(json.dumps(trust.to_document()))
    reloaded = TrustList.load(path)

    assert reloaded.trusts(live)
    assert reloaded.grants(live, "code-exec") is True
    assert reloaded.is_revoked(dead)
    assert reloaded.revocation_for(dead)["reason"] == "rotated out"


def test_to_document_always_declares_a_revoked_list():
    document = TrustList({"alice": some_key()}).to_document()
    assert document["version"] == TRUST_FILE_VERSION
    assert document["revoked"] == []


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------

def test_rotation_trusts_the_new_key_and_revokes_the_old():
    old, new = some_key(), some_key()
    trust = TrustList({"alice": old})

    returned = trust.rotate("alice", new)

    assert returned == old
    assert trust.trusts(new)
    assert not trust.trusts(old)
    assert trust.is_revoked(old)


def test_rotation_carries_the_grants_across():
    old, new = some_key(), some_key()
    trust = TrustList({"alice": old}, {"alice": ["code-exec", "web-retrieval"]})

    trust.rotate("alice", new)

    assert trust.capabilities_for(new) == frozenset({"code-exec", "web-retrieval"})


def test_rotation_can_replace_the_grants():
    old, new = some_key(), some_key()
    trust = TrustList({"alice": old}, {"alice": ["code-exec"]})

    trust.rotate("alice", new, capabilities=["web-retrieval"])

    assert trust.capabilities_for(new) == frozenset({"web-retrieval"})


def test_rotation_keeps_the_label():
    old, new = some_key(), some_key()
    trust = TrustList({"alice": old})

    trust.rotate("alice", new)

    assert trust.name_for(new) == "alice"
    assert trust.key_for("alice") == new


def test_rotation_records_where_the_key_went():
    old, new = some_key(), some_key()
    trust = TrustList({"alice": old})

    trust.rotate("alice", new)

    assert new in trust.revocation_for(old)["reason"]


def test_rotation_reason_can_be_given():
    old, new = some_key(), some_key()
    trust = TrustList({"alice": old})

    trust.rotate("alice", new, reason="annual rotation")

    assert trust.revocation_for(old)["reason"] == "annual rotation"


def test_rotating_an_unknown_peer_is_an_error():
    trust = TrustList({"alice": some_key()})
    with pytest.raises(TrustError, match="unknown peer"):
        trust.rotate("bob", some_key())


def test_rotating_onto_the_same_key_is_an_error():
    """Would otherwise revoke the key and then refuse to re-add it."""
    key = some_key()
    trust = TrustList({"alice": key})

    with pytest.raises(TrustError, match="already the current key"):
        trust.rotate("alice", key)

    assert trust.trusts(key)


def test_rotating_onto_a_revoked_key_is_an_error():
    old, dead = some_key(), some_key()
    trust = TrustList({"alice": old})
    trust.revoke(dead, reason="compromised")

    with pytest.raises(TrustError, match="revoked key"):
        trust.rotate("alice", dead)

    # The rotation did not half-happen: alice still holds her original key.
    assert trust.trusts(old)


def test_rotating_onto_another_peers_key_is_an_error():
    alice, bob = some_key(), some_key()
    trust = TrustList({"alice": alice, "bob": bob})

    with pytest.raises(TrustError, match="'bob'"):
        trust.rotate("alice", bob)

    assert trust.trusts(alice)
    assert trust.name_for(bob) == "bob"


@pytest.mark.parametrize("bad", ["not-hex", "", "0" * 63, 42, None])
def test_rotating_onto_an_invalid_key_is_an_error_and_changes_nothing(bad):
    old = some_key()
    trust = TrustList({"alice": old})

    with pytest.raises(TrustError):
        trust.rotate("alice", bad)

    assert trust.trusts(old)
    assert not trust.is_revoked(old)


def test_rotation_survives_a_round_trip(tmp_path):
    old, new = some_key(), some_key()
    trust = TrustList({"alice": old}, {"alice": ["code-exec"]})
    trust.rotate("alice", new)

    path = tmp_path / "trust.json"
    path.write_text(json.dumps(trust.to_document()))
    reloaded = TrustList.load(path)

    assert reloaded.trusts(new)
    assert reloaded.is_revoked(old)
    assert reloaded.grants(new, "code-exec") is True


def test_key_for_an_unknown_name_is_none():
    assert TrustList({"alice": some_key()}).key_for("bob") is None


# ---------------------------------------------------------------------------
# Enforcement in the handshake
# ---------------------------------------------------------------------------

def test_a_revoked_responder_cannot_authenticate(tmp_path):
    responder = make_node("node_responder")
    initiator = make_node("node_initiator")
    responder.trust_list.add(initiator.node_id, initiator.public_key_hex)
    initiator.trust_list.add(responder.node_id, responder.public_key_hex)
    initiator.trust_list.revoke(responder.public_key_hex, reason="compromised")

    result = run(initiator.handshake(responder))

    assert result["authenticated"] is False
    assert result["reason"] == REASON_REVOKED_KEY
    assert responder.node_id not in initiator.peers


def test_a_revoked_initiator_is_refused_at_message_one():
    responder = make_node("node_responder")
    initiator = make_node("node_initiator")
    responder.trust_list.add(initiator.node_id, initiator.public_key_hex)
    responder.trust_list.revoke(initiator.public_key_hex, reason="compromised")

    reply = responder.answer_handshake_offer(
        initiator.create_handshake_offer(responder.node_id)
    )

    assert reply["authenticated"] is False
    assert reply["reason"] == REASON_REVOKED_KEY
    # Refused before any counter-challenge was minted.
    assert reply.get("counter_challenge") is None
    assert initiator.node_id not in responder.peers


def test_revocation_is_reported_distinctly_from_never_having_been_trusted():
    """
    Both are refusals, but they call for different operator responses. A log
    that cannot tell "we revoked this peer" from "we have never heard of this
    peer" cannot tell an expired credential from an intrusion attempt.
    """
    responder = make_node("node_responder")
    revoked_peer = make_node("node_revoked")
    stranger = make_node("node_stranger")
    responder.trust_list.add(revoked_peer.node_id, revoked_peer.public_key_hex)
    responder.trust_list.revoke(revoked_peer.public_key_hex)

    revoked_reply = responder.answer_handshake_offer(
        revoked_peer.create_handshake_offer(responder.node_id)
    )
    stranger_reply = responder.answer_handshake_offer(
        stranger.create_handshake_offer(responder.node_id)
    )

    assert revoked_reply["reason"] == REASON_REVOKED_KEY
    assert stranger_reply["reason"] == REASON_UNTRUSTED_KEY


def test_a_rotated_peer_authenticates_on_its_new_key_only():
    responder = make_node("node_responder")
    old_initiator = make_node("node_initiator")
    responder.trust_list.add("initiator", old_initiator.public_key_hex)

    # The peer rotates: same label, new keypair.
    new_initiator = EurekaNode(
        node_id="node_initiator", crypto_engine=EurekaCrypto(),
        capabilities=["code-exec"],
    )
    responder.trust_list.rotate("initiator", new_initiator.public_key_hex)

    accepted = responder.answer_handshake_offer(
        new_initiator.create_handshake_offer(responder.node_id)
    )
    refused = responder.answer_handshake_offer(
        old_initiator.create_handshake_offer(responder.node_id)
    )

    assert accepted.get("counter_challenge") is not None
    assert refused["reason"] == REASON_REVOKED_KEY


# ---------------------------------------------------------------------------
# Reaching a running daemon: reload_trust()
# ---------------------------------------------------------------------------

def handshaken_pair(tmp_path, grants=("code-exec",)):
    """
    A completed mutual handshake where the responder loads its trust from a
    real file, so the file can be rewritten and reloaded mid-session.

    Returns (initiator, responder, responder_trust_path).
    """
    initiator = make_node("node_initiator")
    trust_path = write_trust(tmp_path / "responder-trust.json", peers={
        "initiator": {"public_key": initiator.public_key_hex,
                      "capabilities": list(grants)},
    })
    responder = make_node("node_responder", trust_path=str(trust_path))
    initiator.trust_list.add("responder", responder.public_key_hex)

    assert run(initiator.handshake(responder))["authenticated"] is True
    assert responder.peers["node_initiator"]["status"] == "authenticated"
    return initiator, responder, trust_path


def test_revoking_mid_session_takes_effect_without_a_new_handshake(tmp_path):
    initiator, responder, trust_path = handshaken_pair(tmp_path)
    assert responder.is_permitted("node_initiator", "code-exec") is True

    responder.trust_list.revoke(initiator.public_key_hex, reason="compromised")

    assert responder.is_permitted("node_initiator", "code-exec") is False
    assert responder.granted_capabilities("node_initiator") == set()


def test_reload_applies_a_revocation_written_to_the_file(tmp_path):
    initiator, responder, trust_path = handshaken_pair(tmp_path)

    write_trust(trust_path, peers={},
                revoked=[{"public_key": initiator.public_key_hex,
                          "reason": "compromised"}])
    summary = responder.reload_trust()

    assert responder.trust_list.is_revoked(initiator.public_key_hex)
    assert summary["revoked"] == 1
    assert summary["dropped"] == [
        {"peer_id": "node_initiator", "reason": REASON_REVOKED_KEY}
    ]
    # Not left sitting in the peer table marked authenticated.
    assert "node_initiator" not in responder.peers
    assert responder.is_permitted("node_initiator", "code-exec") is False


def test_reload_drops_a_peer_that_was_simply_removed(tmp_path):
    """Deleting the entry is a weaker act than revoking, but it still ends
    the session."""
    initiator, responder, trust_path = handshaken_pair(tmp_path)

    write_trust(trust_path, peers={})
    summary = responder.reload_trust()

    assert summary["dropped"] == [
        {"peer_id": "node_initiator", "reason": REASON_UNTRUSTED_KEY}
    ]
    assert "node_initiator" not in responder.peers


def test_reload_keeps_a_peer_that_is_still_trusted(tmp_path):
    initiator, responder, trust_path = handshaken_pair(tmp_path)

    # Same peer, grants narrowed.
    write_trust(trust_path, peers={
        "initiator": {"public_key": initiator.public_key_hex,
                      "capabilities": ["web-retrieval"]},
    })
    summary = responder.reload_trust()

    assert summary["dropped"] == []
    assert responder.peers["node_initiator"]["status"] == "authenticated"
    assert responder.is_permitted("node_initiator", "web-retrieval") is True
    assert responder.is_permitted("node_initiator", "code-exec") is False


def test_reload_after_a_rotation_ends_the_old_keys_session(tmp_path):
    initiator, responder, trust_path = handshaken_pair(tmp_path)
    replacement = some_key()

    trust = TrustList.load(trust_path)
    trust.rotate("initiator", replacement)
    trust_path.write_text(json.dumps(trust.to_document()))
    summary = responder.reload_trust()

    assert summary["dropped"] == [
        {"peer_id": "node_initiator", "reason": REASON_REVOKED_KEY}
    ]
    assert responder.trust_list.trusts(replacement)


def test_a_corrupt_file_leaves_the_old_trust_list_in_place(tmp_path):
    """
    The reload failed, so the revocation it carried has NOT been applied --
    which is exactly why this raises instead of returning a summary. Keeping
    the old list only avoids adding a second failure on top of the first.
    """
    initiator, responder, trust_path = handshaken_pair(tmp_path)

    trust_path.write_text("{ not json")

    with pytest.raises(TrustError):
        responder.reload_trust()

    assert responder.trust_list.trusts(initiator.public_key_hex)
    assert responder.peers["node_initiator"]["status"] == "authenticated"


def test_reload_refuses_when_the_trust_list_was_injected():
    """
    There is no file behind an injected list. Resolving the default path would
    silently swap in a completely different allowlist.
    """
    node = make_node("node_a", trust_list=TrustList({"alice": some_key()}))

    with pytest.raises(TrustError, match="injected"):
        node.reload_trust()


def test_reload_works_when_a_path_was_given_alongside_a_list(tmp_path):
    """An explicit path means there is something real to reload from."""
    key = some_key()
    path = write_trust(tmp_path / "trust.json", peers={"alice": key})
    node = make_node("node_a", trust_path=str(path),
                     trust_list=TrustList({"bob": some_key()}))

    node.reload_trust()

    assert node.trust_list.trusts(key)


def test_reload_reports_the_new_totals(tmp_path):
    initiator, responder, trust_path = handshaken_pair(tmp_path)
    write_trust(trust_path,
                peers={"initiator": {"public_key": initiator.public_key_hex},
                       "carol": {"public_key": some_key()}},
                revoked=[some_key(), some_key()])

    summary = responder.reload_trust()

    assert summary == {"peers": 2, "revoked": 2, "dropped": []}


def test_reload_refuses_a_grant_the_node_does_not_advertise(tmp_path):
    """The load-time capability gate still applies on a reload."""
    initiator, responder, trust_path = handshaken_pair(tmp_path)
    write_trust(trust_path, peers={
        "initiator": {"public_key": initiator.public_key_hex,
                      "capabilities": ["code-exex"]},
    })

    with pytest.raises(TrustError, match="does not advertise"):
        responder.reload_trust()
