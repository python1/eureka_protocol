"""
Per-peer capability grants and their enforcement.

Advertised capabilities used to be decorative. A grant now says what a
specific public key may ask of this node, and authorisation is default-deny:
everything unknown answers no. Grants are keyed by public key exactly as
trust is, so a peer cannot be authenticated as one identity and authorised
as another.
"""
import asyncio
import json

import pytest

from eureka_protocol.src.eureka_daemon.crypto import EurekaCrypto
from eureka_protocol.src.eureka_daemon.node import EurekaNode
from eureka_protocol.src.eureka_daemon.trust import (
    TRUST_ALGORITHM,
    TRUST_FILE_VERSION,
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


def write_v2(path, peers):
    """peers maps name -> {"public_key": ..., "capabilities": [...]}."""
    path.write_text(json.dumps({
        "version": TRUST_FILE_VERSION,
        "algorithm": TRUST_ALGORITHM,
        "peers": peers,
    }))
    return path


def write_v1(path, peers):
    """The legacy shape: name -> bare public key hex."""
    path.write_text(json.dumps({
        "version": TRUST_FILE_VERSION_LEGACY,
        "algorithm": TRUST_ALGORITHM,
        "peers": peers,
    }))
    return path


def handshaken_pair(tmp_path, initiator_grants=(), responder_capabilities=None):
    """
    A completed mutual handshake where the responder grants the initiator
    `initiator_grants`. Returns (initiator, responder).
    """
    initiator = make_node("node_initiator")
    responder = make_node(
        "node_responder",
        capabilities=(responder_capabilities
                      if responder_capabilities is not None
                      else ("code-exec", "web-retrieval")),
    )
    responder.trust_list.add(
        initiator.node_id, initiator.public_key_hex, list(initiator_grants)
    )
    initiator.trust_list.add(responder.node_id, responder.public_key_hex)

    assert run(initiator.handshake(responder))["authenticated"] is True
    return initiator, responder


# ---------------------------------------------------------------------------
# Enforcement
# ---------------------------------------------------------------------------

def test_a_granted_capability_is_allowed(tmp_path):
    _, responder = handshaken_pair(tmp_path, initiator_grants=["code-exec"])

    assert responder.is_permitted("node_initiator", "code-exec") is True
    assert responder.granted_capabilities("node_initiator") == {"code-exec"}


def test_an_ungranted_capability_is_denied(tmp_path):
    _, responder = handshaken_pair(tmp_path, initiator_grants=["code-exec"])

    assert responder.is_permitted("node_initiator", "web-retrieval") is False


def test_a_peer_with_no_grants_may_do_nothing(tmp_path):
    _, responder = handshaken_pair(tmp_path, initiator_grants=[])

    assert responder.granted_capabilities("node_initiator") == set()
    assert responder.is_permitted("node_initiator", "code-exec") is False


@pytest.mark.parametrize("peer_id, capability", [
    ("node_stranger", "code-exec"),      # never handshaken
    ("node_initiator", "not-a-thing"),   # capability nobody has
    ("node_initiator", ""),              # empty
    ("node_initiator", "   "),           # whitespace
    ("node_initiator", None),            # wrong type
    ("node_initiator", 1234),
    (None, "code-exec"),
    (1234, "code-exec"),
])
def test_default_deny(tmp_path, peer_id, capability):
    _, responder = handshaken_pair(tmp_path, initiator_grants=["code-exec"])

    assert responder.is_permitted(peer_id, capability) is False


def test_an_unauthenticated_peer_is_denied(tmp_path):
    """A record that is not authenticated grants nothing."""
    _, responder = handshaken_pair(tmp_path, initiator_grants=["code-exec"])
    responder.peers["node_initiator"]["status"] = "pending"

    assert responder.is_permitted("node_initiator", "code-exec") is False
    assert responder.granted_capabilities("node_initiator") == set()


def test_a_node_cannot_grant_what_it_does_not_offer(tmp_path):
    """
    The second gate. A trust file may name any capability, but this node can
    only be asked for what it actually advertises -- so an over-broad or
    stale trust file cannot widen what a peer can reach.
    """
    _, responder = handshaken_pair(
        tmp_path,
        initiator_grants=["code-exec", "launch-missiles"],
        responder_capabilities=["code-exec"],
    )

    assert responder.is_permitted("node_initiator", "code-exec") is True
    assert responder.is_permitted("node_initiator", "launch-missiles") is False
    assert responder.granted_capabilities("node_initiator") == {"code-exec"}


def test_revoking_a_grant_takes_effect_without_a_new_handshake(tmp_path):
    """Authorisation reads the live trust list, not the handshake snapshot."""
    initiator, responder = handshaken_pair(tmp_path, initiator_grants=["code-exec"])
    assert responder.is_permitted("node_initiator", "code-exec") is True

    # Re-provision the same key with no grants.
    responder.trust_list.add(initiator.node_id, initiator.public_key_hex, [])

    assert responder.is_permitted("node_initiator", "code-exec") is False
    assert responder.granted_capabilities("node_initiator") == set()


def test_the_peer_record_carries_a_snapshot(tmp_path):
    _, responder = handshaken_pair(tmp_path, initiator_grants=["code-exec"])

    assert responder.peers["node_initiator"]["capabilities"] == ["code-exec"]


def test_handshake_still_succeeds_with_no_grants(tmp_path):
    """Authentication and authorisation are separate decisions."""
    _, responder = handshaken_pair(tmp_path, initiator_grants=[])

    assert responder.peers["node_initiator"]["status"] == "authenticated"
    assert responder.granted_capabilities("node_initiator") == set()


# ---------------------------------------------------------------------------
# Grants are keyed by public key, not by name
# ---------------------------------------------------------------------------

def test_grants_follow_the_key_not_the_label(tmp_path):
    key = some_key()
    trust = TrustList()
    trust.add("original-label", key, ["code-exec"])

    assert trust.grants(key, "code-exec") is True
    # The same key under a different label is the same peer...
    assert trust.name_for(key) == "original-label"
    # ...and a different key with a familiar-looking label holds nothing.
    assert trust.grants(some_key(), "code-exec") is False


def test_renaming_a_peer_preserves_its_grants(tmp_path):
    key = some_key()
    path = write_v2(tmp_path / "trust.json", {
        "old-name": {"public_key": key, "capabilities": ["code-exec"]},
    })
    before = TrustList.load(path)

    path = write_v2(tmp_path / "trust2.json", {
        "new-name": {"public_key": key, "capabilities": ["code-exec"]},
    })
    after = TrustList.load(path)

    assert before.grants(key, "code-exec") is True
    assert after.grants(key, "code-exec") is True
    assert after.name_for(key) == "new-name"


def test_grants_are_matched_case_insensitively_like_trust(tmp_path):
    key = some_key()
    path = write_v2(tmp_path / "trust.json", {
        "peer": {"public_key": key.upper(), "capabilities": ["code-exec"]},
    })

    trust = TrustList.load(path)

    assert trust.grants(key.lower(), "code-exec") is True


def test_grants_query_rejects_non_string_keys():
    trust = TrustList()
    trust.add("peer", some_key(), ["code-exec"])

    assert trust.grants(None, "code-exec") is False
    assert trust.grants(1234, "code-exec") is False
    assert trust.capabilities_for(None) == frozenset()


# ---------------------------------------------------------------------------
# Version 1 files still load, and grant nothing
# ---------------------------------------------------------------------------

def test_v1_file_loads(tmp_path):
    key = some_key()
    trust = TrustList.load(write_v1(tmp_path / "trust.json", {"legacy-peer": key}))

    assert len(trust) == 1
    assert trust.trusts(key) is True
    assert trust.name_for(key) == "legacy-peer"


def test_v1_file_grants_nothing(tmp_path):
    """The safe migration direction: authenticate, but authorise nothing."""
    key = some_key()
    trust = TrustList.load(write_v1(tmp_path / "trust.json", {"legacy-peer": key}))

    assert trust.capabilities_for(key) == frozenset()
    assert trust.grants(key, "code-exec") is False


def test_v1_deployment_authenticates_but_authorises_nothing(tmp_path):
    """End to end on a node still running a v1 trust file."""
    initiator = make_node("node_initiator")
    path = write_v1(tmp_path / "trust.json", {"init": initiator.public_key_hex})
    responder = make_node("node_responder", trust_path=path)
    initiator.trust_list.add(responder.node_id, responder.public_key_hex)

    assert run(initiator.handshake(responder))["authenticated"] is True
    assert responder.is_permitted("node_initiator", "code-exec") is False
    assert responder.granted_capabilities("node_initiator") == set()


def test_v1_file_may_not_carry_entry_objects(tmp_path):
    """A v2-shaped entry in a v1 file would grant from a file that cannot say so."""
    path = write_v1(tmp_path / "trust.json", {
        "peer": {"public_key": some_key(), "capabilities": ["code-exec"]},
    })

    with pytest.raises(TrustError, match="v1 entries are a public key string"):
        TrustList.load(path)


def test_v2_file_may_not_carry_bare_keys(tmp_path):
    """A half-finished migration is an error, not a silent partial load."""
    path = write_v2(tmp_path / "trust.json", {"peer": some_key()})

    with pytest.raises(TrustError, match="must be an object"):
        TrustList.load(path)


def test_unsupported_versions_are_still_rejected(tmp_path):
    # One past the current version rather than a literal, so this keeps
    # testing "the next version does not exist yet" after every bump.
    for version in (0, TRUST_FILE_VERSION + 1, 99, "2", None):
        path = tmp_path / f"trust-{version}.json"
        path.write_text(json.dumps({
            "version": version, "algorithm": TRUST_ALGORITHM, "peers": {},
        }))
        with pytest.raises(TrustError, match="unsupported version"):
            TrustList.load(path)


# ---------------------------------------------------------------------------
# Load-time validation of grants
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("capabilities, match", [
    ("code-exec", "must be a list"),          # bare string would iterate chars
    (42, "must be a list"),
    ({"code-exec": True}, "must be a list"),
    ([""], "non-empty string"),
    (["   "], "non-empty string"),
    ([None], "non-empty string"),
    ([123], "non-empty string"),
    (["ok", 5], "non-empty string"),
])
def test_malformed_capability_lists_are_rejected_at_load(tmp_path, capabilities, match):
    path = write_v2(tmp_path / "trust.json", {
        "peer": {"public_key": some_key(), "capabilities": capabilities},
    })

    with pytest.raises(TrustError, match=match):
        TrustList.load(path)


def test_a_misspelled_field_is_rejected(tmp_path):
    """'capabilties' silently granting nothing is the failure this catches."""
    path = write_v2(tmp_path / "trust.json", {
        "peer": {"public_key": some_key(), "capabilties": ["code-exec"]},
    })

    with pytest.raises(TrustError, match="unexpected field"):
        TrustList.load(path)


def test_a_missing_public_key_is_rejected(tmp_path):
    path = write_v2(tmp_path / "trust.json", {"peer": {"capabilities": ["x"]}})

    with pytest.raises(TrustError, match="missing 'public_key'"):
        TrustList.load(path)


def test_a_bad_key_in_a_v2_entry_is_still_rejected(tmp_path):
    path = write_v2(tmp_path / "trust.json", {
        "peer": {"public_key": "zz", "capabilities": ["x"]},
    })

    with pytest.raises(TrustError, match="64 hex characters"):
        TrustList.load(path)


def test_omitted_capabilities_grant_nothing(tmp_path):
    key = some_key()
    path = write_v2(tmp_path / "trust.json", {"peer": {"public_key": key}})

    trust = TrustList.load(path)

    assert trust.trusts(key) is True
    assert trust.capabilities_for(key) == frozenset()


def test_duplicate_capabilities_collapse(tmp_path):
    key = some_key()
    path = write_v2(tmp_path / "trust.json", {
        "peer": {"public_key": key, "capabilities": ["code-exec", "code-exec"]},
    })

    assert TrustList.load(path).capabilities_for(key) == frozenset({"code-exec"})


def test_capabilities_are_whitespace_trimmed(tmp_path):
    key = some_key()
    path = write_v2(tmp_path / "trust.json", {
        "peer": {"public_key": key, "capabilities": ["  code-exec  "]},
    })

    assert TrustList.load(path).grants(key, "code-exec") is True


def test_duplicate_keys_are_still_rejected_in_v2(tmp_path):
    shared = some_key()
    path = write_v2(tmp_path / "trust.json", {
        "one": {"public_key": shared, "capabilities": ["a"]},
        "two": {"public_key": shared, "capabilities": ["b"]},
    })

    with pytest.raises(TrustError, match="duplicate public key"):
        TrustList.load(path)


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------

def test_to_document_writes_the_current_version_with_grants(tmp_path):
    key = some_key()
    trust = TrustList()
    trust.add("peer", key, ["code-exec", "web-retrieval"])

    document = trust.to_document()

    assert document["version"] == TRUST_FILE_VERSION
    entry = document["peers"]["peer"]
    assert entry["public_key"] == key
    assert entry["capabilities"] == ["code-exec", "web-retrieval"]  # sorted


def test_document_round_trips_with_grants(tmp_path):
    key = some_key()
    original = TrustList()
    original.add("peer", key, ["web-retrieval", "code-exec"])

    path = tmp_path / "trust.json"
    path.write_text(json.dumps(original.to_document()))
    reloaded = TrustList.load(path)

    assert reloaded.capabilities_for(key) == original.capabilities_for(key)
    assert reloaded.name_for(key) == "peer"


def test_a_v1_file_round_trips_forward_to_v2_granting_nothing(tmp_path):
    """Migration path: load a v1 file, write it back, still no grants."""
    key = some_key()
    loaded = TrustList.load(write_v1(tmp_path / "v1.json", {"peer": key}))

    path = tmp_path / "v2.json"
    path.write_text(json.dumps(loaded.to_document()))
    migrated = TrustList.load(path)

    assert migrated.trusts(key) is True
    assert migrated.capabilities_for(key) == frozenset()
    assert json.loads(path.read_text())["version"] == TRUST_FILE_VERSION


def test_constructor_accepts_grants():
    key = some_key()
    trust = TrustList({"peer": key}, capabilities={"peer": ["code-exec"]})

    assert trust.grants(key, "code-exec") is True


# ---------------------------------------------------------------------------
# A grant naming an unadvertised capability is a load-time error
# ---------------------------------------------------------------------------

def test_a_grant_for_an_unadvertised_capability_fails_to_load(tmp_path):
    """
    The first gate, and the one that fails loudly. The runtime intersection
    below would deny 'launch-missiles' anyway, but denying it silently leaves
    a trust file that reads as if it grants something it never can.
    """
    path = write_v2(tmp_path / "trust.json", {
        "peer": {"public_key": some_key(),
                 "capabilities": ["code-exec", "launch-missiles"]},
    })

    with pytest.raises(TrustError, match="does not advertise") as exc:
        TrustList.load(path, advertised=["code-exec", "web-retrieval"])
    assert "launch-missiles" in str(exc.value)
    assert "code-exec'," not in str(exc.value)  # the valid grant is not blamed


def test_a_misspelled_capability_value_fails_to_load(tmp_path):
    """'code-exex' granting nothing in silence is the failure this catches."""
    path = write_v2(tmp_path / "trust.json", {
        "peer": {"public_key": some_key(), "capabilities": ["code-exex"]},
    })

    with pytest.raises(TrustError, match="code-exex"):
        TrustList.load(path, advertised=["code-exec"])


def test_a_node_refuses_to_start_on_a_trust_file_it_cannot_honour(tmp_path):
    path = write_v2(tmp_path / "trust.json", {
        "peer": {"public_key": some_key(), "capabilities": ["launch-missiles"]},
    })

    with pytest.raises(TrustError, match="does not advertise"):
        make_node("node_a", capabilities=["code-exec"], trust_path=path)


def test_grants_within_the_advertised_set_load(tmp_path):
    key = some_key()
    path = write_v2(tmp_path / "trust.json", {
        "peer": {"public_key": key, "capabilities": ["code-exec"]},
    })

    trust = TrustList.load(path, advertised=["code-exec", "web-retrieval"])

    assert trust.grants(key, "code-exec") is True


def test_the_check_is_applied_after_trimming(tmp_path):
    """'  code-exec  ' is the advertised capability, not an unadvertised one."""
    key = some_key()
    path = write_v2(tmp_path / "trust.json", {
        "peer": {"public_key": key, "capabilities": ["  code-exec  "]},
    })

    assert TrustList.load(path, advertised=["code-exec"]).grants(key, "code-exec")


def test_a_node_with_no_capabilities_cannot_be_granted_anything(tmp_path):
    path = write_v2(tmp_path / "trust.json", {
        "peer": {"public_key": some_key(), "capabilities": ["code-exec"]},
    })

    with pytest.raises(TrustError, match="does not advertise"):
        TrustList.load(path, advertised=[])


def test_loading_without_an_advertised_set_skips_the_check(tmp_path):
    """Reading a trust file is not the same as enforcing against one."""
    key = some_key()
    path = write_v2(tmp_path / "trust.json", {
        "peer": {"public_key": key, "capabilities": ["launch-missiles"]},
    })

    assert TrustList.load(path).grants(key, "launch-missiles") is True


def test_a_v1_file_loads_against_any_advertised_set(tmp_path):
    """v1 grants nothing, so it can never name something unadvertised."""
    key = some_key()
    path = write_v1(tmp_path / "trust.json", {"legacy-peer": key})

    trust = TrustList.load(path, advertised=[])

    assert trust.trusts(key) is True
    assert trust.capabilities_for(key) == frozenset()
