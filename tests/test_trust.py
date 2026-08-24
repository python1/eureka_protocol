"""
Tests for the peer trust list and its enforcement in the handshake.

The property under test: a valid signature is necessary but no longer
sufficient. Anyone can generate a keypair, so the responder's key must also
appear on this node's allowlist. An empty allowlist trusts nobody, and there
is no trust-on-first-use anywhere in the handshake path.
"""
import asyncio
import json

import pytest

from eureka_protocol.src.eureka_daemon.crypto import EurekaCrypto
from eureka_protocol.src.eureka_daemon.node import (
    EurekaNode,
    REASON_BAD_SIGNATURE,
    REASON_UNTRUSTED_KEY,
)
from eureka_protocol.src.eureka_daemon.trust import (
    DEFAULT_TRUST_PATH,
    TRUST_ALGORITHM,
    TRUST_FILE_VERSION,
    TRUST_PATH_ENV_VAR,
    TrustError,
    TrustList,
    resolve_trust_path,
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


def let_responder_trust(responder, initiator):
    """
    Provision the responder to accept the initiator.

    The handshake is mutual and the responder checks the initiator's key at
    message 1, before the initiator ever receives a message 2 to verify. These
    tests are about the *initiator's* trust decision, so without this the
    exchange would stop one step early and never reach the check under test.
    """
    responder.trust_list.add(initiator.node_id, initiator.public_key_hex)
    return responder


def write_trust_file(path, peers, version=TRUST_FILE_VERSION,
                     algorithm=TRUST_ALGORITHM):
    """
    Write a trust file.

    `peers` maps name -> public key hex, or name -> a full entry dict. At the
    current version a bare key is wrapped into an entry granting nothing,
    which is what these tests mean when they name a peer without grants.
    Pass version=1 to write the legacy bare-string shape verbatim.
    """
    if version == TRUST_FILE_VERSION:
        peers = {
            name: (value if isinstance(value, dict) else {"public_key": value})
            for name, value in peers.items()
        }
    path.write_text(json.dumps({
        "version": version,
        "algorithm": algorithm,
        "peers": peers,
    }))
    return path


def some_key():
    return EurekaCrypto().get_public_key_hex()


# ---------------------------------------------------------------------------
# Enforcement in the handshake
# ---------------------------------------------------------------------------

def test_trusted_peer_authenticates(tmp_path):
    responder = make_node("node_responder")
    trust_file = write_trust_file(tmp_path / "trust.json", {
        responder.node_id: responder.crypto.get_public_key_hex(),
    })
    initiator = make_node("node_initiator", trust_path=trust_file)
    let_responder_trust(responder, initiator)

    result = run(initiator.handshake(responder))

    assert result["authenticated"] is True
    assert initiator.peers[responder.node_id]["status"] == "authenticated"


def test_untrusted_key_with_a_valid_signature_is_rejected(tmp_path):
    """The signature is perfect; the key is simply not one we accept."""
    responder = make_node("node_responder")
    stranger = make_node("node_stranger")
    # The trust file names a different peer entirely.
    trust_file = write_trust_file(tmp_path / "trust.json", {
        stranger.node_id: stranger.crypto.get_public_key_hex(),
    })
    initiator = make_node("node_initiator", trust_path=trust_file)

    challenge = initiator.create_challenge(responder.node_id)
    response = responder.answer_challenge(challenge)
    # The signature itself is genuine.
    assert EurekaCrypto.verify_handshake(
        response["public_key"], response["signature"], challenge
    ) is True

    result = run(initiator.complete_handshake(response))

    assert result["authenticated"] is False
    assert result["reason"] == REASON_UNTRUSTED_KEY
    assert responder.node_id not in initiator.peers
    assert initiator.peers == {}


def test_absent_trust_file_rejects_everyone(tmp_path):
    responder = make_node("node_responder")
    initiator = make_node("node_initiator", trust_path=tmp_path / "absent.json")
    let_responder_trust(responder, initiator)

    assert len(initiator.trust_list) == 0

    result = run(initiator.handshake(responder))

    assert result["authenticated"] is False
    assert result["reason"] == REASON_UNTRUSTED_KEY
    assert initiator.peers == {}


def test_empty_trust_file_rejects_everyone(tmp_path):
    responder = make_node("node_responder")
    trust_file = write_trust_file(tmp_path / "trust.json", {})
    initiator = make_node("node_initiator", trust_path=trust_file)
    let_responder_trust(responder, initiator)

    assert len(initiator.trust_list) == 0

    result = run(initiator.handshake(responder))

    assert result["authenticated"] is False
    assert result["reason"] == REASON_UNTRUSTED_KEY
    assert initiator.peers == {}


def test_trust_check_runs_after_signature_verification(tmp_path):
    """
    A bad signature from a trusted key must still report the signature
    failure. Ordering matters: reporting 'untrusted' first would hide the
    forgery, and reporting 'untrusted' for a genuine peer whose signature was
    tampered with would send an operator hunting the wrong problem.
    """
    responder = make_node("node_responder")
    trust_file = write_trust_file(tmp_path / "trust.json", {
        responder.node_id: responder.crypto.get_public_key_hex(),
    })
    initiator = make_node("node_initiator", trust_path=trust_file)

    challenge = initiator.create_challenge(responder.node_id)
    response = responder.answer_challenge(challenge)
    response["signature"] = EurekaCrypto().sign_handshake(challenge)  # wrong key

    result = run(initiator.complete_handshake(response))

    assert result["reason"] == REASON_BAD_SIGNATURE
    assert initiator.peers == {}


def test_untrusted_bad_signature_still_reports_signature_failure(tmp_path):
    """Both wrong: the signature failure is the one reported."""
    responder = make_node("node_responder")
    initiator = make_node("node_initiator", trust_path=tmp_path / "absent.json")

    challenge = initiator.create_challenge(responder.node_id)
    response = responder.answer_challenge(challenge)
    response["signature"] = EurekaCrypto().sign_handshake(challenge)

    result = run(initiator.complete_handshake(response))

    assert result["reason"] == REASON_BAD_SIGNATURE


def test_rejected_peer_is_not_added_to_the_trust_list(tmp_path):
    """No trust-on-first-use: a stranger cannot talk its way onto the list."""
    responder = make_node("node_responder")
    initiator = make_node("node_initiator", trust_path=tmp_path / "absent.json")
    let_responder_trust(responder, initiator)

    for _ in range(3):
        assert run(initiator.handshake(responder))["reason"] == REASON_UNTRUSTED_KEY

    assert len(initiator.trust_list) == 0
    assert initiator.peers == {}


def test_trusting_a_different_key_of_the_same_name_does_not_help(tmp_path):
    """Trust is by key, not by name -- a peer cannot borrow a trusted label."""
    responder = make_node("node_responder")
    trust_file = write_trust_file(tmp_path / "trust.json", {
        # Same name the responder uses, but somebody else's key.
        responder.node_id: some_key(),
    })
    initiator = make_node("node_initiator", trust_path=trust_file)
    let_responder_trust(responder, initiator)

    result = run(initiator.handshake(responder))

    assert result["authenticated"] is False
    assert result["reason"] == REASON_UNTRUSTED_KEY


def test_trust_survives_across_many_handshakes(tmp_path):
    responder = make_node("node_responder")
    trust_file = write_trust_file(tmp_path / "trust.json", {
        responder.node_id: responder.crypto.get_public_key_hex(),
    })
    initiator = make_node("node_initiator", trust_path=trust_file)
    let_responder_trust(responder, initiator)

    for _ in range(5):
        assert run(initiator.handshake(responder))["authenticated"] is True


# ---------------------------------------------------------------------------
# Loading and validation
# ---------------------------------------------------------------------------

def test_missing_trust_file_is_an_empty_list_not_an_error(tmp_path):
    trust_list = TrustList.load_or_empty(tmp_path / "absent.json")

    assert len(trust_list) == 0
    assert trust_list.trusts(some_key()) is False


def test_missing_trust_file_raises_for_explicit_load(tmp_path):
    with pytest.raises(TrustError, match="no trust file"):
        TrustList.load(tmp_path / "absent.json")


@pytest.mark.parametrize("content, match", [
    ("not json at all", "not valid JSON"),
    ("[]", "must contain a JSON object"),
    ('{"algorithm": "ed25519", "peers": {}}', "unsupported version"),
    ('{"version": 99, "algorithm": "ed25519", "peers": {}}', "unsupported version"),
    ('{"version": 1, "algorithm": "rsa", "peers": {}}', "unsupported algorithm"),
    ('{"version": 1, "algorithm": "ed25519"}', "must have a 'peers' object"),
    ('{"version": 1, "algorithm": "ed25519", "peers": []}', "must have a 'peers' object"),
])
def test_corrupt_trust_file_raises(tmp_path, content, match):
    path = tmp_path / "trust.json"
    path.write_text(content)

    with pytest.raises(TrustError, match=match):
        TrustList.load(path)


def test_corrupt_trust_file_does_not_degrade_to_empty(tmp_path):
    """
    The distinction that matters: a corrupt file must not look like an empty
    allowlist, because an empty allowlist is what a failed deployment also
    looks like. One is loud, the other silently rejects everyone forever.
    """
    path = tmp_path / "trust.json"
    path.write_text("{ this is not json")

    with pytest.raises(TrustError):
        TrustList.load_or_empty(path)


def test_corrupt_trust_file_raises_at_node_construction(tmp_path):
    path = tmp_path / "trust.json"
    path.write_text("{ broken")

    with pytest.raises(TrustError):
        make_node("node_initiator", trust_path=path)


@pytest.mark.parametrize("bad_key, match", [
    ("", "64 hex characters"),
    ("aabb", "64 hex characters"),
    ("z" * 64, "not valid hex"),
    ("a" * 63, "64 hex characters"),
    ("a" * 65, "64 hex characters"),
    (12345, "must be a string"),
    (None, "must be a string"),
])
def test_malformed_key_entries_are_rejected_at_load(tmp_path, bad_key, match):
    path = write_trust_file(tmp_path / "trust.json", {"node_bad": bad_key})

    with pytest.raises(TrustError, match=match):
        TrustList.load(path)


def test_empty_peer_name_is_rejected(tmp_path):
    path = write_trust_file(tmp_path / "trust.json", {"": some_key()})

    with pytest.raises(TrustError, match="non-empty string"):
        TrustList.load(path)


def test_duplicate_keys_under_different_names_are_rejected(tmp_path):
    shared = some_key()
    path = write_trust_file(tmp_path / "trust.json", {
        "node_one": shared,
        "node_two": shared,
    })

    with pytest.raises(TrustError, match="duplicate public key"):
        TrustList.load(path)


def test_duplicate_keys_differing_only_in_case_are_rejected(tmp_path):
    shared = some_key()
    path = write_trust_file(tmp_path / "trust.json", {
        "node_one": shared.lower(),
        "node_two": shared.upper(),
    })

    with pytest.raises(TrustError, match="duplicate public key"):
        TrustList.load(path)


def test_keys_are_matched_case_insensitively(tmp_path):
    key = some_key()
    path = write_trust_file(tmp_path / "trust.json", {"node_one": key.upper()})

    trust_list = TrustList.load(path)

    assert trust_list.trusts(key.lower()) is True
    assert trust_list.name_for(key.lower()) == "node_one"


def test_valid_trust_file_loads_every_peer(tmp_path):
    keys = {f"node_{i}": some_key() for i in range(5)}
    path = write_trust_file(tmp_path / "trust.json", keys)

    trust_list = TrustList.load(path)

    assert len(trust_list) == 5
    for name, key in keys.items():
        assert trust_list.trusts(key) is True
        assert trust_list.name_for(key) == name


def test_trusts_rejects_non_string_input():
    trust_list = TrustList({"node_one": some_key()})

    assert trust_list.trusts(None) is False
    assert trust_list.trusts(1234) is False


def test_to_document_round_trips(tmp_path):
    keys = {f"node_{i}": some_key() for i in range(3)}
    original = TrustList(keys)

    path = tmp_path / "trust.json"
    path.write_text(json.dumps(original.to_document()))
    reloaded = TrustList.load(path)

    assert len(reloaded) == len(original)
    for key in keys.values():
        assert reloaded.trusts(key) is True


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

def test_explicit_path_wins_over_environment(tmp_path, monkeypatch):
    monkeypatch.setenv(TRUST_PATH_ENV_VAR, str(tmp_path / "from-env.json"))
    explicit = tmp_path / "explicit.json"

    assert resolve_trust_path(explicit) == explicit


def test_environment_variable_is_honoured(tmp_path, monkeypatch):
    target = write_trust_file(tmp_path / "from-env.json", {"node_one": some_key()})
    monkeypatch.setenv(TRUST_PATH_ENV_VAR, str(target))

    assert resolve_trust_path() == target
    assert len(TrustList.load_or_empty()) == 1


def test_node_honours_the_environment_variable(tmp_path, monkeypatch):
    responder = make_node("node_responder")
    target = write_trust_file(tmp_path / "from-env.json", {
        responder.node_id: responder.crypto.get_public_key_hex(),
    })
    monkeypatch.setenv(TRUST_PATH_ENV_VAR, str(target))

    initiator = make_node("node_initiator")
    let_responder_trust(responder, initiator)

    assert run(initiator.handshake(responder))["authenticated"] is True


def test_default_path_is_used_when_nothing_is_configured(monkeypatch):
    monkeypatch.delenv(TRUST_PATH_ENV_VAR, raising=False)

    assert resolve_trust_path() == DEFAULT_TRUST_PATH


def test_user_home_is_expanded(monkeypatch):
    monkeypatch.setenv(TRUST_PATH_ENV_VAR, "~/somewhere/trust.json")

    resolved = resolve_trust_path()
    assert "~" not in str(resolved)
    assert resolved.is_absolute()


def test_no_test_touches_the_real_default_trust_path():
    """
    The suite must never read or write the operator's real trust file.

    Asserted by showing the suite resolves somewhere else and loads nothing
    from there -- NOT by asserting the default path is absent. On a deployed
    node that file exists by design, and a test that fails because the host
    it runs on is actually in service is testing the wrong thing.
    """
    assert resolve_trust_path() != DEFAULT_TRUST_PATH
    # If the real allowlist were leaking in, this would carry its peers.
    assert len(TrustList.load_or_empty()) == 0
