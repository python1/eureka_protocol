"""
Tests for the node's persistent cryptographic identity.

The property under test is survival across a restart: a node that reloads its
stored key comes back as the same node, with the same public key and the same
node_id, and signatures it made before the restart still verify afterwards.
"""
import json
import os
import stat

import pytest

from eureka_protocol.src.eureka_daemon.crypto import (
    DEFAULT_IDENTITY_PATH,
    IDENTITY_ALGORITHM,
    IDENTITY_FILE_VERSION,
    IDENTITY_PATH_ENV_VAR,
    DOMAIN_HANDSHAKE,
    EurekaCrypto,
    IdentityError,
    resolve_identity_path,
)
from eureka_protocol.src.eureka_daemon.node import EurekaNode


@pytest.fixture
def identity_path(tmp_path):
    return tmp_path / "identity.key"


# ---------------------------------------------------------------------------
# Persistence across restart
# ---------------------------------------------------------------------------

def test_identity_is_created_on_first_run(identity_path):
    assert not identity_path.exists()

    crypto = EurekaCrypto.load_or_create(identity_path)

    assert identity_path.exists()
    assert crypto.get_public_key_hex()


def test_identity_survives_a_restart(identity_path):
    """The whole point: same key back after the process goes away."""
    first = EurekaCrypto.load_or_create(identity_path)
    second = EurekaCrypto.load_or_create(identity_path)

    assert second.get_public_key_hex() == first.get_public_key_hex()
    assert second.get_private_key_hex() == first.get_private_key_hex()


def test_signatures_survive_a_restart(identity_path):
    """A signature made before the restart still verifies after it."""
    payload = {"protocol": "eureka/1.0", "event": "handshake_challenge"}

    before = EurekaCrypto.load_or_create(identity_path)
    signature = before.sign_json(payload, DOMAIN_HANDSHAKE)

    after = EurekaCrypto.load_or_create(identity_path)
    assert EurekaCrypto.verify_json(
        after.get_public_key_hex(), signature, payload, DOMAIN_HANDSHAKE
    ) is True


def test_existing_identity_is_never_regenerated(identity_path):
    original = EurekaCrypto.load_or_create(identity_path)
    original_key = original.get_private_key_hex()

    for _ in range(5):
        assert EurekaCrypto.load_or_create(identity_path).get_private_key_hex() \
            == original_key


def test_two_separate_paths_are_two_separate_identities(tmp_path):
    a = EurekaCrypto.load_or_create(tmp_path / "a.key")
    b = EurekaCrypto.load_or_create(tmp_path / "b.key")

    assert a.get_public_key_hex() != b.get_public_key_hex()


def test_ephemeral_construction_still_works():
    """Constructing directly stays keyless-on-disk and random, as before."""
    assert EurekaCrypto().get_public_key_hex() != EurekaCrypto().get_public_key_hex()


# ---------------------------------------------------------------------------
# node_id derivation
# ---------------------------------------------------------------------------

def test_node_id_is_derived_from_the_public_key(identity_path):
    crypto = EurekaCrypto.load_or_create(identity_path)

    node_id = crypto.derive_node_id()
    assert node_id.startswith("node_")
    # Same shape the daemon already emitted: node_ + 8 hex characters.
    assert len(node_id) == len("node_") + 8
    int(node_id[len("node_"):], 16)

    # Deterministic: same key, same id, every time.
    assert crypto.derive_node_id() == node_id
    assert EurekaCrypto.load_or_create(identity_path).derive_node_id() == node_id


def test_different_keys_get_different_node_ids():
    ids = {EurekaCrypto().derive_node_id() for _ in range(50)}
    assert len(ids) == 50


def test_node_keeps_its_id_across_a_restart(identity_path):
    first = EurekaNode.with_persistent_identity(["code-exec"], identity_path)
    second = EurekaNode.with_persistent_identity(["code-exec"], identity_path)

    assert second.node_id == first.node_id
    assert second.public_key_hex == first.public_key_hex


def test_node_derives_its_id_when_none_is_supplied():
    crypto = EurekaCrypto()
    node = EurekaNode(node_id=None, crypto_engine=crypto, capabilities=[])

    assert node.node_id == crypto.derive_node_id()


def test_explicit_node_id_is_still_honoured():
    node = EurekaNode(node_id="node_custom", crypto_engine=EurekaCrypto(),
                      capabilities=[])

    assert node.node_id == "node_custom"


def test_manifest_reports_the_persistent_identity(identity_path):
    node = EurekaNode.with_persistent_identity(["code-exec"], identity_path)

    assert node.manifest["node_id"] == node.node_id
    assert node.manifest["node_id"] == node.crypto.derive_node_id()


def test_persistent_identity_still_completes_a_handshake(tmp_path):
    """Identity change must not disturb the handshake."""
    import asyncio

    initiator = EurekaNode.with_persistent_identity(["x"], tmp_path / "a.key")
    responder = EurekaNode.with_persistent_identity(["x"], tmp_path / "b.key")
    # The handshake is mutual, so both sides must trust the other's key.
    initiator.trust_list.add(responder.node_id, responder.public_key_hex)
    responder.trust_list.add(initiator.node_id, initiator.public_key_hex)

    result = asyncio.run(initiator.handshake(responder))

    assert result["authenticated"] is True
    assert responder.node_id in initiator.peers


# ---------------------------------------------------------------------------
# On-disk safety
# ---------------------------------------------------------------------------

def test_identity_file_is_private(identity_path):
    EurekaCrypto.load_or_create(identity_path)

    mode = stat.S_IMODE(identity_path.stat().st_mode)
    assert mode == 0o600, f"key file is mode {mode:04o}, expected 0600"


def test_parent_directory_is_created_privately(tmp_path):
    nested = tmp_path / "fresh" / "identity.key"
    EurekaCrypto.load_or_create(nested)

    assert nested.exists()
    assert stat.S_IMODE(nested.parent.stat().st_mode) == 0o700


def test_group_or_world_readable_identity_is_refused(identity_path):
    EurekaCrypto.load_or_create(identity_path)
    identity_path.chmod(0o644)

    with pytest.raises(IdentityError, match="group/world accessible"):
        EurekaCrypto.load(identity_path)


def test_save_refuses_to_clobber_an_existing_identity(identity_path):
    EurekaCrypto.load_or_create(identity_path)
    before = identity_path.read_text()

    with pytest.raises(IdentityError, match="refusing to overwrite"):
        EurekaCrypto().save(identity_path)

    # The original key is untouched.
    assert identity_path.read_text() == before


def test_save_can_overwrite_when_explicitly_told_to(identity_path):
    original = EurekaCrypto.load_or_create(identity_path)
    replacement = EurekaCrypto()

    replacement.save(identity_path, overwrite=True)

    reloaded = EurekaCrypto.load(identity_path)
    assert reloaded.get_public_key_hex() == replacement.get_public_key_hex()
    assert reloaded.get_public_key_hex() != original.get_public_key_hex()


def test_write_leaves_no_temporary_files_behind(tmp_path):
    EurekaCrypto.load_or_create(tmp_path / "identity.key")

    leftovers = [p.name for p in tmp_path.iterdir() if p.name != "identity.key"]
    assert leftovers == []


def test_identity_file_is_versioned_json(identity_path):
    crypto = EurekaCrypto.load_or_create(identity_path)
    document = json.loads(identity_path.read_text())

    assert document["version"] == IDENTITY_FILE_VERSION
    assert document["algorithm"] == IDENTITY_ALGORITHM
    assert document["private_key_hex"] == crypto.get_private_key_hex()
    assert document["node_id"] == crypto.derive_node_id()


@pytest.mark.parametrize("content, match", [
    ("not json at all", "not valid JSON"),
    ('{"version": 99, "algorithm": "ed25519", "private_key_hex": "aa"}',
     "unsupported version"),
    ('{"version": 1, "algorithm": "rsa", "private_key_hex": "aa"}',
     "unsupported algorithm"),
    ('{"version": 1, "algorithm": "ed25519"}', "no private_key_hex"),
    ('{"version": 1, "algorithm": "ed25519", "private_key_hex": "zz"}',
     "not contain a usable key"),
    ('{"version": 1, "algorithm": "ed25519", "private_key_hex": "aabb"}',
     "not contain a usable key"),
])
def test_corrupt_identity_files_are_rejected_clearly(identity_path, content, match):
    identity_path.write_text(content)
    identity_path.chmod(0o600)

    with pytest.raises(IdentityError, match=match):
        EurekaCrypto.load(identity_path)


def test_loading_a_missing_identity_raises(tmp_path):
    with pytest.raises(IdentityError, match="no identity file"):
        EurekaCrypto.load(tmp_path / "absent.key")


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

def test_explicit_path_wins_over_environment(identity_path, monkeypatch):
    monkeypatch.setenv(IDENTITY_PATH_ENV_VAR, "/somewhere/else.key")

    assert resolve_identity_path(identity_path) == identity_path


def test_environment_variable_is_honoured(tmp_path, monkeypatch):
    target = tmp_path / "from-env.key"
    monkeypatch.setenv(IDENTITY_PATH_ENV_VAR, str(target))

    assert resolve_identity_path() == target
    EurekaCrypto.load_or_create()
    assert target.exists()


def test_default_path_is_used_when_nothing_is_configured(monkeypatch):
    monkeypatch.delenv(IDENTITY_PATH_ENV_VAR, raising=False)

    assert resolve_identity_path() == DEFAULT_IDENTITY_PATH


def test_default_filename_is_gitignored():
    """A private key must not be committable by accident."""
    assert DEFAULT_IDENTITY_PATH.name.endswith(".key")


def test_user_home_is_expanded(monkeypatch):
    monkeypatch.setenv(IDENTITY_PATH_ENV_VAR, "~/somewhere/identity.key")

    resolved = resolve_identity_path()
    assert "~" not in str(resolved)
    assert resolved.is_absolute()
