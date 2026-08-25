"""
Transport encryption, and the pin that gives it meaning.

The design decision under test: TLS carries the node's EXISTING ed25519
identity rather than a second one. A node's certificate is a wrapper around
the key its peers already have in their trust file, so the client authenticates
the server by pinning that raw key -- no certificate authority, no fingerprint
format, and nothing new to distribute.

The consequence worth protecting: there is exactly one place to revoke a peer.
Client certificates would have moved peer identity into a CA store read once at
startup, where reload_trust() could never reach it.
"""
import asyncio
import datetime
import socket
import signal
import ssl
import stat
import threading
import time

import httpx
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from eureka_protocol.src.eureka_daemon import api
from eureka_protocol.src.eureka_daemon import client as client_module
from eureka_protocol.src.eureka_daemon.api import app
from eureka_protocol.src.eureka_daemon.client import handshake_over_http
from eureka_protocol.src.eureka_daemon.crypto import EurekaCrypto
from eureka_protocol.src.eureka_daemon.node import (
    EurekaNode,
    REASON_REVOKED_KEY,
    REASON_TLS_IDENTITY_MISMATCH,
    REASON_TLS_REQUIRED,
    REASON_UNTRUSTED_KEY,
)
from eureka_protocol.src.eureka_daemon.tls import (
    SERVER_CERT_FILENAME,
    SERVER_KEY_FILENAME,
    TLSError,
    build_self_signed_cert,
    ensure_server_materials,
    peer_key_from_response,
    pinning_ssl_context,
    public_key_hex_from_cert,
    server_material_paths,
)
from eureka_protocol.src.eureka_daemon.trust import TrustList

STATE_TABLES = ("peers", "pending_challenges", "seen_nonces", "pending_peers")


def run(coro):
    return asyncio.run(coro)


def make_node(node_id):
    return EurekaNode(node_id=node_id, crypto_engine=EurekaCrypto(),
                      capabilities=["code-exec"])


@pytest.fixture
def daemon():
    """The module-level node behind the app, with its state isolated per test."""
    node = api.node_engine
    saved = {name: dict(getattr(node, name)) for name in STATE_TABLES}
    saved_trust = node.trust_list
    for name in STATE_TABLES:
        getattr(node, name).clear()
    node.trust_list = TrustList()
    yield node
    for name, contents in saved.items():
        table = getattr(node, name)
        table.clear()
        table.update(contents)
    node.trust_list = saved_trust


# ---------------------------------------------------------------------------
# The certificate carries the identity the node already has
# ---------------------------------------------------------------------------

def test_certificate_wraps_the_nodes_existing_key():
    """
    The property the whole design rests on. If the certificate carried its own
    keypair, a node would have two identities that could drift apart, and the
    trust file would no longer describe who can connect.
    """
    crypto = EurekaCrypto()
    pem = build_self_signed_cert(crypto, "node_example")

    assert public_key_hex_from_cert(pem) == crypto.get_public_key_hex()


def test_certificate_is_named_but_the_name_is_not_the_identity():
    """
    The subject name is for humans reading openssl output. Nothing verifies it,
    which is why the client turns hostname checking off.
    """
    crypto = EurekaCrypto()
    certificate = x509.load_pem_x509_certificate(
        build_self_signed_cert(crypto, "node_example"))

    common_name = certificate.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME)[0].value
    assert common_name == "node_example"
    assert certificate.issuer == certificate.subject          # self-signed


def test_certificate_is_readable_as_pem_or_der():
    crypto = EurekaCrypto()
    pem = build_self_signed_cert(crypto, "node_example")
    der = x509.load_pem_x509_certificate(pem).public_bytes(
        serialization.Encoding.DER)

    assert public_key_hex_from_cert(pem) == public_key_hex_from_cert(der)


@pytest.mark.parametrize("node_id", ["", "   ", None, 42])
def test_a_certificate_needs_a_node_id(node_id):
    with pytest.raises(TLSError):
        build_self_signed_cert(EurekaCrypto(), node_id)


def test_a_non_ed25519_certificate_is_refused():
    """
    An RSA or EC certificate cannot be checked against this trust file at all.
    Accepting one would mean a connection nobody pinned.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "impostor")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    pem = certificate.public_bytes(serialization.Encoding.PEM)

    with pytest.raises(TLSError, match="ed25519"):
        public_key_hex_from_cert(pem)


@pytest.mark.parametrize("value, match", [
    (b"not a certificate", "cannot parse"),
    (b"", "cannot parse"),
    ("a string", "must be bytes"),
    (None, "must be bytes"),
])
def test_unparseable_certificates_are_refused(value, match):
    with pytest.raises(TLSError, match=match):
        public_key_hex_from_cert(value)


# ---------------------------------------------------------------------------
# Materials on disk
# ---------------------------------------------------------------------------

def test_materials_are_written_for_the_current_identity(tmp_path):
    crypto = EurekaCrypto()
    cert_path, key_path = ensure_server_materials(crypto, "node_a", tmp_path)

    assert cert_path == tmp_path / SERVER_CERT_FILENAME
    assert key_path == tmp_path / SERVER_KEY_FILENAME
    assert public_key_hex_from_cert(cert_path.read_bytes()) == \
        crypto.get_public_key_hex()


def test_the_tls_key_file_is_private(tmp_path):
    """It is a second copy of the node's private key. It gets the same 0600."""
    _, key_path = ensure_server_materials(EurekaCrypto(), "node_a", tmp_path)

    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600


def test_the_tls_key_file_really_is_the_identity_key(tmp_path):
    crypto = EurekaCrypto()
    _, key_path = ensure_server_materials(crypto, "node_a", tmp_path)

    loaded = serialization.load_pem_private_key(key_path.read_bytes(),
                                                password=None)
    assert loaded.private_bytes_raw() == crypto.private_key.private_bytes_raw()


def test_materials_are_reused_when_the_identity_has_not_changed(tmp_path):
    crypto = EurekaCrypto()
    cert_path, _ = ensure_server_materials(crypto, "node_a", tmp_path)
    first = cert_path.read_bytes()

    ensure_server_materials(crypto, "node_a", tmp_path)

    assert cert_path.read_bytes() == first


def test_materials_are_regenerated_after_the_identity_rotates(tmp_path):
    """
    The interaction that matters between rotation and TLS. Serving a stale
    certificate would present peers with a key this node can no longer prove it
    holds -- every connection would then fail in a way that looks like an
    attack rather than like a stale file.
    """
    identity_path = tmp_path / "identity.key"
    original = EurekaCrypto.load_or_create(identity_path)
    cert_path, key_path = ensure_server_materials(original, "node_a", tmp_path)
    assert public_key_hex_from_cert(cert_path.read_bytes()) == \
        original.get_public_key_hex()

    rotated, _ = EurekaCrypto.rotate(identity_path)
    ensure_server_materials(rotated, rotated.derive_node_id(), tmp_path)

    assert public_key_hex_from_cert(cert_path.read_bytes()) == \
        rotated.get_public_key_hex()
    loaded = serialization.load_pem_private_key(key_path.read_bytes(),
                                                password=None)
    assert loaded.private_bytes_raw() == rotated.private_key.private_bytes_raw()


def test_a_corrupt_certificate_on_disk_is_replaced(tmp_path):
    crypto = EurekaCrypto()
    cert_path, _ = ensure_server_materials(crypto, "node_a", tmp_path)
    cert_path.write_bytes(b"not a certificate at all")

    ensure_server_materials(crypto, "node_a", tmp_path)

    assert public_key_hex_from_cert(cert_path.read_bytes()) == \
        crypto.get_public_key_hex()


def test_materials_default_to_living_beside_the_identity():
    cert_path, key_path = server_material_paths()
    from eureka_protocol.src.eureka_daemon.crypto import resolve_identity_path
    assert cert_path.parent == resolve_identity_path().parent
    assert key_path.parent == resolve_identity_path().parent


# ---------------------------------------------------------------------------
# The client context
# ---------------------------------------------------------------------------

def test_pinning_context_trusts_no_certificate_authority():
    """
    Not "verification off". Chain verification is replaced by pinning, which is
    strictly narrower: the default context accepts hundreds of public CAs,
    this one accepts nothing until the pin says so.
    """
    context = pinning_ssl_context()

    assert context.verify_mode == ssl.CERT_NONE
    assert context.check_hostname is False
    assert context.minimum_version == ssl.TLSVersion.TLSv1_3
    assert context.get_ca_certs() == []


def test_no_peer_key_for_a_plain_connection():
    """A response with no TLS underneath yields no pin, not a false one."""
    class Fake:
        extensions = {}
    assert peer_key_from_response(Fake()) is None


# ---------------------------------------------------------------------------
# End to end over a real TLS socket
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def tls_server(tmp_path_factory):
    """
    The real daemon app, served over TLS with a certificate generated from its
    own identity key. An in-process ASGI transport cannot exercise any of this:
    the pin only exists once there is a socket with a certificate on it.
    """
    directory = tmp_path_factory.mktemp("tls-materials")
    node = api.node_engine
    cert_path, key_path = ensure_server_materials(
        node.crypto, node.node_id, directory)

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    server = uvicorn.Server(uvicorn.Config(
        app, host="127.0.0.1", port=port, log_level="error",
        ssl_certfile=str(cert_path), ssl_keyfile=str(key_path),
    ))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 20
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    if not server.started:
        pytest.fail("TLS server did not start")

    yield f"https://127.0.0.1:{port}"

    server.should_exit = True
    thread.join(timeout=10)


def pinning_client(base_url):
    return httpx.AsyncClient(base_url=base_url, verify=pinning_ssl_context(),
                             timeout=10)


def test_handshake_over_real_tls_authenticates_both_sides(daemon, tls_server):
    """
    require_tls=True is what makes this a real assertion: if the connection had
    not been TLS, the driver would have refused with tls_required rather than
    quietly completing in the clear.
    """
    initiator = make_node("node_tls_initiator")
    daemon.trust_list.add(initiator.node_id, initiator.public_key_hex)
    initiator.trust_list.add(daemon.node_id, daemon.public_key_hex)

    async def exchange():
        async with pinning_client(tls_server) as http:
            return await handshake_over_http(initiator, http=http,
                                             require_tls=True)

    result = run(exchange())

    assert result["authenticated"] is True
    assert result["mutual"] is True
    assert daemon.peers[initiator.node_id]["status"] == "authenticated"


def test_an_untrusted_server_key_is_refused_before_the_handshake(daemon, tls_server):
    """
    The pin is checked on the manifest response, so an untrusted server never
    receives an offer at all -- we do not tell it anything before deciding.
    """
    initiator = make_node("node_tls_stranger")
    daemon.trust_list.add(initiator.node_id, initiator.public_key_hex)
    # The initiator does NOT trust the daemon's key.

    async def exchange():
        async with pinning_client(tls_server) as http:
            return await handshake_over_http(initiator, http=http)

    result = run(exchange())

    assert result["authenticated"] is False
    assert result["reason"] == REASON_UNTRUSTED_KEY
    assert daemon.seen_nonces == {}
    assert daemon.pending_peers == {}
    assert initiator.node_id not in daemon.peers


def test_a_revoked_server_key_is_refused(daemon, tls_server):
    """
    Revocation reaches the transport with no separate mechanism: the pin reads
    the same trust list, so revoking once is enough.
    """
    initiator = make_node("node_tls_revoker")
    daemon.trust_list.add(initiator.node_id, initiator.public_key_hex)
    initiator.trust_list.add(daemon.node_id, daemon.public_key_hex)
    initiator.trust_list.revoke(daemon.public_key_hex, reason="compromised")

    async def exchange():
        async with pinning_client(tls_server) as http:
            return await handshake_over_http(initiator, http=http)

    result = run(exchange())

    assert result["authenticated"] is False
    assert result["reason"] == REASON_REVOKED_KEY


def test_the_pin_survives_connection_reuse(daemon, tls_server):
    """
    All three messages go over one client. Each response is pinned again rather
    than trusting the check made on the first one.
    """
    initiator = make_node("node_tls_reuse")
    daemon.trust_list.add(initiator.node_id, initiator.public_key_hex)
    initiator.trust_list.add(daemon.node_id, daemon.public_key_hex)

    async def exchange():
        async with pinning_client(tls_server) as http:
            first = await handshake_over_http(initiator, http=http,
                                              require_tls=True)
            second = await handshake_over_http(initiator, http=http,
                                               require_tls=True)
            return first, second

    first, second = run(exchange())

    assert first["authenticated"] is True
    assert second["authenticated"] is True


def test_require_tls_refuses_a_plain_connection(daemon):
    """A deployment that says it will not speak in the clear must not."""
    initiator = make_node("node_plain")
    daemon.trust_list.add(initiator.node_id, initiator.public_key_hex)
    initiator.trust_list.add(daemon.node_id, daemon.public_key_hex)

    async def exchange():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport,
                                     base_url="http://daemon") as http:
            return await handshake_over_http(initiator, http=http,
                                             require_tls=True)

    result = run(exchange())

    assert result["authenticated"] is False
    assert result["reason"] == REASON_TLS_REQUIRED
    assert initiator.node_id not in daemon.peers


def test_a_plain_connection_is_still_allowed_by_default(daemon):
    """The current deployment speaks plain HTTP; that is not broken here."""
    initiator = make_node("node_plain_ok")
    daemon.trust_list.add(initiator.node_id, initiator.public_key_hex)
    initiator.trust_list.add(daemon.node_id, daemon.public_key_hex)

    async def exchange():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport,
                                     base_url="http://daemon") as http:
            return await handshake_over_http(initiator, http=http)

    assert run(exchange())["authenticated"] is True


def test_the_channel_is_bound_to_the_handshake_identity(daemon, monkeypatch):
    """
    A peer we trust terminates TLS, then relays a DIFFERENT trusted peer's
    handshake. Both keys pass their own check; only comparing them catches it.
    Without this the client ends up authenticated to one identity over a
    channel held by another.
    """
    initiator = make_node("node_bound")
    relay_key = EurekaCrypto().get_public_key_hex()
    daemon.trust_list.add(initiator.node_id, initiator.public_key_hex)
    initiator.trust_list.add(daemon.node_id, daemon.public_key_hex)
    initiator.trust_list.add("relay", relay_key)      # the relay is trusted too

    monkeypatch.setattr(client_module.tls, "peer_key_from_response",
                        lambda response: relay_key)

    async def exchange():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport,
                                     base_url="http://daemon") as http:
            return await handshake_over_http(initiator, http=http)

    result = run(exchange())

    assert result["authenticated"] is False
    assert result["reason"] == REASON_TLS_IDENTITY_MISMATCH
    assert daemon.node_id not in initiator.peers


# ---------------------------------------------------------------------------
# Daemon wiring
# ---------------------------------------------------------------------------

def test_serving_with_tls_wires_the_nodes_own_key(tmp_path):
    from eureka_protocol.src.eureka_daemon.server import build_config

    config = build_config(8000, use_tls=True, materials_dir=tmp_path)

    assert config.ssl_certfile is not None
    assert config.ssl_keyfile is not None
    served = public_key_hex_from_cert(open(config.ssl_certfile, "rb").read())
    assert served == api.node_engine.public_key_hex


def test_serving_without_tls_wires_no_certificate():
    from eureka_protocol.src.eureka_daemon.server import build_config

    config = build_config(8000, use_tls=False)

    assert config.ssl_certfile is None


def test_serving_with_tls_does_not_request_client_certificates(tmp_path):
    """
    Deliberate. Client certificates would move peer identity into a CA store
    read once at startup, giving revocation a second home that reload_trust()
    cannot reach. Callers are authenticated by the ed25519 handshake instead.
    """
    from eureka_protocol.src.eureka_daemon.server import build_config

    config = build_config(8000, use_tls=True, materials_dir=tmp_path)

    assert config.ssl_cert_reqs == ssl.CERT_NONE


def swapping_pin(monkeypatch, keys):
    """
    Return a different pinned key per call, simulating httpx opening a fresh
    connection part-way through the exchange -- pool expiry, a dropped socket,
    or an address that now resolves somewhere else. Each response has to earn
    the pin on its own; the check made on the first one does not carry.
    """
    calls = {"n": 0}

    def fake(response):
        index = min(calls["n"], len(keys) - 1)
        calls["n"] += 1
        return keys[index]

    monkeypatch.setattr(client_module.tls, "peer_key_from_response", fake)
    return calls


def test_a_connection_swapped_before_the_offer_is_refused(daemon, monkeypatch):
    initiator = make_node("node_swap_offer")
    daemon.trust_list.add(initiator.node_id, initiator.public_key_hex)
    initiator.trust_list.add(daemon.node_id, daemon.public_key_hex)
    stranger_key = EurekaCrypto().get_public_key_hex()

    # Manifest lands on the real peer; the offer lands somewhere else.
    swapping_pin(monkeypatch, [daemon.public_key_hex, stranger_key])

    async def exchange():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport,
                                     base_url="http://daemon") as http:
            return await handshake_over_http(initiator, http=http)

    result = run(exchange())

    assert result["authenticated"] is False
    assert result["reason"] == REASON_UNTRUSTED_KEY
    assert daemon.node_id not in initiator.peers


def test_a_connection_swapped_before_the_confirmation_is_refused(daemon, monkeypatch):
    """
    Message 3 carries our signature over the peer's challenge. Delivering it to
    a connection nobody pinned is the one that actually gives something away.
    """
    initiator = make_node("node_swap_confirm")
    daemon.trust_list.add(initiator.node_id, initiator.public_key_hex)
    initiator.trust_list.add(daemon.node_id, daemon.public_key_hex)
    stranger_key = EurekaCrypto().get_public_key_hex()

    swapping_pin(monkeypatch, [daemon.public_key_hex, daemon.public_key_hex,
                               stranger_key])

    async def exchange():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport,
                                     base_url="http://daemon") as http:
            return await handshake_over_http(initiator, http=http)

    result = run(exchange())

    assert result["authenticated"] is False
    assert result["reason"] == REASON_UNTRUSTED_KEY


def test_serving_both_opens_a_plaintext_and_a_tls_listener(tmp_path):
    """
    A migration needs both at once: TLS cannot share a port with a peer that
    still speaks plain HTTP, so the daemon listens twice rather than making
    every peer cut over on the same day.
    """
    from eureka_protocol.src.eureka_daemon.server import build_configs

    plain, tls_config = build_configs(plain_port=8000, tls_port=8443,
                                      materials_dir=tmp_path)

    assert (plain.port, plain.ssl_certfile) == (8000, None)
    assert tls_config.port == 8443
    served = public_key_hex_from_cert(open(tls_config.ssl_certfile, "rb").read())
    assert served == api.node_engine.public_key_hex


def test_serving_both_shares_one_node(tmp_path):
    """
    One node means one replay table and one peer table. Two processes under a
    single identity would keep two of each, so a nonce spent on one port would
    still be unspent on the other.
    """
    from eureka_protocol.src.eureka_daemon.server import build_configs

    configs = build_configs(plain_port=8000, tls_port=8443,
                            materials_dir=tmp_path)

    assert configs[0].app is configs[1].app


def test_plaintext_only_is_still_available():
    from eureka_protocol.src.eureka_daemon.server import build_configs

    configs = build_configs(plain_port=8000)

    assert len(configs) == 1
    assert configs[0].ssl_certfile is None


def test_tls_only_is_still_available(tmp_path):
    from eureka_protocol.src.eureka_daemon.server import build_configs

    configs = build_configs(tls_port=8443, materials_dir=tmp_path)

    assert len(configs) == 1
    assert configs[0].ssl_certfile is not None


def test_a_daemon_with_no_listeners_is_refused():
    """
    A typo that turns off plaintext without turning on TLS would otherwise
    start a daemon that serves nothing and looks healthy doing it.
    """
    from eureka_protocol.src.eureka_daemon.server import build_configs

    with pytest.raises(ValueError, match="no listeners"):
        build_configs()


def test_the_two_listeners_cannot_share_a_port(tmp_path):
    from eureka_protocol.src.eureka_daemon.server import build_configs

    with pytest.raises(ValueError, match="cannot share port"):
        build_configs(plain_port=8443, tls_port=8443, materials_dir=tmp_path)


def test_co_servers_do_not_fight_over_signal_handlers():
    """
    Whichever server installed its handler second would otherwise win, and a
    systemd stop would shut down one listener while the other ran on until the
    stop timed out.
    """
    from eureka_protocol.src.eureka_daemon.server import _CoServer

    config = uvicorn.Config(app=app, host="127.0.0.1", port=0)
    server = _CoServer(config)

    # The base class installs handlers here; this override must not.
    before = signal.getsignal(signal.SIGTERM)
    assert server.install_signal_handlers() is None
    assert signal.getsignal(signal.SIGTERM) is before
