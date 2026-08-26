"""
Authenticated reads: the peer table, the audit log, and the full manifest.

The daemon used to answer GET /v1/peers to anyone who could reach the port,
which handed a stranger the map of who this node talks to -- the one record
the protocol claims no third party holds. These tests cover the gate that
closed it, and mostly they cover the ways it must not go wrong: a refusal that
looks the same whether or not there are peers, a caller that sees only what it
already knows about, and the several things that are emphatically not
authentication.

The nodes here are real, and so are the handshakes: real ASGI apps, real JSON,
real signatures. A mocked peer table would test the wrong thing.
"""
import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from eureka_protocol.src.eureka_daemon.api import create_app
from eureka_protocol.src.eureka_daemon.crypto import EurekaCrypto
from eureka_protocol.src.eureka_daemon.discovery import build_query
from eureka_protocol.src.eureka_daemon.node import (
    EurekaNode,
    REASON_BAD_SIGNATURE,
    REASON_MALFORMED,
    REASON_OK,
    REASON_REVOKED_KEY,
    REASON_STALE,
    REASON_UNTRUSTED_KEY,
)
from eureka_protocol.src.eureka_daemon.reads import (
    LOGS_EVENT,
    MANIFEST_EVENT,
    PEERS_EVENT,
    REJECTED_EVENT,
    answer_logs,
    answer_manifest,
    answer_peers,
    build_read_query,
    rejected,
)
from eureka_protocol.src.eureka_daemon.signed_request import (
    PROTOCOL,
    REASON_NOT_AUTHENTICATED,
)
from eureka_protocol.src.eureka_daemon.trust import TrustList


def run(coro):
    return asyncio.run(coro)


def make_node(node_id, capabilities=("code-exec",)):
    return EurekaNode(node_id=node_id, crypto_engine=EurekaCrypto(),
                      capabilities=list(capabilities), trust_list=TrustList())


def trust(a, b):
    a.trust_list.add(b.node_id, b.public_key_hex)


def mutually_trust(a, b):
    trust(a, b)
    trust(b, a)


def handshaked(caller, daemon):
    """A caller that has completed a real mutual handshake with the daemon."""
    mutually_trust(caller, daemon)
    result = run(caller.handshake(daemon))
    assert result["authenticated"] is True
    return caller


@pytest.fixture
def daemon():
    return make_node("node_daemon")


@pytest.fixture
def caller(daemon):
    return handshaked(make_node("node_caller"), daemon)


# ---------------------------------------------------------------------------
# The headline: an unauthenticated caller learns nothing, and cannot tell
# whether there is anything to learn
# ---------------------------------------------------------------------------

def test_unauthenticated_peers_read_discloses_nothing(daemon):
    stranger = make_node("node_stranger")
    answer = answer_peers(daemon, build_read_query(stranger, PEERS_EVENT))

    assert answer["event"] == REJECTED_EVENT
    assert answer["peers"] == {}


def test_unauthenticated_logs_read_discloses_nothing(daemon):
    stranger = make_node("node_stranger")
    answer = answer_logs(daemon, build_read_query(stranger, LOGS_EVENT))

    assert answer["event"] == REJECTED_EVENT
    assert answer["logs"] == []


def test_refusal_is_identical_whether_or_not_peers_exist():
    """
    The acceptance criterion, stated directly.

    Two daemons, identical but for their peer tables: one has authenticated
    peers, the other has never seen anyone. The same stranger asks both. The
    two refusals must be byte-identical, or the refusal itself is a way to ask
    whether this node talks to anybody.
    """
    empty = make_node("node_same")
    populated = make_node("node_same")
    handshaked(make_node("node_peer_one"), populated)
    handshaked(make_node("node_peer_two"), populated)

    assert len(populated.peers) == 2
    assert populated.event_log == empty.event_log == []

    stranger = make_node("node_stranger")
    query = build_read_query(stranger, PEERS_EVENT)

    assert answer_peers(empty, query) == answer_peers(populated, query)


def test_refusal_carries_no_count_of_anything(daemon):
    handshaked(make_node("node_a"), daemon)
    handshaked(make_node("node_b"), daemon)
    stranger = make_node("node_stranger")

    answer = answer_peers(daemon, build_read_query(stranger, PEERS_EVENT))

    # Not an empty list rendered from a real table -- exactly the constant
    # refusal, built without the table being consulted at all. Whatever reason
    # the caller earned, the document carries that and nothing else.
    assert answer == rejected(PEERS_EVENT, answer["reason"])
    assert "node_a" not in str(answer)
    assert "node_b" not in str(answer)


# ---------------------------------------------------------------------------
# What is not authentication
# ---------------------------------------------------------------------------

def test_trusted_but_never_handshaked_is_refused(daemon):
    """
    Being on the allowlist is not being authenticated.

    This is the same distinction the transport makes: completing TLS proves
    the peer holds a key, and the daemon asks for no client certificate
    anyway. Only the handshake makes a caller someone.
    """
    peer = make_node("node_trusted")
    mutually_trust(peer, daemon)

    answer = answer_peers(daemon, build_read_query(peer, PEERS_EVENT))

    assert answer["reason"] == REASON_NOT_AUTHENTICATED
    assert answer["peers"] == {}


def test_claiming_another_peers_node_id_is_refused(daemon, caller):
    """A requester_id is a claim; the signature is what makes it true."""
    impostor = make_node("node_impostor")
    document = build_read_query(impostor, PEERS_EVENT)
    document["requester_id"] = caller.node_id
    document["query"]["requester_id"] = caller.node_id

    answer = answer_peers(daemon, document)

    # The signature no longer matches the edited body.
    assert answer["reason"] == REASON_BAD_SIGNATURE
    assert answer["peers"] == {}


def test_envelope_and_signed_body_must_agree(daemon, caller):
    document = build_read_query(caller, PEERS_EVENT)
    document["requester_id"] = "node_somebody_else"

    answer = answer_peers(daemon, document)

    assert answer["reason"] == REASON_MALFORMED
    assert answer["peers"] == {}


def test_signing_with_a_key_other_than_the_one_handshaked_is_refused(daemon, caller):
    """
    A peer authenticated under one key cannot read under another, even if the
    second key is also trusted.
    """
    second = make_node(caller.node_id)          # same id, different key
    trust(daemon, second)

    answer = answer_peers(daemon, build_read_query(second, PEERS_EVENT))

    assert answer["reason"] == REASON_NOT_AUTHENTICATED
    assert answer["peers"] == {}


def test_untrusted_key_is_refused(daemon):
    answer = answer_peers(daemon, build_read_query(make_node("node_x"), PEERS_EVENT))
    assert answer["reason"] in (REASON_UNTRUSTED_KEY, REASON_NOT_AUTHENTICATED)
    assert answer["peers"] == {}


def test_revoking_a_peer_ends_its_read_access(daemon, caller):
    """Revocation reaches reads through the same live trust list."""
    before = answer_peers(daemon, build_read_query(caller, PEERS_EVENT))
    assert before["reason"] == REASON_OK

    daemon.trust_list.revoke(caller.public_key_hex, reason="test")

    after = answer_peers(daemon, build_read_query(caller, PEERS_EVENT))
    assert after["reason"] == REASON_REVOKED_KEY
    assert after["peers"] == {}


def test_a_stale_read_cannot_be_replayed_later(daemon, caller):
    old = datetime.now(timezone.utc) - timedelta(seconds=300)
    document = build_read_query(caller, PEERS_EVENT, now=old)

    answer = answer_peers(daemon, document)

    assert answer["reason"] == REASON_STALE
    assert answer["peers"] == {}


# ---------------------------------------------------------------------------
# Domain separation: a signature minted elsewhere does not read
# ---------------------------------------------------------------------------

def test_a_discovery_signature_cannot_be_replayed_as_a_peers_read(daemon, caller):
    """
    The two carry the same envelope fields. Only the signing domain keeps a
    request for addresses from becoming a request for the peer table.
    """
    discovery_document = build_query(caller)
    forged = build_read_query(caller, PEERS_EVENT)
    forged["signature"] = discovery_document["signature"]

    answer = answer_peers(daemon, forged)

    assert answer["reason"] == REASON_BAD_SIGNATURE
    assert answer["peers"] == {}


def test_the_signing_domain_is_what_separates_a_read_from_a_discovery_query():
    """
    Isolate the domain tag itself.

    The replay test above passes even against an implementation with no domain
    separation at all: a discovery payload and a read payload differ in their
    event field anyway, so the signature fails for that reason and the tag is
    never exercised. Found by mutation -- pointing DOMAIN_READ_QUERY at the
    discovery tag left that test green.

    This signs one identical payload in both domains and shows the two
    signatures are not interchangeable, which is the property the tag provides
    and the only way to see it fail.
    """
    crypto = EurekaCrypto()
    pub = crypto.get_public_key_hex()
    payload = {
        "protocol": PROTOCOL,
        "event": PEERS_EVENT,
        "requester_id": "node_x",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "keys": [],
    }

    as_read = crypto.sign_read_query(payload)
    as_discovery = crypto.sign_discovery_query(payload)

    assert as_read != as_discovery
    assert EurekaCrypto.verify_read_query(pub, as_read, payload) is True
    assert EurekaCrypto.verify_read_query(pub, as_discovery, payload) is False
    assert EurekaCrypto.verify_discovery_query(pub, as_read, payload) is False


def test_a_manifest_read_signature_cannot_read_the_peer_table(daemon, caller):
    """The event is inside the signed payload, so one read does not become another."""
    manifest_document = build_read_query(caller, MANIFEST_EVENT)
    forged = dict(manifest_document)
    forged["query"] = dict(manifest_document["query"], event=PEERS_EVENT, keys=[])
    forged["event"] = PEERS_EVENT

    answer = answer_peers(daemon, forged)

    assert answer["reason"] == REASON_BAD_SIGNATURE
    assert answer["peers"] == {}


# ---------------------------------------------------------------------------
# An authenticated caller sees only what it already knows about
# ---------------------------------------------------------------------------

def test_authenticated_caller_sees_a_peer_it_named(daemon, caller):
    other = handshaked(make_node("node_other"), daemon)
    trust(caller, other)

    answer = answer_peers(daemon, build_read_query(caller, PEERS_EVENT,
                                                   keys=[other.public_key_hex]))

    assert answer["reason"] == REASON_OK
    assert answer["peers"][other.public_key_hex]["peer_id"] == other.node_id
    assert answer["peers"][other.public_key_hex]["status"] == "authenticated"


def test_a_peer_the_caller_did_not_name_stays_invisible(daemon, caller):
    """
    Discovery's rule, applied to the peer table: authenticating to one node
    does not enumerate the mesh behind it.
    """
    secret = handshaked(make_node("node_secret"), daemon)

    # The caller asks about the only key it knows: the daemon's own.
    answer = answer_peers(daemon, build_read_query(
        caller, PEERS_EVENT, keys=[daemon.public_key_hex]))

    assert answer["reason"] == REASON_OK
    assert secret.public_key_hex not in answer["peers"]
    assert secret.node_id not in str(answer)


def test_naming_no_keys_discloses_no_peers(daemon, caller):
    handshaked(make_node("node_other"), daemon)

    answer = answer_peers(daemon, build_read_query(caller, PEERS_EVENT, keys=[]))

    assert answer["reason"] == REASON_OK
    assert answer["peers"] == {}


def test_a_peer_revoked_since_it_handshaked_is_not_reported(daemon, caller):
    other = handshaked(make_node("node_other"), daemon)
    trust(caller, other)
    daemon.trust_list.revoke(other.public_key_hex, reason="test")

    answer = answer_peers(daemon, build_read_query(caller, PEERS_EVENT,
                                                   keys=[other.public_key_hex]))

    assert answer["reason"] == REASON_OK
    assert answer["peers"] == {}


def test_an_oversized_key_list_is_refused_not_truncated(daemon, caller):
    document = build_read_query(caller, PEERS_EVENT)
    document["query"]["keys"] = [EurekaCrypto().get_public_key_hex()
                                 for _ in range(200)]

    answer = answer_peers(daemon, document)

    assert answer["reason"] == REASON_MALFORMED
    assert answer["peers"] == {}


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

def test_authenticated_caller_sees_only_logs_attributed_to_it(daemon, caller):
    other = handshaked(make_node("node_other"), daemon)

    run(daemon.log_event({"task_name": "for_caller"}, {"status": "completed"},
                         peer=caller.node_id))
    run(daemon.log_event({"task_name": "for_other"}, {"status": "completed"},
                         peer=other.node_id))
    run(daemon.log_event({"task_name": "for_nobody"}, {"status": "completed"}))

    answer = answer_logs(daemon, build_read_query(caller, LOGS_EVENT))

    assert answer["reason"] == REASON_OK
    assert [e["payload"]["task_summary"] for e in answer["logs"]] == ["for_caller"]
    assert "for_other" not in str(answer)
    assert "for_nobody" not in str(answer)


def test_unattributed_log_entries_reach_no_peer(daemon, caller):
    """
    assign() attributes nothing today, so its entries are readable by nobody
    over the network. The operator reads them from the journal instead.
    """
    run(daemon.assign({"task_name": "any_task", "payload": {}}))
    assert daemon.event_log

    answer = answer_logs(daemon, build_read_query(caller, LOGS_EVENT))

    assert answer["reason"] == REASON_OK
    assert answer["logs"] == []


# ---------------------------------------------------------------------------
# Manifest: open enough for first contact, and no more
# ---------------------------------------------------------------------------

def test_open_manifest_carries_identity_but_not_capabilities(daemon):
    with TestClient(create_app(daemon)) as client:
        body = client.get("/v1/manifest").json()

    assert body["node_id"] == daemon.node_id
    assert "capabilities" not in body
    assert "peers" not in body


def test_capabilities_are_served_to_an_authenticated_peer(daemon, caller):
    answer = answer_manifest(daemon, build_read_query(caller, MANIFEST_EVENT))

    assert answer["reason"] == REASON_OK
    assert answer["manifest"]["capabilities"] == list(daemon.capabilities)


def test_capabilities_are_withheld_from_a_stranger(daemon):
    stranger = make_node("node_stranger")

    answer = answer_manifest(daemon, build_read_query(stranger, MANIFEST_EVENT))

    assert answer["event"] == REJECTED_EVENT
    assert answer["manifest"] == {}
    assert "code-exec" not in str(answer)


# ---------------------------------------------------------------------------
# Over the real transport
# ---------------------------------------------------------------------------

def test_get_on_the_read_routes_is_refused_by_the_router(daemon):
    with TestClient(create_app(daemon)) as client:
        assert client.get("/v1/peers").status_code == 405
        assert client.get("/v1/logs").status_code == 405


def test_read_routes_refuse_a_garbage_body_without_disclosing(daemon):
    handshaked(make_node("node_peer"), daemon)

    with TestClient(create_app(daemon)) as client:
        for path, field in (("/v1/peers", "peers"), ("/v1/logs", "logs")):
            response = client.post(path, content=b"not json at all")
            body = response.json()
            assert body["event"] == REJECTED_EVENT
            assert body[field] in ({}, [])
            assert "node_peer" not in str(body)


def test_a_real_peer_reads_over_http(daemon):
    """End to end: handshake over the transport, then read across it."""
    caller = make_node("node_http_caller")
    other = handshaked(make_node("node_http_other"), daemon)
    mutually_trust(caller, daemon)
    trust(caller, other)

    app = create_app(daemon)

    async def go():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport,
                                     base_url="http://daemon") as http:
            from eureka_protocol.src.eureka_daemon.client import handshake_over_http
            result = await handshake_over_http(caller, peer_id=daemon.node_id,
                                               http=http)
            assert result["authenticated"] is True
            response = await http.post("/v1/peers", json=build_read_query(
                caller, PEERS_EVENT, keys=[other.public_key_hex]))
            return response.json()

    answer = run(go())

    assert answer["reason"] == REASON_OK
    assert answer["peers"][other.public_key_hex]["peer_id"] == other.node_id
