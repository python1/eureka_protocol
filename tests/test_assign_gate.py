"""
The assign gate: authentication, authorization, and single-use requests.

/v1/assign was the last open endpoint on the daemon -- an unauthenticated POST
straight into the dispatch stub. These tests cover the gate that closed it,
and the two things it needs beyond what reads need: is_permitted deciding what
an authenticated caller may run (its first caller on a request path), and a
nonce making every request single-use, because replaying a read discloses what
was already disclosed while replaying an assign would run the task again.

The stub still executes nothing. What is under test is who can reach it.
"""
import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from eureka_protocol.src.eureka_daemon.api import create_app
from eureka_protocol.src.eureka_daemon.assign import (
    ASSIGN_EVENT,
    REASON_NOT_PERMITTED,
    REJECTED_EVENT,
    answer_assign,
    build_assign_query,
    rejected,
)
from eureka_protocol.src.eureka_daemon.crypto import EurekaCrypto
from eureka_protocol.src.eureka_daemon.node import (
    EurekaNode,
    REASON_MALFORMED,
    REASON_OK,
    REASON_REPLAYED_NONCE,
    REASON_REVOKED_KEY,
)
from eureka_protocol.src.eureka_daemon.reads import LOGS_EVENT, build_read_query, answer_logs
from eureka_protocol.src.eureka_daemon.signed_request import PROTOCOL
from eureka_protocol.src.eureka_daemon.trust import TrustList


def run(coro):
    return asyncio.run(coro)


def make_node(node_id, capabilities=("code-exec", "data-analysis")):
    return EurekaNode(node_id=node_id, crypto_engine=EurekaCrypto(),
                      capabilities=list(capabilities), trust_list=TrustList())


def handshaked(caller, daemon, grants=()):
    """A caller that completed a real handshake, holding the given grants."""
    daemon.trust_list.add(caller.node_id, caller.public_key_hex, list(grants))
    caller.trust_list.add(daemon.node_id, daemon.public_key_hex)
    result = run(caller.handshake(daemon))
    assert result["authenticated"] is True
    return caller


def audit_entries_for(daemon, peer_id):
    return [e for e in daemon.event_log
            if e["payload"].get("peer") == peer_id]


@pytest.fixture
def daemon():
    return make_node("node_daemon")


@pytest.fixture
def granted(daemon):
    """An authenticated peer holding the code-exec grant."""
    return handshaked(make_node("node_granted"), daemon, grants=["code-exec"])


@pytest.fixture
def ungranted(daemon):
    """An authenticated peer holding no grants at all."""
    return handshaked(make_node("node_ungranted"), daemon)


# ---------------------------------------------------------------------------
# Unauthenticated callers learn nothing and run nothing
# ---------------------------------------------------------------------------

def test_unsigned_post_discloses_nothing_and_executes_nothing(daemon):
    with TestClient(create_app(daemon)) as client:
        response = client.post("/v1/assign", json={"task_name": "x", "payload": {}})

    body = response.json()
    assert body["event"] == REJECTED_EVENT
    assert body["result"] == {}
    # Nothing was dispatched and nothing was logged: an unverified caller
    # neither reaches the stub nor writes attributed history.
    assert daemon.event_log == []
    assert "node_daemon" not in str(body.get("result"))


def test_garbage_body_gets_the_same_empty_refusal(daemon):
    with TestClient(create_app(daemon)) as client:
        response = client.post("/v1/assign", content=b"not json")

    body = response.json()
    assert body["event"] == REJECTED_EVENT
    assert body["result"] == {}
    assert daemon.event_log == []


def test_stranger_with_a_valid_signature_is_refused(daemon):
    """A well-formed, well-signed request from a key nobody trusts."""
    stranger = make_node("node_stranger")
    answer = run(answer_assign(daemon, build_assign_query(
        stranger, "code-exec", "task")))

    assert answer["event"] == REJECTED_EVENT
    assert answer["result"] == {}
    assert daemon.event_log == []


def test_refusal_is_built_from_the_reason_alone(daemon, granted):
    """Same discipline as the reads: the refusal is exactly the constant."""
    stranger = make_node("node_stranger")
    answer = run(answer_assign(daemon, build_assign_query(
        stranger, "code-exec", "task")))

    assert answer == rejected(answer["reason"])


# ---------------------------------------------------------------------------
# Authorization: authenticated is not authorized
# ---------------------------------------------------------------------------

def test_authenticated_peer_with_the_grant_reaches_the_stub(daemon, granted):
    answer = run(answer_assign(daemon, build_assign_query(
        granted, "code-exec", "compute", {"n": 1})))

    assert answer["reason"] == REASON_OK
    # The stub's behaviour is unchanged: canned result, completed status.
    assert answer["result"]["status"] == "completed"
    assert answer["result"]["output"] == f"Processed by {daemon.node_id}"
    # And the audit entry is attributed to the requesting peer.
    entries = audit_entries_for(daemon, granted.node_id)
    assert [e["payload"]["result"] for e in entries] == ["completed"]


def test_authenticated_peer_without_the_grant_is_refused_distinctly(daemon, ungranted):
    answer = run(answer_assign(daemon, build_assign_query(
        ungranted, "code-exec", "compute")))

    assert answer["reason"] == REASON_NOT_PERMITTED
    assert answer["result"] == {}
    # Refused, not executed: no completed entry anywhere.
    assert all(e["payload"]["result"] != "completed" for e in daemon.event_log)


def test_a_grant_for_x_does_not_permit_y(daemon):
    peer = handshaked(make_node("node_x_only"), daemon, grants=["code-exec"])

    allowed = run(answer_assign(daemon, build_assign_query(
        peer, "code-exec", "task_a")))
    denied = run(answer_assign(daemon, build_assign_query(
        peer, "data-analysis", "task_b")))

    assert allowed["reason"] == REASON_OK
    assert denied["reason"] == REASON_NOT_PERMITTED
    assert denied["result"] == {}


def test_a_grant_for_something_this_node_does_not_offer_is_refused(daemon):
    """
    is_permitted's second gate: the trust file granted it, the node does not
    advertise it. Same refusal as no grant at all -- an attacker cannot use
    the difference to map the inventory, because there is no difference.
    """
    peer = make_node("node_wide_grant")
    daemon.trust_list.add(peer.node_id, peer.public_key_hex, [])
    peer.trust_list.add(daemon.node_id, daemon.public_key_hex)
    assert run(peer.handshake(daemon))["authenticated"] is True

    not_granted = run(answer_assign(daemon, build_assign_query(
        peer, "code-exec", "t")))
    # Rebuild the peer's grant to something the node does not offer, going
    # around load-time validation on purpose to simulate a stale trust state.
    key = peer.public_key_hex.lower()
    daemon.trust_list._grants[key] = frozenset({"quantum-annealing"})
    not_offered = run(answer_assign(daemon, build_assign_query(
        peer, "quantum-annealing", "t")))

    assert not_granted["reason"] == REASON_NOT_PERMITTED
    assert not_offered["reason"] == REASON_NOT_PERMITTED
    assert rejected(REASON_NOT_PERMITTED) == not_granted == not_offered


def test_refusal_does_not_echo_the_capability_or_the_inventory(daemon, ungranted):
    answer = run(answer_assign(daemon, build_assign_query(
        ungranted, "some-capability-name", "task")))

    text = str(answer)
    assert "some-capability-name" not in text
    for offered in daemon.capabilities:
        assert offered not in text


def test_revoking_the_peer_ends_assign_access(daemon, granted):
    first = run(answer_assign(daemon, build_assign_query(
        granted, "code-exec", "t1")))
    assert first["reason"] == REASON_OK

    daemon.trust_list.revoke(granted.public_key_hex, reason="test")

    second = run(answer_assign(daemon, build_assign_query(
        granted, "code-exec", "t2")))
    assert second["reason"] == REASON_REVOKED_KEY
    assert second["result"] == {}


# ---------------------------------------------------------------------------
# Replay: a signed request runs at most once
# ---------------------------------------------------------------------------

def test_replayed_signed_request_is_refused(daemon, granted):
    document = build_assign_query(granted, "code-exec", "compute")

    first = run(answer_assign(daemon, document))
    second = run(answer_assign(daemon, document))

    assert first["reason"] == REASON_OK
    assert second["reason"] == REASON_REPLAYED_NONCE
    assert second["result"] == {}
    # Executed exactly once: one completed entry, and the replay's refusal is
    # also on the record, attributed to the same peer.
    outcomes = [e["payload"]["result"]
                for e in audit_entries_for(daemon, granted.node_id)]
    assert outcomes == ["completed", "refused"]


def test_a_refused_request_cannot_be_replayed_either(daemon, ungranted):
    """The nonce is spent on first authenticated sighting, not on success --
    a captured refusal cannot be resubmitted to probe for a later grant."""
    document = build_assign_query(ungranted, "code-exec", "compute")

    first = run(answer_assign(daemon, document))
    # The operator now grants the capability. The old request stays dead.
    daemon.trust_list._grants[ungranted.public_key_hex.lower()] = frozenset({"code-exec"})
    second = run(answer_assign(daemon, document))

    assert first["reason"] == REASON_NOT_PERMITTED
    assert second["reason"] == REASON_REPLAYED_NONCE


def test_a_stale_request_is_refused_before_the_nonce_table_matters(daemon, granted):
    old = datetime.now(timezone.utc) - timedelta(seconds=300)
    document = build_assign_query(granted, "code-exec", "t", now=old)

    answer = run(answer_assign(daemon, document))

    assert answer["event"] == REJECTED_EVENT
    assert answer["result"] == {}


def test_two_distinct_requests_both_run(daemon, granted):
    """The nonce refuses replays, not throughput."""
    a = run(answer_assign(daemon, build_assign_query(granted, "code-exec", "t1")))
    b = run(answer_assign(daemon, build_assign_query(granted, "code-exec", "t2")))
    assert a["reason"] == b["reason"] == REASON_OK


def test_the_assign_nonce_table_is_bounded(daemon, granted):
    for _ in range(daemon.max_seen_nonces + 50):
        daemon.seen_assign_nonces[EurekaCrypto().derive_node_id() + str(_)] = (
            datetime.now(timezone.utc))
    run(answer_assign(daemon, build_assign_query(granted, "code-exec", "t")))
    assert len(daemon.seen_assign_nonces) <= daemon.max_seen_nonces


def test_an_assign_nonce_cannot_spend_a_handshake_nonce(daemon, granted):
    """The tables are separate on purpose: quoting a handshake nonce in an
    assign request must not poison the handshake's replay protection."""
    challenge = daemon.create_challenge("node_someone")
    document = build_assign_query(granted, "code-exec", "t",
                                  nonce=challenge["nonce"])
    answer = run(answer_assign(daemon, document))

    assert answer["reason"] == REASON_OK
    assert challenge["nonce"] not in daemon.seen_nonces
    assert challenge["nonce"] in daemon.pending_challenges


# ---------------------------------------------------------------------------
# Domain separation
# ---------------------------------------------------------------------------

def test_assign_signature_verifies_in_no_other_domain():
    """One identical payload, signed for assign: dead everywhere else."""
    crypto = EurekaCrypto()
    pub = crypto.get_public_key_hex()
    payload = {
        "protocol": PROTOCOL,
        "event": ASSIGN_EVENT,
        "requester_id": "node_x",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "nonce": "n" * 32,
        "capability": "code-exec",
        "task_name": "t",
        "payload": {},
    }
    signature = crypto.sign_assign_query(payload)

    assert EurekaCrypto.verify_assign_query(pub, signature, payload) is True
    assert EurekaCrypto.verify_read_query(pub, signature, payload) is False
    assert EurekaCrypto.verify_discovery_query(pub, signature, payload) is False
    assert EurekaCrypto.verify_handshake(pub, signature, payload) is False
    assert EurekaCrypto.verify_handshake_offer(pub, signature, payload) is False
    assert EurekaCrypto.verify_handshake_confirm(pub, signature, payload) is False
    assert EurekaCrypto.verify_audit_log(pub, signature, payload) is False


def test_no_other_domains_signature_verifies_as_an_assign(daemon, granted):
    """The inverse, end to end: a read-domain signature on an assign document."""
    document = build_assign_query(granted, "code-exec", "t")
    document["signature"] = granted.crypto.sign_read_query(document["query"])

    answer = run(answer_assign(daemon, document))

    assert answer["event"] == REJECTED_EVENT
    assert answer["result"] == {}
    assert daemon.event_log == []


# ---------------------------------------------------------------------------
# The audit trail
# ---------------------------------------------------------------------------

def test_refusals_are_attributed_and_readable_by_the_refused_peer(daemon, ungranted):
    run(answer_assign(daemon, build_assign_query(ungranted, "code-exec", "denied_task")))

    entries = audit_entries_for(daemon, ungranted.node_id)
    assert [e["payload"]["result"] for e in entries] == ["refused"]
    # And the refused peer can read its own refusal back through /v1/logs,
    # while a different peer cannot see it.
    own = answer_logs(daemon, build_read_query(ungranted, LOGS_EVENT))
    assert [e["payload"]["task_summary"] for e in own["logs"]] == ["denied_task"]

    other = handshaked(make_node("node_other"), daemon)
    theirs = answer_logs(daemon, build_read_query(other, LOGS_EVENT))
    assert theirs["logs"] == []


def test_audit_entries_from_the_gate_verify_in_the_audit_domain(daemon, ungranted):
    run(answer_assign(daemon, build_assign_query(ungranted, "code-exec", "t")))
    entry = daemon.event_log[-1]
    assert EurekaCrypto.verify_audit_log(
        daemon.public_key_hex, entry["signature"], entry["payload"]) is True


# ---------------------------------------------------------------------------
# Over the real transport, and the peer that must not notice
# ---------------------------------------------------------------------------

def test_full_flow_over_http(daemon):
    caller = make_node("node_http")
    daemon.trust_list.add(caller.node_id, caller.public_key_hex, ["code-exec"])
    caller.trust_list.add(daemon.node_id, daemon.public_key_hex)
    app = create_app(daemon)

    async def go():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport,
                                     base_url="http://daemon") as http:
            from eureka_protocol.src.eureka_daemon.client import handshake_over_http
            result = await handshake_over_http(caller, peer_id=daemon.node_id,
                                               http=http)
            assert result["authenticated"] is True
            document = build_assign_query(caller, "code-exec", "over_http")
            first = (await http.post("/v1/assign", json=document)).json()
            replay = (await http.post("/v1/assign", json=document)).json()
            return first, replay

    first, replay = run(go())

    assert first["reason"] == REASON_OK
    assert first["result"]["status"] == "completed"
    assert replay["reason"] == REASON_REPLAYED_NONCE


def test_wsl_hermes_flow_is_untouched(daemon):
    """
    The deployed older client calls the handshake endpoints and GET
    /v1/manifest, nothing else. Both must behave exactly as before this
    change: open manifest with node_id, full mutual handshake, no assign
    involvement anywhere.
    """
    caller = make_node("node_hermes")
    daemon.trust_list.add(caller.node_id, caller.public_key_hex)
    caller.trust_list.add(daemon.node_id, daemon.public_key_hex)
    app = create_app(daemon)

    async def go():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport,
                                     base_url="http://daemon") as http:
            manifest = (await http.get("/v1/manifest")).json()
            from eureka_protocol.src.eureka_daemon.client import handshake_over_http
            result = await handshake_over_http(caller, http=http)
            return manifest, result

    manifest, result = run(go())

    assert manifest["node_id"] == daemon.node_id
    assert result["authenticated"] is True
    assert result["mutual"] is True
