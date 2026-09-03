"""
The assign gate: authentication, authorization, and single-use requests.

/v1/assign was the last open endpoint on the daemon -- an unauthenticated POST
straight into the dispatch stub. These tests cover the gate that closed it,
and the two things it needs beyond what reads need: is_permitted deciding what
an authenticated caller may run (its first caller on a request path), and a
nonce making every request single-use, because replaying a read discloses what
was already disclosed while replaying an assign would run the task again.

What is behind the gate is no longer a stub. Most of these tests still only
care who can reach it, so the daemon fixture registers a trivial handler for
the capabilities they use -- a node with no executor would refuse every one of
them for the wrong reason, and the gate is what is under test here. The tests
at the end of this file are the other half: a real capability, fetched over a
real socket, through the whole gate.
"""
import asyncio
import json
import time
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
from eureka_protocol.src.eureka_daemon.handlers import (
    AddressPolicy,
    HandlerRegistry,
    INFERENCE_DEADLINE_SECONDS,
    INFERENCE_MODEL,
    MAX_PROMPT_CHARS,
    OllamaInference,
    REASON_ADDRESS_NOT_ALLOWED,
    REASON_PROMPT_TOO_LONG,
    REASON_TIMEOUT,
    REASON_UPSTREAM_UNAVAILABLE,
    STATUS_COMPLETED,
    STATUS_FAILED,
    WebRetrieval,
    completed,
)
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
# The origin server these tests fetch from is the one test_handlers.py builds:
# one real HTTP server, defined once, rather than two that can drift apart.
# Same for the fake Ollama the inference tests at the bottom of this file run
# against, and for the prompts that steer it.
from eureka_protocol.tests.test_handlers import (   # noqa: F401  (fixtures)
    SLOW_PROMPT,
    dead_endpoint,
    ollama,
    origin,
)


def run(coro):
    return asyncio.run(coro)


async def _trivial(payload, context):
    """
    Stands in for whatever a capability does, so these tests can be about the
    gate rather than about any particular work. It returns the string the old
    stub returned, which is why the assertions below still read the way they
    did when the stub was the only thing there was.
    """
    return completed(f"Processed by {context.node_id}")


def stub_registry(capabilities):
    """A registry that can run exactly what the node advertises."""
    registry = HandlerRegistry()
    for capability in capabilities:
        registry.register(capability, _trivial)
    return registry


def make_node(node_id, capabilities=("code-exec", "data-analysis"),
              handlers=None):
    """
    A node with an executor for what it advertises.

    Every node here gets one now: a node built without a registry cannot
    execute at all, so a gate test on one would pass through every gate and
    then be refused by the empty executor -- green for the wrong reason.
    """
    capabilities = list(capabilities)
    return EurekaNode(node_id=node_id, crypto_engine=EurekaCrypto(),
                      capabilities=capabilities, trust_list=TrustList(),
                      handlers=handlers if handlers is not None
                      else stub_registry(capabilities))


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

def test_authenticated_peer_with_the_grant_reaches_its_handler(daemon, granted):
    answer = run(answer_assign(daemon, build_assign_query(
        granted, "code-exec", "compute", {"n": 1})))

    assert answer["reason"] == REASON_OK
    # Dispatched to the handler registered for that capability, and its
    # outcome is what comes back.
    assert answer["result"]["status"] == "completed"
    assert answer["result"]["capability"] == "code-exec"
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


# ---------------------------------------------------------------------------
# The executor behind the gate: one real capability, end to end
#
# Everything above this line is about who may ask. These are about what
# happens when the answer is yes -- a real fetch over a real socket, through
# the whole gate, from a peer holding exactly the grant CT 101's trust file
# gives wsl-hermes.
# ---------------------------------------------------------------------------

def web_daemon():
    """
    A daemon advertising web-retrieval, able to reach the loopback origin.

    The policy is the one difference from the deployed node: `allow_loopback`
    so the test's own origin server is reachable. Everything else -- the gate,
    the registry, the handler, the signature -- is what runs on CT 101.
    """
    registry = HandlerRegistry().register(
        "web-retrieval",
        WebRetrieval(policy=AddressPolicy(allow_loopback=True),
                     timeout_seconds=5.0),
    )
    return make_node("node_web", capabilities=["web-retrieval"],
                     handlers=registry)


def fetch_answer(daemon, peer, url, task_name="fetch"):
    return run(answer_assign(daemon, build_assign_query(
        peer, "web-retrieval", task_name, {"url": url})))


def test_a_granted_peer_gets_a_real_fetched_result(origin):
    """
    The acceptance criterion this whole change exists for: a peer holding
    web-retrieval asks for a URL and gets the page back, not a canned string.
    """
    daemon = web_daemon()
    peer = handshaked(make_node("node_fetcher", capabilities=[]), daemon,
                      grants=["web-retrieval"])

    answer = fetch_answer(daemon, peer, f"{origin}/hello")
    result = answer["result"]

    assert answer["reason"] == REASON_OK
    assert result["status"] == STATUS_COMPLETED
    assert result["capability"] == "web-retrieval"
    assert result["output"]["http_status"] == 200
    assert result["output"]["body"] == "hello from the origin"
    assert result["output"]["content_type"].startswith("text/plain")
    assert result["output"]["truncated"] is False


def test_the_result_is_signed_in_the_result_domain_and_no_other(origin):
    """
    The responder signs what it did, in a domain nothing else can mint. A
    result signature that verified as an assign query would be a result this
    node could be handed back as a request to run something.
    """
    daemon = web_daemon()
    peer = handshaked(make_node("node_verifier", capabilities=[]), daemon,
                      grants=["web-retrieval"])

    answer = fetch_answer(daemon, peer, f"{origin}/hello")
    pub, signature, result = (daemon.public_key_hex,
                              answer["result_signature"], answer["result"])

    assert EurekaCrypto.verify_assign_result(pub, signature, result) is True
    assert EurekaCrypto.verify_assign_query(pub, signature, result) is False
    assert EurekaCrypto.verify_read_query(pub, signature, result) is False
    assert EurekaCrypto.verify_discovery_query(pub, signature, result) is False
    assert EurekaCrypto.verify_handshake(pub, signature, result) is False
    assert EurekaCrypto.verify_handshake_offer(pub, signature, result) is False
    assert EurekaCrypto.verify_handshake_confirm(pub, signature, result) is False
    assert EurekaCrypto.verify_audit_log(pub, signature, result) is False


def test_a_result_signature_does_not_carry_to_another_request(origin):
    """
    The nonce is in the signed payload, so a result is evidence about one
    request and not about the next one that looks like it.
    """
    daemon = web_daemon()
    peer = handshaked(make_node("node_binding", capabilities=[]), daemon,
                      grants=["web-retrieval"])

    first = fetch_answer(daemon, peer, f"{origin}/hello", "first")
    second = fetch_answer(daemon, peer, f"{origin}/hello", "second")

    assert first["result"]["nonce"] != second["result"]["nonce"]
    assert EurekaCrypto.verify_assign_result(
        daemon.public_key_hex, first["result_signature"],
        second["result"]) is False
    # And the requester is inside the signature too, so a result cannot be
    # replayed to a peer it was not produced for.
    lifted = dict(first["result"], requester_id="node_somebody_else")
    assert EurekaCrypto.verify_assign_result(
        daemon.public_key_hex, first["result_signature"], lifted) is False


def test_a_refusal_carries_no_signature_to_tell_refusals_apart(daemon, ungranted):
    """The refusal stays the bare constant it has always been."""
    answer = run(answer_assign(daemon, build_assign_query(
        ungranted, "code-exec", "denied")))

    assert "result_signature" not in answer
    assert answer == rejected(REASON_NOT_PERMITTED)


def test_a_peer_granted_web_retrieval_cannot_invoke_an_unregistered_capability(origin):
    """
    The grant is for one capability, and the node advertises one capability.
    Asking for anything else is refused by the gate -- before the registry is
    consulted at all, which is why the refusal cannot say whether a handler
    for it exists.
    """
    daemon = web_daemon()
    peer = handshaked(make_node("node_overreach", capabilities=[]), daemon,
                      grants=["web-retrieval"])
    # Granted in the trust file as well, to prove it is the advertised list
    # doing the refusing rather than a missing grant.
    daemon.trust_list._grants[peer.public_key_hex.lower()] = frozenset(
        {"web-retrieval", "code-exec"})

    answer = run(answer_assign(daemon, build_assign_query(
        peer, "code-exec", "run_something")))

    assert answer == rejected(REASON_NOT_PERMITTED)
    assert all(e["payload"]["outcome"] != "completed"
               for e in daemon.event_log)


def test_a_handler_refusal_is_not_a_gate_refusal(origin):
    """
    A blocked URL is work this node accepted and declined to do, which is a
    different fact from a peer that may not ask. The gate says authenticated,
    the result says address_not_allowed, and the caller can tell which of its
    problems it has.
    """
    daemon = web_daemon()
    peer = handshaked(make_node("node_ssrf", capabilities=[]), daemon,
                      grants=["web-retrieval"])

    answer = fetch_answer(daemon, peer, "http://169.254.169.254/latest/meta-data/")

    assert answer["reason"] == REASON_OK
    assert answer["result"]["status"] == STATUS_FAILED
    assert answer["result"]["reason"] == REASON_ADDRESS_NOT_ALLOWED
    assert answer["result"]["output"] is None
    # Still signed: the responder is on the record for having refused it.
    assert EurekaCrypto.verify_assign_result(
        daemon.public_key_hex, answer["result_signature"],
        answer["result"]) is True


def test_the_daemons_own_api_cannot_be_fetched_through_a_grant():
    """
    The SSRF case that matters here specifically: a peer using its grant to
    make this node read its own endpoints from inside. Every address the
    daemon answers on is loopback or private, so the default policy is what
    refuses it -- no special case for "me".
    """
    registry = HandlerRegistry().register("web-retrieval", WebRetrieval())
    daemon = make_node("node_selfreach", capabilities=["web-retrieval"],
                       handlers=registry)
    peer = handshaked(make_node("node_curious", capabilities=[]), daemon,
                      grants=["web-retrieval"])

    for url in ("http://127.0.0.1:8443/v1/peers",
                "http://192.168.1.180:8443/v1/manifest",
                "http://localhost:8000/v1/logs"):
        answer = fetch_answer(daemon, peer, url)
        assert answer["result"]["reason"] == REASON_ADDRESS_NOT_ALLOWED


def test_the_audit_log_records_peer_and_outcome_but_never_the_body(origin):
    """
    The log is the record of what this node did, and it is readable back by
    the peer it names. What it must never become is a copy of what this node
    fetched: that would republish somebody else's page under this node's
    signature, for as long as the log is kept.
    """
    daemon = web_daemon()
    peer = handshaked(make_node("node_audited", capabilities=[]), daemon,
                      grants=["web-retrieval"])

    fetched = fetch_answer(daemon, peer, f"{origin}/hello", "fetch_a_page")
    refused = fetch_answer(daemon, peer, "http://10.0.0.9/secrets", "fetch_private")

    entries = audit_entries_for(daemon, peer.node_id)
    assert [e["payload"]["capability"] for e in entries] == ["web-retrieval"] * 2
    assert [e["payload"]["outcome"] for e in entries] == [
        "completed", REASON_ADDRESS_NOT_ALLOWED]
    assert [e["payload"]["task_summary"] for e in entries] == [
        "fetch_a_page", "fetch_private"]

    # The body came back to the caller and went nowhere near the log.
    body = fetched["result"]["output"]["body"]
    assert body == "hello from the origin"
    log_text = str(daemon.event_log)
    assert body not in log_text
    assert "origin" not in log_text
    # Nor does the URL the peer asked for: it is the peer's business and it is
    # not what the entry is a record of.
    assert "10.0.0.9" not in log_text
    assert refused["result"]["status"] == STATUS_FAILED


def test_the_peer_can_read_its_own_fetch_history_back(origin):
    """The entries are attributed, so /v1/logs discloses them to that peer."""
    daemon = web_daemon()
    peer = handshaked(make_node("node_reader", capabilities=[]), daemon,
                      grants=["web-retrieval"])
    fetch_answer(daemon, peer, f"{origin}/hello", "my_fetch")

    own = answer_logs(daemon, build_read_query(peer, LOGS_EVENT))
    assert [e["payload"]["task_summary"] for e in own["logs"]] == ["my_fetch"]
    assert own["logs"][0]["payload"]["outcome"] == "completed"
    assert "hello from the origin" not in str(own)


def test_concurrent_assigns_do_not_interfere_and_do_not_stall_a_handshake(origin):
    """
    Three things at once over the real transport: a slow fetch, a fast one,
    and a handshake from a peer that has nothing to do with either.

    The handshake must complete while the slow fetch is still in flight. If
    dispatch blocked the event loop -- a synchronous fetch, a resolver called
    on the loop thread -- the handshake would queue behind it and finish after
    it, which is what this asserts it does not do.
    """
    daemon = web_daemon()
    slow_peer = handshaked(make_node("node_slow", capabilities=[]), daemon,
                           grants=["web-retrieval"])
    fast_peer = handshaked(make_node("node_fast", capabilities=[]), daemon,
                           grants=["web-retrieval"])
    newcomer = make_node("node_newcomer", capabilities=[])
    daemon.trust_list.add(newcomer.node_id, newcomer.public_key_hex)
    newcomer.trust_list.add(daemon.node_id, daemon.public_key_hex)

    app = create_app(daemon)

    async def go():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport,
                                     base_url="http://daemon",
                                     timeout=30) as http:
            from eureka_protocol.src.eureka_daemon.client import handshake_over_http

            started = time.monotonic()
            timings = {}

            async def post(peer, url, label):
                document = build_assign_query(peer, "web-retrieval", label,
                                              {"url": url})
                answer = (await http.post("/v1/assign", json=document)).json()
                timings[label] = time.monotonic() - started
                return answer

            async def shake():
                result = await handshake_over_http(newcomer,
                                                   peer_id=daemon.node_id,
                                                   http=http)
                timings["handshake"] = time.monotonic() - started
                return result

            slow, fast, shaken = await asyncio.gather(
                post(slow_peer, f"{origin}/delay?ms=800", "slow"),
                post(fast_peer, f"{origin}/hello", "fast"),
                shake(),
            )
            return slow, fast, shaken, timings

    slow, fast, shaken, timings = run(go())

    # Each request got its own answer, not the other one's.
    assert slow["result"]["output"]["body"] == "worth the wait"
    assert fast["result"]["output"]["body"] == "hello from the origin"
    assert slow["result"]["requester_id"] == "node_slow"
    assert fast["result"]["requester_id"] == "node_fast"
    assert slow["result"]["task_name"] == "slow"

    # The handshake did not wait for the slow fetch, and neither did the fast
    # one -- both finished while it was still running.
    assert shaken["authenticated"] is True
    assert shaken["mutual"] is True
    assert timings["handshake"] < timings["slow"]
    assert timings["fast"] < timings["slow"]


# ---------------------------------------------------------------------------
# inference behind the same gate
#
# The second capability, and the first one whose input is worth protecting.
# These run against the fake Ollama on loopback, never a real one, so what is
# under test is this node's behaviour rather than a model's.
# ---------------------------------------------------------------------------

def inference_daemon(endpoint, **kwargs):
    """
    A daemon advertising inference and web-retrieval, as WSL will.

    The endpoint is the one difference from the deployed node, and it is still
    loopback -- OllamaInference refuses anything else at construction, so a
    test cannot widen this into a network client even by trying.
    """
    registry = HandlerRegistry()
    registry.register("web-retrieval",
                      WebRetrieval(policy=AddressPolicy(allow_loopback=True),
                                   timeout_seconds=5.0))
    registry.register("inference", OllamaInference(endpoint=endpoint, **kwargs),
                      deadline_seconds=INFERENCE_DEADLINE_SECONDS)
    return make_node("node_infer",
                     capabilities=["inference", "web-retrieval"],
                     handlers=registry)


def infer_answer(daemon, peer, prompt, task_name="infer"):
    return run(answer_assign(daemon, build_assign_query(
        peer, "inference", task_name, {"prompt": prompt})))


def test_a_granted_peer_gets_a_real_completion(ollama):
    """The acceptance criterion: a grant, a prompt, and an answer back."""
    endpoint, _spy = ollama
    daemon = inference_daemon(endpoint)
    peer = handshaked(make_node("node_asker", capabilities=[]), daemon,
                      grants=["inference"])

    answer = infer_answer(daemon, peer, "what is the capital of France")
    result = answer["result"]

    assert answer["reason"] == REASON_OK
    assert result["status"] == STATUS_COMPLETED
    assert result["capability"] == "inference"
    assert result["output"]["completion"] == (
        "echo: what is the capital of France")
    assert result["output"]["model"] == INFERENCE_MODEL
    assert result["output"]["truncated"] is False


def test_the_inference_result_is_signed_in_the_result_domain_and_no_other(ollama):
    """
    Same guarantee web-retrieval has. A completion is this node saying what it
    did, in a domain nothing else in the protocol can mint -- so a result
    cannot be handed back to it as a request to run something.
    """
    endpoint, _spy = ollama
    daemon = inference_daemon(endpoint)
    peer = handshaked(make_node("node_infer_verifier", capabilities=[]),
                      daemon, grants=["inference"])

    answer = infer_answer(daemon, peer, "hello")
    pub, signature, result = (daemon.public_key_hex,
                              answer["result_signature"], answer["result"])

    assert EurekaCrypto.verify_assign_result(pub, signature, result) is True
    assert EurekaCrypto.verify_assign_query(pub, signature, result) is False
    assert EurekaCrypto.verify_read_query(pub, signature, result) is False
    assert EurekaCrypto.verify_discovery_query(pub, signature, result) is False
    assert EurekaCrypto.verify_handshake(pub, signature, result) is False
    assert EurekaCrypto.verify_handshake_offer(pub, signature, result) is False
    assert EurekaCrypto.verify_handshake_confirm(pub, signature, result) is False
    assert EurekaCrypto.verify_audit_log(pub, signature, result) is False


def test_a_peer_without_the_inference_grant_is_refused(ollama):
    """
    Holding web-retrieval is not holding inference. The refusal is the same
    constant every other refusal is, so it discloses nothing about which of
    the two this node offers.
    """
    endpoint, spy = ollama
    daemon = inference_daemon(endpoint)
    peer = handshaked(make_node("node_ungranted", capabilities=[]), daemon,
                      grants=["web-retrieval"])
    before = spy.requests

    answer = infer_answer(daemon, peer, "let me in")

    assert answer["reason"] == REASON_NOT_PERMITTED
    assert answer == rejected(REASON_NOT_PERMITTED)
    # The refusal is the shared constant, so its result is the empty dict
    # every other refusal carries -- not an empty completion, which would be
    # a different thing to have been told.
    assert answer["result"] == {}
    # Refused before dispatch: the prompt never reached Ollama.
    assert spy.requests == before


def test_a_peer_with_no_grants_at_all_is_refused(ollama):
    """
    Where CT 101 stands in WSL's trust file today: present, authenticating,
    granted nothing.

    It stood for ct102-openclaw too until 2026-09-03, when that peer was
    granted `inference` -- so this is no longer "both responders", and the
    entry it now describes is the one that was deliberately left alone by that
    edit. The peer built here is synthetic either way; what the deployment
    supplies is the reason an empty grant is worth a test of its own rather
    than a case nobody is in.
    """
    endpoint, _spy = ollama
    daemon = inference_daemon(endpoint)
    peer = handshaked(make_node("node_nogrants", capabilities=[]), daemon,
                      grants=[])

    assert infer_answer(daemon, peer, "hello") == rejected(REASON_NOT_PERMITTED)


def test_the_audit_log_records_the_peer_and_outcome_and_not_the_prompt(ollama):
    """
    The reason this capability can exist. The entry has to be enough to answer
    "who asked this node to do what, and what came of it" and must contain
    neither the question nor the answer -- a log is read by every peer with
    the logs grant and kept for as long as the log is kept.
    """
    endpoint, _spy = ollama
    daemon = inference_daemon(endpoint)
    peer = handshaked(make_node("node_logged", capabilities=[]), daemon,
                      grants=["inference"])

    prompt = "my bank password is correct-horse-battery-staple"
    answer = infer_answer(daemon, peer, prompt, task_name="private-question")
    completion = answer["result"]["output"]["completion"]

    entries = audit_entries_for(daemon, "node_logged")
    assert len(entries) == 1
    payload = entries[0]["payload"]

    # What it must record.
    assert payload["peer"] == "node_logged"
    assert payload["capability"] == "inference"
    assert payload["result"] == STATUS_COMPLETED
    assert payload["outcome"] == STATUS_COMPLETED
    assert payload["task_summary"] == "private-question"

    # What it must not. Checked against the serialised entry rather than a
    # list of fields, because the failure this guards against is a new field
    # somebody adds later, which no assertion about today's fields would see.
    serialised = json.dumps(entries[0])
    assert "correct-horse-battery-staple" not in serialised
    assert prompt not in serialised
    assert completion not in serialised
    assert "prompt" not in serialised
    assert "completion" not in serialised


def test_a_refused_inference_is_logged_as_a_refusal_without_the_prompt(ollama):
    """
    The other half: "we said no to X" is part of the record of what this node
    did about X, and it must not be the record of what X asked.
    """
    endpoint, _spy = ollama
    daemon = inference_daemon(endpoint)
    peer = handshaked(make_node("node_refused_infer", capabilities=[]), daemon,
                      grants=["web-retrieval"])

    infer_answer(daemon, peer, "secret-phrase-nobody-should-see")

    entries = audit_entries_for(daemon, "node_refused_infer")
    assert len(entries) == 1
    assert entries[0]["payload"]["outcome"] == REASON_NOT_PERMITTED
    assert "secret-phrase-nobody-should-see" not in json.dumps(entries[0])


def test_a_failed_inference_is_logged_by_its_reason_and_still_not_the_prompt(ollama):
    """
    An upstream that is not there is a request this node accepted, ran, and
    could not complete -- the log says which, and the caller is not told its
    grant was taken away.
    """
    daemon = inference_daemon(dead_endpoint())
    peer = handshaked(make_node("node_upstream_down", capabilities=[]), daemon,
                      grants=["inference"])

    answer = infer_answer(daemon, peer, "unreachable-prompt-text")

    assert answer["reason"] == REASON_OK          # the gate said yes
    assert answer["result"]["status"] == STATUS_FAILED
    assert answer["result"]["reason"] == REASON_UPSTREAM_UNAVAILABLE
    assert answer["result"]["output"] is None

    entries = audit_entries_for(daemon, "node_upstream_down")
    assert entries[-1]["payload"]["outcome"] == REASON_UPSTREAM_UNAVAILABLE
    assert "unreachable-prompt-text" not in json.dumps(entries[-1])


def test_an_over_length_prompt_is_refused_through_the_gate(ollama):
    """
    Accepted by the gate, refused by the handler, and the two are different
    records: this peer's grant is intact and its prompt was too long.
    """
    endpoint, _spy = ollama
    daemon = inference_daemon(endpoint)
    peer = handshaked(make_node("node_verbose", capabilities=[]), daemon,
                      grants=["inference"])

    answer = infer_answer(daemon, peer, "w" * (MAX_PROMPT_CHARS + 1))

    assert answer["reason"] == REASON_OK
    assert answer["result"]["status"] == STATUS_FAILED
    assert answer["result"]["reason"] == REASON_PROMPT_TOO_LONG
    entries = audit_entries_for(daemon, "node_verbose")
    assert entries[-1]["payload"]["outcome"] == REASON_PROMPT_TOO_LONG


def test_a_timeout_comes_back_through_the_gate_as_a_timeout(ollama):
    """
    The handler's own timeout fires first, well inside the registry deadline.
    Both say `timeout` to the caller; what matters is that neither raises and
    the request is not left to occupy a slot for 90 seconds.
    """
    endpoint, _spy = ollama
    daemon = inference_daemon(endpoint, timeout_seconds=0.4)
    peer = handshaked(make_node("node_slow_infer", capabilities=[]), daemon,
                      grants=["inference"])

    answer = infer_answer(daemon, peer, SLOW_PROMPT)

    assert answer["result"]["status"] == STATUS_FAILED
    assert answer["result"]["reason"] == REASON_TIMEOUT
    entries = audit_entries_for(daemon, "node_slow_infer")
    assert entries[-1]["payload"]["outcome"] == REASON_TIMEOUT


def test_web_retrieval_is_unchanged_on_a_node_that_also_serves_inference(origin,
                                                                        ollama):
    """
    WSL will advertise two capabilities and CT 101 one. The second must not
    disturb the first: same grant, same result, same separation between them.
    """
    endpoint, _spy = ollama
    daemon = inference_daemon(endpoint)
    fetcher = handshaked(make_node("node_still_fetching", capabilities=[]),
                         daemon, grants=["web-retrieval"])

    answer = run(answer_assign(daemon, build_assign_query(
        fetcher, "web-retrieval", "fetch", {"url": f"{origin}/hello"})))

    assert answer["result"]["status"] == STATUS_COMPLETED
    assert answer["result"]["output"]["body"] == "hello from the origin"
    # And the fetcher still cannot reach the other capability.
    assert infer_answer(daemon, fetcher, "hello") == rejected(
        REASON_NOT_PERMITTED)


def test_the_two_capabilities_are_granted_independently(ollama, origin):
    """
    Two grants, two peers, and neither one implies the other. This is what
    makes advertising two capabilities safe: the trust file still decides
    each one separately.
    """
    endpoint, _spy = ollama
    daemon = inference_daemon(endpoint)
    both = handshaked(make_node("node_both_grants", capabilities=[]), daemon,
                      grants=["inference", "web-retrieval"])

    assert daemon.granted_capabilities("node_both_grants") == {
        "inference", "web-retrieval"}
    assert infer_answer(daemon, both, "hi")["result"]["status"] == (
        STATUS_COMPLETED)
    fetched = run(answer_assign(daemon, build_assign_query(
        both, "web-retrieval", "fetch", {"url": f"{origin}/hello"})))
    assert fetched["result"]["status"] == STATUS_COMPLETED
