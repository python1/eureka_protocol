"""
The protocol tests, black-box, against both daemons (see conftest.py).

Each test names the Python test(s) it carries over. Tests that reach inside the
Python node (its tables, an injected trust list, monkeypatched internals) have
no black-box form and stay in tests/; what can be seen from the wire is here.
"""
import asyncio
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from conftest import client_node, grant
from eureka_protocol.src.eureka_daemon import assign, discovery, reads
from eureka_protocol.src.eureka_daemon.client import CONFIRM_PATH, OFFER_PATH, handshake_over_http
from eureka_protocol.src.eureka_daemon.crypto import EurekaCrypto

ORIGIN = "https://knights-circle.vercel.app"
LIMIT = 64 * 1024


def post(daemon, path, document=None, **kwargs):
    if document is not None:
        kwargs["json"] = document
    return httpx.post(daemon.base + path, timeout=30, **kwargs)


def trusting(node, daemon):
    node.trust_list.add(f"daemon-{daemon.port}", daemon.public_key)
    return node


def handshake(node, daemon):
    return asyncio.run(handshake_over_http(node, daemon.base))


def joined(start, *capabilities, **kwargs):
    """A daemon, and a client it trusts with these grants that has completed a handshake."""
    node = client_node("client")
    daemon = start(peers=grant(node, *capabilities), **kwargs)
    trusting(node, daemon)
    assert handshake(node, daemon)["authenticated"] is True
    return node, daemon


def room(*texts, system="You are the Critic."):
    return {"messages": [{"role": "system", "content": system}, *({"role": "user", "content": t} for t in texts)]}


def run_assign(node, daemon, capability="room-turn", payload=None, task_name="knights-circle-turn", **kwargs):
    query = assign.build_assign_query(node, capability, task_name, payload if payload is not None else room("Plan the beds"), **kwargs)
    return query, post(daemon, "/v1/assign", query).json()


# ---------------------------------------------------------------------------
# Manifest and handshake (test_api.py, test_http_handshake.py)
# ---------------------------------------------------------------------------

def test_open_manifest_is_node_id_and_runtime_only(start):
    daemon = start()
    body = httpx.get(daemon.base + "/v1/manifest").json()
    assert body == {"node_id": daemon.node_id, "runtime": "eureka-daemon-mvd"}
    assert daemon.node_id == "node_" + __import__("hashlib").sha256(bytes.fromhex(daemon.public_key)).hexdigest()[:8]


def test_full_handshake_over_http_authenticates_both_sides(start):
    node = client_node("a")
    daemon = start(peers=grant(node))
    result = handshake(trusting(node, daemon), daemon)
    assert result["authenticated"] is True and result["mutual"] is True
    assert result["peer_id"] == daemon.node_id


def test_http_rejects_an_untrusted_initiator(start):
    stranger = client_node("stranger")
    daemon = start()
    body = post(daemon, OFFER_PATH, trusting(stranger, daemon).create_handshake_offer(daemon.node_id)).json()
    assert body["authenticated"] is False and body["reason"] == "untrusted_key"
    assert "counter_challenge" not in body


def test_a_revoked_key_is_refused_as_revoked_not_untrusted(start):
    node = client_node("revoked")
    daemon = start(revoked=[{"public_key": node.public_key_hex, "reason": "lost laptop"}])
    body = post(daemon, OFFER_PATH, trusting(node, daemon).create_handshake_offer(daemon.node_id)).json()
    assert body["reason"] == "revoked_key"


def test_http_rejects_a_tampered_offer(start):
    node = client_node("a")
    daemon = start(peers=grant(node))
    offer = node.create_handshake_offer(daemon.node_id)
    offer["challenge"]["initiator_id"] = "node_attacker"
    assert post(daemon, OFFER_PATH, offer).json()["reason"] == "signature_verification_failed"


def test_http_rejects_a_replayed_offer(start):
    node = client_node("a")
    daemon = start(peers=grant(node))
    offer = node.create_handshake_offer(daemon.node_id)
    assert post(daemon, OFFER_PATH, offer).json()["event"] == "handshake_response"
    assert post(daemon, OFFER_PATH, offer).json()["reason"] == "replayed_nonce"


def test_http_rejects_a_stale_offer(start):
    node = client_node("a")
    daemon = start(peers=grant(node))
    challenge = node.create_challenge(daemon.node_id)
    challenge["timestamp"] = (datetime.now(timezone.utc) - timedelta(seconds=300)).isoformat()
    offer = {"event": "handshake_offer", "initiator_id": node.node_id, "challenge": challenge,
             "public_key": node.public_key_hex, "signature": node.crypto.sign_handshake_offer(challenge)}
    assert post(daemon, OFFER_PATH, offer).json()["reason"] == "stale_timestamp"


def test_http_rejects_a_mismatched_initiator_id(start):
    node = client_node("a")
    daemon = start(peers=grant(node))
    offer = node.create_handshake_offer(daemon.node_id)
    offer["initiator_id"] = "node_somebody_else"
    body = post(daemon, OFFER_PATH, offer).json()
    assert body["reason"] == "unexpected_responder" and body["peer_id"] == "node_somebody_else"


@pytest.mark.parametrize("bad_signature", ["!!!!", "abc", "", "@@@@", "AAAA=", "A" * 86 + "=="])
def test_http_rejects_malformed_signatures(start, bad_signature):
    node = client_node("a")
    daemon = start(peers=grant(node))
    offer = node.create_handshake_offer(daemon.node_id)
    offer["signature"] = bad_signature
    assert post(daemon, OFFER_PATH, offer).json()["reason"] == "signature_verification_failed"


def test_an_offer_signed_in_another_domain_is_refused(start):
    node = client_node("a")
    daemon = start(peers=grant(node))
    offer = node.create_handshake_offer(daemon.node_id)
    offer["signature"] = node.crypto.sign_handshake_confirm(offer["challenge"])
    assert post(daemon, OFFER_PATH, offer).json()["reason"] == "signature_verification_failed"


def test_message_two_verifies_after_the_round_trip(start):
    node = client_node("a")
    daemon = start(peers=grant(node))
    offer = node.create_handshake_offer(daemon.node_id)
    two = post(daemon, OFFER_PATH, offer).json()
    assert two["challenge"] == offer["challenge"]
    assert EurekaCrypto.verify_handshake(daemon.public_key, two["signature"], offer["challenge"])
    assert two["public_key"] == daemon.public_key and two["responder_id"] == daemon.node_id
    counter = two["counter_challenge"]
    assert set(counter) == {"protocol", "event", "initiator_id", "peer_id", "nonce", "timestamp"}
    assert counter["peer_id"] == node.node_id and counter["initiator_id"] == daemon.node_id
    assert len(counter["nonce"]) == 32 and counter["timestamp"].endswith("+00:00")


def test_http_rejects_an_unknown_confirmation(start):
    node = client_node("a")
    daemon = start(peers=grant(node))
    rogue = client_node("rogue")
    confirmation = node.confirm_handshake({"counter_challenge": rogue.create_challenge(node.node_id)})
    assert post(daemon, CONFIRM_PATH, confirmation).json()["reason"] == "unknown_nonce"


def test_http_rejects_a_replayed_confirmation(start):
    node = client_node("a")
    daemon = start(peers=grant(node))
    trusting(node, daemon)
    two = post(daemon, OFFER_PATH, node.create_handshake_offer(daemon.node_id)).json()
    asyncio.run(node.complete_handshake(two))
    confirmation = node.confirm_handshake(two)
    assert post(daemon, CONFIRM_PATH, confirmation).json()["authenticated"] is True
    assert post(daemon, CONFIRM_PATH, confirmation).json()["reason"] == "replayed_nonce"


def test_http_rejects_a_tampered_confirmation(start):
    node = client_node("a")
    daemon = start(peers=grant(node))
    two = post(daemon, OFFER_PATH, node.create_handshake_offer(daemon.node_id)).json()
    confirmation = node.confirm_handshake(two)
    confirmation["challenge"]["initiator_id"] = "node_attacker"
    assert post(daemon, CONFIRM_PATH, confirmation).json()["reason"] == "signature_verification_failed"


def test_one_initiator_cannot_answer_anothers_challenge(start):
    a, b = client_node("a"), client_node("b")
    daemon = start(peers={**grant(a), **grant(b)})
    two = post(daemon, OFFER_PATH, a.create_handshake_offer(daemon.node_id)).json()
    # b signs a's counter-challenge with its own (also trusted) key.
    stolen = b.confirm_handshake(two)
    stolen["initiator_id"] = a.node_id
    assert post(daemon, CONFIRM_PATH, stolen).json()["reason"] == "unexpected_responder"


# ---------------------------------------------------------------------------
# Transport (test_http_handshake.py)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", [OFFER_PATH, CONFIRM_PATH])
@pytest.mark.parametrize("body", [b"{ this is not json", b"", b"\xff\xfe\x00broken", b"{'single': 'quotes'}", b"{\"unterminated\": "])
def test_malformed_json_returns_400_not_500(start, path, body):
    response = post(start(), path, content=body)
    assert response.status_code == 400
    assert response.json() == {"event": "handshake_rejected", "authenticated": False, "reason": "malformed_response",
                               "peer_id": None, "auth_type": "Ed25519"}


@pytest.mark.parametrize("path", [OFFER_PATH, CONFIRM_PATH])
@pytest.mark.parametrize("document", [[], "a string", 42, None, {"event": "handshake_offer"}, {"challenge": "not a mapping"},
                                      {"challenge": {"nonce": 1234}}, {"challenge": None, "signature": None, "public_key": None},
                                      {"challenge": {}, "signature": [], "public_key": {}}])
def test_wrong_shape_returns_a_reason_not_500(start, path, document):
    response = post(start(), path, content=json.dumps(document).encode())
    assert response.status_code == 200
    body = response.json()
    assert body["authenticated"] is False and body["reason"] in {"malformed_response", "unknown_nonce"}
    assert set(body) == {"event", "authenticated", "reason", "session_id", "peer_id", "auth_type", "timestamp"}


@pytest.mark.parametrize("path", [OFFER_PATH, CONFIRM_PATH, "/v1/assign", "/v1/peers"])
def test_oversized_bodies_are_refused_declared_or_streamed(start, path):
    daemon = start()
    declared = post(daemon, path, content=b"{ not json " + b"x" * (LIMIT + 1024))
    streamed = post(daemon, path, content=iter([b"x" * 1024] * (LIMIT // 1024 + 8)))
    assert declared.status_code == streamed.status_code == 413
    assert declared.json()["reason"] == streamed.json()["reason"] == "malformed_response"


def test_a_body_at_the_limit_is_still_processed(start):
    response = post(start(), OFFER_PATH, {"pad": "x" * (LIMIT // 2)})
    assert response.status_code == 200 and response.json()["reason"] == "malformed_response"


def test_routes_methods_and_redirects(start):
    daemon = start()
    assert httpx.get(daemon.base + "/v1/assign").status_code == 405
    assert httpx.get(daemon.base + "/v1/assign").headers["allow"] == "POST"
    assert httpx.delete(daemon.base + "/v1/manifest").headers["allow"] == "GET"
    assert httpx.get(daemon.base + "/nope").json() == {"detail": "Not Found"}
    moved = httpx.post(daemon.base + "/v1/manifest/")
    assert moved.status_code == 307 and moved.headers["location"] == daemon.base + "/v1/manifest"


# ---------------------------------------------------------------------------
# Assign gate and room-turn (test_assign_gate.py, test_room_turn.py)
# ---------------------------------------------------------------------------

def test_unsigned_post_discloses_nothing_and_executes_nothing(start, ollama):
    daemon = start()
    body = post(daemon, "/v1/assign", {"capability": "room-turn", "payload": room("hi")}).json()
    assert body == {"event": "assign_rejected", "reason": "malformed_response", "result": {}}
    assert ollama.requests == []


def test_a_room_turn_end_to_end_with_a_signed_result(start, ollama):
    node, daemon = joined(start, "room-turn")
    query, answer = run_assign(node, daemon)
    assert answer["event"] == "assign_answer" and answer["reason"] == "authenticated"
    result = answer["result"]
    assert EurekaCrypto.verify_assign_result(daemon.public_key, answer["result_signature"], result)
    for other in ("verify_assign_query", "verify_read_query", "verify_handshake", "verify_audit_log"):
        assert not getattr(EurekaCrypto, other)(daemon.public_key, answer["result_signature"], result)
    assert result["nonce"] == query["query"]["nonce"] and result["requester_id"] == node.node_id
    assert result["capability"] == "room-turn" and result["status"] == "completed" and result["reason"] == "ok"
    assert result["output"] == {"model": "qwen3.5:4b", "text": "The beds should face south.", "chars": 27,
                                "truncated": False, "done_reason": "stop", "eval_count": 7}
    assert set(result) == {"protocol", "event", "task_id", "status", "reason", "capability", "task_name",
                           "responder_id", "requester_id", "nonce", "output", "timestamp"}


def test_ollama_receives_constants_the_preamble_and_only_role_and_content(start, ollama):
    node, daemon = joined(start, "room-turn")
    payload = room("one", "two")
    payload["messages"][1]["images"] = ["x"]
    payload["model"] = "llama-big"
    run_assign(node, daemon, payload=payload)
    sent = ollama.requests[-1]
    assert sent["path"] == "/api/chat"
    assert sent["body"]["model"] == "qwen3.5:4b" and sent["body"]["stream"] is False and sent["body"]["think"] is False
    assert sent["body"]["options"] == {"num_predict": 1024}
    assert sent["body"]["messages"][0]["role"] == "system" and "Knights Circle room" in sent["body"]["messages"][0]["content"]
    assert sent["body"]["messages"][1:] == [{"role": "system", "content": "You are the Critic."},
                                           {"role": "user", "content": "one"}, {"role": "user", "content": "two"}]


@pytest.mark.parametrize("payload,reason", [
    ({}, "invalid_payload"),
    ({"messages": []}, "invalid_payload"),
    ({"messages": [{"role": "system", "content": "only"}]}, "invalid_payload"),
    ({"messages": [{"role": "tool", "content": "x"}]}, "invalid_payload"),
    ({"messages": [{"role": "user", "content": 5}]}, "invalid_payload"),
    ({"messages": [{"role": "user", "content": "x"}] * 201}, "invalid_payload"),
    ({"messages": [{"role": "user", "content": "x" * 48001}]}, "room_turn_too_long"),
])
def test_bad_room_payloads_are_refused_before_ollama_is_asked(start, ollama, payload, reason):
    node, daemon = joined(start, "room-turn")
    _, answer = run_assign(node, daemon, payload=payload)
    assert answer["result"]["status"] == "failed" and answer["result"]["reason"] == reason
    assert answer["result"]["output"] is None
    assert ollama.requests == []


def test_long_replies_are_capped_in_characters_and_say_so(start, ollama):
    node, daemon = joined(start, "room-turn")
    ollama.reply = "🌱" * 12_005
    output = run_assign(node, daemon)[1]["result"]["output"]
    assert output["truncated"] is True and output["chars"] == 12_000 and output["text"] == "🌱" * 12_000


@pytest.mark.parametrize("mode,reason", [("missing", "model_not_available"), ("error", "upstream_error"), ("garbage", "upstream_error")])
def test_ollama_failures_are_told_apart(start, ollama, mode, reason):
    node, daemon = joined(start, "room-turn")
    ollama.mode = mode
    result = run_assign(node, daemon)[1]["result"]
    assert (result["status"], result["reason"]) == ("failed", reason)


def test_a_stopped_ollama_is_upstream_unavailable(start):
    node = client_node("a")
    daemon = start(peers=grant(node, "room-turn"), env={"EUREKA_OLLAMA_URL": "http://127.0.0.1:9"})
    trusting(node, daemon)
    handshake(node, daemon)
    assert run_assign(node, daemon)[1]["result"]["reason"] == "upstream_unavailable"


def test_inference_is_its_own_grant(start, ollama):
    node, daemon = joined(start, "inference")
    _, answer = run_assign(node, daemon, capability="inference", payload={"prompt": "  hello  ", "model": "x"})
    assert answer["result"]["output"]["completion"] == "The beds should face south."
    assert ollama.requests[-1]["body"]["prompt"] == "hello" and ollama.requests[-1]["body"]["options"] == {"num_predict": 512}
    assert run_assign(node, daemon)[1] == {"event": "assign_rejected", "reason": "capability_not_granted", "result": {}}


def test_authenticated_peer_without_the_grant_is_refused_distinctly(start, ollama):
    node, daemon = joined(start)
    assert run_assign(node, daemon)[1] == {"event": "assign_rejected", "reason": "capability_not_granted", "result": {}}
    assert ollama.requests == []


def test_a_grant_for_something_this_node_does_not_offer_is_refused(start):
    node, daemon = joined(start, "room-turn")
    assert run_assign(node, daemon, capability="code-exec")[1]["reason"] == "capability_not_granted"


def test_stranger_with_a_valid_signature_is_refused(start):
    daemon = start()
    stranger = client_node("stranger")
    assert run_assign(stranger, daemon)[1]["reason"] == "untrusted_key"


def test_trusted_but_no_handshake_is_not_authenticated(start):
    node = client_node("a")
    daemon = start(peers=grant(node, "room-turn"))
    assert run_assign(node, daemon)[1]["reason"] == "not_authenticated"


def test_replayed_signed_request_is_refused_and_runs_once(start, ollama):
    node, daemon = joined(start, "room-turn")
    query, first = run_assign(node, daemon)
    again = post(daemon, "/v1/assign", query).json()
    assert first["event"] == "assign_answer" and again["reason"] == "replayed_nonce"
    assert len(ollama.requests) == 1


def test_a_refused_request_cannot_be_replayed_either(start):
    node, daemon = joined(start)
    query, first = run_assign(node, daemon)
    assert first["reason"] == "capability_not_granted"
    assert post(daemon, "/v1/assign", query).json()["reason"] == "replayed_nonce"


def test_a_stale_request_is_refused(start):
    node, daemon = joined(start, "room-turn")
    old = datetime.now(timezone.utc) - timedelta(seconds=120)
    assert run_assign(node, daemon, now=old)[1]["reason"] == "stale_timestamp"


def test_no_other_domains_signature_verifies_as_an_assign(start):
    node, daemon = joined(start, "room-turn")
    query = assign.build_assign_query(node, "room-turn", "turn", room("hi"))
    query["signature"] = node.crypto.sign_read_query(query["query"])
    assert post(daemon, "/v1/assign", query).json()["reason"] == "signature_verification_failed"


@pytest.mark.parametrize("change", ["extra_key", "missing_key", "long_nonce", "blank_task", "payload_list", "envelope_id"])
def test_malformed_assign_queries(start, change):
    node, daemon = joined(start, "room-turn")
    query = assign.build_assign_query(node, "room-turn", "turn", room("hi"))
    q = query["query"]
    if change == "extra_key":
        q["model"] = "x"
    elif change == "missing_key":
        del q["task_name"]
    elif change == "long_nonce":
        q["nonce"] = "n" * 129
    elif change == "blank_task":
        q["task_name"] = "   "
    elif change == "payload_list":
        q["payload"] = []
    else:
        query["requester_id"] = "node_other"
    query["signature"] = node.crypto.sign_assign_query(q)
    assert post(daemon, "/v1/assign", query).json() == {"event": "assign_rejected", "reason": "malformed_response", "result": {}}


# ---------------------------------------------------------------------------
# Reads and discovery (test_reads.py, test_discovery.py)
# ---------------------------------------------------------------------------

def test_reads_need_a_handshake_and_return_only_the_callers_own_records(start, ollama):
    a, b = client_node("a"), client_node("b")
    daemon = start(peers={**grant(a, "room-turn"), **grant(b)})
    for n in (a, b):
        trusting(n, daemon)
    before = post(daemon, "/v1/logs", reads.build_read_query(a, reads.LOGS_EVENT)).json()
    assert before == {"event": "read_rejected", "reason": "not_authenticated", "logs": []}
    handshake(a, daemon)
    handshake(b, daemon)
    run_assign(a, daemon)
    run_assign(b, daemon)

    logs_a = post(daemon, "/v1/logs", reads.build_read_query(a, reads.LOGS_EVENT)).json()
    assert logs_a["event"] == "logs_answer" and len(logs_a["logs"]) == 1
    entry = logs_a["logs"][0]
    assert entry["payload"]["peer"] == a.node_id and entry["payload"]["outcome"] == "completed"
    assert "Plan the beds" not in json.dumps(entry) and "south" not in json.dumps(entry)
    assert EurekaCrypto.verify_audit_log(daemon.public_key, entry["signature"], entry["payload"])
    logs_b = post(daemon, "/v1/logs", reads.build_read_query(b, reads.LOGS_EVENT)).json()
    assert [e["payload"]["outcome"] for e in logs_b["logs"]] == ["capability_not_granted"]
    assert logs_b["logs"][0]["payload"]["result"] == "refused"

    peers = post(daemon, "/v1/peers", reads.build_read_query(a, reads.PEERS_EVENT, keys=[b.public_key_hex, "00" * 32])).json()
    assert peers["peers"] == {b.public_key_hex: {"peer_id": b.node_id, "status": "authenticated"}}

    manifest = post(daemon, "/v1/manifest", reads.build_read_query(a, reads.MANIFEST_EVENT)).json()
    assert manifest["event"] == "manifest_answer"
    assert {"room-turn", "inference"} <= set(manifest["manifest"]["capabilities"])
    assert manifest["manifest"]["runtime"] == "eureka-daemon" and manifest["manifest"]["node_id"] == daemon.node_id


def test_a_read_signature_cannot_be_used_for_another_record(start):
    node, daemon = joined(start)
    query = reads.build_read_query(node, reads.LOGS_EVENT)
    query["query"]["event"] = reads.MANIFEST_EVENT
    assert post(daemon, "/v1/manifest", query).json()["reason"] == "signature_verification_failed"


def test_discovery_answers_only_an_authenticated_peer_and_knows_no_addresses(start):
    node = client_node("a")
    daemon = start(peers=grant(node))
    trusting(node, daemon)
    assert post(daemon, "/v1/discovery/addresses", discovery.build_query(node)).json()["reason"] == "not_authenticated"
    handshake(node, daemon)
    body = post(daemon, "/v1/discovery/addresses", discovery.build_query(node, keys=[node.public_key_hex])).json()
    assert body == {"event": "discovery_answer", "responder_id": daemon.node_id, "reason": "authenticated", "addresses": {}}


# ---------------------------------------------------------------------------
# CORS (test_cors.py)
# ---------------------------------------------------------------------------

def preflight(daemon, origin=ORIGIN, method="POST", headers="content-type", **extra):
    h = {"Origin": origin, "Access-Control-Request-Method": method, "Access-Control-Request-Headers": headers, **extra}
    return httpx.options(daemon.base + "/v1/assign", headers=h)


def test_without_origins_no_page_may_read_replies(start):
    daemon = start()
    response = httpx.get(daemon.base + "/v1/manifest", headers={"Origin": ORIGIN})
    assert "access-control-allow-origin" not in response.headers and "vary" not in response.headers
    assert preflight(daemon).status_code == 405


def test_a_listed_origin_may_read_replies_and_preflight_succeeds(start):
    daemon = start(cors=[ORIGIN])
    ok = preflight(daemon)
    assert ok.status_code == 200 and ok.text == "OK"
    assert ok.headers["access-control-allow-origin"] == ORIGIN
    assert ok.headers["access-control-allow-methods"] == "GET, POST"
    assert ok.headers["access-control-allow-headers"] == "Accept, Accept-Language, Content-Language, Content-Type, content-type"
    assert ok.headers["access-control-max-age"] == "600"
    read = httpx.get(daemon.base + "/v1/manifest", headers={"Origin": ORIGIN})
    assert read.headers["access-control-allow-origin"] == ORIGIN and read.headers["vary"] == "Origin"


@pytest.mark.parametrize("kwargs,text", [
    ({"origin": "https://evil.example"}, "Disallowed CORS origin"),
    ({"method": "PUT", "headers": "x-foo"}, "Disallowed CORS method, headers"),
    ({"method": "post"}, "Disallowed CORS method"),
    ({"Access-Control-Request-Private-Network": "true"}, "Disallowed CORS private-network"),
])
def test_other_preflights_are_refused_with_starlettes_words(start, kwargs, text):
    response = preflight(start(cors=[ORIGIN]), **kwargs)
    assert response.status_code == 400 and response.text == text


def test_cors_grants_nothing_a_listed_page_is_still_refused_without_a_handshake(start):
    daemon = start(cors=[ORIGIN])
    response = post(daemon, "/v1/assign", {}, headers={"Origin": ORIGIN})
    assert response.headers["access-control-allow-origin"] == ORIGIN
    assert response.json()["reason"] == "malformed_response"


def test_cors_origins_come_from_the_environment_too(start):
    daemon = start(env={"EUREKA_CORS_ORIGINS": "http://127.0.0.1:4173, https://knights-circle.vercel.app/"})
    for origin in ("http://127.0.0.1:4173", ORIGIN):
        assert httpx.get(daemon.base + "/v1/manifest", headers={"Origin": origin}).headers["access-control-allow-origin"] == origin
