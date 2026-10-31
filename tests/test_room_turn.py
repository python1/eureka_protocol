"""
room-turn: one Knights Circle room turn, answered by the local Ollama.

Driven against a fake Ollama on loopback, as inference is, so the real socket
paths run. The end-to-end test at the bottom goes through the daemon's own
gate: handshake, signed assign, grant, signed result.
"""
import asyncio
import socket
import threading
import time

import httpx
import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from eureka_protocol.src.eureka_daemon import assign
from eureka_protocol.src.eureka_daemon.api import create_app
from eureka_protocol.src.eureka_daemon.client import handshake_over_http
from eureka_protocol.src.eureka_daemon.crypto import EurekaCrypto
from eureka_protocol.src.eureka_daemon.handlers import (
    HandlerContext, HandlerError, HandlerRegistry, REASON_INVALID_PAYLOAD,
    REASON_MODEL_NOT_AVAILABLE, REASON_UPSTREAM_UNAVAILABLE, default_registry,
    room_turn_enabled,
)
from eureka_protocol.src.eureka_daemon.node import EurekaNode
from eureka_protocol.src.eureka_daemon import room_turn as rt
from eureka_protocol.src.eureka_daemon.trust import TrustList

CONTEXT = HandlerContext(node_id="node_test", capability=rt.CAPABILITY, task_name="turn")


def free_port():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


class Spy:
    def __init__(self):
        self.last_body = None


@pytest.fixture(scope="module")
def ollama():
    spy = Spy()
    app = FastAPI()

    @app.post("/api/chat")
    async def chat(request: Request):
        body = await request.json()
        spy.last_body = body
        last = body["messages"][-1]["content"]
        if last == "MISSING-MODEL":
            return JSONResponse({"error": "model not found"}, status_code=404)
        if last == "LONG":
            return JSONResponse({"message": {"role": "assistant", "content": "z" * 20000},
                                 "done_reason": "length", "eval_count": 1024})
        return JSONResponse({"message": {"role": "assistant", "content": f"reply to: {last}"},
                             "done_reason": "stop", "eval_count": 5})

    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 20
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}/api/chat", spy
    server.should_exit = True
    thread.join(timeout=10)


def turn(endpoint, **kwargs):
    return rt.OllamaRoomTurn(endpoint=endpoint, model="qwen3.5:4b", **kwargs)


def run(handler, payload):
    return asyncio.run(handler(payload, CONTEXT))


def messages(*texts, system="You are the Critic."):
    return {"messages": [{"role": "system", "content": system},
                         *({"role": "user", "content": t} for t in texts)]}


def test_a_turn_returns_the_models_reply(ollama):
    endpoint, _ = ollama
    result = run(turn(endpoint), messages("What should we plant?"))
    assert result.ok
    assert result.output == {"model": "qwen3.5:4b", "text": "reply to: What should we plant?",
                             "chars": 31, "truncated": False, "done_reason": "stop", "eval_count": 5}


def test_ollama_receives_constants_the_preamble_and_only_role_and_content(ollama):
    """The room chooses the text and nothing else -- not the model, not the budget, not extra fields."""
    endpoint, spy = ollama
    payload = messages("hi")
    payload["model"] = "llama-giant:405b"
    payload["options"] = {"num_predict": 999999}
    payload["messages"][1]["images"] = ["AAAA"]
    run(turn(endpoint), payload)
    body = spy.last_body
    assert body["model"] == "qwen3.5:4b"
    assert body["options"] == {"num_predict": rt.MAX_COMPLETION_TOKENS}
    assert body["think"] is False and body["stream"] is False
    assert body["messages"][0] == {"role": "system", "content": rt.PREAMBLE}
    assert body["messages"][1:] == [{"role": "system", "content": "You are the Critic."},
                                    {"role": "user", "content": "hi"}]


def test_malformed_payloads_are_refused_before_ollama_is_asked(ollama):
    endpoint, _ = ollama
    for payload in ({}, {"messages": []}, {"messages": "hi"},
                    {"messages": [{"role": "tool", "content": "x"}]},
                    {"messages": [{"role": "user", "content": 5}]},
                    {"messages": [{"role": "system", "content": "only a system message"}]},
                    {"messages": [{"role": "user", "content": "x"}] * (rt.MAX_MESSAGES + 1)}):
        assert run(turn(endpoint), payload).reason == REASON_INVALID_PAYLOAD, payload


def test_a_room_over_the_character_cap_is_refused_with_its_own_reason(ollama):
    endpoint, spy = ollama
    spy.last_body = None
    result = run(turn(endpoint), messages("x" * (rt.MAX_TOTAL_CHARS - len("You are the Critic.") + 1)))
    assert result.reason == rt.REASON_TOO_LONG and result.output is None
    assert spy.last_body is None
    assert run(turn(endpoint), messages("x" * (rt.MAX_TOTAL_CHARS - len("You are the Critic.")))).ok


def test_long_replies_are_capped_and_say_so(ollama):
    endpoint, _ = ollama
    result = run(turn(endpoint), messages("LONG"))
    assert result.output["truncated"] is True
    assert result.output["chars"] == rt.MAX_COMPLETION_CHARS == len(result.output["text"])


def test_a_missing_model_and_a_stopped_ollama_are_told_apart(ollama):
    endpoint, _ = ollama
    assert run(turn(endpoint), messages("MISSING-MODEL")).reason == REASON_MODEL_NOT_AVAILABLE
    dead = f"http://127.0.0.1:{free_port()}/api/chat"
    assert run(turn(dead), messages("hi")).reason == REASON_UPSTREAM_UNAVAILABLE


def test_the_endpoint_must_be_literal_loopback_and_the_model_a_model_name():
    for endpoint in ("http://localhost:11434/api/chat", "http://10.0.0.5:11434/api/chat"):
        with pytest.raises(HandlerError):
            rt.OllamaRoomTurn(endpoint=endpoint)
    for model in ("", "a b", "../x", "x;rm"):
        with pytest.raises(HandlerError):
            rt.OllamaRoomTurn(model=model)


def test_room_turn_is_off_unless_the_host_turns_it_on():
    assert room_turn_enabled({}) is False
    assert room_turn_enabled({rt.ENABLE_ENV: "1"}) is True
    with pytest.raises(HandlerError, match="neither on nor off"):
        room_turn_enabled({rt.ENABLE_ENV: "please"})
    assert rt.CAPABILITY not in default_registry(inference=False, room_turn=False).names()
    registry = default_registry(inference=False, room_turn=True)
    assert rt.CAPABILITY in registry.names()
    assert registry.deadline_for(rt.CAPABILITY) == rt.DEADLINE_SECONDS > rt.TIMEOUT_SECONDS


def test_the_model_comes_from_the_environment_and_is_checked():
    assert rt.model_from_environment({}) == rt.DEFAULT_MODEL
    assert rt.model_from_environment({rt.MODEL_ENV: " qwen3.5:4b "}) == "qwen3.5:4b"
    with pytest.raises(HandlerError):
        rt.model_from_environment({rt.MODEL_ENV: "bad name"})


def test_a_room_turn_end_to_end_through_the_gate_with_a_signed_result(ollama):
    """Handshake, signed assign, grant check, then a result signed over this request's nonce."""
    endpoint, _ = ollama
    agent_crypto, room_crypto = EurekaCrypto(), EurekaCrypto()
    agent_trust, room_trust = TrustList(), TrustList()
    agent_trust_key = room_crypto.get_public_key_hex()
    registry = HandlerRegistry().register(rt.CAPABILITY, turn(endpoint))
    agent_trust.add("room", agent_trust_key, [rt.CAPABILITY])
    room_trust.add("agent", agent_crypto.get_public_key_hex(), [])
    agent = EurekaNode(agent_crypto.derive_node_id(), agent_crypto, trust_list=agent_trust, handlers=registry)
    room = EurekaNode(room_crypto.derive_node_id(), room_crypto, trust_list=room_trust, capabilities=[])

    async def scenario():
        transport = httpx.ASGITransport(app=create_app(agent))
        async with httpx.AsyncClient(transport=transport, base_url="http://agent") as http:
            shaken = await handshake_over_http(room, http=http)
            assert shaken["authenticated"] and shaken["mutual"]
            request = assign.build_assign_query(room, rt.CAPABILITY, "turn", messages("Plan the beds"))
            answer = (await http.post("/v1/assign", json=request)).json()
        return request, answer

    request, answer = asyncio.run(scenario())
    assert answer["reason"] == "authenticated"
    result = answer["result"]
    assert result["status"] == "completed" and result["output"]["text"] == "reply to: Plan the beds"
    assert result["nonce"] == request["query"]["nonce"]
    assert EurekaCrypto.verify_assign_result(agent_crypto.get_public_key_hex(),
                                             answer["result_signature"], result)
