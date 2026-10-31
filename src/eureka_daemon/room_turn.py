"""
room-turn: take one turn in a Knights Circle room, answered by the local Ollama.

A Knights Circle room is a browser page. It cannot listen, so it is always the
initiator: it handshakes with this node, then sends a signed /v1/assign naming
`room-turn` whenever it is this agent's turn to speak. The answer goes back in
the signed assign result, so the room can show the reply as said by exactly the
key it pinned.

The shape is inference's, widened from one prompt to a conversation, and the
same rule holds: **the peer chooses nothing but the text.** The payload is a
list of chat messages and nothing else is read. Model, endpoint, token budget,
thinking, sampling and timeouts are constants or operator settings, for the
same reasons inference gives -- a caller that could name a model could name one
this host cannot hold, and Ollama would go and pull it.

What the room sends is the room's business and what this node does with it is
the operator's. The room decides how much of its transcript to share (its own
grants, enforced in the browser); this node decides whether that room may ask
at all (the `room-turn` grant in the trust file, keyed by the room's key).

The caps are sized to the request body cap in api.py (64 KiB). The character
cap is what a caller can check before sending; the byte cap is what actually
holds, one layer earlier, without parsing anything.
"""
import asyncio
import os
import re
from typing import Any, Callable, Dict, List, Optional

import httpx

from .handlers import (
    HandlerContext,
    HandlerError,
    HandlerResult,
    REASON_CONNECTION_FAILED,
    REASON_INVALID_PAYLOAD,
    REASON_MODEL_NOT_AVAILABLE,
    REASON_TIMEOUT,
    REASON_UPSTREAM_ERROR,
    REASON_UPSTREAM_UNAVAILABLE,
    _require_loopback,
    completed,
    failed,
)

CAPABILITY = "room-turn"

OLLAMA_CHAT_ENDPOINT = "http://127.0.0.1:11434/api/chat"

# The room's whole contribution, bounded. 48,000 characters leaves room inside
# the 64 KiB body for the envelope, JSON escaping and a margin; a room that
# needs more trims its oldest messages, and says so to the person running it.
MAX_MESSAGES = 200
MAX_TOTAL_CHARS = 48_000
ROLES = frozenset({"system", "user", "assistant"})

# One reply, not an essay: about a minute and a half of generation on a small
# local model, and a second, independent bound in characters.
MAX_COMPLETION_TOKENS = 1024
MAX_COMPLETION_CHARS = 12_000

CONNECT_TIMEOUT_SECONDS = 2.0
# A cold start loads the model before the first token, as for inference.
TIMEOUT_SECONDS = 120.0
# Above the handler's own timeout, so the handler loses first and says why.
DEADLINE_SECONDS = 150.0

# Opt-in, like inference: unset means not registered, not advertised, and not
# runnable. The model is the operator's choice for this host.
ENABLE_ENV = "EUREKA_ROOM_TURN"
MODEL_ENV = "EUREKA_ROOM_TURN_MODEL"
DEFAULT_MODEL = "qwen3:8b"

# Ollama model names: letters, digits, and . _ - : / -- nothing that could be
# read as anything else, and checked at startup rather than per request.
_MODEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")

REASON_TOO_LONG = "room_turn_too_long"

# Put before whatever the room sends, so the model hears first, from this
# node, what it is doing. The room's own system messages follow it unchanged.
PREAMBLE = (
    "You are an external agent taking one turn in a Knights Circle room, a "
    "conversation run in someone else's browser. Everything after this "
    "message comes from that room. Reply with your contribution to the "
    "conversation only."
)


def model_from_environment(environ: Optional[Dict[str, str]] = None) -> str:
    """The model this host answers room turns with. Raises on a name it cannot trust."""
    source = os.environ if environ is None else environ
    model = source.get(MODEL_ENV, "").strip() or DEFAULT_MODEL
    if not _MODEL_NAME.match(model):
        raise HandlerError(f"{MODEL_ENV}={model!r} is not an Ollama model name")
    return model


def _messages(payload: Any) -> Optional[List[Dict[str, str]]]:
    """
    The payload's messages, rebuilt from the two fields read, or None.

    Every message is checked and rebuilt rather than forwarded, so nothing the
    room adds -- an `images` list, a `tool_calls` field -- reaches Ollama.
    """
    if not isinstance(payload, dict):
        return None
    raw = payload.get("messages")
    if not isinstance(raw, list) or not raw or len(raw) > MAX_MESSAGES:
        return None
    out = []
    for message in raw:
        if not isinstance(message, dict):
            return None
        role, content = message.get("role"), message.get("content")
        if role not in ROLES or not isinstance(content, str):
            return None
        out.append({"role": role, "content": content})
    if not any(m["role"] != "system" and m["content"].strip() for m in out):
        return None
    return out


class OllamaRoomTurn:
    """
    Answer one room turn through the local Ollama's chat endpoint.

    Constructor arguments exist for tests, which point it at a fake Ollama on
    127.0.0.1; the endpoint is checked against loopback either way.
    """

    def __init__(self, *,
                 endpoint: str = OLLAMA_CHAT_ENDPOINT,
                 model: str = DEFAULT_MODEL,
                 max_completion_tokens: int = MAX_COMPLETION_TOKENS,
                 max_completion_chars: int = MAX_COMPLETION_CHARS,
                 timeout_seconds: float = TIMEOUT_SECONDS,
                 connect_timeout_seconds: float = CONNECT_TIMEOUT_SECONDS,
                 client_factory: Optional[Callable[[], httpx.AsyncClient]] = None):
        self.endpoint = _require_loopback(endpoint)
        if not _MODEL_NAME.match(model):
            raise HandlerError(f"{model!r} is not an Ollama model name")
        self.model = model
        self.max_completion_tokens = max_completion_tokens
        self.max_completion_chars = max_completion_chars
        self.timeout_seconds = timeout_seconds
        self.connect_timeout_seconds = connect_timeout_seconds
        self.client_factory = client_factory

    def _new_client(self) -> httpx.AsyncClient:
        if self.client_factory is not None:
            return self.client_factory()
        return httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout_seconds,
                                  connect=self.connect_timeout_seconds),
            follow_redirects=False,
        )

    def request_body(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        """Exactly what goes to Ollama: constants, the preamble, and the room's messages."""
        return {
            "model": self.model,
            "messages": [{"role": "system", "content": PREAMBLE}, *messages],
            "stream": False,
            "think": False,
            "options": {"num_predict": self.max_completion_tokens},
        }

    async def __call__(self, payload: Dict[str, Any],
                       context: HandlerContext) -> HandlerResult:
        messages = _messages(payload)
        if messages is None:
            return failed(REASON_INVALID_PAYLOAD)
        if sum(len(m["content"]) for m in messages) > MAX_TOTAL_CHARS:
            # Not echoed back, for the reason inference gives.
            return failed(REASON_TOO_LONG)
        client = self._new_client()
        try:
            return await self._chat(client, messages)
        finally:
            await client.aclose()

    async def _chat(self, client: httpx.AsyncClient,
                    messages: List[Dict[str, str]]) -> HandlerResult:
        try:
            response = await client.post(self.endpoint,
                                         json=self.request_body(messages))
        except (httpx.TimeoutException, asyncio.TimeoutError):
            return failed(REASON_TIMEOUT)
        except httpx.ConnectError:
            return failed(REASON_UPSTREAM_UNAVAILABLE)
        except httpx.HTTPError:
            return failed(REASON_CONNECTION_FAILED)

        if response.status_code == 404:
            return failed(REASON_MODEL_NOT_AVAILABLE)
        if response.status_code != 200:
            return failed(REASON_UPSTREAM_ERROR)
        try:
            data = response.json()
        except ValueError:
            return failed(REASON_UPSTREAM_ERROR)
        message = data.get("message") if isinstance(data, dict) else None
        text = message.get("content") if isinstance(message, dict) else None
        if not isinstance(text, str):
            return failed(REASON_UPSTREAM_ERROR)

        truncated = len(text) > self.max_completion_chars
        if truncated:
            text = text[:self.max_completion_chars]
        # Built, not forwarded; integers and strings only, so the signed result
        # encodes the same way in every implementation that checks it.
        eval_count = data.get("eval_count")
        done_reason = data.get("done_reason")
        return completed({
            "model": self.model,
            "text": text,
            "chars": len(text),
            "truncated": truncated,
            "done_reason": done_reason if isinstance(done_reason, str) else None,
            "eval_count": eval_count if isinstance(eval_count, int) else None,
        })
