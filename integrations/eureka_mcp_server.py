#!/usr/bin/env python3
"""
eureka_mcp_server.py -- expose a Eureka peer's capabilities to Hermes over MCP.

Hermes speaks MCP over stdio; this process speaks Eureka. It holds no keys of
its own: it loads the identity and trust list this host already has, completes
the mutual handshake with the configured peer, and issues signed /v1/assign
requests. What comes back is verified before Hermes ever sees it.

Why a separate process rather than a Hermes plugin: a plugin runs inside
Hermes's interpreter, and Hermes never installs a plugin's declared
dependencies ("VALIDATED AND SURFACED ONLY" -- hermes_cli/plugins.py). The
Eureka client needs eureka_protocol, httpx and cryptography, which already
work together in this venv and are proven against the live daemon. Running
here keeps that environment intact and hands Hermes only the tool surface.

Two things about stdio that are easy to get wrong and fatal if you do:

  1. **stdout belongs to the protocol.** Every byte written to it must be
     JSON-RPC. EurekaNode prints progress ("[NODE ...] Challenge issued")
     to stdout, so every call into Eureka runs under redirect_stdout(stderr).
     Without that the first handshake corrupts the stream and Hermes sees a
     dead server rather than a chatty one.

  2. **Diagnostics go to stderr**, which Hermes captures as the server's log.

Identity and trust come from $EUREKA_IDENTITY_PATH and $EUREKA_TRUST_PATH and
are required to exist. The loader creates a key when it finds none -- correct
for a daemon's first boot, catastrophic here, where it would silently mint an
identity no peer trusts and turn every refusal into a lie about the grant.
"""
from __future__ import annotations

import contextlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

def _die(message: str) -> "NoReturn":  # type: ignore[valid-type]
    """Fail loudly, on stderr, before the protocol starts."""
    print(f"eureka-mcp: FATAL: {message}", file=sys.stderr, flush=True)
    raise SystemExit(2)


def _find_package_root() -> Path:
    """
    The directory to put on sys.path so ``eureka_protocol`` imports.

    Walk up from this file looking for the one ancestor that *contains* the
    package, rather than assuming a fixed depth. That is what lets the same
    file work in both places it legitimately lives: beside the checkout when
    it is deployed (``~/eureka/eureka_mcp_server.py``), and inside it when it
    is version controlled (``~/eureka/eureka_protocol/integrations/``). A
    hardcoded ``parent`` works in exactly one of those, so committing the file
    would otherwise mean keeping a second copy that drifts.

    The marker is the daemon package itself, not the directory name, so a
    stray empty ``eureka_protocol/`` somewhere up the tree cannot capture the
    search.
    """
    here = Path(__file__).resolve()
    for candidate in here.parents:
        if (candidate / "eureka_protocol" / "src" / "eureka_daemon").is_dir():
            return candidate
    _die(
        f"cannot locate the eureka_protocol package from {here}. Expected an "
        "ancestor directory containing eureka_protocol/src/eureka_daemon."
    )


sys.path.insert(0, str(_find_package_root()))


# --- (b) identity and trust are required, and must already exist -----------
for _var in ("EUREKA_IDENTITY_PATH", "EUREKA_TRUST_PATH"):
    if not (os.environ.get(_var) or "").strip():
        _die(
            f"{_var} is not set. Set it in the MCP server's env: block. "
            "Refusing to fall back to a default path, because the identity "
            "loader creates a key when it finds none and this process would "
            "come up as a node no peer trusts."
        )

from mcp.server import MCPServer  # noqa: E402

from eureka_protocol.src.eureka_daemon import assign, client, tls  # noqa: E402
from eureka_protocol.src.eureka_daemon.crypto import (  # noqa: E402
    EurekaCrypto,
    resolve_identity_path,
)
from eureka_protocol.src.eureka_daemon.handlers import REASON_OK as WORK_OK  # noqa: E402
from eureka_protocol.src.eureka_daemon.node import (  # noqa: E402
    EurekaNode,
    REASON_OK as GATE_OK,
)
from eureka_protocol.src.eureka_daemon.trust import resolve_trust_path  # noqa: E402

for _label, _path in (("identity", resolve_identity_path()),
                      ("trust list", resolve_trust_path())):
    if not _path.exists():
        _die(f"no {_label} at {_path} -- it must exist; this process will not create one")

PEER_URL = (os.environ.get("EUREKA_PEER") or "https://192.168.1.180:8443").strip()
# (d) Must outlast the responder's registry deadline (30s), not its fetch
# timeout (10s): the pre-flight DNS resolution is not covered by the latter,
# so a client sized to 10s races the work it asked for and loses.
CLIENT_TIMEOUT = float(os.environ.get("EUREKA_CLIENT_TIMEOUT", "60"))
# Hermes spills mcp_* tool results over 50,000 chars to disk. Truncating here
# keeps a normal page inside the model's context and says so when it cuts.
DEFAULT_MAX_CHARS = int(os.environ.get("EUREKA_MAX_CHARS", "20000"))

# --- (c) every refusal this protocol can produce, in words -----------------
# Keyed by the reason strings the daemon actually returns. Anything missing
# falls back to the raw reason rather than a guess, so an unknown refusal is
# reported as itself instead of being flattened into "something went wrong".
OUTCOMES: Dict[str, str] = {
    # gate: who is asking
    "untrusted_key": (
        "The peer refused our identity: this node's key is not in its trust "
        "file. Nothing was run. Provisioning fix, not a retry."
    ),
    "revoked_key": "The peer has revoked this node's key. Nothing was run.",
    "capability_not_granted": (
        "Authenticated, but not permitted to run that capability. The peer "
        "folds 'not granted' and 'not offered here' into one answer, so this "
        "does not reveal whether the capability exists there."
    ),
    "replayed_nonce": (
        "That request's nonce was already spent. Every assign is single-use; "
        "this is replay protection working, and a fresh request will succeed."
    ),
    "stale_timestamp": (
        "The request was outside the peer's freshness window (30s). Usually a "
        "clock skew problem on this host -- check the system clock."
    ),
    "signature_verification_failed": "The peer could not verify our signature.",
    "tls_required": "The peer requires TLS and the connection was not.",
    "tls_identity_mismatch": (
        "The key that terminated TLS did not sign the handshake. Refused: "
        "that is the shape of a relay between two trusted peers."
    ),
    "malformed_response": "The peer's reply was not a usable protocol message.",
    # work: what happened when it ran
    "address_not_allowed": (
        "The peer refused to fetch that address. Its policy allows only "
        "globally routable unicast addresses -- loopback, private ranges, "
        "link-local, CGNAT and multicast are refused, checked after DNS "
        "resolution and again on every redirect. A hostname resolving into "
        "one of those ranges is refused too."
    ),
    "scheme_not_allowed": "Only http and https URLs can be fetched.",
    "body_too_large": "The page exceeded the peer's 1 MiB body cap and was refused.",
    "too_many_redirects": "The URL redirected more times than the peer allows.",
    "timeout": "The peer accepted the request but the fetch timed out.",
    "connection_failed": "The peer could not connect to that target.",
    "dns_resolution_failed": "The peer could not resolve that hostname.",
    "invalid_payload": "The request payload was not usable.",
    "capability_not_implemented": (
        "The peer has no handler registered for that capability. It should "
        "not advertise one it cannot run, so this suggests a misconfigured peer."
    ),
    "handler_error": "The peer's handler failed unexpectedly. Nothing usable came back.",
}


def _explain(reason: Optional[str]) -> str:
    if not reason:
        return "no reason given"
    return OUTCOMES.get(reason, f"unmapped outcome from the peer: {reason!r}")


def _fail(stage: str, reason: Optional[str], **extra: Any) -> str:
    """A refusal Hermes can read. Never a traceback, never a bare exception."""
    return json.dumps({
        "ok": False,
        "stage": stage,
        "reason": reason,
        "outcome": _explain(reason),
        **extra,
    }, ensure_ascii=False)


@contextlib.contextmanager
def _protocol_safe_stdout():
    """
    Keep Eureka's progress prints off the JSON-RPC stream.

    EurekaNode writes "[NODE ...] Challenge issued to ..." to stdout. On stdio
    transport that is the wire, so anything printed there is a protocol
    violation that presents as an unreachable server rather than as noise.
    """
    with contextlib.redirect_stdout(sys.stderr):
        yield


def _build_node() -> EurekaNode:
    """
    A client node: it advertises nothing and executes nothing.

    Passing an explicit (empty) capability list is what keeps it a client --
    called with neither a list nor a registry, with_persistent_identity builds
    the daemon's own executor and would advertise web-retrieval.
    """
    return EurekaNode.with_persistent_identity(capabilities=[])


async def _handshake(node: EurekaNode, http) -> Tuple[bool, Optional[str], Dict[str, Any]]:
    result = await client.handshake_over_http(node, http=http, require_tls=True)
    if result.get("authenticated") is not True:
        return False, result.get("reason"), result
    return True, None, result


server = MCPServer(
    name="eureka",
    version="1.0.0",
    instructions=(
        "Fetch web pages through a Eureka peer rather than directly. The peer "
        "performs the fetch under its own policy and signs the result; this "
        "server verifies that signature before returning anything. Refusals "
        "are normal outcomes and are reported with a reason, not an error."
    ),
)


@server.tool(
    name="eureka_fetch",
    description=(
        "Fetch a URL through the configured Eureka peer and return its content. "
        "The peer does the fetching, so its address policy applies: only "
        "publicly routable http/https addresses are allowed, and loopback, "
        "private, link-local and CGNAT targets are refused after DNS "
        "resolution. The result is signed by the peer and the signature is "
        "verified before the content is returned. Returns JSON with ok, "
        "http_status, content_type, content, and on refusal a reason and a "
        "readable outcome."
    ),
)
async def eureka_fetch(url: str, max_chars: int = DEFAULT_MAX_CHARS) -> str:
    try:
        with _protocol_safe_stdout():
            node = _build_node()
            async with tls.pinning_client(PEER_URL, CLIENT_TIMEOUT) as http:
                ok, reason, hs = await _handshake(node, http)
                if not ok:
                    return _fail("handshake", reason, peer=PEER_URL)

                query = assign.build_assign_query(
                    node, "web-retrieval", "hermes-fetch", {"url": url})
                response = await http.post("/v1/assign", json=query)
                answer = response.json()
                pin = tls.peer_key_from_response(response)

                if answer.get("reason") != GATE_OK:
                    return _fail("gate", answer.get("reason"), url=url)

                result = answer.get("result") or {}
                signature = answer.get("result_signature")

                # (e) Verify before the content is handed over. An unverified
                # result is a failure: without the signature this is just a
                # string from the network, and the whole point of the protocol
                # is that it is evidence.
                if not isinstance(signature, str) or not signature:
                    return _fail("verification", "missing_result_signature", url=url)
                if not pin:
                    return _fail("verification", "no_tls_pin", url=url)
                if not EurekaCrypto.verify_assign_result(pin, signature, result):
                    return _fail("verification", "result_signature_invalid", url=url)
                if result.get("nonce") != query["query"]["nonce"]:
                    # The signature is valid but over a different request.
                    return _fail("verification", "result_bound_to_another_request", url=url)

                if result.get("status") != "completed" or result.get("reason") != WORK_OK:
                    return _fail("fetch", result.get("reason"), url=url,
                                 verified=True)

                output = result.get("output") or {}
                body = output.get("body") or ""
                clipped = len(body) > max_chars
                return json.dumps({
                    "ok": True,
                    "verified": True,
                    "url": url,
                    "final_url": output.get("final_url"),
                    "http_status": output.get("http_status"),
                    "content_type": output.get("content_type"),
                    "bytes": output.get("bytes"),
                    "truncated_by_peer": output.get("truncated"),
                    "truncated_for_context": clipped,
                    "content": body[:max_chars],
                    "responder": result.get("responder_id"),
                }, ensure_ascii=False)
    except Exception as exc:
        # Last resort. A traceback must not reach Hermes, and must not reach
        # stdout at all.
        print(f"eureka-mcp: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        return _fail("transport", "client_error", detail=f"{type(exc).__name__}: {exc}")


@server.tool(
    name="eureka_peer_status",
    description=(
        "Check the Eureka peer: complete a mutual handshake and report whether "
        "this node is trusted by it. Use this to tell a provisioning problem "
        "(untrusted_key) from a permission problem (capability_not_granted)."
    ),
)
async def eureka_peer_status() -> str:
    try:
        with _protocol_safe_stdout():
            node = _build_node()
            async with tls.pinning_client(PEER_URL, CLIENT_TIMEOUT) as http:
                ok, reason, hs = await _handshake(node, http)
                if not ok:
                    return _fail("handshake", reason, peer=PEER_URL,
                                 this_node=node.node_id)
                return json.dumps({
                    "ok": True,
                    "peer": PEER_URL,
                    "peer_id": hs.get("peer_id"),
                    "this_node": node.node_id,
                    "mutual": hs.get("mutual", False),
                    "identity_path": str(resolve_identity_path()),
                    "trust_path": str(resolve_trust_path()),
                }, ensure_ascii=False)
    except Exception as exc:
        print(f"eureka-mcp: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        return _fail("transport", "client_error", detail=f"{type(exc).__name__}: {exc}")


if __name__ == "__main__":
    print(f"eureka-mcp: peer={PEER_URL} timeout={CLIENT_TIMEOUT}s "
          f"identity={resolve_identity_path()}", file=sys.stderr, flush=True)
    server.run("stdio")
