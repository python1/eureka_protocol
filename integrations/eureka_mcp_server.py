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

One peer per capability, and no fallback between them. This file was written
when the mesh had one peer and one capability. `inference` is served by a
different host than `web-retrieval`, so the peer is now chosen per tool, each
from its own variable: $EUREKA_PEER serves web-retrieval, $EUREKA_INFERENCE_PEER
serves inference, and an unset one is a refusal that names the variable.

    Never a quiet retarget at the other host. Asking a node for a capability
    it does not offer returns `capability_not_granted` -- the same sentence a
    missing grant produces, because the peer deliberately folds "not granted"
    and "not offered here" into one answer. A fallback would therefore turn an
    unset variable on THIS host into what reads like a provisioning fault on a
    peer, and send an operator to fix a grant on the wrong machine.
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

from eureka_protocol.src.eureka_daemon import assign, client, reads, tls  # noqa: E402
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

# --- (c) one peer per capability, and no fallback between them -------------
# web-retrieval's peer, keeping the default it has always had: both deployed
# hosts fetch from CT 101, and changing it would retarget them on the day they
# picked up a new commit.
PEER_URL = (os.environ.get("EUREKA_PEER") or "https://192.168.1.180:8443").strip()
# inference's peer, deliberately WITHOUT a default. No address is right for
# every host -- WSL serves inference itself and CT 101 has no Ollama at all --
# and the only default available here is PEER_URL, which is the one answer
# that must not be given: see the module docstring on why falling back turns a
# local misconfiguration into what reads as a missing grant on a peer. Unset
# is a refusal from eureka_inference naming this variable, and nothing else in
# this file is affected by it -- eureka_fetch on a host that never runs
# inference must not be taken down by an env block that does not mention it.
INFERENCE_PEER_URL = (os.environ.get("EUREKA_INFERENCE_PEER") or "").strip()

# --- (d) the timeout ladder, longest at the top ----------------------------
# Each figure must outlast the one below it, or the layer that knows least
# about the work is the one that gives up first and the honest answer from the
# layer that knows most never gets a chance to travel.
#
#   OpenClaw's per-server `timeout`   150s   config, not code -- see DEPLOYMENT
#   EUREKA_INFERENCE_TIMEOUT          120s   this client, for inference
#   INFERENCE_DEADLINE_SECONDS         90s   the peer's registry deadline
#   INFERENCE_TIMEOUT_SECONDS          75s   the peer's Ollama exchange
#
# Read bottom-up. 90 > 75 is the responder's own rule (handlers.py): the
# handler must lose first, or every slow inference comes back as the
# registry's generic `timeout` and prompt_too_long, upstream_unavailable and
# model_not_available become unreachable. 120 > 90 extends that rule across
# the wire: the peer's deadline is a *signed, verified* answer that says which
# refusal it was, whereas a client-side timeout is an exception on this side
# and is indistinguishable from a peer that refused. The 30s of headroom is
# for what the deadline does not cover -- TLS, the three-message handshake and
# the response body -- all of which happen outside the 90s the peer is
# counting. And 150 > 120 leaves OpenClaw's ceiling above the longest wait
# this file will ever choose, so a request cut off at that layer means
# something is genuinely wedged rather than merely slow.
CLIENT_TIMEOUT = float(os.environ.get("EUREKA_CLIENT_TIMEOUT", "60"))
# web-retrieval's 60s is unchanged and stays sized against ITS deadline (30s):
# the two capabilities run under different deadlines on the responder, so one
# number for both would be wrong at one end or the other.
INFERENCE_TIMEOUT = float(os.environ.get("EUREKA_INFERENCE_TIMEOUT", "120"))
# Hermes spills mcp_* tool results over 50,000 chars to disk. Truncating here
# keeps a normal page inside the model's context and says so when it cuts.
DEFAULT_MAX_CHARS = int(os.environ.get("EUREKA_MAX_CHARS", "20000"))
# What the peer records this host as having asked for. It lands in the
# responder's audit log verbatim, so it is the name a future reader uses to
# work out WHO ran a task -- which makes a wrong one worse than none at all.
# It was hardcoded "hermes-fetch" while WSL was the only caller; CT 102 now
# runs this same file, and its fetches were being filed under Hermes's name.
# The default stays "hermes-fetch" so the host that predates this variable
# keeps writing exactly what it always wrote, and does not silently change
# identity in the log the day it picks up a new commit.
TASK_NAME = (os.environ.get("EUREKA_TASK_NAME") or "hermes-fetch").strip()
# The same field for inference, and a separate variable rather than a reuse of
# TASK_NAME. Both deployed values of that one end in "-fetch", so an inference
# request would be filed in the peer's audit log under a name that says it was
# a fetch -- and this repo's own rule is that a log which misattributes work is
# worse than one that says nothing. The default has no legacy to protect the
# way "hermes-fetch" does, because no host has ever sent an inference request
# through this file, so it can simply be accurate. It names the ENTRY POINT and
# not the host: the host is already named, in every log line, by the key that
# signed the request.
INFERENCE_TASK_NAME = (
    os.environ.get("EUREKA_INFERENCE_TASK_NAME") or "mcp-inference").strip()

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
    "timeout": (
        "The peer accepted the request and the work timed out on its side. "
        "This is the peer's own deadline, signed and verified, not this "
        "client giving up -- so the request really did run there and really "
        "did not finish."
    ),
    "connection_failed": "The peer could not connect to that target.",
    "dns_resolution_failed": "The peer could not resolve that hostname.",
    "invalid_payload": "The request payload was not usable.",
    "capability_not_implemented": (
        "The peer has no handler registered for that capability. It should "
        "not advertise one it cannot run, so this suggests a misconfigured peer."
    ),
    "handler_error": "The peer's handler failed unexpectedly. Nothing usable came back.",
    # work: inference. Four outcomes rather than one, because an operator acts
    # differently on each and only one of them is fixed by trying again.
    "prompt_too_long": (
        "The prompt was longer than the peer's character cap and was refused "
        "before the model saw it. Nothing ran. This is the one inference "
        "refusal a caller can fix: send a shorter prompt. The cap is the "
        "peer's and is not disclosed here, and neither is the prompt."
    ),
    "upstream_unavailable": (
        "The peer authenticated us and its local model server is not "
        "answering. The capability is granted; the thing behind it is down. "
        "An operator on that host has to start it -- retrying will not."
    ),
    "model_not_available": (
        "The peer's model server is running and does not hold the model it is "
        "configured to use. An operator on that host has to pull it. Not a "
        "grant problem and not something a different prompt fixes."
    ),
    "upstream_error": (
        "The peer's model server answered and the answer was not usable. The "
        "detail is that host's view of its own machine and does not travel."
    ),
    # local: refusals this server produces before anything is sent
    "inference_peer_not_configured": (
        "This server has no inference peer: EUREKA_INFERENCE_PEER is unset in "
        "its env. Nothing was sent. It will not fall back to the "
        "web-retrieval peer, which does not serve inference and would answer "
        "capability_not_granted -- the same words a missing grant produces, "
        "which would send somebody to fix a grant on the wrong machine. "
        "Configuration fix on this host."
    ),
    "unknown_capability": (
        "This server routes only web-retrieval and inference, and was asked "
        "about neither. Nothing was sent. The known names are in `known`."
    ),
    "empty_prompt": (
        "The prompt was empty or only whitespace. Nothing was sent: the peer "
        "would refuse it as invalid_payload, which is a vaguer answer to the "
        "same question, and a nonce would have been spent asking it."
    ),
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


async def _assign_verified(
    *, peer: str, timeout: float, capability: str, task_name: str,
    payload: Dict[str, Any], work_stage: str, context: Dict[str, Any],
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    The whole protocol path -- handshake, signed assign, verified result --
    once, for every tool. Returns (result, None) or (None, refusal_json).

    Extracted when the second capability arrived, and the reason is the block
    below the gate check rather than the boilerplate above it. Steps 3 to 5 of
    the verification -- a signature is present, it verifies against the key
    that terminated TLS, and the nonce inside it is the one we sent -- are what
    make the answer evidence instead of a string off the network. A copy of
    that per tool is a copy that can be fixed in one place and not the other,
    and the failure mode of the stale copy is a tool that returns unverified
    content while looking exactly like the tool that does not.

    `context` is what a refusal is allowed to say about the request it refused,
    and it is the caller's choice because the two tools differ on precisely
    this point: a URL is safe to repeat back and a prompt is not.

    `work_stage` names the half of the protocol a failure happened in, and is
    the caller's for one narrow reason: eureka_fetch has always said "fetch"
    there and something reading its output should not have to learn a new word
    because a second tool was added beside it.
    """
    node = _build_node()
    async with tls.pinning_client(peer, timeout) as http:
        ok, reason, _handshake_result = await _handshake(node, http)
        if not ok:
            return None, _fail("handshake", reason, peer=peer)

        query = assign.build_assign_query(node, capability, task_name, payload)
        response = await http.post("/v1/assign", json=query)
        answer = response.json()
        # The pin is read from the response the answer actually arrived on.
        pin = tls.peer_key_from_response(response)

        if answer.get("reason") != GATE_OK:
            return None, _fail("gate", answer.get("reason"), **context)

        result = answer.get("result") or {}
        signature = answer.get("result_signature")

        # (e) Verify before anything is handed over. An unverified result is a
        # failure: without the signature this is just a string from the
        # network, and the whole point of the protocol is that it is evidence.
        if not isinstance(signature, str) or not signature:
            return None, _fail("verification", "missing_result_signature", **context)
        if not pin:
            return None, _fail("verification", "no_tls_pin", **context)
        if not EurekaCrypto.verify_assign_result(pin, signature, result):
            return None, _fail("verification", "result_signature_invalid", **context)
        if result.get("nonce") != query["query"]["nonce"]:
            # The signature is valid but over a different request.
            return None, _fail("verification", "result_bound_to_another_request",
                               **context)

        if result.get("status") != "completed" or result.get("reason") != WORK_OK:
            return None, _fail(work_stage, result.get("reason"), **context,
                               verified=True)

        return result, None


def _cut_short(truncated: Any, done_reason: Any) -> Optional[str]:
    """
    Whether a completion is a whole answer, in a sentence, or None if it is.

    `truncated` and `done_reason` are two independent ways of being cut off --
    the peer's character cap and its token budget -- and a completion can hit
    either without hitting the other. Both are passed through raw as well,
    because they are the peer's facts and this is only a reading of them.

    It exists because the failure it prevents is silent. A four-character
    completion that ran out of tokens is character-for-character
    indistinguishable from a four-character completion that finished, and a
    consumer that sees a short string and no visible warning has no reason to
    doubt it. `done_reason: "length"` is the only evidence, and it is a field
    on an object rather than anything about the text.
    """
    cuts = []
    if truncated is True:
        cuts.append("the peer's character cap truncated it")
    if done_reason == "length":
        cuts.append("the token budget ended it (done_reason 'length')")
    if not cuts:
        return None
    return ("This completion was cut short and is not the model's finished "
            "answer: " + ", and ".join(cuts) + ".")


server = MCPServer(
    name="eureka",
    version="1.0.0",
    instructions=(
        "Reach another machine's capabilities through the Eureka protocol: "
        "fetch a web page, or run a prompt on a peer that serves inference. "
        "The peer does the work under its own policy and signs the result; "
        "this server verifies that signature before returning anything. Each "
        "capability has its own peer, configured separately, because they are "
        "not served by the same host. Refusals are normal outcomes and are "
        "reported with a reason and a readable outcome, not an error -- read "
        "the outcome before deciding whether anything is worth retrying."
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
            result, refusal = await _assign_verified(
                peer=PEER_URL, timeout=CLIENT_TIMEOUT,
                capability="web-retrieval", task_name=TASK_NAME,
                payload={"url": url}, work_stage="fetch",
                context={"url": url},
            )
            if refusal is not None:
                return refusal

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
    name="eureka_inference",
    description=(
        "Run a prompt on the Eureka peer that serves inference and return the "
        "completion. This is a different machine than eureka_fetch reaches: "
        "inference and web-retrieval are served by different peers and "
        "configured separately, so a refusal from one says nothing about the "
        "other. The peer chooses the model, the token budget and the sampling "
        "options; the only thing sent is the text. The prompt is not echoed "
        "back, not written to this server's log, and not recorded in the "
        "peer's audit log -- only its length. The result is signed by the peer "
        "and the signature is verified before the completion is returned. "
        "Returns JSON with ok, completion, model, chars, truncated, "
        "done_reason and eval_count, and on refusal a reason and a readable "
        "outcome. ALWAYS read done_reason and truncated before using the "
        "completion: done_reason 'length' means the token budget ended the "
        "answer mid-thought rather than the model finishing, which a short "
        "completion does not otherwise show. cut_short says so in words when "
        "either applies."
    ),
)
async def eureka_inference(prompt: str) -> str:
    # prompt_chars, never the prompt. It is the whole of what this tool is
    # allowed to say about its input, in a refusal, in a result and on stderr,
    # and it is enough to tell an empty prompt from a long one -- which is the
    # only question the length was ever asked to answer. The responder keeps
    # prompts out of its audit log deliberately; there is no reason for the
    # caller to be the leak the daemon refused to be.
    prompt_chars = len(prompt)
    try:
        if not INFERENCE_PEER_URL:
            # Before anything else, and loudly. No peer means no request, not
            # a request to the other peer.
            return _fail("config", "inference_peer_not_configured",
                         prompt_chars=prompt_chars)
        if not prompt.strip():
            # The one thing checked locally. An empty prompt is refused by the
            # peer as invalid_payload, which is a real answer to a vaguer
            # question, and asking it spends a nonce and a round trip.
            #
            # The LENGTH cap is deliberately NOT checked here. MAX_PROMPT_CHARS
            # is the peer's number, it belongs to the host that runs the model,
            # and a copy of it in this file is a second number that can drift
            # from the first -- refusing prompts a peer would have accepted, or
            # forwarding ones it will not. prompt_too_long is the peer's to
            # say, and this server's job is to make it readable when it does.
            return _fail("request", "empty_prompt", prompt_chars=prompt_chars)

        with _protocol_safe_stdout():
            result, refusal = await _assign_verified(
                peer=INFERENCE_PEER_URL, timeout=INFERENCE_TIMEOUT,
                capability="inference", task_name=INFERENCE_TASK_NAME,
                payload={"prompt": prompt}, work_stage="work",
                context={"prompt_chars": prompt_chars},
            )
            if refusal is not None:
                return refusal

            output = result.get("output") or {}
            truncated = output.get("truncated")
            done_reason = output.get("done_reason")
            completion = output.get("completion")
            # The completion is not clipped here the way a fetched body is.
            # The peer already caps it at its own character limit and signs
            # the flag that says whether it did, which lands well inside any
            # consumer's context; a second cap on this side would add a third
            # way for the same answer to be short and would be the only one of
            # the three that nothing signed.
            return json.dumps({
                "ok": True,
                "verified": True,
                "prompt_chars": prompt_chars,
                "model": output.get("model"),
                "completion": completion if isinstance(completion, str) else "",
                "chars": output.get("chars"),
                "truncated": truncated,
                "done_reason": done_reason,
                "cut_short": _cut_short(truncated, done_reason),
                "eval_count": output.get("eval_count"),
                "responder": result.get("responder_id"),
                "peer": INFERENCE_PEER_URL,
            }, ensure_ascii=False)
    except Exception as exc:
        # The exception text is printed locally and does not travel, on this
        # tool for one reason more than the others: an httpx error can carry
        # the request it failed on, and the request holds the prompt.
        print(f"eureka-mcp: {type(exc).__name__} on inference "
              f"({prompt_chars} prompt chars)", file=sys.stderr, flush=True)
        return _fail("transport", "client_error",
                     detail=type(exc).__name__, prompt_chars=prompt_chars)


@server.tool(
    name="eureka_peer_status",
    description=(
        "Check a Eureka peer: complete a mutual handshake, report whether this "
        "node is trusted by it, and list the capabilities the peer advertises. "
        "Use this to tell a provisioning problem (untrusted_key) from a "
        "permission problem (capability_not_granted). The capability argument "
        "selects WHICH peer to check, because web-retrieval and inference are "
        "served by different hosts -- 'web-retrieval' is the default and is "
        "the peer eureka_fetch uses; 'inference' is the peer eureka_inference "
        "uses. NOTE: the advertised list is what the peer offers to "
        "authenticated callers, NOT proof that this node may run any of it -- "
        "grants are held on the peer and only an actual request reveals them."
    ),
)
async def eureka_peer_status(capability: str = "web-retrieval") -> str:
    # The argument names a capability rather than a URL. The peer to check is
    # then a configured value, not a caller-supplied address: a status tool
    # that took a host would let a model point this node's handshake at
    # anything it could name, which is the shape web-retrieval's address policy
    # exists to refuse one layer down. The default is web-retrieval, so a call
    # with no argument checks exactly what it always checked.
    peers = {"web-retrieval": PEER_URL, "inference": INFERENCE_PEER_URL}
    if capability not in peers:
        return _fail("request", "unknown_capability", capability=capability,
                     known=sorted(peers))
    peer_url = peers[capability]
    if not peer_url:
        return _fail("config", "inference_peer_not_configured",
                     capability=capability)
    try:
        with _protocol_safe_stdout():
            node = _build_node()
            async with tls.pinning_client(peer_url, CLIENT_TIMEOUT) as http:
                ok, reason, hs = await _handshake(node, http)
                if not ok:
                    return _fail("handshake", reason, peer=peer_url,
                                 this_node=node.node_id)

                # The capability list is a real disclosure, so it rides the
                # authenticated POST rather than the open GET. Its failure is
                # reported without failing the status call: the handshake is
                # the fact being established here, and it already succeeded.
                advertised: Optional[list] = None
                manifest_reason: Optional[str] = None
                answer = (await http.post(
                    "/v1/manifest",
                    json=reads.build_read_query(node, reads.MANIFEST_EVENT),
                )).json()
                if answer.get("reason") == GATE_OK:
                    manifest = answer.get("manifest") or {}
                    got = manifest.get("capabilities")
                    advertised = list(got) if isinstance(got, list) else None
                else:
                    manifest_reason = answer.get("reason")

                return json.dumps({
                    "ok": True,
                    "for_capability": capability,
                    "peer": peer_url,
                    "peer_id": hs.get("peer_id"),
                    "this_node": node.node_id,
                    "mutual": hs.get("mutual", False),
                    # What the peer OFFERS. Not what this node is permitted to
                    # run: is_permitted intersects this with a grant held on
                    # the peer, and the refusal for "not granted" and "not
                    # offered" is deliberately the same, so the two cannot be
                    # told apart from here.
                    "peer_advertises": advertised,
                    "advertised_read_failed": manifest_reason,
                    "note": (
                        "peer_advertises is the peer's offered list, not a "
                        "grant. Only an assign shows whether this node may "
                        "run one of them."
                    ),
                    "identity_path": str(resolve_identity_path()),
                    "trust_path": str(resolve_trust_path()),
                }, ensure_ascii=False)
    except Exception as exc:
        print(f"eureka-mcp: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        return _fail("transport", "client_error", detail=f"{type(exc).__name__}: {exc}")


if __name__ == "__main__":
    print(f"eureka-mcp: peer={PEER_URL} timeout={CLIENT_TIMEOUT}s "
          f"task={TASK_NAME} identity={resolve_identity_path()}",
          file=sys.stderr, flush=True)
    # Said at startup as well as at call time. eureka_inference refuses with a
    # reason that names the variable, but only once something asks it; this
    # line is in the log before anybody does, which is where an operator looks
    # after wiring the env block and wondering whether it took.
    print("eureka-mcp: inference_peer="
          + (f"{INFERENCE_PEER_URL} timeout={INFERENCE_TIMEOUT}s "
             f"task={INFERENCE_TASK_NAME}" if INFERENCE_PEER_URL else
             "(unset -- EUREKA_INFERENCE_PEER is not in this server's env, so "
             "eureka_inference will refuse every call; eureka_fetch is "
             "unaffected)"),
          file=sys.stderr, flush=True)
    server.run("stdio")
