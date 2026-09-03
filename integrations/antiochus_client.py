#!/usr/bin/env python3
"""
antiochus_client.py -- issue a signed /v1/assign from CT 102 to a Eureka peer.

The Antiochus-side counterpart to eureka_mcp_server.py. That one exposes a
peer's capabilities to Hermes over MCP; this one is a plain CLI, so the node
can be exercised and proven before anything is wired into OpenClaw. The
protocol path is identical -- mutual handshake, signed assign, verified result
-- because the point of this script is to prove the node works, and a proof
that runs a different path than production proves the wrong thing.

Antiochus is a CLIENT node. It advertises nothing and executes nothing: it is
built with an empty capability list and no handler registry, so an assign that
somehow reached it would be refused rather than dispatched. Its trust file
therefore grants CT 101 nothing. Trusting a key and granting it a capability
are different acts, and only the first is needed to *call* a peer -- grants
govern what a peer may ask of us, and there is nothing here to ask for.

Identity and trust paths are REQUIRED and must already exist.

    Why this matters more than it looks. EurekaCrypto.load_or_create() mints a
    key when the file is missing, and EurekaNode's constructor falls back to
    TrustList.load_or_empty(), which turns a missing trust file into an empty
    allowlist. Both are right for a daemon's first boot and both are wrong
    here: a typo'd path would produce a node with a brand new identity that no
    peer trusts, trusting nobody, and every refusal downstream would be a lie
    about the grant. So this script uses EurekaCrypto.load() and
    TrustList.load(), which raise on a missing file, and injects the result.
    A wrong path fails here, in the shell, naming the path it could not read.

What is verified before any content is returned, in this order:

  1. The handshake authenticated, over TLS (require_tls=True), with the key
     that terminated TLS pinned against the trust file.
  2. The gate accepted the assign -- reason "authenticated", not a refusal.
  3. A result signature is present, and a TLS pin was captured to check it by.
  4. The signature verifies over the result in the assign-result domain.
  5. The nonce inside the signed result is the nonce we sent. A valid
     signature over somebody else's result is still not an answer to us.

Only then is the body read. Steps 3-5 are the difference between evidence and
a string off the network.

The positional argument is the capability's one input: a URL for
web-retrieval, a prompt for inference. Which capability is asked for decides
how the payload is built, how long the client waits, and what a successful
answer carries -- see CAPABILITY_TIMEOUTS and _payload_for.

Usage:
    export EUREKA_IDENTITY_PATH=/var/lib/eureka-antiochus/identity.key
    export EUREKA_TRUST_PATH=/var/lib/eureka-antiochus/trust.json
    ./antiochus_client.py https://example.com
    ./antiochus_client.py --peer https://192.168.1.180:8443 https://example.com
    ./antiochus_client.py --peer https://192.168.1.152:8443 \
        --capability inference "Say the single word: ping"

stdout is the JSON result and nothing else, so the caller can pipe it. All
progress and diagnostics go to stderr -- including EurekaNode's own prints,
which are redirected there rather than allowed to interleave with the payload.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, NoReturn


def _die(message: str) -> NoReturn:
    print(f"antiochus-client: FATAL: {message}", file=sys.stderr, flush=True)
    raise SystemExit(2)


def _find_package_root() -> Path:
    """
    The directory to put on sys.path so ``eureka_protocol`` imports.

    Walks up looking for the ancestor that *contains* the package rather than
    assuming a fixed depth, so this file works both inside the checkout and
    beside it. The marker is the daemon package itself, not a directory name,
    so a stray empty ``eureka_protocol/`` cannot capture the search.
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

from eureka_protocol.src.eureka_daemon import assign, client, tls  # noqa: E402
from eureka_protocol.src.eureka_daemon.crypto import EurekaCrypto, IdentityError  # noqa: E402
from eureka_protocol.src.eureka_daemon.handlers import REASON_OK as WORK_OK  # noqa: E402
from eureka_protocol.src.eureka_daemon.node import (  # noqa: E402
    EurekaNode,
    REASON_OK as GATE_OK,
)
from eureka_protocol.src.eureka_daemon.trust import TrustError, TrustList  # noqa: E402

DEFAULT_PEER = "https://192.168.1.180:8443"

# How long to wait, per capability. Each figure is sized against the
# responder's registry DEADLINE for that capability and not against the
# handler timeout inside it: web-retrieval's fetch gives up at 10s but runs
# under the registry default of 30s, and the peer's pre-flight DNS resolution
# is not covered by the fetch timeout, so a client sized to 10s races the work
# it asked for and loses.
#
# inference is the reason this stopped being one number. It runs under a 90s
# deadline with a 75s handler timeout, so the web-retrieval figure would have
# this client give up at 60s on a request the peer is still honestly working
# on -- and from the shell a client-side timeout is indistinguishable from a
# peer that refused. That is the wrong thing to learn on the run that is
# supposed to prove a grant.
CAPABILITY_TIMEOUTS = {
    "web-retrieval": 60.0,
    "inference": 120.0,
}


def _required_path(flag_value: str | None, env_var: str, label: str) -> Path:
    """An explicit path that must already exist. No default, no fallback."""
    raw = (flag_value or os.environ.get(env_var) or "").strip()
    if not raw:
        _die(
            f"no {label} path. Pass it explicitly or set {env_var}. "
            "Refusing to fall back to a default: the loaders create an "
            "identity and treat a missing trust file as an empty allowlist, "
            "so a default here comes up as a node no peer trusts."
        )
    path = Path(raw).expanduser()
    if not path.exists():
        _die(f"no {label} at {path} -- it must exist; this script will not create one")
    return path


def build_node(identity_path: Path, trust_path: Path) -> EurekaNode:
    """
    A client node on explicitly loaded material.

    load() rather than load_or_create()/load_or_empty(): both failure modes
    they paper over are silent here, and a silent one is the whole problem.
    The trust list is passed alongside its path, so reload_trust() still knows
    where to read from rather than treating the list as injected.
    """
    try:
        crypto = EurekaCrypto.load(identity_path)
    except IdentityError as exc:
        _die(f"identity: {exc}")
    try:
        # advertised=[] -- this node offers nothing, so any grant written into
        # its trust file names a capability it cannot honour, and that is a
        # load error rather than a line that sits there looking effective.
        trust_list = TrustList.load(trust_path, advertised=[])
    except TrustError as exc:
        _die(f"trust list: {exc}")

    return EurekaNode(
        node_id=None,                 # name me after my key
        crypto_engine=crypto,
        capabilities=[],              # client: advertises nothing
        handlers=None,                # client: executes nothing
        trust_list=trust_list,
        trust_path=str(trust_path),
    )


def _payload_for(capability: str, subject: str) -> Dict[str, Any]:
    """
    The one value each capability's handler reads out of the payload.

    A table rather than a branch at the call site, because the failure to
    avoid is a client that sends {"url": ...} to a handler that wanted a
    prompt: the peer answers invalid_payload, which is a refusal about the
    REQUEST, and on the run that is meant to prove a grant it reads like a
    refusal about the grant.
    """
    if capability == "inference":
        return {"prompt": subject}
    return {"url": subject}


def _context(capability: str, subject: str) -> Dict[str, Any]:
    """
    What a refusal says about the request it refused.

    The prompt is deliberately not in here. The responder keeps prompts out of
    its audit log on purpose; this stdout gets piped into logs too, and there
    is no reason for the client to be the leak the daemon refused to be. The
    caller knows what it sent -- a character count is enough to tell a prompt
    that was too long from one that was empty.
    """
    described = {"capability": capability}
    if capability == "inference":
        described["prompt_chars"] = len(subject)
    else:
        described["url"] = subject
    return described


def _describe(capability: str, subject: str,
              output: Dict[str, Any]) -> Dict[str, Any]:
    """The capability-specific half of a successful answer."""
    if capability == "inference":
        # truncated and done_reason are two different ways of being cut short
        # -- the responder's character cap and its token budget -- and a
        # completion can hit either without hitting the other. A caller that
        # reads only one of them treats a clipped answer as a whole one.
        return {
            "prompt_chars": len(subject),
            "model": output.get("model"),
            "completion": output.get("completion"),
            "chars": output.get("chars"),
            "truncated": output.get("truncated"),
            "done_reason": output.get("done_reason"),
            "eval_count": output.get("eval_count"),
        }
    body = output.get("body") or ""
    return {
        "url": subject,
        "final_url": output.get("final_url"),
        "http_status": output.get("http_status"),
        "content_type": output.get("content_type"),
        "bytes": output.get("bytes"),
        "body_preview": body[:500],
    }


def _fail(stage: str, reason: str | None, **extra: Any) -> Dict[str, Any]:
    return {"ok": False, "stage": stage, "reason": reason, **extra}


async def run(node: EurekaNode, peer: str, subject: str, capability: str,
              task_name: str, timeout: float) -> Dict[str, Any]:
    context = _context(capability, subject)
    async with tls.pinning_client(peer, timeout) as http:
        handshake = await client.handshake_over_http(node, http=http, require_tls=True)
        if handshake.get("authenticated") is not True:
            return _fail("handshake", handshake.get("reason"), peer=peer)

        query = assign.build_assign_query(node, capability, task_name,
                                          _payload_for(capability, subject))
        response = await http.post("/v1/assign", json=query)
        answer = response.json()
        # Read the pin from the response the answer actually arrived on.
        pin = tls.peer_key_from_response(response)

        if answer.get("reason") != GATE_OK:
            return _fail("gate", answer.get("reason"), **context)

        result = answer.get("result") or {}
        signature = answer.get("result_signature")

        if not isinstance(signature, str) or not signature:
            return _fail("verification", "missing_result_signature", **context)
        if not pin:
            return _fail("verification", "no_tls_pin", **context)
        if not EurekaCrypto.verify_assign_result(pin, signature, result):
            return _fail("verification", "result_signature_invalid", **context)
        if result.get("nonce") != query["query"]["nonce"]:
            # A good signature over a different request is not our answer.
            return _fail("verification", "result_bound_to_another_request",
                         **context)

        if result.get("status") != "completed" or result.get("reason") != WORK_OK:
            # "work", not "fetch": the stage is named for the half of the
            # protocol it failed in, and that half is no longer always a fetch.
            return _fail("work", result.get("reason"), verified=True, **context)

        return {
            "ok": True,
            "verified": True,
            "capability": capability,
            "responder_id": answer.get("responder_id"),
            "pinned_key": pin,
            **_describe(capability, subject, output=result.get("output") or {}),
        }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Issue a signed /v1/assign from Antiochus to a Eureka peer.")
    parser.add_argument("subject",
                        help="the capability's input: the URL to have the peer "
                             "fetch, or with --capability inference the prompt "
                             "to have it run")
    parser.add_argument("--peer", default=os.environ.get("EUREKA_PEER", DEFAULT_PEER))
    parser.add_argument("--identity", default=None,
                        help="identity file (or $EUREKA_IDENTITY_PATH)")
    parser.add_argument("--trust", default=None,
                        help="trust file (or $EUREKA_TRUST_PATH)")
    # choices, not a free string: an unknown capability would otherwise be
    # sent with a web-retrieval payload and come back capability_not_granted,
    # which names the grant for what is actually a typo on this side.
    parser.add_argument("--capability", default="web-retrieval",
                        choices=sorted(CAPABILITY_TIMEOUTS))
    # Names the ENTRY POINT, not the host -- the host is already named by the
    # signing key in every log line. CT 102 reaches CT 101 two ways, and while
    # both wrote "antiochus-fetch" the peer's audit log could not tell a
    # hand-run script from a Telegram message, which left "which path was
    # that?" answerable only by whoever remembered what they had run.
    parser.add_argument("--task-name", default="antiochus-cli")
    parser.add_argument("--timeout", type=float, default=None,
                        help="seconds; defaults to the figure for the chosen "
                             "capability -- see CAPABILITY_TIMEOUTS")
    args = parser.parse_args()
    timeout = (args.timeout if args.timeout is not None
               else CAPABILITY_TIMEOUTS[args.capability])

    identity_path = _required_path(args.identity, "EUREKA_IDENTITY_PATH", "identity")
    trust_path = _required_path(args.trust, "EUREKA_TRUST_PATH", "trust list")

    # EurekaNode prints progress to stdout; stdout here is the JSON payload.
    with contextlib.redirect_stdout(sys.stderr):
        node = build_node(identity_path, trust_path)
        print(f"antiochus-client: node {node.node_id} "
              f"({node.public_key_hex[:16]}...) -> {args.peer} "
              f"[{args.capability}, {timeout:g}s]", file=sys.stderr)
        outcome = asyncio.run(run(node, args.peer, args.subject, args.capability,
                                  args.task_name, timeout))

    json.dump(outcome, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0 if outcome.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
