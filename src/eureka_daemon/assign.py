"""
The assign endpoint's gate: who may ask this node to run something.

The gate was built before the executor, and that order was the point: an
execution endpoint that grows authentication later starts life as the hole in
the fence, and this one was exactly that -- an open POST that anything
reaching the port could call. Behind it now is a real handler registry rather
than a stub, so a granted peer's request is dispatched to code that does the
work. Nothing about the gate changed to allow that; what changed is what is on
the other side of it.

Reads share a gate with discovery; assign shares it too, plus two things a
read does not need:

  1. **Authorization after authentication.** Knowing who the caller is says
     nothing about what it may run. The request names a capability, and
     EurekaNode.is_permitted -- default deny, both gates: the grant must be
     held AND the capability actually offered -- decides. This is that
     function's first caller on a request path; until now it guarded nothing
     because there was nothing to guard.
  2. **Single-use requests.** A read discloses state that exists anyway, so
     replaying one inside the freshness window buys an attacker nothing new.
     Replaying an assign would run the task again. So every request carries a
     nonce, spent on arrival: within the freshness window the nonce table
     refuses the replay, and past it the timestamp is stale -- the same
     two-layer scheme the handshake uses, in a separate table so an assign
     can never spend a handshake nonce.

What a refusal discloses: the decision, nothing else. The rejection is built
from the reason alone -- no capability list, no echo of what was asked, no
hint whether the named capability exists here at all. is_permitted already
folds "not offered" and "not granted" into one False, so the refusal cannot be
used to enumerate what this node advertises.

What the answer carries: the result, and a signature over it in the
assign-result domain. The signature is the responder saying "this is what I
did", in a domain nothing else in the protocol can mint -- so a peer keeps
evidence of the answer rather than a string it has to take on trust, and a
result cannot be lifted onto a different request because the nonce it was
signed over belongs to the first one.

A refusal is deliberately NOT signed. It is a constant built from the reason
alone -- identical for every caller and every question -- so a signature over
it would attest to nothing the refused caller could not compute for itself,
while making refusals distinguishable by their signature is exactly the side
channel the constant exists to close.

The protocol-level `reason` stays "authenticated" whenever the request was
accepted and run. Whether the *work* succeeded lives in the result, under its
own status and reason: a fetch that times out is a request this node accepted,
ran, and could not complete, and collapsing that into a gate refusal would
tell the caller its grant had been taken away.

What the audit log records: every decision about an authenticated caller,
attributed to it -- granted requests through the dispatch's own log entry,
refused ones here with status "refused" and the reason that refused them. "We
said no to X" is part of the record of what this node did about X, and X can
read its own refusals back through /v1/logs. Unauthenticated noise is not logged: an unverified requester_id is a
claim, and attributing log entries to claims would let anyone write history
under anyone's name.
"""
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .crypto import EurekaCrypto
from .node import EurekaNode, REASON_OK, REASON_REPLAYED_NONCE
from . import signed_request
from .signed_request import BASE_QUERY_KEYS, PROTOCOL

ASSIGN_EVENT = "assign_query"
ANSWER_EVENT = "assign_answer"
REJECTED_EVENT = "assign_rejected"

# The distinct refusal for an authenticated peer without the grant. Says the
# decision and no more: not whether the capability exists here, not what the
# caller should have asked for instead.
REASON_NOT_PERMITTED = "capability_not_granted"

ASSIGN_QUERY_KEYS = BASE_QUERY_KEYS | {"nonce", "capability", "task_name", "payload"}

# A nonce is 32 hex chars from token_hex(16); anything wildly longer is not a
# nonce, it is someone using the field as storage.
MAX_NONCE_LENGTH = 128
MAX_TASK_NAME_LENGTH = 256
MAX_CAPABILITY_LENGTH = 256


def rejected(reason: str) -> Dict[str, Any]:
    """
    A refusal, carrying an empty result.

    Built from the reason alone. Nothing from the request is echoed and
    nothing of the node's state is consulted, so the refusal is identical
    whatever was asked for and whatever this node offers.
    """
    return {"event": REJECTED_EVENT, "reason": reason, "result": {}}


def build_assign_query(node: EurekaNode, capability: str, task_name: str,
                       payload: Optional[Dict[str, Any]] = None,
                       now: Optional[datetime] = None,
                       nonce: Optional[str] = None) -> Dict[str, Any]:
    """A signed, single-use request for a peer to run one task."""
    query = {
        "protocol": PROTOCOL,
        "event": ASSIGN_EVENT,
        "requester_id": node.node_id,
        "timestamp": (now or datetime.now(timezone.utc)).isoformat(),
        "nonce": nonce if nonce is not None else secrets.token_hex(16),
        "capability": capability,
        "task_name": task_name,
        "payload": payload if payload is not None else {},
    }
    return signed_request.build_envelope(node, query, node.crypto.sign_assign_query)


def _body_is_valid(query: dict) -> bool:
    nonce = query.get("nonce")
    capability = query.get("capability")
    task_name = query.get("task_name")
    return (isinstance(nonce, str) and 0 < len(nonce) <= MAX_NONCE_LENGTH
            and isinstance(capability, str)
            and 0 < len(capability.strip()) <= MAX_CAPABILITY_LENGTH
            and isinstance(task_name, str)
            and 0 < len(task_name.strip()) <= MAX_TASK_NAME_LENGTH
            and isinstance(query.get("payload"), dict))


async def answer_assign(node: EurekaNode, document: Any,
                        now: Optional[datetime] = None) -> Dict[str, Any]:
    """
    Decide one assign request: authenticate, then check replay, then
    authorize, then -- and only then -- dispatch.

    The order is the design. Replay is checked before authorization so a
    captured request cannot be resubmitted to probe whether a grant has since
    appeared; authorization is checked before dispatch so no handler is ever
    reached by a caller that may not run anything; and the nonce is spent on
    the first authenticated sighting, whatever the verdict, so a refused
    request cannot be replayed either.

    Dispatch is awaited, not fired and forgotten: the answer carries the
    result, so the request is open for as long as the work takes. It does not
    block anything else -- the handler is async and the registry caps how many
    run at once -- but it does mean a slow fetch is a slow response, which is
    the honest shape for a call whose whole purpose is to return what it got.
    """
    reason, _public_key, peer_id = signed_request.verify(
        node, document,
        event=ASSIGN_EVENT,
        verify_signature=EurekaCrypto.verify_assign_query,
        required_keys=ASSIGN_QUERY_KEYS,
        validate_body=_body_is_valid,
        now=now,
    )
    if reason is not None:
        # Not authenticated: refused without an audit entry. The requester_id
        # in an unverified document is a claim, and writing it into the log
        # would let anyone put entries under anyone's name.
        return rejected(reason)

    query = document["query"]
    nonce = query["nonce"]
    task_name = query["task_name"].strip()
    capability = query["capability"].strip()

    # Spend the nonce. prune_expired keeps the table bounded and aged; the
    # freshness check in the gate already refused anything old enough to have
    # been pruned, so expiry cannot re-open a replay.
    node.prune_expired(now)
    if nonce in node.seen_assign_nonces:
        await node.log_event({"task_name": task_name},
                             {"status": "refused",
                              "reason": REASON_REPLAYED_NONCE},
                             peer=peer_id, capability=capability)
        return rejected(REASON_REPLAYED_NONCE)
    node.seen_assign_nonces[nonce] = now or datetime.now(timezone.utc)
    # Enforce the cap after inserting, so the table never sits above it even
    # transiently -- prune_expired ran before the insert, not after.
    EurekaNode._evict_oldest(node.seen_assign_nonces, node.max_seen_nonces)

    # Authorization. Both of is_permitted's gates must pass: the peer's key
    # holds the grant in the live trust list, and this node actually offers
    # the capability. One False for every way to fail, which is what keeps
    # the refusal from disclosing the inventory.
    if not node.is_permitted(peer_id, capability):
        await node.log_event({"task_name": task_name},
                             {"status": "refused",
                              "reason": REASON_NOT_PERMITTED},
                             peer=peer_id, capability=capability)
        return rejected(REASON_NOT_PERMITTED)

    # Dispatch. The nonce travels into the result so the signature below binds
    # the answer to this one request and no other.
    result = await node.assign(
        {"task_name": task_name, "payload": query["payload"]},
        peer=peer_id, capability=capability, nonce=nonce,
    )
    return {
        "event": ANSWER_EVENT,
        "responder_id": node.node_id,
        "reason": REASON_OK,
        "result": result,
        "result_signature": node.crypto.sign_assign_result(result),
    }
