"""
Authenticated reads of this node's own records.

The peer table is the map of who this node talks to. Publishing it to any
caller that can reach the port hands a stranger exactly the metadata this
protocol exists to keep local -- and it does so from the running daemon,
whatever the design documents say. These endpoints put the same gate in front
of it that discovery already uses.

Three rules, and every function here exists to keep one of them true:

  1. **Reading requires a completed handshake, not a connection.** TLS proves
     nothing about a caller: the daemon asks for no client certificate, so a
     TLS peer is anonymous on the server side. Only the three-message ed25519
     handshake makes a caller someone, and only for as long as its key stays
     trusted -- reload_trust() drops revoked peers from the table these
     requests are checked against, so a revocation ends read access with it.
  2. **A refusal is built before any record is touched.** Nothing about
     whether this node has peers, how many, or who they are can reach a
     caller that failed the gate, because the refusal is constructed without
     consulting any of it.
  3. **An authenticated caller sees only what it already knows about.** This
     is discovery's rule applied to the peer table: the caller names the keys
     it is asking about, and the answer covers only those. A peer the caller
     has never heard of stays invisible, so authenticating to one node does
     not enumerate the rest of the mesh.
"""
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from .address_book import normalise_key
from .crypto import EurekaCrypto
from .node import EurekaNode, REASON_MALFORMED, REASON_OK
from . import signed_request
from .signed_request import BASE_QUERY_KEYS, PROTOCOL

# One event per record, pinned inside the signed payload. A signature minted to
# read the manifest therefore cannot be replayed to read the peer table.
PEERS_EVENT = "peers_query"
LOGS_EVENT = "logs_query"
MANIFEST_EVENT = "manifest_query"

PEERS_ANSWER_EVENT = "peers_answer"
LOGS_ANSWER_EVENT = "logs_answer"
MANIFEST_ANSWER_EVENT = "manifest_answer"
REJECTED_EVENT = "read_rejected"

# A peers query names the keys it is asking about, exactly as a discovery query
# does. Same cap, same reason: a truncated query would answer a different
# question than the one asked, so an oversized one is refused instead.
PEERS_QUERY_KEYS = BASE_QUERY_KEYS | {"keys"}
MAX_QUERY_KEYS = 128

# The field each answer carries its result in, and the empty value a refusal
# carries instead. A client that reads the result field without checking the
# event still learns nothing from a refusal.
_RESULT_FIELD = {
    PEERS_EVENT: ("peers", dict),
    LOGS_EVENT: ("logs", list),
    MANIFEST_EVENT: ("manifest", dict),
}


def rejected(event: str, reason: str) -> Dict[str, Any]:
    """
    A refusal, carrying an empty result.

    Built from the event and the reason alone. No argument to this function is
    derived from the peer table, the log, or anything else a caller might want
    to learn, which is what makes the refusal identical whether or not this
    node has peers.
    """
    field, empty = _RESULT_FIELD.get(event, ("result", dict))
    return {"event": REJECTED_EVENT, "reason": reason, field: empty()}


# ---------------------------------------------------------------------------
# Caller side
# ---------------------------------------------------------------------------

def build_read_query(node: EurekaNode, event: str,
                     keys: Optional[Iterable[object]] = None,
                     now: Optional[datetime] = None) -> Dict[str, Any]:
    """
    A signed request to read one of a peer's records.

    For a peers query, `keys` defaults to every key this node trusts -- the
    only set worth asking about, since an answer for any other key would name
    a peer we could not place anyway.
    """
    query = {
        "protocol": PROTOCOL,
        "event": event,
        "requester_id": node.node_id,
        "timestamp": (now or datetime.now(timezone.utc)).isoformat(),
    }
    if event == PEERS_EVENT:
        if keys is None:
            wanted = list(node.trust_list.public_keys())
        else:
            wanted = [normalise_key(key) for key in keys]
            wanted = [key for key in wanted if key is not None]
        query["keys"] = sorted(set(wanted))[:MAX_QUERY_KEYS]
    return signed_request.build_envelope(node, query, node.crypto.sign_read_query)


# ---------------------------------------------------------------------------
# Responder side
# ---------------------------------------------------------------------------

def _peers_body_is_valid(query: dict) -> bool:
    requested = query.get("keys")
    return isinstance(requested, list) and len(requested) <= MAX_QUERY_KEYS


def _authenticate(node: EurekaNode, document: Any, event: str,
                  now: Optional[datetime] = None):
    """Run the shared gate for one read. Returns (rejection, public_key, peer_id)."""
    required = PEERS_QUERY_KEYS if event == PEERS_EVENT else BASE_QUERY_KEYS
    reason, public_key, requester_id = signed_request.verify(
        node, document,
        event=event,
        verify_signature=EurekaCrypto.verify_read_query,
        required_keys=required,
        validate_body=_peers_body_is_valid if event == PEERS_EVENT else None,
        now=now,
    )
    if reason is not None:
        return rejected(event, reason), None, None
    return None, public_key, requester_id


def answer_peers(node: EurekaNode, document: Any,
                 now: Optional[datetime] = None) -> Dict[str, Any]:
    """
    The peer table, intersected with what the caller already knows.

    The caller names public keys; the answer covers only those it named that
    are also currently authenticated peers of ours under a key we still trust.
    Nothing is returned for a key the caller did not name, so this never
    reveals that some other peer exists -- which is the whole point, since the
    set of peers is the record this protocol refuses to publish.
    """
    rejection, _public_key, _peer_id = _authenticate(node, document, PEERS_EVENT, now)
    if rejection is not None:
        return rejection

    wanted = {normalise_key(entry) for entry in document["query"]["keys"]}
    wanted.discard(None)

    disclosed: Dict[str, Dict[str, str]] = {}
    for peer_id, record in node.peers.items():
        key = normalise_key(record.get("public_key"))
        if key is None or key not in wanted:
            continue
        if record.get("status") != "authenticated":
            continue
        # A peer whose key we have since revoked or dropped is not ours to
        # report. reload_trust() removes it from the table, but a table read
        # between a file edit and the reload would otherwise still name it.
        if node.trust_list.is_revoked(key) or not node.trust_list.trusts(key):
            continue
        disclosed[key] = {"peer_id": peer_id, "status": record["status"]}

    return {
        "event": PEERS_ANSWER_EVENT,
        "responder_id": node.node_id,
        "reason": REASON_OK,
        "peers": disclosed,
    }


def answer_logs(node: EurekaNode, document: Any,
                now: Optional[datetime] = None) -> Dict[str, Any]:
    """
    Audit-log entries attributable to the calling peer, and no others.

    An entry records something this node did. Which peer it was done for is
    that peer's business; it is nobody else's, and the whole log is a record of
    this node's activity that no caller is entitled to in full. So an entry is
    disclosed only when its signed payload names this caller.

    Today that filter returns nothing to anyone, because the only thing that
    writes entries is assign(), which is a stub with no requesting peer to
    attribute work to. That is the correct empty rather than an accidental one:
    when assign() grows a real implementation it will attribute entries to the
    peer that asked, and this rule already says who may read them. An operator
    reading the local log is not affected -- that path is the journal, not the
    network.
    """
    rejection, _public_key, peer_id = _authenticate(node, document, LOGS_EVENT, now)
    if rejection is not None:
        return rejection

    entitled = [
        entry for entry in node.event_log
        if isinstance(entry.get("payload"), dict)
        and entry["payload"].get("peer") == peer_id
    ]
    return {
        "event": LOGS_ANSWER_EVENT,
        "responder_id": node.node_id,
        "reason": REASON_OK,
        "logs": entitled,
    }


def answer_manifest(node: EurekaNode, document: Any,
                    now: Optional[datetime] = None) -> Dict[str, Any]:
    """
    The full manifest, including the capability list.

    The open GET /v1/manifest carries node_id and runtime only -- see api.py
    for why those two cannot be withheld. What this adds is the capability
    list, which is a real disclosure (it says what this node can be asked to
    do) and which nothing in the handshake needs, so it waits until the caller
    has proved who it is.
    """
    rejection, _public_key, _peer_id = _authenticate(node, document, MANIFEST_EVENT, now)
    if rejection is not None:
        return rejection

    return {
        "event": MANIFEST_ANSWER_EVENT,
        "responder_id": node.node_id,
        "reason": REASON_OK,
        "manifest": {
            "node_id": node.node_id,
            "runtime": "eureka-daemon",
            "capabilities": list(node.capabilities),
        },
    }


ANSWER = {
    PEERS_EVENT: answer_peers,
    LOGS_EVENT: answer_logs,
    MANIFEST_EVENT: answer_manifest,
}
