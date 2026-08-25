"""
Peer discovery over a private mesh: learning *where* peers are, never *who*.

trust.json says which keys this node trusts. It has never said where those
peers live, so addresses were maintained by hand and went stale whenever an IP
changed. This module closes that gap by gossiping addresses between peers that
have already authenticated to each other.

Three rules hold the design together, and every function here exists to keep
one of them true:

  1. **An address is never a trust decision.** Learning an address for a key
     grants that key nothing. A gossiped address for a key we do not trust, or
     one we have revoked, is dropped without comment -- it cannot even be
     stored, so it can never be dialled.
  2. **An address is advice until a handshake proves it.** A learned address is
     unconfirmed until a handshake against it authenticates *the key we
     expected*. A peer that gossips a wrong address costs us one failed
     connection; it can never move trust from one key to another.
  3. **Nothing outside the configured mesh is ever contacted.** There is no
     DHT, no bootstrap server, no well-known address. A node with an empty
     bootstrap list dials nothing at all.

On the disclosure rule, and the honest limit in it
--------------------------------------------------
The requirement is that a node discloses only addresses for keys the caller
already trusts. A responder cannot compute that intersection on its own: it
knows its own trust list and the caller's key, and nothing whatsoever about
whom the caller trusts.

So the query is **caller-driven**. The caller names the keys it wants addresses
for -- keys it already trusts -- and the responder answers only for keys it
also trusts and has an address for. Nothing is disclosed about any key the
caller did not name, so the responder never reveals the existence of peers the
caller does not know about.

The residual leak is real and worth stating plainly: the caller tells the
responder which keys it is asking about. Someone has to speak first, and this
is the smaller disclosure of the two -- it is the caller's own choice, it is
limited to the keys it actually wants, and it goes to a peer it has already
authenticated and already trusts. The alternatives are worse: dumping the
responder's table leaks strictly more, and a Bloom filter of the caller's trust
list leaks the same thing while adding false positives that would make the
responder disclose addresses for keys the caller does *not* trust, breaking the
very rule it was meant to serve. A private set intersection would fix it
properly and needs cryptography this project does not have a dependency for.
"""
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .address_book import (
    MAX_ADDRESSES_PER_KEY,
    AddressBook,
    normalise_address,
    normalise_key,
)
from .crypto import EurekaCrypto
from .node import (
    EurekaNode,
    REASON_BAD_SIGNATURE,
    REASON_MALFORMED,
    REASON_OK,
    REASON_REVOKED_KEY,
    REASON_STALE,
    REASON_UNTRUSTED_KEY,
)

# A query naming more keys than this is refused rather than truncated. A
# truncated query would answer a different question than the one asked.
MAX_QUERY_KEYS = 128

DISCOVERY_PROTOCOL = "eureka/1.0"
QUERY_EVENT = "discovery_query"
ANSWER_EVENT = "discovery_answer"
REJECTED_EVENT = "discovery_rejected"

# Discovery-specific refusal. The rest are shared with the handshake so an
# operator reads one vocabulary across the whole protocol.
REASON_NOT_AUTHENTICATED = "not_authenticated"

QUERY_REQUIRED_KEYS = frozenset(
    ("protocol", "event", "requester_id", "timestamp", "keys")
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Gossip: the caller names the keys, the responder answers for the ones it
# shares. Neither side ever hands over its whole table.
# ---------------------------------------------------------------------------

def build_query(node: EurekaNode, keys: Optional[Iterable[object]] = None,
                now: Optional[datetime] = None) -> Dict[str, Any]:
    """
    A signed request for addresses.

    `keys` defaults to every key this node trusts, which is the only set worth
    asking about: an address for a key we do not trust could not be stored and
    could not be dialled, so asking for one would leak our curiosity for
    nothing in return.
    """
    if keys is None:
        wanted = list(node.trust_list.public_keys())
    else:
        wanted = [normalise_key(key) for key in keys]
        wanted = [key for key in wanted if key is not None]
    wanted = sorted(set(wanted))[:MAX_QUERY_KEYS]

    query = {
        "protocol": DISCOVERY_PROTOCOL,
        "event": QUERY_EVENT,
        "requester_id": node.node_id,
        "timestamp": (now or _utc_now()).isoformat(),
        "keys": wanted,
    }
    return {
        "event": QUERY_EVENT,
        "requester_id": node.node_id,
        "public_key": node.public_key_hex,
        "query": query,
        "signature": node.crypto.sign_discovery_query(query),
    }


def rejected(reason: str) -> Dict[str, Any]:
    """
    A refusal, carrying an empty address map.

    The empty map is deliberate: a client that reads `answer["addresses"]`
    without checking the event still learns nothing from a refusal.
    """
    return {"event": REJECTED_EVENT, "reason": reason, "addresses": {}}


def answer_query(node: EurekaNode, document: Any,
                 now: Optional[datetime] = None) -> Dict[str, Any]:
    """
    Responder side. Returns the addresses this node is willing to disclose.

    Every gate must pass: the request is well formed, its signature verifies,
    it is fresh, the asking key is trusted and not revoked, and that peer has
    actually completed a handshake with us. Gossip is not public: an
    unauthenticated caller gets nothing, whatever it asks for.
    """
    if not isinstance(document, dict):
        return rejected(REASON_MALFORMED)

    query = document.get("query")
    public_key = normalise_key(document.get("public_key"))
    signature = document.get("signature")
    if (not isinstance(query, dict) or public_key is None
            or not isinstance(signature, str)):
        return rejected(REASON_MALFORMED)
    if set(query) != QUERY_REQUIRED_KEYS:
        return rejected(REASON_MALFORMED)
    if query.get("protocol") != DISCOVERY_PROTOCOL or query.get("event") != QUERY_EVENT:
        return rejected(REASON_MALFORMED)

    requester_id = query.get("requester_id")
    if not isinstance(requester_id, str) or not requester_id:
        return rejected(REASON_MALFORMED)
    if document.get("requester_id") != requester_id:
        # The envelope and the signed body must agree about who is asking.
        return rejected(REASON_MALFORMED)

    requested = query.get("keys")
    if not isinstance(requested, list) or len(requested) > MAX_QUERY_KEYS:
        return rejected(REASON_MALFORMED)

    if not EurekaCrypto.verify_discovery_query(public_key, signature, query):
        return rejected(REASON_BAD_SIGNATURE)

    # Reuse the handshake's clock-skew handling rather than growing a second
    # implementation of freshness that could drift from it.
    age = node._challenge_age_seconds(query.get("timestamp"))
    if age is None:
        return rejected(REASON_MALFORMED)
    if abs(age) > node.freshness_seconds:
        return rejected(REASON_STALE)

    if node.trust_list.is_revoked(public_key):
        return rejected(REASON_REVOKED_KEY)
    if not node.trust_list.trusts(public_key):
        return rejected(REASON_UNTRUSTED_KEY)

    # A trusted key is not enough. Gossip is served only to a peer that has
    # completed a handshake, and only under the key that handshake proved.
    record = node.peers.get(requester_id)
    if (not record or record.get("status") != "authenticated"
            or normalise_key(record.get("public_key")) != public_key):
        return rejected(REASON_NOT_AUTHENTICATED)

    return {
        "event": ANSWER_EVENT,
        "responder_id": node.node_id,
        "reason": REASON_OK,
        "addresses": addresses_to_disclose(node, requested),
    }


def addresses_to_disclose(node: EurekaNode,
                          requested: Sequence[object]) -> Dict[str, List[str]]:
    """
    The intersection: keys the caller named that we also trust and can locate.

    Nothing is returned for a key the caller did not name, so the answer never
    reveals that some other peer exists. Nothing is returned for a key we do
    not trust or have revoked either -- a revoked peer's whereabouts stop being
    ours to share the moment it is revoked, with no separate cleanup step.
    """
    disclosed: Dict[str, List[str]] = {}
    for entry in requested:
        key = normalise_key(entry)
        if key is None:
            continue
        if node.trust_list.is_revoked(key) or not node.trust_list.trusts(key):
            continue
        known = node.address_book.addresses(key)
        if known:
            disclosed[key] = known
    return disclosed


def learn_addresses(node: EurekaNode, answer: Any,
                    source: Optional[str] = None) -> int:
    """
    Store the addresses in an answer. Returns how many were accepted.

    This is the gate requirement (b) names: an address is accepted only for a
    key already on the local trust list, and one for an unknown or revoked key
    is dropped without comment. Learning an address adds no trust to anything.
    """
    if not isinstance(answer, dict):
        return 0
    offered = answer.get("addresses")
    if not isinstance(offered, dict):
        return 0

    accepted = 0
    for raw_key, addresses in offered.items():
        key = normalise_key(raw_key)
        if key is None:
            continue
        if node.trust_list.is_revoked(key) or not node.trust_list.trusts(key):
            # Silently. A peer gossiping about keys we do not trust is not an
            # error worth reporting back to it, and telling it which keys we
            # dropped would disclose our trust list.
            continue
        if not isinstance(addresses, (list, tuple)):
            continue
        for address in addresses[:MAX_ADDRESSES_PER_KEY]:
            if node.address_book.add(key, address, source=source):
                accepted += 1
    return accepted


# ---------------------------------------------------------------------------
# Driving a round. Nothing here reaches any address that did not come from the
# configured bootstrap list or from the address book, and the address book
# holds nothing for a key this node does not already trust.
# ---------------------------------------------------------------------------

DISCOVERY_PATH = "/v1/discovery/addresses"


def default_client_factory(address: str, timeout: float):
    """
    Open an HTTP client for one peer address.

    Injectable so tests can drive real ASGI apps in process, and so a
    deployment can supply a pinning TLS context without this module having to
    know how transports are built.
    """
    import httpx
    return httpx.AsyncClient(base_url=address, timeout=timeout)


async def confirm_address(node: EurekaNode, expected_key: object, address: object,
                          *, client_factory=default_client_factory,
                          timeout: float = 10.0,
                          require_tls: bool = False) -> bool:
    """
    Handshake against an address and confirm it only if the RIGHT key answers.

    This is rule 2. A gossiped address is a claim about where a key lives, and
    the handshake is the only thing that settles it. Note what happens when the
    claim is wrong but the address is live: some *other* trusted peer answers,
    the handshake legitimately succeeds with that peer, and this still returns
    False and confirms nothing -- the address was wrong for the key it was
    filed under. A peer that gossips bad addresses wastes our connections and
    moves no trust anywhere.
    """
    from .client import handshake_over_http

    key = normalise_key(expected_key)
    target = normalise_address(address)
    if key is None or target is None:
        return False

    http = None
    try:
        http = client_factory(target, timeout)
        result = await handshake_over_http(node, http=http,
                                           require_tls=require_tls)
    except Exception:
        # An address that cannot be dialled is simply not confirmed. It is
        # advice that did not pan out, not an error the caller must handle.
        # Opening the client counts: a bad URL fails here, not at the request.
        return False
    finally:
        if http is not None:
            await http.aclose()

    if not result.get("authenticated"):
        return False
    peer_id = result.get("peer_id")
    record = node.peers.get(peer_id) if isinstance(peer_id, str) else None
    if not record or normalise_key(record.get("public_key")) != key:
        # Someone answered, and it was not who this address claimed to be.
        return False
    return node.address_book.confirm(key, target)


async def query_peer(node: EurekaNode, address: str,
                     keys: Optional[Iterable[object]] = None, *,
                     client_factory=default_client_factory,
                     timeout: float = 10.0) -> Dict[str, Any]:
    """Ask one peer for addresses and return its answer, unprocessed."""
    http = None
    try:
        http = client_factory(address, timeout)
        response = await http.post(DISCOVERY_PATH, json=build_query(node, keys))
        document = response.json()
    except Exception:
        return rejected(REASON_MALFORMED)
    finally:
        if http is not None:
            await http.aclose()
    return document if isinstance(document, dict) else rejected(REASON_MALFORMED)


async def discover(node: EurekaNode, bootstrap: Sequence[str] = (), *,
                   client_factory=default_client_factory,
                   timeout: float = 10.0, require_tls: bool = False,
                   confirm: bool = True) -> Dict[str, Any]:
    """
    One discovery round: bootstrap, ask, learn, confirm.

    With an empty bootstrap list and an empty address book this dials nothing
    at all and returns immediately. There is no fallback, no well-known
    address, and no public directory to fall back *to* -- that is the point.
    """
    summary = {"contacted": [], "learned": 0, "confirmed": [], "failed": []}

    # 1. The configured entry points, plus anything a previous round confirmed.
    targets = list(dict.fromkeys(
        [address for address in bootstrap if isinstance(address, str)]
        + [address for key in node.address_book.keys()
           for address in node.address_book.addresses(key)]
    ))
    if not targets:
        return summary

    for address in targets:
        summary["contacted"].append(address)
        # Handshake BEFORE asking. The query names the keys we trust, so
        # sending it first would hand our trust list to whoever picked up --
        # the exact disclosure this design is careful about everywhere else.
        responder_key = await _handshake_and_record(
            node, address, client_factory=client_factory, timeout=timeout,
            require_tls=require_tls)
        if responder_key is None:
            summary["failed"].append(address)
            continue
        answer = await query_peer(node, address, client_factory=client_factory,
                                  timeout=timeout)
        summary["learned"] += learn_addresses(node, answer, source=address)

    # 2. Turn advice into fact. Only unconfirmed addresses are dialled, and
    #    only for keys still on the trust list.
    if confirm:
        for key in node.address_book.keys():
            for address in node.address_book.addresses(key):
                if node.address_book.is_confirmed(key, address):
                    continue
                if await confirm_address(node, key, address,
                                         client_factory=client_factory,
                                         timeout=timeout,
                                         require_tls=require_tls):
                    summary["confirmed"].append((key, address))
    return summary


async def _handshake_and_record(node: EurekaNode, address: str, *,
                                client_factory, timeout: float,
                                require_tls: bool) -> Optional[str]:
    """
    Handshake against a bootstrap address and file it under whoever answered.

    The address is recorded under the key the handshake proved, never under a
    key someone claimed in advance, so a bootstrap entry pointing at the wrong
    host records that host and nothing else.
    """
    from .client import handshake_over_http

    http = None
    try:
        http = client_factory(address, timeout)
        result = await handshake_over_http(node, http=http,
                                           require_tls=require_tls)
    except Exception:
        return None
    finally:
        if http is not None:
            await http.aclose()

    if not result.get("authenticated"):
        return None
    peer_id = result.get("peer_id")
    record = node.peers.get(peer_id) if isinstance(peer_id, str) else None
    key = normalise_key(record.get("public_key")) if record else None
    if key is None:
        return None
    node.address_book.add(key, address, source="bootstrap")
    node.address_book.confirm(key, address)
    return key
