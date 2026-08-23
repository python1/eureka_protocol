"""
HTTP client for the mutual handshake.

The in-process driver takes an EurekaNode object. Over a network there is no
object -- only JSON in and JSON out -- so this module drives the same three
messages against a base URL and returns the same result shape, so callers can
swap one for the other without reading the outcome differently.
"""
from typing import Any, Dict, Optional

import httpx

from .node import EurekaNode, REASON_MALFORMED

# Endpoint paths, kept next to the client that calls them.
OFFER_PATH = "/v1/handshake/offer"
CONFIRM_PATH = "/v1/handshake/confirm"
MANIFEST_PATH = "/v1/manifest"

DEFAULT_TIMEOUT = 10.0


def _transport_rejection(reason: str, detail: str) -> Dict[str, Any]:
    """A local rejection for something that went wrong before/around the protocol."""
    return {
        "event": "handshake_rejected",
        "authenticated": False,
        "reason": reason,
        "peer_id": None,
        "auth_type": "Ed25519",
        "detail": detail,
    }


def _decode(response: httpx.Response) -> Dict[str, Any]:
    """
    Turn a peer's HTTP response into a protocol message.

    A non-JSON or non-object body is treated as a malformed peer message
    rather than being allowed to raise: the peer is untrusted in both
    directions, and its *replies* are no more trustworthy than its requests.
    """
    try:
        document = response.json()
    except ValueError:
        return _transport_rejection(
            REASON_MALFORMED, f"peer returned non-JSON body (HTTP {response.status_code})"
        )
    if not isinstance(document, dict):
        return _transport_rejection(
            REASON_MALFORMED, f"peer returned {type(document).__name__}, expected object"
        )
    return document


async def fetch_peer_id(http: httpx.AsyncClient, base_url: str = "") -> Optional[str]:
    """Read a peer's node_id from its manifest, so a caller need only pass a URL."""
    response = await http.get(f"{base_url}{MANIFEST_PATH}")
    if response.status_code != 200:
        return None
    document = _decode(response)
    node_id = document.get("node_id")
    return node_id if isinstance(node_id, str) else None


async def handshake_over_http(
    node: EurekaNode,
    base_url: str = "",
    *,
    http: Optional[httpx.AsyncClient] = None,
    peer_id: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """
    Drive the full three-message handshake against `base_url`.

    Returns the same shape as EurekaNode.handshake(): this node's own result on
    success (with ``mutual`` set), or whichever side's rejection ended the
    exchange. `http` may be an existing client -- including one wired to an
    ASGI app -- otherwise one is created for the call.

    The signed payloads are passed through verbatim. They are only ever
    serialised by json, never rebuilt, because every byte of them is covered
    by a signature.
    """
    owns_client = http is None
    if owns_client:
        http = httpx.AsyncClient(base_url=base_url, timeout=timeout)
        base_url = ""
    try:
        if peer_id is None:
            peer_id = await fetch_peer_id(http, base_url)
            if peer_id is None:
                return _transport_rejection(
                    REASON_MALFORMED, "peer manifest did not yield a node_id"
                )

        offer = node.create_handshake_offer(peer_id)
        message_two = _decode(await http.post(f"{base_url}{OFFER_PATH}", json=offer))
        if message_two.get("authenticated") is False:
            # The peer refused message 1; nothing was exchanged to verify.
            return message_two

        mine = await node.complete_handshake(message_two)
        if not mine["authenticated"]:
            return mine

        confirmation = node.confirm_handshake(message_two)
        theirs = _decode(
            await http.post(f"{base_url}{CONFIRM_PATH}", json=confirmation)
        )
        if theirs.get("authenticated") is not True:
            return theirs

        mine["mutual"] = True
        return mine
    except httpx.HTTPError as exc:
        # A transport failure is not an authentication outcome, but it is
        # still reported in the protocol's shape so callers have one thing
        # to check.
        return _transport_rejection(REASON_MALFORMED, f"transport error: {exc}")
    finally:
        if owns_client:
            await http.aclose()
