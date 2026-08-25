"""
HTTP client for the mutual handshake.

The in-process driver takes an EurekaNode object. Over a network there is no
object -- only JSON in and JSON out -- so this module drives the same three
messages against a base URL and returns the same result shape, so callers can
swap one for the other without reading the outcome differently.
"""
from typing import Any, Dict, Optional

import httpx

from . import tls
from .node import (
    EurekaNode,
    REASON_MALFORMED,
    REASON_REVOKED_KEY,
    REASON_TLS_IDENTITY_MISMATCH,
    REASON_TLS_REQUIRED,
    REASON_UNTRUSTED_KEY,
)

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


def _peer_id_from_manifest(response: httpx.Response) -> Optional[str]:
    if response.status_code != 200:
        return None
    document = _decode(response)
    node_id = document.get("node_id")
    return node_id if isinstance(node_id, str) else None


async def fetch_peer_id(http: httpx.AsyncClient, base_url: str = "") -> Optional[str]:
    """Read a peer's node_id from its manifest, so a caller need only pass a URL."""
    return _peer_id_from_manifest(await http.get(f"{base_url}{MANIFEST_PATH}"))


def _pin_failure(node: EurekaNode, tls_key: Optional[str],
                 require_tls: bool) -> Optional[Dict[str, Any]]:
    """
    Check the key that terminated TLS against this node's trust list.

    Returns a rejection, or None if the connection is acceptable. The pin uses
    the same trust list and the same revocation table as the handshake, so
    there is exactly one place to revoke a peer -- which is the whole reason
    this design does not use client certificates and a CA store.

    A plain-HTTP connection has no key to pin. That is allowed unless the
    caller asked for TLS, because it is what the current deployment does; it
    is not silently treated as a passed check.
    """
    if tls_key is None:
        if require_tls:
            return _transport_rejection(
                REASON_TLS_REQUIRED,
                "peer was not reached over TLS and require_tls is set",
            )
        return None
    if node.trust_list.is_revoked(tls_key):
        return _transport_rejection(
            REASON_REVOKED_KEY, "the key terminating TLS has been revoked"
        )
    if not node.trust_list.trusts(tls_key):
        return _transport_rejection(
            REASON_UNTRUSTED_KEY, "the key terminating TLS is not trusted"
        )
    return None


async def handshake_over_http(
    node: EurekaNode,
    base_url: str = "",
    *,
    http: Optional[httpx.AsyncClient] = None,
    peer_id: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    require_tls: bool = False,
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

    Over TLS the server is pinned: the key that terminated the connection must
    be trusted, unrevoked, and the same key that signs message 2. Pinning
    happens whether or not `require_tls` is set -- the flag decides whether a
    *plain* connection is allowed at all, not whether a TLS one is checked.
    """
    owns_client = http is None
    if owns_client:
        # An https peer gets a pinning client, never a CA-verifying one. There
        # is no certificate authority in this protocol: chaining to the system
        # store rejects every peer, and the obvious workaround for that
        # (verify=False) would switch the pin off too. Pinning is both the
        # stricter choice and the only one that works.
        if base_url.strip().lower().startswith("https://"):
            http = tls.pinning_client(base_url, timeout)
        else:
            http = httpx.AsyncClient(base_url=base_url, timeout=timeout)
        base_url = ""
    try:
        tls_key = None
        if peer_id is None:
            response = await http.get(f"{base_url}{MANIFEST_PATH}")
            tls_key = tls.peer_key_from_response(response)
            failure = _pin_failure(node, tls_key, require_tls)
            if failure is not None:
                # Refused before we say anything to this peer.
                return failure
            peer_id = _peer_id_from_manifest(response)
            if peer_id is None:
                return _transport_rejection(
                    REASON_MALFORMED, "peer manifest did not yield a node_id"
                )

        offer = node.create_handshake_offer(peer_id)
        response = await http.post(f"{base_url}{OFFER_PATH}", json=offer)
        # Re-read the pin from this response rather than trusting the one taken
        # from the manifest: with connection reuse it is the same connection,
        # and without it, it is a different one that has to earn the pin again.
        tls_key = tls.peer_key_from_response(response)
        failure = _pin_failure(node, tls_key, require_tls)
        if failure is not None:
            return failure

        message_two = _decode(response)
        if message_two.get("authenticated") is False:
            # The peer refused message 1; nothing was exchanged to verify.
            return message_two

        # Bind the channel to the identity. Without this a peer we trust could
        # terminate TLS and relay a *different* trusted peer's handshake: both
        # keys pass their own check, and we would end up authenticated to one
        # identity over a channel held by another.
        if tls_key is not None:
            signed_by = message_two.get("public_key")
            signed_by = signed_by.strip().lower() if isinstance(signed_by, str) else None
            if signed_by != tls_key:
                return _transport_rejection(
                    REASON_TLS_IDENTITY_MISMATCH,
                    "the key that terminated TLS did not sign the handshake",
                )

        mine = await node.complete_handshake(message_two)
        if not mine["authenticated"]:
            return mine

        confirmation = node.confirm_handshake(message_two)
        response = await http.post(f"{base_url}{CONFIRM_PATH}", json=confirmation)
        failure = _pin_failure(node, tls.peer_key_from_response(response), require_tls)
        if failure is not None:
            return failure
        theirs = _decode(response)
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
