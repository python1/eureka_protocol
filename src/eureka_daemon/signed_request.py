"""
One gate for every request that must come from a peer we have authenticated.

Discovery had this logic inline, and then the read endpoints needed exactly
the same sequence of checks: well-formed, signed by the key it claims, fresh,
trusted, unrevoked, and belonging to a peer that has actually completed a
handshake under that key. Two copies of a check sequence is how one of them
grows a hole -- the same argument write_private_file makes about secrets on
disk -- so it lives here once and both callers pass through it.

What this deliberately does NOT accept as authentication:

  * A TLS connection. Terminating TLS proves the peer holds *a* key, and the
    pinning client checks that key against the trust list, but the pin is the
    caller's check of the server, not the server's check of the caller. The
    daemon serves ssl_cert_reqs=CERT_NONE and asks for no client certificate,
    so on the server side a TLS connection carries no caller identity at all.
  * A claimed node_id. The requester_id names who is asking; the signature is
    what makes it true.

The check ORDER matters and is not arbitrary: shape before signature, and
signature before any consultation of the trust list. A malformed document is
rejected without an ed25519 verification being attempted, and nothing about
who this node trusts is consulted until the caller has proved it holds the key
it is asking under.
"""
from datetime import datetime
from typing import Any, Callable, FrozenSet, Optional, Tuple

from .address_book import normalise_key
from .crypto import EurekaCrypto
from .node import (
    EurekaNode,
    REASON_BAD_SIGNATURE,
    REASON_MALFORMED,
    REASON_REVOKED_KEY,
    REASON_STALE,
    REASON_UNTRUSTED_KEY,
)

# The protocol tag every signed request carries, shared with the handshake and
# discovery so an operator reads one vocabulary across the whole daemon.
PROTOCOL = "eureka/1.0"

# The caller is trusted and its signature verifies, but it has not completed a
# handshake -- or completed one under a different key than it is now signing
# with. Trust alone is not enough to read anything.
REASON_NOT_AUTHENTICATED = "not_authenticated"

# The envelope fields every signed request shares. A specific request adds its
# own body fields on top of these.
BASE_QUERY_KEYS = frozenset(("protocol", "event", "requester_id", "timestamp"))


def verify(node: EurekaNode, document: Any, *,
           event: str,
           verify_signature: Callable[[str, str, dict], bool],
           required_keys: FrozenSet[str] = BASE_QUERY_KEYS,
           validate_body: Optional[Callable[[dict], bool]] = None,
           now: Optional[datetime] = None
           ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Check one signed request. Returns (rejection_reason, public_key, requester_id).

    A reason of None means every gate passed and the caller is an authenticated
    peer; `public_key` is then the key the handshake proved, not merely the key
    the document carried. Callers wrap the reason in whatever refusal shape
    their endpoint uses -- this function deliberately builds no response, so it
    cannot leak anything through one.
    """
    if not isinstance(document, dict):
        return REASON_MALFORMED, None, None

    query = document.get("query")
    public_key = normalise_key(document.get("public_key"))
    signature = document.get("signature")
    if (not isinstance(query, dict) or public_key is None
            or not isinstance(signature, str)):
        return REASON_MALFORMED, None, None

    # Exact key set, not a superset: an unexpected field is a document this
    # node does not understand, and understanding it partially is worse than
    # refusing it.
    if set(query) != required_keys:
        return REASON_MALFORMED, None, None
    if query.get("protocol") != PROTOCOL or query.get("event") != event:
        return REASON_MALFORMED, None, None

    requester_id = query.get("requester_id")
    if not isinstance(requester_id, str) or not requester_id:
        return REASON_MALFORMED, None, None
    if document.get("requester_id") != requester_id:
        # The envelope and the signed body must agree about who is asking.
        # Only the body is covered by the signature; an envelope that says
        # something else is either a bug or an attempt to have the two read
        # differently.
        return REASON_MALFORMED, None, None

    if validate_body is not None and not validate_body(query):
        return REASON_MALFORMED, None, None

    if not verify_signature(public_key, signature, query):
        return REASON_BAD_SIGNATURE, None, None

    # Reuse the handshake's clock-skew handling rather than growing a second
    # implementation of freshness that could drift from it.
    age = node._challenge_age_seconds(query.get("timestamp"))
    if age is None:
        return REASON_MALFORMED, None, None
    if abs(age) > node.freshness_seconds:
        return REASON_STALE, None, None

    if node.trust_list.is_revoked(public_key):
        return REASON_REVOKED_KEY, None, None
    if not node.trust_list.trusts(public_key):
        return REASON_UNTRUSTED_KEY, None, None

    # A trusted key is still not enough. The caller must have completed a
    # handshake, and it must be signing with the same key that handshake
    # proved -- otherwise a peer could authenticate under one trusted key and
    # then read under another.
    record = node.peers.get(requester_id)
    if (not record or record.get("status") != "authenticated"
            or normalise_key(record.get("public_key")) != public_key):
        return REASON_NOT_AUTHENTICATED, None, None

    return None, public_key, requester_id


def build_envelope(node: EurekaNode, query: dict, sign: Callable[[dict], str]) -> dict:
    """
    Wrap a signed query in the envelope the verifier expects.

    The envelope repeats requester_id outside the signature so a responder can
    log who claimed to be calling even when the signature does not verify; the
    verifier insists the two agree, so the copy outside cannot be believed on
    its own.
    """
    return {
        "event": query["event"],
        "requester_id": node.node_id,
        "public_key": node.public_key_hex,
        "query": query,
        "signature": sign(query),
    }
