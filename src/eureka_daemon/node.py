import asyncio
import json
import secrets
import uuid
import time
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, List, Optional, Any, Set
from .crypto import EurekaCrypto
from .address_book import AddressBook
from .trust import TrustError, TrustList

# Default window a challenge stays valid for, in seconds. A response that
# arrives outside this window is rejected even if its signature is perfect,
# which is what stops a captured handshake being replayed later.
HANDSHAKE_FRESHNESS_SECONDS = 30.0

# Hard ceilings on the handshake state tables.
#
# Age-based pruning alone does not bound memory: an attacker can request tens
# of thousands of challenges well inside the freshness window, and every one
# of them is legitimately "fresh". The caps are what actually bound the
# tables; the age pruning is what keeps them small in normal operation.
MAX_PENDING_CHALLENGES = 1024
MAX_SEEN_NONCES = 4096

# The exact shape of a well-formed challenge. answer_challenge() signs nothing
# that does not match this precisely -- see the signing-oracle note there.
CHALLENGE_PROTOCOL = "eureka/1.0"
CHALLENGE_EVENT = "handshake_challenge"
CHALLENGE_STRING_FIELDS = ("nonce", "timestamp", "initiator_id", "peer_id")
CHALLENGE_REQUIRED_KEYS = frozenset(
    ("protocol", "event") + CHALLENGE_STRING_FIELDS
)


class InvalidChallengeError(ValueError):
    """
    Raised by answer_challenge() when asked to sign something that is not a
    well-formed handshake challenge.

    This is raised rather than returned so a caller cannot mistake a rejection
    for a signed response and forward it onto the wire.
    """

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)

# Rejection reasons, exposed as constants so callers and tests assert on a
# stable value instead of matching prose.
REASON_OK = "authenticated"
REASON_UNKNOWN_NONCE = "unknown_nonce"
REASON_REPLAYED_NONCE = "replayed_nonce"
REASON_MALFORMED = "malformed_response"
REASON_STALE = "stale_timestamp"
REASON_BAD_SIGNATURE = "signature_verification_failed"
REASON_CHALLENGE_MISMATCH = "challenge_mismatch"
REASON_WRONG_RESPONDER = "unexpected_responder"
REASON_UNTRUSTED_KEY = "untrusted_key"
# A revoked key is already absent from the allowlist, so it would be refused as
# untrusted anyway. This reason exists to say *which* refusal it was: "we
# revoked you" and "we have never heard of you" call for very different
# operator responses, and a log full of untrusted_key cannot tell them apart.
# It does disclose to the holder of a revoked key that it was specifically
# revoked -- accepted deliberately, since losing access reveals as much.
REASON_REVOKED_KEY = "revoked_key"
# Transport-level refusals from the pinning client. tls_required is a
# deployment saying it will not speak in the clear; tls_identity_mismatch is
# the serious one -- the key that terminated TLS is not the key that signed the
# handshake, which is what a trusted peer relaying someone else's exchange
# looks like from the inside.
REASON_TLS_REQUIRED = "tls_required"
REASON_TLS_IDENTITY_MISMATCH = "tls_identity_mismatch"
# The same check sequence runs on both sides of the exchange, so the
# "responder" in this reason is really "the peer we addressed". Same value,
# readable name for the responder-side call.
REASON_WRONG_PEER = REASON_WRONG_RESPONDER


def _utc_now() -> datetime:
    """Single source of 'now' so the freshness window is easy to reason about."""
    return datetime.now(timezone.utc)


class EurekaState(Enum):
    IDENTITY = "identity"
    BEACON = "beacon"
    SCAN = "scan"
    HANDSHAKE = "handshake"
    ASSIGN = "assign"
    LOG = "log"

class EurekaNode:
    """
    The core 5-layer state machine engine for the Eureka Protocol.
    Man_ages identity, peer discovery, authentication, and task execution.
    """
    def __init__(self, node_id: Optional[str], crypto_engine: EurekaCrypto,
                 capabilities: List[str],
                 freshness_seconds: float = HANDSHAKE_FRESHNESS_SECONDS,
                 max_pending_challenges: int = MAX_PENDING_CHALLENGES,
                 max_seen_nonces: int = MAX_SEEN_NONCES,
                 trust_path: Optional[str] = None,
                 trust_list: Optional[TrustList] = None):
        self.crypto = crypto_async_wrapper(crypto_engine) if hasattr(self, 'crypto_async_wrapper') else crypto_engine
        # node_id=None means "name me after my key", so a node that reloads a
        # stored identity comes back under the same id instead of a fresh
        # random one. An explicit id is still honoured verbatim.
        self.node_id = node_id if node_id is not None else self.crypto.derive_node_id()
        self.capabilities = capabilities
        self.state = EurekaState.IDENTITY
        self.peers: Dict[str, Dict[str, Any]] = {}
        self.active_tasks: Dict[str, Any] = {}
        self.event_log: List[Dict[str, Any]] = []
        self.session_id = f"urn:uuid:{uuid.uuid4()}"

        # Who this node is willing to authenticate, loaded at construction.
        # An absent trust file is a legitimate state and yields an empty
        # allowlist -- which trusts nobody. A corrupt one raises TrustError
        # rather than pretending to be empty. A caller may hand in a prebuilt
        # TrustList instead of a path; an empty one is still empty, so this is
        # a provisioning seam, not a bypass.
        self.trust_list = (
            trust_list if trust_list is not None
            else TrustList.load_or_empty(trust_path, advertised=self.capabilities)
        )
        # Where reload_trust() should read from. An injected list with no
        # explicit path has no file behind it, and resolving the default would
        # silently swap in a completely different allowlist -- so that case
        # refuses to reload rather than guessing.
        self.trust_path = trust_path
        self._trust_list_injected = trust_list is not None and trust_path is None

        # Handshake state. freshness_seconds is per-node so a deployment can
        # tighten or loosen the replay window without touching the protocol.
        self.freshness_seconds = freshness_seconds
        self.max_pending_challenges = max_pending_challenges
        self.max_seen_nonces = max_seen_nonces
        # Challenges we have issued and are still waiting on, keyed by nonce.
        # Insertion order is issue order, which is what eviction relies on.
        self.pending_challenges: Dict[str, Dict[str, Any]] = {}
        # Nonces already spent, mapped to the instant they were spent so they
        # can be aged out. A nonce is single-use: once it completes a
        # handshake it can never authenticate another one.
        self.seen_nonces: Dict[str, datetime] = {}
        # Responder side: who we provisionally saw in message 1, keyed by the
        # nonce of the counter-challenge we sent back. Nothing here is
        # authenticated -- it is discarded unless message 3 verifies. Keyed to
        # pending_challenges so it is pruned and capped in lockstep, which is
        # what stops initiators that never finish from accumulating state.
        self.pending_peers: Dict[str, Dict[str, Any]] = {}
        # Where peers might be, as opposed to who they are. Bounded, and it
        # holds addresses only for keys this node already trusts, so it can
        # never grow into a second and looser notion of who is known.
        # Populated by discovery.py; nothing in the handshake reads it.
        self.address_book = AddressBook()
        
        # Manifest of this node's capabilities
        self.manifest = {
            "node_id": self.node_id,
            "runtime": "eureka-daemon",
            "capabilities": self.capabilities,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    @classmethod
    def with_persistent_identity(cls, capabilities: List[str],
                                 identity_path: Optional[str] = None,
                                 **kwargs) -> "EurekaNode":
        """
        Build a node backed by the on-disk identity, creating it on first run.

        This is the entry point a daemon should use: restart the process and
        the node keeps the same key and the same node_id.
        """
        crypto = EurekaCrypto.load_or_create(identity_path)
        return cls(node_id=None, crypto_engine=crypto,
                   capabilities=capabilities, **kwargs)

    @property
    def public_key_hex(self) -> str:
        """This node's long-term public key, as advertised to peers."""
        return self.crypto.get_public_key_hex()

    async def transition_to(self, new_state: EurekaState):
        """Handles state transitions and logging."""
        print(f"[NODE {self.node_id}] Transitioning: {self.state.value} -> {new_state.value}")
        self.state = new_state

    async def beacon(self):
        """Layer 1/2: Broadcast presence and identity to the network."""
        await self.transition_to(EurekaState.BEACON)
        beacon_payload = {
            "event": "eureka-beacon",
            "node_id": self.node_id,
            "manifest": self.manifest,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        # In a real implementation, this would trigger DHT/UDP broadcast
        return beacon_payload

    async def scan(self):
        """Layer 2: Active scanning for new peers."""
        await self.transition_to(EurekaState.SCAN)
        print(f"[NODE {self.node_id}] Scanning for active beacons...")
        # Simulation: In MVD, this is a passive listener loop
        return {"status": "listening", "mode": "active"}

    # ------------------------------------------------------------------
    # Layer 3: Ed25519 challenge-response handshake
    #
    # Two messages on the wire:
    #   1. initiator -> responder : create_challenge()  (nonce + timestamp)
    #   2. responder -> initiator : answer_challenge()  (signature + pubkey)
    # The initiator then calls complete_handshake(), which is the only place
    # a peer can ever be recorded as authenticated.
    # ------------------------------------------------------------------

    def create_challenge(self, peer_id: str) -> Dict[str, Any]:
        """
        Handshake message 1. Returns a challenge addressed to `peer_id`.

        The nonce and the timestamp are minted here, at send time. Building
        them in __init__ would give every handshake of this node's lifetime
        the same nonce and the same timestamp, which would defeat both the
        replay set and the freshness window.
        """
        challenge = {
            "protocol": "eureka/1.0",
            "event": "handshake_challenge",
            "initiator_id": self.node_id,
            "peer_id": peer_id,
            "nonce": secrets.token_hex(16),
            "timestamp": _utc_now().isoformat(),
        }
        # Keep our own copy: if the response echoes back a mutated challenge
        # we must still be able to compare it against what we actually sent.
        self.pending_challenges[challenge["nonce"]] = dict(challenge)
        # Bound the table on the way in. Issuing challenges is the one step an
        # unauthenticated peer can drive, so it is where growth is bounded.
        self.prune_expired()
        print(f"[NODE {self.node_id}] Challenge issued to {peer_id}")
        return challenge

    @staticmethod
    def validate_challenge(challenge: Any) -> None:
        """
        Raises InvalidChallengeError unless `challenge` is exactly a
        well-formed handshake challenge.

        This is the gate on the signing oracle. Without it answer_challenge
        signs any dict handed to it, so a caller could submit an audit-log or
        task-shaped payload as a "challenge" and walk away with this node's
        valid signature on it. Domain separation in crypto.py makes such a
        signature unusable in the log context; this check means it is never
        produced in the first place.
        """
        if not isinstance(challenge, dict):
            raise InvalidChallengeError(
                "not_a_mapping", f"got {type(challenge).__name__}"
            )

        keys = set(challenge)
        missing = CHALLENGE_REQUIRED_KEYS - keys
        if missing:
            raise InvalidChallengeError("missing_fields", ", ".join(sorted(missing)))

        # Reject unknown keys outright. Anything extra is either a payload
        # from another context or a field this version does not understand;
        # signing it blind is exactly the oracle being closed here.
        extra = keys - CHALLENGE_REQUIRED_KEYS
        if extra:
            raise InvalidChallengeError("unexpected_fields", ", ".join(sorted(extra)))

        if challenge["protocol"] != CHALLENGE_PROTOCOL:
            raise InvalidChallengeError(
                "wrong_protocol", repr(challenge["protocol"])
            )
        if challenge["event"] != CHALLENGE_EVENT:
            raise InvalidChallengeError("wrong_event", repr(challenge["event"]))

        for field in CHALLENGE_STRING_FIELDS:
            value = challenge[field]
            if not isinstance(value, str) or not value:
                raise InvalidChallengeError(
                    "bad_field_type",
                    f"{field} must be a non-empty string, got {type(value).__name__}",
                )

    def answer_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handshake message 2. Signs the challenge and returns the signature
        together with the public key needed to check it.

        Raises InvalidChallengeError without signing anything if the payload
        is not a well-formed challenge.
        """
        # Validate BEFORE any signing happens, so a rejected payload never
        # touches the private key.
        self.validate_challenge(challenge)
        return {
            "event": "handshake_response",
            "responder_id": self.node_id,
            "challenge": challenge,
            "signature": self.crypto.sign_handshake(challenge),
            "public_key": self.crypto.get_public_key_hex(),
        }

    @staticmethod
    def _parse_timestamp(timestamp: Any) -> Optional[datetime]:
        """Parse an ISO timestamp to an aware datetime, or None if unusable."""
        if not isinstance(timestamp, str):
            return None
        try:
            parsed = datetime.fromisoformat(timestamp)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            # Treat a naive timestamp as UTC rather than crashing on the
            # aware/naive subtraction done by callers.
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed

    def _challenge_age_seconds(self, timestamp: Any) -> Optional[float]:
        """Age of a challenge in seconds, or None if the timestamp is unusable."""
        sent_at = self._parse_timestamp(timestamp)
        if sent_at is None:
            return None
        return (_utc_now() - sent_at).total_seconds()

    @staticmethod
    def _evict_oldest(table: Dict[str, Any], limit: int) -> int:
        """Drop oldest entries (dicts keep insertion order) until within limit."""
        evicted = 0
        while len(table) > limit:
            del table[next(iter(table))]
            evicted += 1
        return evicted

    def _drop_pending(self, nonce: str) -> None:
        """
        Forget an outstanding challenge and anything provisionally attached.

        The two tables are always dropped together; leaving a provisional peer
        behind after its challenge is gone would be state nobody prunes.
        """
        self.pending_challenges.pop(nonce, None)
        self.pending_peers.pop(nonce, None)

    def _evict_oldest_pending(self, limit: int) -> int:
        """Cap enforcement for the paired pending tables."""
        evicted = 0
        while len(self.pending_challenges) > limit:
            self._drop_pending(next(iter(self.pending_challenges)))
            evicted += 1
        return evicted

    def prune_expired(self, now: Optional[datetime] = None) -> Dict[str, int]:
        """
        Drop handshake state that can no longer affect an authentication, then
        enforce the hard caps. Returns per-table counts so the effect is
        observable.

        Called inline from create_challenge and complete_handshake -- there is
        no background thread, so pruning is deterministic and a test can drive
        it by passing an explicit `now`.

        Dropping a spent nonce is safe: once it ages past the window its
        challenge is stale, and it was removed from pending_challenges when it
        was spent, so a replay is rejected as an unknown nonce instead.

        Both tables are scanned from the front only. Entries are inserted in
        time order, so everything expired forms a prefix and the scan can stop
        at the first live entry -- otherwise every call would re-parse the
        whole table and a flood of challenges would be quadratic. A back-dated
        entry in the middle simply survives until the cap evicts it; it can
        never authenticate, because the freshness check rejects it anyway.
        """
        now = now or _utc_now()
        cutoff = now - timedelta(seconds=self.freshness_seconds)

        pending_expired = 0
        while self.pending_challenges:
            nonce = next(iter(self.pending_challenges))
            issued = self._parse_timestamp(
                self.pending_challenges[nonce].get("timestamp")
            )
            # An unparseable timestamp can never pass the freshness check, so
            # it is dead weight and goes too.
            if issued is not None and issued >= cutoff:
                break
            self._drop_pending(nonce)
            pending_expired += 1

        nonces_expired = 0
        while self.seen_nonces:
            nonce = next(iter(self.seen_nonces))
            if self.seen_nonces[nonce] >= cutoff:
                break
            del self.seen_nonces[nonce]
            nonces_expired += 1

        return {
            "pending_expired": pending_expired,
            "pending_evicted": self._evict_oldest_pending(
                self.max_pending_challenges
            ),
            "nonces_expired": nonces_expired,
            "nonces_evicted": self._evict_oldest(
                self.seen_nonces, self.max_seen_nonces
            ),
        }

    def _handshake_result(self, authenticated: bool, reason: str,
                          peer_id: Optional[str] = None) -> Dict[str, Any]:
        return {
            "event": "handshake_established" if authenticated else "handshake_rejected",
            "authenticated": authenticated,
            "reason": reason,
            "session_id": self.session_id,
            "peer_id": peer_id,
            "auth_type": "Ed25519",
            "timestamp": _utc_now().isoformat(),
        }

    async def complete_handshake(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handshake message 2 arrives here. Verifies the response and records
        the peer as authenticated only if every check passes.

        `response` is untrusted input, so missing or wrongly typed fields are
        rejected as a protocol failure rather than raising.
        """
        await self.transition_to(EurekaState.HANDSHAKE)
        try:
            return self._evaluate_handshake_response(response)
        finally:
            # Prune AFTER evaluating, never before. Pruning first would delete
            # a stale-but-still-present challenge and downgrade a precise
            # "stale timestamp" rejection into a vague "unknown nonce".
            self.prune_expired()

    def _verify_challenge_reply(self, reply: Any, verifier, identity_field: str):
        """
        The single ordered check sequence, run by BOTH sides of the exchange.

        The initiator runs it over message 2 against the challenge it issued;
        the responder runs it over message 3 against the counter-challenge it
        issued. Same steps, same order, same reason constants -- the asymmetry
        is only which signing domain verifies and which field names the peer.

        Returns (rejection_result, nonce, public_key, peer_id). On success the
        rejection is None and the caller is responsible for recording; nothing
        here mutates state, so a failed check leaves no trace.
        """
        if not isinstance(reply, dict):
            return self._handshake_result(False, REASON_MALFORMED), None, None, None

        challenge = reply.get("challenge")
        if not isinstance(challenge, dict):
            return self._handshake_result(False, REASON_MALFORMED), None, None, None

        nonce = challenge.get("nonce")
        if not isinstance(nonce, str):
            return self._handshake_result(False, REASON_MALFORMED), None, None, None

        # 1. Replay: a nonce is single-use, even with a flawless signature.
        if nonce in self.seen_nonces:
            print(f"[NODE {self.node_id}] Rejected handshake: nonce already used")
            return (self._handshake_result(False, REASON_REPLAYED_NONCE),
                    nonce, None, None)

        # 2. The nonce must be one we actually issued and are still awaiting.
        pending = self.pending_challenges.get(nonce)
        if pending is None:
            return (self._handshake_result(False, REASON_UNKNOWN_NONCE),
                    nonce, None, None)

        peer_id = pending.get("peer_id")

        # 3. Freshness, checked against the timestamp that was signed.
        age = self._challenge_age_seconds(challenge.get("timestamp"))
        if age is None:
            return (self._handshake_result(False, REASON_MALFORMED, peer_id),
                    nonce, None, peer_id)
        if abs(age) > self.freshness_seconds:
            print(f"[NODE {self.node_id}] Rejected handshake: challenge {age:.1f}s old")
            return (self._handshake_result(False, REASON_STALE, peer_id),
                    nonce, None, peer_id)

        # 4. Signature over the exact challenge bytes the peer signed.
        signature = reply.get("signature")
        public_key = reply.get("public_key")
        if not isinstance(signature, str) or not isinstance(public_key, str):
            return (self._handshake_result(False, REASON_MALFORMED, peer_id),
                    nonce, None, peer_id)

        # Verified in this message's own domain: a signature harvested from
        # another position in the exchange covers different bytes and fails.
        if not verifier(public_key, signature, challenge):
            print(f"[NODE {self.node_id}] Rejected handshake: bad signature")
            return (self._handshake_result(False, REASON_BAD_SIGNATURE, peer_id),
                    nonce, public_key, peer_id)

        # 5. A valid signature only proves the peer signed *something*.
        #    It must be the challenge we sent, unaltered.
        if challenge != pending:
            return (self._handshake_result(False, REASON_CHALLENGE_MISMATCH, peer_id),
                    nonce, public_key, peer_id)

        # 6. ...and it must come from the peer we addressed, not a third party
        #    replaying a legitimately signed challenge under another name.
        if reply.get(identity_field) != peer_id:
            return (self._handshake_result(False, REASON_WRONG_PEER, peer_id),
                    nonce, public_key, peer_id)

        # 7. Finally: a valid signature only proves the peer holds the keypair
        #    it presented, and anyone can generate a keypair. The key must be
        #    one we were told to trust. This runs last, so a bad signature from
        #    a trusted key still reports the signature failure rather than
        #    being masked by a trust decision.
        if self.trust_list.is_revoked(public_key):
            print(f"[NODE {self.node_id}] Rejected handshake: revoked key")
            return (self._handshake_result(False, REASON_REVOKED_KEY, peer_id),
                    nonce, public_key, peer_id)

        if not self.trust_list.trusts(public_key):
            print(f"[NODE {self.node_id}] Rejected handshake: untrusted key")
            return (self._handshake_result(False, REASON_UNTRUSTED_KEY, peer_id),
                    nonce, public_key, peer_id)

        return None, nonce, public_key, peer_id

    def _record_peer(self, nonce: str, peer_id: str, public_key: str) -> Dict[str, Any]:
        """Spend the nonce and record the peer. Only ever called after every
        check in _verify_challenge_reply has passed."""
        # Removing it from pending_challenges is what actually prevents reuse;
        # seen_nonces additionally gives replays a precise rejection reason.
        self.seen_nonces[nonce] = _utc_now()
        self._drop_pending(nonce)
        self.peers[peer_id] = {
            "public_key": public_key,
            "last_seen": time.time(),
            "status": "authenticated",
            # A snapshot for introspection only. Authorisation decisions read
            # the live trust list, so revoking a grant takes effect without
            # waiting for the peer to handshake again.
            "capabilities": sorted(self.trust_list.capabilities_for(public_key)),
        }
        print(f"[NODE {self.node_id}] Handshake established with {peer_id}")
        return self._handshake_result(True, REASON_OK, peer_id)

    # ------------------------------------------------------------------
    # Capability enforcement
    # ------------------------------------------------------------------

    def granted_capabilities(self, peer_id: object) -> Set[str]:
        """
        What an authenticated peer may actually ask of this node.

        Two gates, both of which must pass:
          1. the peer's key holds the grant in our trust list, and
          2. this node actually offers that capability.

        The second gate is why the advertised capability list stops being
        decorative: a node cannot grant away something it does not have, so a
        stale or over-broad trust file cannot widen what a peer can reach.

        Reads the live trust list rather than the snapshot taken at handshake
        time, so a revoked grant takes effect immediately.
        """
        if not isinstance(peer_id, str):
            return set()
        record = self.peers.get(peer_id)
        # Default deny: unknown peer, or one not authenticated.
        if not record or record.get("status") != "authenticated":
            return set()
        granted = self.trust_list.capabilities_for(record.get("public_key"))
        return set(granted) & set(self.capabilities)

    def reload_trust(self) -> Dict[str, Any]:
        """
        Re-read the trust file, applying revocations to live sessions.

        This is how a revocation reaches a running daemon. Peers whose key is
        now revoked -- or simply no longer listed -- are dropped from the peer
        table, so a revoked peer is not left sitting there marked
        "authenticated" with an empty grant set.

        On a bad file the old list is kept and TrustError is raised. That is
        the honest failure: the caller must treat it as an error and not as a
        warning, because the revocation it was trying to apply has NOT been
        applied. Keeping the old list only avoids adding a second failure --
        dropping every peer -- on top of the first.
        """
        if self._trust_list_injected:
            raise TrustError(
                "this node's trust list was injected directly; "
                "there is no trust file to reload"
            )
        # Raises before anything is swapped in, so a corrupt file leaves the
        # node exactly as it was.
        reloaded = TrustList.load_or_empty(
            self.trust_path, advertised=self.capabilities
        )
        self.trust_list = reloaded

        dropped = []
        for peer_id, record in list(self.peers.items()):
            public_key = record.get("public_key")
            if reloaded.is_revoked(public_key):
                dropped.append({"peer_id": peer_id, "reason": REASON_REVOKED_KEY})
                del self.peers[peer_id]
            elif not reloaded.trusts(public_key):
                dropped.append({"peer_id": peer_id, "reason": REASON_UNTRUSTED_KEY})
                del self.peers[peer_id]
        for entry in dropped:
            print(f"[NODE {self.node_id}] Dropped peer {entry['peer_id']}: "
                  f"{entry['reason']}")
        return {
            "peers": len(reloaded),
            "revoked": len(list(reloaded.revocations())),
            "dropped": dropped,
        }

    def is_permitted(self, peer_id: object, capability: object) -> bool:
        """
        Default-deny authorisation check for a single capability.

        Everything unknown answers False: an unknown peer, an unauthenticated
        one, an ungranted capability, and a capability this node does not
        offer.
        """
        if not isinstance(capability, str) or not capability.strip():
            return False
        return capability.strip() in self.granted_capabilities(peer_id)

    def _evaluate_handshake_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Initiator side: verify message 2 and record the responder.

        Recording here is correct even though the responder has not yet
        verified us: a node records a peer once *its own* verification of that
        peer has passed. Our own proof travels in message 3.
        """
        rejection, nonce, public_key, peer_id = self._verify_challenge_reply(
            response, EurekaCrypto.verify_handshake, "responder_id"
        )
        if rejection is not None:
            return rejection
        return self._record_peer(nonce, peer_id, public_key)

    # ------------------------------------------------------------------
    # Message 1 (initiator -> responder) and message 3 (initiator -> responder)
    # ------------------------------------------------------------------

    def create_handshake_offer(self, peer_id: str) -> Dict[str, Any]:
        """
        Message 1. A challenge the initiator signs, carrying its public key so
        the responder can check the signature and look the key up in its own
        trust list.
        """
        challenge = self.create_challenge(peer_id)
        return {
            "event": "handshake_offer",
            "initiator_id": self.node_id,
            "challenge": challenge,
            "public_key": self.crypto.get_public_key_hex(),
            "signature": self.crypto.sign_handshake_offer(challenge),
        }

    def answer_handshake_offer(self, offer: Any) -> Dict[str, Any]:
        """
        Responder side: check message 1, then reply with message 2.

        Returns either message 2 or a rejection result (``authenticated`` is
        False). The trust check happens here, before any counter-challenge is
        minted, so an initiator we do not trust never gets a reply to verify
        and neither side ends up half-authenticated.
        """
        if not isinstance(offer, dict):
            return self._handshake_result(False, REASON_MALFORMED)

        challenge = offer.get("challenge")
        # Schema first, exactly as answer_challenge does -- we will not sign
        # or act on anything that is not a well-formed challenge.
        try:
            self.validate_challenge(challenge)
        except InvalidChallengeError:
            return self._handshake_result(False, REASON_MALFORMED)

        nonce = challenge["nonce"]
        peer_id = offer.get("initiator_id")

        # Replay: an offer nonce is single-use here too, which also stops a
        # captured message 1 being replayed at us later.
        if nonce in self.seen_nonces:
            return self._handshake_result(False, REASON_REPLAYED_NONCE, peer_id)

        # Freshness of the timestamp the initiator signed.
        age = self._challenge_age_seconds(challenge["timestamp"])
        if age is None:
            return self._handshake_result(False, REASON_MALFORMED, peer_id)
        if abs(age) > self.freshness_seconds:
            return self._handshake_result(False, REASON_STALE, peer_id)

        signature = offer.get("signature")
        public_key = offer.get("public_key")
        if not isinstance(signature, str) or not isinstance(public_key, str):
            return self._handshake_result(False, REASON_MALFORMED, peer_id)

        if not EurekaCrypto.verify_handshake_offer(public_key, signature, challenge):
            return self._handshake_result(False, REASON_BAD_SIGNATURE, peer_id)

        # The envelope must agree with the challenge about who is calling.
        if peer_id != challenge["initiator_id"]:
            return self._handshake_result(False, REASON_WRONG_PEER, peer_id)

        # Trust last, same as everywhere else.
        if self.trust_list.is_revoked(public_key):
            print(f"[NODE {self.node_id}] Rejected offer: revoked key")
            return self._handshake_result(False, REASON_REVOKED_KEY, peer_id)

        if not self.trust_list.trusts(public_key):
            print(f"[NODE {self.node_id}] Rejected offer: untrusted key")
            return self._handshake_result(False, REASON_UNTRUSTED_KEY, peer_id)

        # Provisional only. Nothing is authenticated until message 3 verifies.
        self.seen_nonces[nonce] = _utc_now()
        counter_challenge = self.create_challenge(peer_id)
        self.pending_peers[counter_challenge["nonce"]] = {
            "peer_id": peer_id,
            "public_key": public_key,
        }

        message_two = self.answer_challenge(challenge)
        message_two["counter_challenge"] = counter_challenge
        return message_two

    def confirm_handshake(self, response: Any) -> Dict[str, Any]:
        """
        Message 3. Signs the responder's counter-challenge, proving to the
        responder that we hold the key we advertised in message 1.
        """
        if not isinstance(response, dict):
            raise InvalidChallengeError("not_a_mapping",
                                        f"got {type(response).__name__}")
        counter_challenge = response.get("counter_challenge")
        # Same gate as answer_challenge: never sign an arbitrary payload.
        self.validate_challenge(counter_challenge)
        return {
            "event": "handshake_confirm",
            "initiator_id": self.node_id,
            "challenge": counter_challenge,
            "public_key": self.crypto.get_public_key_hex(),
            "signature": self.crypto.sign_handshake_confirm(counter_challenge),
        }

    async def complete_mutual_handshake(self, confirmation: Any) -> Dict[str, Any]:
        """
        Responder side: verify message 3 and record the initiator.

        Runs the same check sequence the initiator ran over message 2. On any
        failure the peer provisionally seen in message 1 is discarded.
        """
        await self.transition_to(EurekaState.HANDSHAKE)
        try:
            rejection, nonce, public_key, peer_id = self._verify_challenge_reply(
                confirmation, EurekaCrypto.verify_handshake_confirm, "initiator_id"
            )
            if rejection is not None:
                if nonce is not None:
                    # Discard the provisional peer from message 1.
                    self._drop_pending(nonce)
                return rejection

            # The key that finished the exchange must be the key that started
            # it, otherwise a peer could open with one trusted identity and
            # prove possession of a different one.
            provisional = self.pending_peers.get(nonce)
            if provisional is not None and provisional["public_key"] != public_key:
                self._drop_pending(nonce)
                return self._handshake_result(False, REASON_WRONG_PEER, peer_id)

            return self._record_peer(nonce, peer_id, public_key)
        finally:
            # Prune AFTER evaluating, for the same reason complete_handshake
            # does: pruning first would downgrade a precise rejection.
            self.prune_expired()

    async def handshake(self, responder: "EurekaNode") -> Dict[str, Any]:
        """
        Convenience driver that runs the full three-message exchange in
        process. Real transports call create_handshake_offer /
        answer_handshake_offer / complete_handshake / confirm_handshake /
        complete_mutual_handshake separately across the network.

        Returns this node's own result. When the responder is the one that
        rejects, its rejection is returned so the reason is not lost.
        """
        offer = self.create_handshake_offer(responder.node_id)

        message_two = responder.answer_handshake_offer(offer)
        if message_two.get("authenticated") is False:
            # The responder refused message 1; we never get anything to
            # verify, so neither side records anything.
            return message_two

        mine = await self.complete_handshake(message_two)
        if not mine["authenticated"]:
            return mine

        confirmation = self.confirm_handshake(message_two)
        theirs = await responder.complete_mutual_handshake(confirmation)
        if not theirs["authenticated"]:
            return theirs

        mine["mutual"] = True
        return mine

    async def assign(self, task_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Layer 4: Task negotiation and execution dispatch."""
        await self.transition_to(EurekaState.ASSIGN)
        task_id = str(uuid.uuid4())
        print(f"[NODE {self.node_id}] Dispatching task: {task_payload.get('task_name', 'unnamed')}")
        
        # Simulate task execution delay
        await asyncio.sleep(0.5) 
        
        result = {
            "task_id": task_id,
            "status": "completed",
            "output": f"Processed by {self.node_id}",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        # Trigger the Log layer immediately after assignment completion
        await self.log_event(task_payload, result)
        return result

    async def log_event(self, task_info: Dict[str, Any], result_info: Dict[str, Any]):
        """Layer 5: Cryptographically signed audit trail generation."""
        await self.transition_to(EurekaState.LOG)
        
        log_entry = {
            "protocol": "eureka/1.0",
            "event": "task_execution_complete",
            "session_id": self.session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "initiator_node": self.node_id,
            "task_summary": task_info.get("task_name", "unknown"),
            "result": result_info["status"]
        }
        
        # Audit-log domain: this signature is structurally unusable as a
        # handshake signature, and a handshake signature is unusable here.
        signature = self.crypto.sign_audit_log(log_entry)
        signed_log = {
            "payload": log_entry,
            "signature": signature,
            "auth_type": "Ed25519"
        }
        
        self.event_log.append(signed_log)
        print(f"[NODE {self.node_id}] EUREKA-LOG generated for task {task_info.get('task_name')}")
        return signed_log

def crypto_async_wrapper(crypto):
    """Helper to wrap synchronous crypto calls if needed for async compatibility."""
    # In this MVD, we'll keep it simple as the crypto ops are non-blocking CPU tasks
    return crypto

if __name__ == "__main__":
    import asyncio
    from crypto import EurekaCrypto
    
    async def test():
        c = EurekaCrypto()
        node = EurekaNode("test_node_01", c, ["code-exec"])
        print(f"Initialized Node: {node.node_im_testing_this_hard}") # Just a placeholder to check init
    
    # Note: This file is intended to be imported by server.py
    pass
