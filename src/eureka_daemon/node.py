import asyncio
import json
import secrets
import uuid
import time
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, List, Optional, Any, Set
from .crypto import EurekaCrypto

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
    def __init__(self, node_id: str, crypto_engine: EurekaCrypto, capabilities: List[str],
                 freshness_seconds: float = HANDSHAKE_FRESHNESS_SECONDS,
                 max_pending_challenges: int = MAX_PENDING_CHALLENGES,
                 max_seen_nonces: int = MAX_SEEN_NONCES):
        self.node_id = node_id
        self.crypto = crypto_async_wrapper(crypto_engine) if hasattr(self, 'crypto_async_wrapper') else crypto_engine
        self.capabilities = capabilities
        self.state = EurekaState.IDENTITY
        self.peers: Dict[str, Dict[str, Any]] = {}
        self.active_tasks: Dict[str, Any] = {}
        self.event_log: List[Dict[str, Any]] = []
        self.session_id = f"urn:uuid:{uuid.uuid4()}"

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
        
        # Manifest of this node's capabilities
        self.manifest = {
            "node_id": self.node_id,
            "runtime": "eureka-daemon",
            "capabilities": self.capabilities,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

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
            del self.pending_challenges[nonce]
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
            "pending_evicted": self._evict_oldest(
                self.pending_challenges, self.max_pending_challenges
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

    def _evaluate_handshake_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """The ordered handshake checks. Sync, so pruning can wrap the call."""
        if not isinstance(response, dict):
            return self._handshake_result(False, REASON_MALFORMED)

        challenge = response.get("challenge")
        if not isinstance(challenge, dict):
            return self._handshake_result(False, REASON_MALFORMED)

        nonce = challenge.get("nonce")
        if not isinstance(nonce, str):
            return self._handshake_result(False, REASON_MALFORMED)

        # 1. Replay: a nonce is single-use, even with a flawless signature.
        if nonce in self.seen_nonces:
            print(f"[NODE {self.node_id}] Rejected handshake: nonce already used")
            return self._handshake_result(False, REASON_REPLAYED_NONCE)

        # 2. The nonce must be one we actually issued and are still awaiting.
        pending = self.pending_challenges.get(nonce)
        if pending is None:
            return self._handshake_result(False, REASON_UNKNOWN_NONCE)

        peer_id = pending.get("peer_id")

        # 3. Freshness, checked against the timestamp that was signed.
        age = self._challenge_age_seconds(challenge.get("timestamp"))
        if age is None:
            return self._handshake_result(False, REASON_MALFORMED, peer_id)
        if abs(age) > self.freshness_seconds:
            print(f"[NODE {self.node_id}] Rejected handshake: challenge {age:.1f}s old")
            return self._handshake_result(False, REASON_STALE, peer_id)

        # 4. Signature over the exact challenge bytes the responder signed.
        signature = response.get("signature")
        public_key = response.get("public_key")
        if not isinstance(signature, str) or not isinstance(public_key, str):
            return self._handshake_result(False, REASON_MALFORMED, peer_id)

        # Verified in the handshake domain: a signature minted for the audit
        # log covers different bytes and will not verify here.
        if not EurekaCrypto.verify_handshake(public_key, signature, challenge):
            print(f"[NODE {self.node_id}] Rejected handshake: bad signature")
            return self._handshake_result(False, REASON_BAD_SIGNATURE, peer_id)

        # 5. A valid signature only proves the responder signed *something*.
        #    It must be the challenge we sent, unaltered.
        if challenge != pending:
            return self._handshake_result(False, REASON_CHALLENGE_MISMATCH, peer_id)

        # 6. ...and it must come from the peer we addressed, not a third party
        #    replaying a legitimately signed challenge under another name.
        if response.get("responder_id") != peer_id:
            return self._handshake_result(False, REASON_WRONG_RESPONDER, peer_id)

        # Every check passed: spend the nonce and record the peer.
        # Removing it from pending_challenges is what actually prevents reuse;
        # seen_nonces additionally gives replays a precise rejection reason.
        self.seen_nonces[nonce] = _utc_now()
        self.pending_challenges.pop(nonce, None)
        self.peers[peer_id] = {
            "public_key": public_key,
            "last_seen": time.time(),
            "status": "authenticated",
        }
        print(f"[NODE {self.node_id}] Handshake established with {peer_id}")
        return self._handshake_result(True, REASON_OK, peer_id)

    async def handshake(self, responder: "EurekaNode") -> Dict[str, Any]:
        """
        Convenience driver that runs the full two-message exchange in process.
        Real transports call create_challenge / answer_challenge /
        complete_handshake separately across the network.
        """
        challenge = self.create_challenge(responder.node_id)
        response = responder.answer_challenge(challenge)
        return await self.complete_handshake(response)

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
