import asyncio
import json
import secrets
import uuid
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any, Set
from .crypto import EurekaCrypto

# Default window a challenge stays valid for, in seconds. A response that
# arrives outside this window is rejected even if its signature is perfect,
# which is what stops a captured handshake being replayed later.
HANDSHAKE_FRESHNESS_SECONDS = 30.0

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
                 freshness_seconds: float = HANDSHAKE_FRESHNESS_SECONDS):
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
        # Challenges we have issued and are still waiting on, keyed by nonce.
        self.pending_challenges: Dict[str, Dict[str, Any]] = {}
        # Nonces already spent. A nonce is single-use: once it completes a
        # handshake it can never authenticate another one.
        self.seen_nonces: Set[str] = set()
        
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
        print(f"[NODE {self.node_id}] Challenge issued to {peer_id}")
        return challenge

    def answer_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handshake message 2. Signs the challenge verbatim and returns the
        signature together with the public key needed to check it.
        """
        return {
            "event": "handshake_response",
            "responder_id": self.node_id,
            "challenge": challenge,
            "signature": self.crypto.sign_json(challenge),
            "public_key": self.crypto.get_public_key_hex(),
        }

    def _challenge_age_seconds(self, timestamp: Any) -> Optional[float]:
        """Age of a challenge in seconds, or None if the timestamp is unusable."""
        if not isinstance(timestamp, str):
            return None
        try:
            sent_at = datetime.fromisoformat(timestamp)
        except ValueError:
            return None
        if sent_at.tzinfo is None:
            # Treat a naive timestamp as UTC rather than crashing on the
            # aware/naive subtraction below.
            sent_at = sent_at.replace(tzinfo=timezone.utc)
        return (_utc_now() - sent_at).total_seconds()

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

        if not EurekaCrypto.verify_json(public_key, signature, challenge):
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
        self.seen_nonces.add(nonce)
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
        
        signature = self.crypto.sign_json(log_entry)
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
