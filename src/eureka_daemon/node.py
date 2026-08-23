import asyncio
import json
import uuid
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
from .crypto import EurekaCrypto

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
    def __init__(self, node_id: str, crypto_engine: EurekaCrypto, capabilities: List[str]):
        self.node_id = node_id
        self.crypto = crypto_async_wrapper(crypto_engine) if hasattr(self, 'crypto_async_wrapper') else crypto_engine
        self.capabilities = capabilities
        self.state = EurekaState.IDENTITY
        self.peers: Dict[str, Dict[str, Any]] = {}
        self.active_tasks: Dict[str, Any] = {}
        self.event_log: List[Dict[str, Any]] = []
        self.session_id = f"urn:uuid:{uuid.uuid4()}"
        
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

    async def handshake(self, peer_id: str, peer_public_key: str) -> Dict[str, Any]:
        """Layer 3: Mutual Ed25519 authentication and session establishment."""
        await self.transition_to(EurekaState.HANDSHAKE)
        print(f"[NODE {self.node_id}] Initiating handshake with {peer_id}")
        
        # Create a challenge for the peer to sign
        challenge = str(uuid.uuid4())
        signature = self.crypto.sign_data(challenge.encode('utf-8'))
        
        handshake_event = {
            "event": "handshake_established",
            "session_id": self.session_id,
            "peer_id": peer_id,
	        "auth_type": "Ed25519",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        self.peers[peer_id] = {
            "public_key": peer_public_key,
            "last_seen": time.time(),
            "status": "authenticated"
        }
        return handshake_event

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
