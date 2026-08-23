import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import uvicorn
from .node import EurekaNode, EurekaState
from .crypto import EurekaCrypto

# Define API Request/Response Schemas
class TaskRequest(BaseModel):
    task_name: str
    payload: Dict[str, Any]

class PeerInfo(BaseModel):
    peer_id: str
    status: str

class NodeManifest(BaseModel):
    node_id: str
    capabilities: List[str]
    runtime: str

# Initialize the API and the Underlying Protocol Engine
app = FastAPI(title="Eureka Protocol Daemon API")
crypto_engine = EurekaCrypto()
# In a real deployment, node_id would come from env/config
node_engine = EurekaNode(
    node_id=f"node_{os.urandom(4).hex()}",
    crypto_engine=crypto_engine, 
    capabilities=["code-exec", "web-retrieval", "data-analysis"]
)

@app.on_event("startup")
async def startup_event():
    print(f"🚀 Eureka Daemon API Starting for {node_engine.node_id}")
    # Automatically trigger the initial Beacon layer on startup
    await node_engine.beacon()

@app.get("/v1/manifest", response_model=NodeManifest)
async def get_manifest():
    """Returns the capability manifest of this local node."""
    return {
        "node_id": node_engine.node_id,
        "capabilities": node_engine.capabilities,
        "runtime": "eureka-daemon-mvd"
    }

@app.get("/v1/peers", response_model=List[PeerInfo])
async def get_peers():
    """Returns a list of all authenticated peers in the registry."""
    return [
        {"peer_id": pid, "status": info["status"]} 
        for pid, info in node_engine.peers.items()
    ]

@app.post("/v1/assign")
async def assign_task(request: TaskRequest):
    """Dispatches a new task to the engine for execution."""
    if not request.task_name:
        raise HTTPException(status_code=400, detail="task_name is required")
    
    try:
        result = await node_engine.assign({"task_name": request.task_name, "payload": request.payload})
        return {"status": "success", "execution_result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/v1/logs")
async def get_logs():
    """Retrietes the cryptographically signed EUREKA-LOG entries."""
    return {"logs": node_engine.event_log}

if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    uvicorn.run(app, host="0.0.0.0", port=port)
