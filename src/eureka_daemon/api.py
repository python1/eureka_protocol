import json
import traceback
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional, Tuple
import uvicorn
from .node import EurekaNode, EurekaState, REASON_MALFORMED
from .crypto import EurekaCrypto

# A handshake message is a few hundred bytes. The cap is generous enough for
# any legitimate message and small enough that an unauthenticated peer cannot
# make us allocate anything meaningful -- the body is refused on the way in,
# before it is buffered or parsed.
MAX_REQUEST_BODY_BYTES = 64 * 1024

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
# The identity is loaded from disk (created on first run), so restarting the
# daemon brings the same node back rather than minting a new one. Override the
# location with $EUREKA_IDENTITY_PATH.
node_engine = EurekaNode.with_persistent_identity(
    capabilities=["code-exec", "web-retrieval", "data-analysis"]
)
crypto_engine = node_engine.crypto

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

# ---------------------------------------------------------------------------
# Handshake transport
#
# These two endpoints carry the three-message mutual handshake over HTTP. The
# bodies are untrusted, so they are read under a size cap and parsed by hand
# rather than through a pydantic model: a model would coerce and re-shape the
# payload, and the payload is the exact thing a signature was computed over.
# Anything that alters those bytes breaks every signature in the exchange.
# ---------------------------------------------------------------------------

def _rejection(reason: str, status_code: int) -> JSONResponse:
    """A transport-level refusal, in the same shape the protocol uses."""
    return JSONResponse(
        status_code=status_code,
        content={
            "event": "handshake_rejected",
            "authenticated": False,
            "reason": reason,
            "peer_id": None,
            "auth_type": "Ed25519",
        },
    )


async def _read_json_body(request: Request) -> Tuple[Any, Optional[JSONResponse]]:
    """
    Read a request body under the size cap and parse it as JSON.

    Returns (document, None) or (None, error_response). The stream is abandoned
    as soon as the cap is passed, so an oversized body is refused before it is
    buffered and long before anything tries to parse it.
    """
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > MAX_REQUEST_BODY_BYTES:
                return None, _rejection(REASON_MALFORMED, 413)
        except ValueError:
            return None, _rejection(REASON_MALFORMED, 400)

    chunks = []
    received = 0
    try:
        async for chunk in request.stream():
            received += len(chunk)
            if received > MAX_REQUEST_BODY_BYTES:
                # Stop reading; do not buffer the rest.
                return None, _rejection(REASON_MALFORMED, 413)
            chunks.append(chunk)
    except Exception:
        return None, _rejection(REASON_MALFORMED, 400)

    try:
        return json.loads(b"".join(chunks)), None
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Not well-formed at all: this never reached the protocol.
        return None, _rejection(REASON_MALFORMED, 400)


def _protocol_failure(where: str, exc: BaseException) -> JSONResponse:
    """
    Last-resort guard so a malformed peer message can never return a 500 or
    leak a traceback. The detail is logged locally and never sent back.

    This is deliberately broader than the library code, which lets unexpected
    errors propagate: at a network boundary an unhandled exception is a denial
    of service and an information leak, not a useful crash.
    """
    print(f"[API] Unhandled error in {where}: {type(exc).__name__}: {exc}")
    traceback.print_exc()
    return _rejection(REASON_MALFORMED, 200)


@app.post("/v1/handshake/offer")
async def handshake_offer(request: Request):
    """
    Message 1 in, message 2 out.

    A completed exchange returns 200 whatever the verdict -- an authentication
    failure is a protocol outcome, not a transport error. Only a body that is
    not well-formed at all gets a 4xx.
    """
    document, error = await _read_json_body(request)
    if error is not None:
        return error
    try:
        return JSONResponse(
            status_code=200,
            content=node_engine.answer_handshake_offer(document),
        )
    except Exception as exc:
        return _protocol_failure("handshake_offer", exc)


@app.post("/v1/handshake/confirm")
async def handshake_confirm(request: Request):
    """Message 3 in, the responder's own verdict out."""
    document, error = await _read_json_body(request)
    if error is not None:
        return error
    try:
        return JSONResponse(
            status_code=200,
            content=await node_engine.complete_mutual_handshake(document),
        )
    except Exception as exc:
        return _protocol_failure("handshake_confirm", exc)


@app.get("/v1/logs")
async def get_logs():
    """Retrietes the cryptographically signed EUREKA-LOG entries."""
    return {"logs": node_engine.event_log}

if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    uvicorn.run(app, host="0.0.0.0", port=port)
