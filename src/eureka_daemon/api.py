import json
import traceback
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional, Tuple
import uvicorn
from . import assign, discovery, reads
from .handlers import default_registry
from .node import EurekaNode, EurekaState, REASON_MALFORMED
from .crypto import EurekaCrypto

# A handshake message is a few hundred bytes. The cap is generous enough for
# any legitimate message and small enough that an unauthenticated peer cannot
# make us allocate anything meaningful -- the body is refused on the way in,
# before it is buffered or parsed.
MAX_REQUEST_BODY_BYTES = 64 * 1024

# Define API Request/Response Schemas
class NodeManifest(BaseModel):
    """
    The open manifest. Deliberately two fields.

    node_id and runtime only. The capability list moved to the authenticated
    read (POST /v1/manifest), because it says what this node can be asked to
    do and nothing in the handshake needs it.
    """
    node_id: str
    runtime: str

def create_app(node_engine: EurekaNode) -> FastAPI:
    """
    Build the daemon API for one node.

    A factory rather than a module-level app because a node is not a global:
    discovery only means anything with several nodes talking to each other, and
    testing that against real ASGI apps -- real JSON, real signatures, real
    rejections -- is worth more than testing it against mocks. The module-level
    `app` below is still the single node a deployed daemon serves.
    """
    app = FastAPI(title="Eureka Protocol Daemon API")

    @app.on_event("startup")
    async def startup_event():
        print(f"🚀 Eureka Daemon API Starting for {node_engine.node_id}")
        # Automatically trigger the initial Beacon layer on startup
        await node_engine.beacon()

    @app.get("/v1/manifest", response_model=NodeManifest)
    async def get_manifest():
        """
        This node's identity, readable without authenticating. The one open
        endpoint, and it stays open on purpose.

        Requiring authentication here would be circular: a caller fetches the
        manifest to learn the node_id it must address its handshake offer to,
        so gating it behind a completed handshake would mean no first contact
        could ever happen. That is the acceptance criterion this route exists
        to satisfy.

        What it discloses is bounded to two things, and neither is a secret
        this daemon was holding:

          * node_id, which is a pure function of the public key -- sha256 of
            it, truncated. Over TLS the certificate hands that same public key
            to anyone who completes a connection, so node_id tells a stranger
            nothing the transport has not already told them. Withholding it
            would hide nothing and break first contact.
          * runtime, a constant string identical on every node.

        What it no longer discloses is the capability list. That was a real
        leak -- it told any caller what this node can be asked to do -- and
        nothing in the handshake reads it: client.py takes node_id from here
        and granted_capabilities() intersects locally, on the responder. It is
        served to authenticated peers by POST to this same path.

        The peer table is not here and never was reachable from here. Learning
        that this node exists is not learning who it talks to.
        """
        return {
            "node_id": node_engine.node_id,
            "runtime": "eureka-daemon-mvd"
        }

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


    @app.post("/v1/discovery/addresses")
    async def discovery_addresses(request: Request):
        """
        Peer discovery: the caller names keys, we answer for the ones we share.

        Served only to a peer that has completed a handshake, and only for keys
        it asked about and we also trust -- so this never reveals that a peer
        the caller does not know about exists. See discovery.py for why the
        query has to be caller-driven.
        """
        document, error = await _read_json_body(request)
        if error is not None:
            return error
        try:
            return JSONResponse(
                status_code=200,
                content=discovery.answer_query(node_engine, document),
            )
        except Exception as exc:
            print(f"[API] Unhandled error in discovery_addresses: "
                  f"{type(exc).__name__}: {exc}")
            return JSONResponse(
                status_code=200,
                content=discovery.rejected(REASON_MALFORMED),
            )

    # ---------------------------------------------------------------------------
    # Authenticated reads
    #
    # POST, not GET, for the same reason discovery is a POST: the request
    # carries a signed body, and a signature is what makes the caller someone.
    # A GET on these paths gets a 405 from the router before any handler runs,
    # which is the strongest possible answer to an unauthenticated read --
    # nothing about this node's records is consulted to produce it.
    #
    # Each returns 200 whatever the verdict, exactly as the handshake does: a
    # refusal is a protocol outcome, not a transport error, and a status code
    # that varied with the verdict would be a side channel of its own.
    # ---------------------------------------------------------------------------

    async def _authenticated_read(request: Request, event: str) -> JSONResponse:
        """Shared plumbing for the three read routes."""
        document, error = await _read_json_body(request)
        if error is not None:
            # A body that is not well-formed at all never reached the protocol.
            # Answer in the read vocabulary rather than the handshake's.
            return JSONResponse(status_code=error.status_code,
                                content=reads.rejected(event, REASON_MALFORMED))
        try:
            return JSONResponse(
                status_code=200,
                content=reads.ANSWER[event](node_engine, document),
            )
        except Exception as exc:
            print(f"[API] Unhandled error in read {event}: "
                  f"{type(exc).__name__}: {exc}")
            # The refusal is built from the event alone, so even this path
            # cannot leak whether there was anything to read.
            return JSONResponse(status_code=200,
                                content=reads.rejected(event, REASON_MALFORMED))

    @app.post("/v1/peers")
    async def read_peers(request: Request):
        """
        The peer table, to an authenticated caller, for the keys it named.

        This is the endpoint the whole change is about. The peer table is the
        record of who this node talks to, and publishing it to any caller that
        could reach the port contradicted the one property the protocol claims
        -- in the running daemon, which is the only place it counts.
        """
        return await _authenticated_read(request, reads.PEERS_EVENT)

    @app.post("/v1/logs")
    async def read_logs(request: Request):
        """Audit-log entries attributable to the calling peer, and no others."""
        return await _authenticated_read(request, reads.LOGS_EVENT)

    @app.post("/v1/manifest")
    async def read_manifest(request: Request):
        """The full manifest, capability list included, for an authenticated peer."""
        return await _authenticated_read(request, reads.MANIFEST_EVENT)

    @app.post("/v1/assign")
    async def assign_task(request: Request):
        """
        Run a task: signed request, authenticated peer, capability grant.

        This was the last open endpoint on the daemon -- an unauthenticated
        POST straight into the dispatch stub. It now passes the same gate the
        reads do, plus authorization and a single-use nonce; see assign.py for
        the order and why it matters. Behind the gate is the handler registry,
        which for this daemon means web-retrieval and nothing else.

        The answer carries a signature over the result in the assign-result
        domain. The catch-all below cannot: it is the same constant refusal
        every other endpoint falls back to, and signing a constant would say
        nothing while making refusals tellable apart by their signature.
        """
        document, error = await _read_json_body(request)
        if error is not None:
            return JSONResponse(status_code=error.status_code,
                                content=assign.rejected(REASON_MALFORMED))
        try:
            return JSONResponse(
                status_code=200,
                content=await assign.answer_assign(node_engine, document),
            )
        except Exception as exc:
            print(f"[API] Unhandled error in assign: "
                  f"{type(exc).__name__}: {exc}")
            # Built from the reason alone; even this path discloses nothing.
            return JSONResponse(status_code=200,
                                content=assign.rejected(REASON_MALFORMED))

    return app


# The identity is loaded from disk (created on first run), so restarting the
# daemon brings the same node back rather than minting a new one. Override the
# location with $EUREKA_IDENTITY_PATH.
#
# The advertised capability list is NOT written here any more. It is derived
# from the handler registry, which is the only thing that knows what this node
# can actually do -- so the list cannot drift from the code, and a capability
# with no handler cannot be advertised at all. That is why this line no longer
# says code-exec and data-analysis: nothing here runs them.
#
# Passing an explicit list alongside a registry is still allowed and is
# validated against it, which is the startup error this arrangement exists to
# produce: add "code-exec" here and the daemon does not start, rather than
# telling a granted peer yes and handing it nothing.
node_engine = EurekaNode.with_persistent_identity(handlers=default_registry())
crypto_engine = node_engine.crypto
app = create_app(node_engine)


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    uvicorn.run(app, host="0.0.0.0", port=port)
