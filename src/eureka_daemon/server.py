"""
Daemon entry point.

TLS is opt-in via --tls. When it is on, the certificate served is generated
from the node's existing identity key, so peers pin the same key they already
have in their trust file and nothing new has to be distributed.
"""
import argparse
import asyncio
import ssl

import uvicorn

from .api import app, node_engine
from .tls import ensure_server_materials


def build_config(port: int, use_tls: bool, materials_dir=None) -> uvicorn.Config:
    """
    The uvicorn config for this node, with TLS wired to its identity.

    Kept separate from main() so the wiring can be tested without binding a
    socket -- in particular that TLS actually serves the node's own key.
    """
    options = dict(app=app, host="0.0.0.0", port=port, log_level="info")
    if use_tls:
        cert_path, key_path = ensure_server_materials(
            node_engine.crypto, node_engine.node_id, materials_dir
        )
        options.update(
            ssl_certfile=str(cert_path),
            ssl_keyfile=str(key_path),
            # No client certificates. Callers are authenticated by the ed25519
            # handshake, which already consults the trust list and its
            # revocations; requiring client certs would move that decision into
            # a CA store read once at startup, where reload_trust() cannot
            # reach it.
            ssl_cert_reqs=ssl.CERT_NONE,
            ssl_version=ssl.PROTOCOL_TLS_SERVER,
        )
    return uvicorn.Config(**options)


async def main() -> None:
    parser = argparse.ArgumentParser(description="Eureka Protocol daemon")
    parser.add_argument("port", nargs="?", type=int, default=8000)
    parser.add_argument("--tls", action="store_true",
                        help="serve HTTPS using the node's own identity key")
    parser.add_argument("--tls-dir", default=None,
                        help="where to write the certificate and key "
                             "(default: beside the identity file)")
    arguments = parser.parse_args()

    config = build_config(arguments.port, arguments.tls, arguments.tls_dir)
    scheme = "https" if arguments.tls else "http"
    print(f"Starting Eureka Daemon API on {scheme}://0.0.0.0:{arguments.port} "
          f"as {node_engine.node_id}")
    if arguments.tls:
        print(f"Peers should pin: {node_engine.public_key_hex}")
    await uvicorn.Server(config).serve()


if __name__ == "__main__":
    asyncio.run(main())
