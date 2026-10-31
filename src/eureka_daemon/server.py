"""
Daemon entry point.

A node can serve plaintext, TLS, or both at once. Both matters during a
migration: a peer still running an older client speaks plain HTTP, and TLS
cannot share a port with it -- an HTTPS socket answers a plaintext request with
a handshake failure, not a manifest. So the daemon listens twice rather than
asking every peer to cut over on the same day.

Both listeners are served from ONE process, sharing one EurekaNode. Running a
second process for the TLS port would be simpler to wire and quietly wrong: two
processes under one identity would keep two independent replay tables, so a
handshake nonce spent on one port would still be unspent on the other, and two
peer tables, so /v1/peers would answer differently depending on which port you
asked. One node means one of each.

The certificate served is generated from the node's existing identity key, so
peers pin the same key they already have in their trust file and nothing new
has to be distributed. node_id is derived from that key and does not change
when TLS is switched on.

Every listener binds loopback unless --host says otherwise. A node reachable
from the LAN is a decision the operator makes on the command line, not a
default they inherit: a plaintext port on 0.0.0.0 hands every machine on the
network an unencrypted line to the daemon, and the trust file would be the only
thing standing in the way.
"""
import argparse
import asyncio
import signal
import ssl
from typing import List, Optional

import uvicorn

from .api import app, node_engine
from .tls import ensure_server_materials


# Where a listener binds unless the operator widens it with --host.
DEFAULT_HOST = "127.0.0.1"


def build_config(port: int, use_tls: bool, materials_dir=None,
                 host: str = DEFAULT_HOST) -> uvicorn.Config:
    """
    The uvicorn config for one listener, with TLS wired to this node's identity.

    Kept separate from main() so the wiring can be tested without binding a
    socket -- in particular that TLS actually serves the node's own key.
    """
    options = dict(app=app, host=host, port=port, log_level="info")
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


def build_configs(plain_port: Optional[int] = None,
                  tls_port: Optional[int] = None,
                  materials_dir=None,
                  host: str = DEFAULT_HOST) -> List[uvicorn.Config]:
    """
    Every listener this node should open. Either may be omitted, not both.

    Refusing the empty case is the point: a typo that turns off plaintext
    without turning on TLS would otherwise start a daemon that serves nothing
    and looks perfectly healthy doing it.
    """
    if plain_port is None and tls_port is None:
        raise ValueError("no listeners configured: give a plaintext port, "
                         "a TLS port, or both")
    if plain_port is not None and plain_port == tls_port:
        # They cannot share a socket, and whichever bound second would fail
        # with an address-in-use error that says nothing about the real cause.
        raise ValueError(f"plaintext and TLS cannot share port {tls_port}")

    configs = []
    if plain_port is not None:
        configs.append(build_config(plain_port, use_tls=False, host=host))
    if tls_port is not None:
        configs.append(build_config(tls_port, use_tls=True,
                                    materials_dir=materials_dir, host=host))
    return configs


class _CoServer(uvicorn.Server):
    """
    A uvicorn server that leaves signal handling to whoever started it.

    Two servers in one event loop would otherwise each install their own
    SIGTERM handler, and the second would replace the first -- so a systemd
    stop would shut down one listener and leave the other running until the
    stop timed out and the process was killed.
    """

    def install_signal_handlers(self) -> None:
        return


async def serve(configs: List[uvicorn.Config]) -> None:
    """Run every listener until a signal asks all of them to stop together."""
    servers = [_CoServer(config) for config in configs]

    def stop_all() -> None:
        for server in servers:
            server.should_exit = True

    loop = asyncio.get_running_loop()
    for signal_number in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signal_number, stop_all)

    await asyncio.gather(*(server.serve() for server in servers))


def parse_arguments(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """The command line, checked. Separate from main() so it can be tested."""
    parser = argparse.ArgumentParser(description="Eureka Protocol daemon")
    parser.add_argument("port", nargs="?", type=int, default=8000,
                        help="plaintext port (default 8000)")
    parser.add_argument("--tls-port", type=int, default=None,
                        help="also serve TLS on this port, using the node's "
                             "own identity key")
    parser.add_argument("--no-plain", action="store_true",
                        help="do not serve plaintext (requires --tls-port)")
    parser.add_argument("--tls", action="store_true",
                        help="serve TLS on the main port and nothing else; "
                             "shorthand for --tls-port PORT --no-plain")
    parser.add_argument("--tls-dir", default=None,
                        help="where to write the certificate and key "
                             "(default: beside the identity file)")
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help="address every listener binds (default "
                             f"{DEFAULT_HOST}, this machine only); pass "
                             "0.0.0.0 or a LAN address to accept peers on "
                             "the network")
    arguments = parser.parse_args(argv)
    if not arguments.host.strip():
        parser.error("--host needs an address; leave it out for loopback")

    tls_port = arguments.tls_port
    serve_plain = not arguments.no_plain
    if arguments.tls:
        if tls_port is not None:
            parser.error("--tls and --tls-port are two ways to say the same "
                         "thing; use one")
        tls_port, serve_plain = arguments.port, False
    if arguments.no_plain and tls_port is None:
        parser.error("--no-plain leaves nothing to serve; add --tls-port")
    arguments.plain_port = arguments.port if serve_plain else None
    arguments.tls_port = tls_port
    return arguments


async def main() -> None:
    arguments = parse_arguments()
    configs = build_configs(
        plain_port=arguments.plain_port,
        tls_port=arguments.tls_port,
        materials_dir=arguments.tls_dir,
        host=arguments.host,
    )
    tls_port = arguments.tls_port

    print(f"Starting Eureka Daemon API as {node_engine.node_id}")
    for config in configs:
        scheme = "https" if config.ssl_certfile else "http"
        print(f"  listening on {scheme}://{config.host}:{config.port}")
    if tls_port is not None:
        print(f"  peers should pin: {node_engine.public_key_hex}")

    await serve(configs)


if __name__ == "__main__":
    asyncio.run(main())
