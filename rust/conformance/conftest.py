"""
Black-box conformance: the same tests, over real sockets, against both daemons.

Each test that takes the `daemon` fixture runs twice -- once against the
Python daemon (unmodified, started through python_daemon.py) and once against
the Rust binary -- and asserts the same answers. The client side is the Python
package's own client code (EurekaNode, handshake_over_http, build_assign_query,
build_read_query), so the Rust daemon is held to exactly what existing Python
peers send and expect.

Run from the parent of the checkout, like the main suite:

    ./venv/bin/python -m pytest eureka_protocol/rust/conformance

EUREKA_RUST_BIN picks the binary (default: rust/target/release, then debug).
EUREKA_CONFORMANCE=rust (or python) runs one side only.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

HERE = Path(__file__).resolve().parent
RUST = HERE.parent
REPO = RUST.parent
sys.path.insert(0, str(REPO.parent))

from eureka_protocol.src.eureka_daemon.crypto import EurekaCrypto  # noqa: E402
from eureka_protocol.src.eureka_daemon.node import EurekaNode  # noqa: E402
from eureka_protocol.src.eureka_daemon.trust import TrustList  # noqa: E402


def rust_binary() -> Path:
    named = os.environ.get("EUREKA_RUST_BIN")
    if named:
        return Path(named)
    for profile in ("release", "debug"):
        candidate = RUST / "target" / profile / "eureka-daemon"
        if candidate.exists():
            return candidate
    pytest.skip("build the Rust daemon first: cargo build --release (in rust/)")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# A fake Ollama: records what it was sent, answers as the test asks.
# ---------------------------------------------------------------------------

class FakeOllama:
    def __init__(self):
        self.requests = []
        self.mode = "ok"
        self.reply = "The beds should face south."
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["content-length"])))
                fake.requests.append({"path": self.path, "body": body})
                if fake.mode == "missing":
                    return self._send(404, {"error": "model not found"})
                if fake.mode == "error":
                    return self._send(500, {"error": "boom"})
                if fake.mode == "garbage":
                    return self._send(200, None, raw=b"not json")
                if fake.mode == "slow":
                    time.sleep(5)
                text = fake.reply
                if self.path == "/api/chat":
                    return self._send(200, {"model": body["model"], "message": {"role": "assistant", "content": text},
                                            "done": True, "done_reason": "stop", "eval_count": 7})
                return self._send(200, {"model": body["model"], "response": text, "done": True,
                                        "done_reason": "stop", "eval_count": 5})

            def _send(self, status, document, raw=None):
                data = raw if raw is not None else json.dumps(document).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def reset(self):
        self.requests.clear()
        self.mode = "ok"
        self.reply = "The beds should face south."


@pytest.fixture(scope="session")
def ollama():
    fake = FakeOllama()
    yield fake
    fake.server.shutdown()


# ---------------------------------------------------------------------------
# A daemon process, either implementation, with its own identity and trust file.
# ---------------------------------------------------------------------------

def client_node(name: str) -> EurekaNode:
    """A Python client node with no trust file behind it (never reads ~/.eureka)."""
    return EurekaNode(node_id=None, crypto_engine=EurekaCrypto(), capabilities=["room-turn"],
                      trust_list=TrustList())


class Daemon:
    def __init__(self, kind, workdir, ollama_url, cors=(), env=None, peers=None, revoked=None, args=()):
        self.kind = kind
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.identity = Path(workdir) / "identity.key"
        self.trust = Path(workdir) / "trust.json"
        self.log_path = Path(workdir) / f"{kind}.log"
        document = {"version": 3, "algorithm": "ed25519", "peers": peers or {}}
        if revoked:
            document["revoked"] = revoked
        self.trust.write_text(json.dumps(document))
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(workdir),
            "EUREKA_IDENTITY_PATH": str(self.identity),
            "EUREKA_TRUST_PATH": str(self.trust),
            "EUREKA_ROOM_TURN": "1",
            "EUREKA_ROOM_TURN_MODEL": "qwen3.5:4b",
            "EUREKA_INFERENCE": "1",
            "EUREKA_OLLAMA_URL": ollama_url,
            "PYTHONUNBUFFERED": "1",
            **(env or {}),
        }
        cors_args = [a for origin in cors for a in ("--cors-origin", origin)]
        if kind == "python":
            command = [sys.executable, str(HERE / "python_daemon.py"), str(self.port), *cors_args, *args]
        else:
            command = [str(rust_binary()), str(self.port), *cors_args, *args]
        self.log = open(self.log_path, "w")
        self.process = subprocess.Popen(command, env=environment, stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"{kind} daemon exited:\n{self.log_path.read_text()}")
            try:
                if httpx.get(self.base + "/v1/manifest", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.1)
        else:
            raise RuntimeError(f"{kind} daemon did not start:\n{self.log_path.read_text()}")
        self.public_key = json.loads(self.identity.read_text())["public_key_hex"]
        self.node_id = httpx.get(self.base + "/v1/manifest").json()["node_id"]

    def output(self) -> str:
        self.log.flush()
        return self.log_path.read_text()

    def stop(self):
        self.process.terminate()
        try:
            self.process.wait(10)
        except subprocess.TimeoutExpired:
            self.process.kill()
        self.log.close()


def kinds():
    only = os.environ.get("EUREKA_CONFORMANCE")
    return [only] if only else ["python", "rust"]


@pytest.fixture(params=kinds())
def kind(request):
    return request.param


@pytest.fixture
def start(kind, ollama):
    """start(peers=..., revoked=..., cors=..., env=...) -> a running daemon of this test's kind."""
    started = []
    workdir = tempfile.TemporaryDirectory(prefix=f"eureka-conformance-{kind}-")

    def _start(**kwargs):
        sub = Path(workdir.name) / str(len(started))
        sub.mkdir()
        daemon = Daemon(kind, sub, ollama.url, **kwargs)
        started.append(daemon)
        return daemon

    ollama.reset()
    yield _start
    for daemon in started:
        daemon.stop()
    workdir.cleanup()


def grant(node: EurekaNode, *capabilities) -> dict:
    """A v3 trust entry for this client node."""
    return {node.node_id: {"public_key": node.public_key_hex, "capabilities": list(capabilities)}}
