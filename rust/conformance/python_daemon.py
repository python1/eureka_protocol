"""
Run the unmodified Python daemon, with its Ollama endpoints pointed where the
conformance suite's fake Ollama listens.

The Python daemon has the Ollama address as a constant (127.0.0.1:11434), so
without this both daemons could only be compared against whatever Ollama
happens to run on the machine. This changes nothing in the daemon's code: it
sets the two handlers' default endpoint before server.main() builds them, and
only when EUREKA_OLLAMA_URL is given -- the same variable the Rust build reads.
Still checked against loopback by the daemon's own _require_loopback.

    python rust/conformance/python_daemon.py PORT [server.py arguments...]
"""
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

base = os.environ.get("EUREKA_OLLAMA_URL", "").strip().rstrip("/")
if base:
    from eureka_protocol.src.eureka_daemon import handlers, room_turn

    room_turn.OllamaRoomTurn.__init__.__kwdefaults__["endpoint"] = base + "/api/chat"
    handlers.OllamaInference.__init__.__kwdefaults__["endpoint"] = base + "/api/generate"

from eureka_protocol.src.eureka_daemon import server  # noqa: E402  (after the patch, before api is imported)

if __name__ == "__main__":
    asyncio.run(server.main())
