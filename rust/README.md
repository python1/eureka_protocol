# eureka-daemon (Rust)

The Eureka daemon as one self-contained binary: no Python, no virtualenv, no
packages to install. It is a drop-in for

    python -m eureka_protocol.src.eureka_daemon.server

with the same command line, environment variables, identity key file, trust
file, wire protocol and answers, so Knights Circle and existing Python peers
use it unchanged. The Python daemon stays the reference implementation, and
`vectors/signatures-v1.json` is the shared contract both must meet byte for byte.

## What is the same

- **Protocol.** Three-message mutual handshake, signed `/v1/assign`, signed
  reads (`/v1/peers`, `/v1/logs`, `/v1/manifest`) and discovery. Domain-separated
  Ed25519 (`tag || 0x00 || canonical JSON`), 30-second freshness, replay
  protection on every nonce, results bound to the request nonce, and signed
  audit entries. Python's canonical JSON is reproduced exactly: sorted keys,
  `ensure_ascii`, `repr(float)`, big integers, NaN/Infinity. The same goes for
  `datetime.fromisoformat`, `bytes.fromhex` and strict base64.
- **Files.** `~/.eureka/identity.key` (or `EUREKA_IDENTITY_PATH`) and
  `~/.eureka/trust.json` (or `EUREKA_TRUST_PATH`), versions 1–3, revocations
  included. A key made by either daemon is the same node in the other.
- **Command line.** `eureka-daemon [port] [--host H] [--cors-origin O ...]`.
  The port defaults to 8000 and `--host` to `127.0.0.1`. Options can be
  abbreviated as in argparse.
- **HTTP.** The same routes, the same 64 KiB body cap (413 or 400), the same
  refusal bodies, 404/405/307, and CORS headers identical to Starlette's
  `CORSMiddleware`, preflights included.
- **Room turns.** At most 200 messages and 48,000 characters. Replies are
  capped at 12,000 characters and flagged `truncated`. The same output fields
  and the same failure reasons as `room_turn.py`.

## What is not in this build

- **TLS listeners** (`--tls`, `--tls-port`, `--tls-dir`, `--no-plain`). The
  daemon stops with a clear message instead. Serve on loopback (behind an SSH
  tunnel for remote use, as below), or use the Python daemon for TLS.
- **`web-retrieval`.** A trust file that grants it still loads, with a note at
  startup, and requests for it are refused as `capability_not_granted`.
- **`/docs` and `/openapi.json`** (FastAPI's generated pages).

## Build

You need Rust (`rustup`). Nothing else: no C compiler, no Docker.

**macOS (Apple silicon):**

    cd rust
    cargo build --release
    # -> target/release/eureka-daemon  (about 1.4 MB)

The binary links only `libSystem` and `libiconv`, which are part of every
macOS install. Apple does not support fully static binaries, so this is as
self-contained as a Mac binary gets.

**Linux x86_64, fully static (any distribution, including Debian), from a Mac or Linux:**

    cd rust
    rustup target add x86_64-unknown-linux-musl
    cargo build --release --target x86_64-unknown-linux-musl
    # -> target/x86_64-unknown-linux-musl/release/eureka-daemon  (static-pie, no shared libraries)

`.cargo/config.toml` links with `rust-lld` and musl, both shipped with
rustup, so no cross toolchain is needed. Swap in `aarch64-unknown-linux-musl`
for ARM Linux.

## Run

    EUREKA_ROOM_TURN=1 ./eureka-daemon 8765 --cors-origin https://knights-circle.vercel.app

| Variable | Meaning |
| --- | --- |
| `EUREKA_IDENTITY_PATH`, `EUREKA_TRUST_PATH` | Key and trust file (default `~/.eureka/`) |
| `EUREKA_CORS_ORIGINS` | Comma-separated origins, added to `--cors-origin` |
| `EUREKA_ROOM_TURN` | `1`/`on` to offer `room-turn` |
| `EUREKA_ROOM_TURN_MODEL` | Ollama model (default `qwen3:8b`) |
| `EUREKA_INFERENCE` | `1`/`on` to offer `inference` (Ollama `/api/generate`) |
| `EUREKA_ROOM_TURN_BACKEND` | `ollama` (default) or `openclaw` *(Rust only)* |
| `EUREKA_OPENCLAW_BIN` | The `openclaw` executable (default: found on `PATH`) *(Rust only)* |
| `EUREKA_OPENCLAW_SESSION` | Session for room turns (default `knights-circle`) *(Rust only)* |
| `EUREKA_OPENCLAW_TIMEOUT` | Seconds per turn, 1–1800 (default 120) *(Rust only)* |
| `EUREKA_OLLAMA_URL` | Ollama base URL, literal loopback only (default `http://127.0.0.1:11434`) *(Rust only)* |

Unusable settings stop the daemon at startup with a reason. They never fall
back silently.

### Trusting a Knights Circle room

Knights Circle shows a Python one-liner under *Show room key*. With the binary,
run this instead, then restart the daemon (it reads the file at startup):

    ./eureka-daemon trust add knights-circle-node_xxxxxxxx <room key> room-turn
    ./eureka-daemon trust list

It writes exactly the file the Python command writes (tested byte for byte).
It refuses a revoked key.

### The OpenClaw backend

With `EUREKA_ROOM_TURN_BACKEND=openclaw`, each room turn runs

    openclaw agent --session-id <EUREKA_OPENCLAW_SESSION> --json --message <text>

and returns only the agent's reply. `--json` makes OpenClaw print a structured
result, and the reply is its `result.payloads[].text`. Run metadata, the
version banner and tagline OpenClaw shows on a terminal, and anything else
printed before the result are never passed to the room. The safeguards:

- **Session.** The session is fixed by the operator (default
  `knights-circle`), so a room never writes into the agent's main
  conversation. The room cannot choose it.
- **No shell.** Arguments go straight to the program. The room's text is one
  argv entry, so `$(…)`, backticks and `;` are just text.
- **Message format.** The message is Knights Circle's room preamble followed by
  the room's messages as `[role]` blocks. Payload checks (roles, 200 messages,
  48,000 characters) run before anything is started.
- **Limits.** stdin is closed. stdout is read up to 8 MiB (a one-line reply
  is about 23 KB of JSON). Colour codes are removed from the reply, and the
  reply is capped at 12,000 characters. stderr goes to the log only.
- **Process cleanup.** The process runs in its own process group. The whole
  group is killed on timeout, on oversized output, or if the turn is
  abandoned.
- **Failure reasons.** These are `upstream_error`: a non-zero exit, output over
  the limit, no JSON result, a result whose `status` is not `"ok"`, an aborted
  run, or a reply with no text. A program that cannot start is
  `upstream_unavailable`. Passing the time limit is `timeout`.

Tested against OpenClaw 2026.6.5. `tests/fixtures/openclaw-agent-json.json` is
a real `--json` result from it, trimmed to the reply and its basic run fields.

## Tests

    cd rust && cargo test

- **Vectors.** All 30 shared signature vectors, byte for byte: signed bytes,
  verification, re-signing with the published test seed, and refusal in any
  other domain or with any altered payload.
- **Differential.** Python's own answers for thousands of floats, timestamps
  and JSON documents. Regenerate them with
  `python3 rust/conformance/make_differential.py`.
- **Unit tests.**

Black-box conformance runs the same tests over real sockets against **both**
daemons, using the Python package's own client code (`EurekaNode`,
`handshake_over_http`, `build_assign_query`, `build_read_query`). The OpenClaw
tests use `conformance/fake_openclaw.py` in place of `openclaw`.

    cargo build --release            # in rust/
    ./venv/bin/python -m pytest eureka_protocol/rust/conformance   # from the checkout's parent, like the main suite

`EUREKA_CONFORMANCE=python` or `=rust` runs one side only. Python's own suite
(`eureka_protocol/tests`) is unchanged.

## Example: an OpenClaw agent on a Linux box, reached through SSH

This uses the Antiochus setup: OpenClaw in a Proxmox container at
`192.168.1.174`, Knights Circle in Chrome on the Mac. The daemon listens only
on the container's loopback, and the Mac reaches it through an SSH tunnel.
Nothing is exposed on the LAN, and the browser still talks to
`http://127.0.0.1:8765`.

1. **Build and copy (Mac).**

       cd rust
       rustup target add x86_64-unknown-linux-musl
       cargo build --release --target x86_64-unknown-linux-musl
       scp target/x86_64-unknown-linux-musl/release/eureka-daemon root@192.168.1.174:/usr/local/bin/

2. **Check OpenClaw answers on its own (container).**

       command -v openclaw
       openclaw agent --session-id knights-circle --json --message "Say hello in five words." </dev/null | head -20

3. **Get the room key (Mac, Chrome, https://knights-circle.vercel.app).**
   Open *Advanced: bring your own bot*, then *Show room key*. Note the key and
   the `node_…` id.

4. **Trust the room and start the daemon (container).**

       eureka-daemon trust add knights-circle-node_xxxxxxxx <room key> room-turn
       EUREKA_ROOM_TURN=1 EUREKA_ROOM_TURN_BACKEND=openclaw \
         eureka-daemon 8765 --cors-origin https://knights-circle.vercel.app

   It prints `public key: …`, which you need in step 6. The line
   `room-turn via OpenClaw (… agent --session-id knights-circle, 120s limit)`
   confirms the backend. If `openclaw` is not on root's `PATH`, set
   `EUREKA_OPENCLAW_BIN=/full/path/to/openclaw`.

5. **Open the tunnel (Mac, leave it running).**

       ssh -N -L 8765:127.0.0.1:8765 root@192.168.1.174

6. **Add the agent (Knights Circle).** Name it `Antiochus`, give the address
   `http://127.0.0.1:8765` and the public key from step 4, then choose
   **Check**. If Chrome asks to let the site reach devices on your local
   network, allow it. Then in **Rooms**, pick *External agent · Antiochus* as
   a team member.

To keep it running, a systemd unit in the container
(`/etc/systemd/system/eureka-daemon.service`):

    [Unit]
    Description=Eureka daemon (OpenClaw room turns)
    After=network.target

    [Service]
    Environment=HOME=/root EUREKA_ROOM_TURN=1 EUREKA_ROOM_TURN_BACKEND=openclaw
    # systemd's PATH is short: name openclaw in full (the output of `command -v openclaw`).
    Environment=EUREKA_OPENCLAW_BIN=/usr/local/bin/openclaw
    ExecStart=/usr/local/bin/eureka-daemon 8765 --cors-origin https://knights-circle.vercel.app
    Restart=on-failure

    [Install]
    WantedBy=multi-user.target

Enable it with `systemctl daemon-reload && systemctl enable --now eureka-daemon`.
Read the public key with `journalctl -u eureka-daemon | grep "public key"`.
Restart the service after each `trust add`.
