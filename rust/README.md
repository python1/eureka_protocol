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
  `eureka-daemon --version` is Rust only.
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

**Windows x64, native (on Windows, with Visual Studio's C++ build tools):**

    cd rust
    $env:RUSTFLAGS = "-C target-feature=+crt-static"
    cargo build --release
    # -> target\release\eureka-daemon.exe  (no Visual C++ runtime needed)

On Windows:

- **Files.** The key and trust file are in `%USERPROFILE%\.eureka`. They are
  protected by a private access list instead of mode 0600: only your account
  and SYSTEM. A key file that any account other than yours, SYSTEM or
  Administrators can reach is refused at startup, with the command to fix it.
  So is one on a drive without access lists, such as FAT or exFAT.
- **Backends.** The `ollama` backend works natively. `openclaw` and `hermes`
  stop at startup with a reason, and need the Linux build inside WSL. Room text
  can reach 48,000 characters and OpenClaw takes it as an argument, past
  Windows' 32,767-character command line. These tools also commonly install as
  `.cmd` wrappers, where arguments pass through cmd.exe's parsing, and Windows
  has no process groups to clean up after a turn.

Every pull request that touches the daemon is built, tested and smoke-tested on
macOS (arm64 and x64), Linux (x64 and arm64) and Windows x64 by
`.github/workflows/rust-build.yml`. That workflow publishes nothing.

## Run

    EUREKA_ROOM_TURN=1 ./eureka-daemon 8765 --cors-origin https://knights-circle.vercel.app

| Variable | Meaning |
| --- | --- |
| `EUREKA_IDENTITY_PATH`, `EUREKA_TRUST_PATH` | Key and trust file (default `~/.eureka/`) |
| `EUREKA_CORS_ORIGINS` | Comma-separated origins, added to `--cors-origin` |
| `EUREKA_ROOM_TURN` | `1`/`on` to offer `room-turn` |
| `EUREKA_ROOM_TURN_MODEL` | Ollama model (default `qwen3:8b`) |
| `EUREKA_INFERENCE` | `1`/`on` to offer `inference` (Ollama `/api/generate`) |
| `EUREKA_ROOM_TURN_BACKEND` | `ollama` (default), `openclaw` or `hermes` *(Rust only)* |
| `EUREKA_OPENCLAW_BIN` | The `openclaw` executable (default: found on `PATH`) *(Rust only)* |
| `EUREKA_OPENCLAW_SESSION` | Session for room turns (default `knights-circle`, or `room-<agent>` with an agent) *(Rust only)* |
| `EUREKA_OPENCLAW_AGENT` | A chat-only OpenClaw agent for room turns (default: none, with a warning) *(Rust only)* |
| `EUREKA_OPENCLAW_REQUIRE_CHAT_ONLY` | `1`/`on` to stop at startup unless that agent is chat only *(Rust only)* |
| `EUREKA_OPENCLAW_TIMEOUT` | Seconds per turn, 1–1800 (default 120) *(Rust only)* |
| `EUREKA_HERMES_BIN` | The `hermes` executable (default: found on `PATH`) *(Rust only)* |
| `EUREKA_HERMES_PROFILE` | Hermes profile for room turns (default `knights-circle`; must exist) *(Rust only)* |
| `EUREKA_HERMES_SESSION` | Optional: one named Hermes session for every turn (default: a new session each turn) *(Rust only)* |
| `EUREKA_HERMES_TIMEOUT` | Seconds per turn, 1–1800 (default 120), also passed to Hermes as `--run-budget` *(Rust only)* |
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

To withdraw trust from a room, by name or by key, then restart the daemon:

    ./eureka-daemon trust revoke knights-circle-node_xxxxxxxx --reason "lost that browser"

Revoking is permanent. The key stays refused for as long as the revocation is in
the file, and `trust add` will not bring it back. A running daemon keeps trusting it
until it restarts. A key that was never trusted can be revoked too, so it can never be
added by mistake.

### Room text is untrusted

Room text includes other models' output and text from people you do not know.
OpenClaw and Hermes turns therefore start with a fixed notice saying so, followed
by the room's messages as one JSON object per line, between markers:

    <room-turn-7f3a…>
    {"role":"room_instructions","content":"You are the Critic."}
    {"role":"user","content":"Plan the beds"}
    </room-turn-7f3a…>

- **Line breaks are escaped**, so a message cannot start a line that looks like
  another message, a role or a closing marker. Control characters, terminal
  escapes and bidirectional overrides are escaped too.
- **The marker is random for each turn**, so room text, written before the marker
  exists, cannot close the block.
- **The room's `system` message becomes `room_instructions`**, because it comes
  from the browser and not from you.

This is labelling. A model can still be talked into things, so what actually limits
the damage is what the agent can do: keep room agents chat only, as below for each
backend. The `ollama` backend keeps its short preamble and the roles as sent. It has
no tools here, and its requests stay identical to the Python daemon's.

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
- **Message format.** See *Room text is untrusted* below. Payload checks (roles,
  200 messages, 48,000 characters) run before anything is started.
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

**Chat only.** OpenClaw's tools run as your user, and with no profile set its core
tools are not filtered. Room turns should go to an agent of their own that cannot
run commands or touch files:

    openclaw agents add knights-circle --workspace ~/.openclaw/workspace-knights-circle --non-interactive
    openclaw config set agents.entries.knights-circle.tools.profile minimal
    openclaw config set agents.entries.knights-circle.tools.deny '["group:runtime","group:fs","group:ui","group:automation","group:nodes","group:plugins","group:agents","group:web","group:messaging","group:media","group:memory"]' --strict-json

Then set `EUREKA_OPENCLAW_AGENT=knights-circle`. Each turn runs with `--agent
knights-circle` and, unless you set `EUREKA_OPENCLAW_SESSION`, the session
`room-knights-circle`. The session has its own name because an existing session keeps
the agent it began with, so reusing an old `knights-circle` session could keep the
main agent and its tools. If you do set a session, use one this agent started.

At startup the daemon reads the policy with `openclaw config get
agents.entries.<id>.tools --json`. It wants the `minimal` profile, every group above
in `deny`, and no `allow`, `alsoAllow`, `byProvider` or `toolsBySender`.

- **Run directly**, a missing or unsafe agent prints a `WARNING:` with the fix, and
  the daemon carries on, so an existing setup keeps working. With no agent set, it
  doesn't read the policy at all.
- **With `EUREKA_OPENCLAW_REQUIRE_CHAT_ONLY=1`**, the same finding stops the daemon,
  and so does a policy it cannot read.

> **Not yet run against a real OpenClaw.** The agent setup, policy check and
> `--agent` turn are tested only against `conformance/fake_openclaw.py`, written
> from OpenClaw's documentation. Confirm them on a spare agent first, for example by
> asking the room agent to run a command and checking that it cannot.

What the check does not cover:

- **It reads your written config, not the tools the model finally gets.** OpenClaw
  documents no command that prints the resolved list. Use the test above, or `openclaw
  logs --follow | grep tools`.
- **Older `agents.list` rosters.** The check reads `agents.entries` and reports a
  policy kept anywhere else as missing. `openclaw doctor` migrates them.
- **`$skill-name` references.** OpenClaw's docs say `--message` still honours these,
  and room text can contain them. Keep skills out of the room agent's workspace.
- **Later edits and new releases.** The check runs at startup, and a later release
  could add a tool group this list doesn't name.

Reply parsing and the command line without `EUREKA_OPENCLAW_AGENT` were tested against
OpenClaw 2026.6.5, before the current message format. `tests/fixtures/openclaw-agent-json.json` is
a real `--json` result from it, trimmed to the reply and its basic run fields.

### The Hermes Agent backend

> **Untested against a real Hermes.** This backend has been tested only against
> `conformance/fake_hermes.py`, a stand-in written from Hermes Agent v0.22.5's
> source. It has not run against a real Hermes install, and won't have until
> it is tried on WSL2 (the example at the end of this file). Until then, treat
> the command line, the reply parsing and the startup check as unconfirmed.

With `EUREKA_ROOM_TURN_BACKEND=hermes`, each room turn runs
[Hermes Agent](https://github.com/NousResearch/hermes-agent) headless:

    hermes -p <EUREKA_HERMES_PROFILE> chat --query-file - --format stream-json \
           --source tool --run-budget <EUREKA_HERMES_TIMEOUT>

The room's message (the same format OpenClaw gets, see *Room text is untrusted*) is
written to its stdin. This is Hermes' documented way to send one message from a
program. `--format stream-json` prints one JSON event per line and ends with a
`{"type": "result", "exit_code": …, "text": …}` event, and the reply is that
event's `text`. Text deltas, tool calls, tool output and stray log lines are
never passed to the room.

**Why a profile of its own.** A Hermes profile is a separate Hermes home, with
its own sessions, memory, `SOUL.md`, config and skills. Running rooms in
`-p knights-circle` means a room never touches your own Hermes sessions or
memory:

- Your `hermes -c` and `--resume latest` cannot continue a room.
- Room text never lands in your main `MEMORY.md`.

Pinning a session in your *main* profile would not give that. A
`-c <name> --create-if-missing` session is stored as source `cli`, the same
history `hermes -c` and `--resume latest` choose from. Hermes refuses a profile
that does not exist, so the daemon checks for it at startup and tells you how to
create it.

**Sessions.** By default each turn is a new session (tagged `--source tool`, which Hermes keeps out of its
session pickers), because every Knights Circle turn already carries the whole room. Set
`EUREKA_HERMES_SESSION=<name>` to send every turn to one named session in that profile instead
(`-c <name> --create-if-missing`). Note that the room is then repeated into that session each turn.

The safeguards are the OpenClaw ones:

- **No shell.** The arguments are a fixed list. The room's text is only on
  stdin, so it never shows in `ps` and can never be read as a flag.
- **Limits.** stdout is read up to 8 MiB. The reply is capped at 12,000
  characters.
- **Process cleanup.** The process runs in its own process group, which is
  killed on timeout, on oversized output, or if the turn is abandoned.
  Hermes' own background gateway starts in a session of its own, so it is not
  killed and exits when idle.
- **Failure reasons.** These are `upstream_error`: a non-zero exit, a result
  whose `exit_code` is not 0, no result event, or a reply with no text. A
  program that cannot start is `upstream_unavailable`. Passing the time limit
  is `timeout`.

#### Chat only: no commands, code or files

Room text includes other models' replies, so a room must never be able to make
the agent run commands or touch files. A profile is not a sandbox: with Hermes'
default `local` terminal backend its tools have your user's access. So the
room profile is set to chat only, using Hermes' own config. Run:

    hermes -p knights-circle config set agent.disabled_toolsets '["terminal", "file", "code_execution", "delegation", "cronjob", "browser", "computer_use", "skills"]'
    hermes -p knights-circle config set platform_toolsets.cli '[]'
    hermes -p knights-circle mcp list            # remove any server: hermes -p knights-circle mcp remove <name>
    hermes -p knights-circle tools --summary     # should show no toolsets enabled

In the profile's `config.yaml` (`hermes -p knights-circle config path`) that
reads:

```yaml
agent:
  disabled_toolsets: [terminal, file, code_execution, delegation, cronjob, browser, computer_use, skills]
platform_toolsets:
  cli: []        # an explicitly empty list: no toolsets for chat / one-shot runs
```

- **`agent.disabled_toolsets` is the guarantee.** Hermes applies it last, over
  every other selection: platform lists, composites like `coding` and
  `debugging`, the `coding_context: focus` posture, and `HERMES_TUI_TOOLSETS`.
  It strips the named toolsets' tools wherever they come from. `--source tool`
  runs use the CLI's selection.
- **The set covers indirect routes too.** `terminal`, `file` and
  `code_execution` are the direct ones. The rest reach the same powers another
  way:
  - `delegation`: subagents;
  - `cronjob`: scheduled runs;
  - `browser`: `browser_exec` runs Python over CDP;
  - `computer_use`: desktop control;
  - `skills`: `skill_manage` writes files.
- **`platform_toolsets.cli: []`** turns off the rest (web, memory, vision and
  so on), so the profile only chats.
- **MCP servers** are removed because their tools can do anything.

**The daemon checks this at startup and refuses to run otherwise.** With
`EUREKA_ROOM_TURN_BACKEND=hermes` it asks Hermes for the profile's settings:

    hermes -p <profile> config get agent.disabled_toolsets --json
    hermes -p <profile> config get mcp_servers --json

`config get` is Hermes' documented, machine-readable reader, so the values come
from Hermes' own config loading rather than the daemon parsing YAML. The daemon
stops with a `WARNING:` naming each problem and printing the commands above in
either case:
- any of the eight toolsets is missing from `agent.disabled_toolsets`;
- an MCP server is not `enabled: false`.

It also stops if the settings can't be read.

What the check does **not** cover:

- **Later edits.** It runs once, at startup. A setting changed while the daemon
  runs is not seen until the next start, so restart it after editing the
  profile.
- **Plugin and hook code.** Plugin tools (each in a toolset of its own) and
  shell `hooks` in the config are code you installed, not anything the agent
  chose. The eight-toolset list does not cover them, and even with
  `platform_toolsets.cli: []` Hermes turns on an enabled plugin's toolset
  unless it was unchecked in `hermes tools`. Keep the room profile free of
  both: `hermes -p knights-circle plugins list` should show no enabled
  plugins, and its `config.yaml` should have no `hooks:`.
- **Tools from a future Hermes release.** A later release could add a new
  toolset that runs commands. Re-check `tools --summary` after upgrading.

Built against Hermes Agent v0.22.5 (`hermes_cli/stream_json.py`).
`tests/fixtures/hermes-stream-json.jsonl` is written field for field as that
emitter writes events. It was not captured from a live run.

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
and Hermes tests use `conformance/fake_openclaw.py` and
`conformance/fake_hermes.py` in place of `openclaw` and `hermes`.

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

   This example has no dedicated agent, so it prints a `WARNING:` with the steps to
   add one (see *The OpenClaw backend*). It prints `public key: …`, which you need in step 6. The line
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

## Example: Hermes Agent under WSL2, with Knights Circle in Windows Chrome

This setup runs Hermes Agent and the daemon in WSL2 (Ubuntu 24.04), with Chrome
on Windows on the same machine. The daemon listens only on loopback, and Chrome
reaches it at `http://127.0.0.1:8765`.

1. **Build the static Linux binary (Ubuntu shell).** Use rustup from
   https://rustup.rs, which is free:

       git clone https://github.com/python1/eureka_protocol && cd eureka_protocol/rust
       rustup target add x86_64-unknown-linux-musl
       cargo build --release --target x86_64-unknown-linux-musl
       install -m 755 target/x86_64-unknown-linux-musl/release/eureka-daemon ~/.local/bin/

   You can also build it on another machine as above and copy it in.

2. **Make a Hermes profile for rooms, and check it answers (Ubuntu).**

       hermes profile create knights-circle
       hermes -p knights-circle setup          # choose its model; a local Ollama keeps it $0
       echo "Say hello in five words." | hermes -p knights-circle chat --query-file - --format stream-json --source tool

   The last line of output should be a `"type": "result"` event with
   `"exit_code": 0`. Then make the profile chat only, as described in
   [Chat only](#chat-only-no-commands-code-or-files):

       hermes -p knights-circle config set agent.disabled_toolsets '["terminal", "file", "code_execution", "delegation", "cronjob", "browser", "computer_use", "skills"]'
       hermes -p knights-circle config set platform_toolsets.cli '[]'
       hermes -p knights-circle tools --summary

   The daemon refuses to start until this is done.

   A fresh profile is used on purpose. `--clone` would also copy your
   `MEMORY.md`, `USER.md` and API keys into a profile whose replies are shared
   with every model in a room.

3. **Get the room key (Windows Chrome, https://knights-circle.vercel.app).**
   Open *Advanced: bring your own bot*, then *Show room key*. Note the key and
   the `node_…` id.

4. **Trust the room and start the daemon (Ubuntu).**

       eureka-daemon trust add knights-circle-node_xxxxxxxx <room key> room-turn
       EUREKA_ROOM_TURN=1 EUREKA_ROOM_TURN_BACKEND=hermes \
         eureka-daemon 8765 --cors-origin https://knights-circle.vercel.app

   It prints `public key: …` and `room-turn via Hermes Agent (… -p knights-circle chat, a new session each turn, 120s limit)`.
   Keep the default `--host 127.0.0.1`.

5. **Check Windows can reach it (PowerShell):**

       curl.exe http://127.0.0.1:8765/v1/manifest

   It should return `{"node_id": "node_…", "runtime": "eureka-daemon-mvd"}`.

   WSL2 forwards Windows `127.0.0.1` to services on WSL's loopback by default
   (`localhostForwarding`). If it doesn't, turn on mirrored networking in
   `%UserProfile%\.wslconfig`:

       [wsl2]
       networkingMode=mirrored

   Then run `wsl --shutdown` and start again. Don't use `--host 0.0.0.0` to work
   around it: that exposes the daemon to your network.

6. **Add the agent (Knights Circle).** Name it `Hermes`, give the address
   `http://127.0.0.1:8765` and the public key from step 4, then choose
   **Check**. If Chrome asks to let the site reach devices on your local
   network, allow it. Then pick *External agent · Hermes* as a team member in
   **Rooms**.

The daemon must be running in WSL while you use the room. Closing the last WSL
terminal can stop the distribution. Keep a terminal open, or run the daemon as
a systemd service if your WSL has systemd enabled (`[boot] systemd=true` in
`/etc/wsl.conf`), as in the OpenClaw example above with
`EUREKA_ROOM_TURN_BACKEND=hermes`.
