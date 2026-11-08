#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Runs a built eureka-daemon the way a stranger would, on the machine that built it:
#   rust/ci/smoke.sh path/to/eureka-daemon
# Everything lives in a temporary home and on a port the system picks.
set -euo pipefail

binary=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
expected=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$(dirname "$0")/../Cargo.toml" | head -1)
home=$(mktemp -d)
log="$home/daemon.log"
daemon=
cleanup() {
  if [ -n "$daemon" ]; then kill "$daemon" 2>/dev/null || true; fi
  rm -rf "$home"
}
trap cleanup EXIT
fail() { echo "smoke: $*" >&2; [ -f "$log" ] && cat "$log" >&2; exit 1; }

windows=
case "$(uname -s)" in MINGW* | MSYS* | CYGWIN*) windows=1 ;; esac
if [ -n "$windows" ]; then export USERPROFILE="$(cygpath -w "$home")"; else export HOME="$home"; fi
unset EUREKA_IDENTITY_PATH EUREKA_TRUST_PATH EUREKA_ROOM_TURN EUREKA_ROOM_TURN_BACKEND EUREKA_CLAUDE_BIN EUREKA_CLAUDE_HOME

echo "== version"
version=$("$binary" --version | tr -d '\r')
echo "$version"
case "$version" in "eureka-daemon $expected ("*) ;; *) fail "expected version $expected, got: $version" ;; esac
[ "$("$binary" -V | tr -d '\r')" = "$version" ] || fail "-V and --version differ"

echo "== trust file"
room_key=$(printf '11%.0s' $(seq 1 32))
"$binary" trust add smoke-room "$room_key" room-turn
"$binary" trust list | tr -d '\r' | grep -q "smoke-room  $room_key  room-turn" || fail "trust list did not show the room"
[ -f "$home/.eureka/trust.json" ] || fail "trust file is not in the home directory"

start() {
  : >"$log"
  EUREKA_ROOM_TURN=1 "$binary" 0 --cors-origin https://example.test >"$log" 2>&1 &
  daemon=$!
  url=
  for _ in $(seq 1 100); do
    url=$(tr -d '\r' <"$log" | sed -n 's/^  listening on \(http:.*\)$/\1/p')
    [ -n "$url" ] && break
    kill -0 "$daemon" 2>/dev/null || fail "the daemon stopped at startup"
    sleep 0.1
  done
  [ -n "$url" ] || fail "the daemon did not start listening"
  node=$(tr -d '\r' <"$log" | sed -n 's/^Starting Eureka Daemon API as \(node_.*\)$/\1/p')
  case "$url" in http://127.0.0.1:*) ;; *) fail "expected loopback by default, got $url" ;; esac
}

stop() {
  kill "$daemon"
  wait "$daemon" 2>/dev/null || true
  daemon=
}

echo "== first start makes an identity"
start
first=$node
[ -f "$home/.eureka/identity.key" ] || fail "identity file is not in the home directory"
curl --silent --show-error --fail --max-time 10 "$url/v1/manifest" | tr -d '\r' | grep -q "\"node_id\":\"$first\"" || fail "manifest did not name $first"
# Windows has no SIGTERM to send from here, so only Unix checks the clean exit.
if [ -z "$windows" ]; then
  kill -TERM "$daemon"
  wait "$daemon" 2>/dev/null || true
  daemon=
  tr -d '\r' <"$log" | grep -q '^Shutting down$' || fail "SIGTERM did not shut down cleanly"
else
  stop
fi

echo "== second start loads the same identity"
start
[ "$node" = "$first" ] || fail "expected $first again, got $node"
stop

if [ -n "$windows" ]; then
  echo "== native Windows refuses the agent CLI backends"
  for backend in openclaw hermes claude-code; do
    if out=$(EUREKA_ROOM_TURN=1 EUREKA_ROOM_TURN_BACKEND=$backend "$binary" 0 2>&1); then fail "$backend started"; fi
    case "$out" in *WSL*) ;; *) fail "$backend refusal does not mention WSL: $out" ;; esac
  done
fi
echo "== a seat: setup, start, doctor, stop"
seat="$home/my seat"
if [ -n "$windows" ]; then seat=$(cygpath -w "$seat"); fi
printf '4\n\n\n%s\n\n' "$room_key" | "$binary" setup --dir "$seat" >"$log" 2>&1 || fail "setup failed"
public_key=$(tr -d '\r' <"$log" | grep -E '^ +Public key: ' | awk '{print $3}')
[ -n "$public_key" ] || fail "setup did not print the public key"
seat_url=$(tr -d '\r' <"$log" | sed -n 's/^ *Host: *\(http:.*\)$/\1/p')
[ -n "$seat_url" ] || fail "setup did not print the host"
"$binary" start --dir "$seat" >"$log" 2>&1 || fail "start failed"
curl --silent --show-error --fail --max-time 10 "$seat_url/v1/manifest" >/dev/null || fail "the started seat did not answer"
# No Ollama here, so doctor reports that and exits 1. The rest of its report must still be clean.
"$binary" doctor --dir "$seat" >"$log" 2>&1 || true
tr -d '\r' <"$log" | grep -q 'ok    identity' || fail "doctor did not pass the identity"
tr -d '\r' <"$log" | grep -q 'ok    trust file' || fail "doctor did not pass the trust file"
tr -d '\r' <"$log" | grep -q 'ok    daemon: running' || fail "doctor did not see the running seat"
"$binary" stop --dir "$seat" >"$log" 2>&1 || fail "stop failed"
if curl --silent --max-time 5 "$seat_url/v1/manifest" >/dev/null; then fail "the seat still answers after stop"; fi
"$binary" start --dir "$seat" >"$log" 2>&1 || fail "restart failed"
"$binary" stop --dir "$seat" >"$log" 2>&1 || fail "second stop failed"

if [ -z "$windows" ]; then
  echo "== a Claude Code seat, with a stand-in for claude"
  # It answers the two questions the seat asks before it starts: the version, and the login.
  fake="$home/bin/claude"
  mkdir -p "$home/bin"
  cat >"$fake" <<'FAKE'
#!/bin/sh
case "$1" in
  --version) echo '2.1.319 (Claude Code)' ;;
  auth) printf '{"loggedIn":true,"authMethod":"claude.ai","apiProvider":"firstParty","subscriptionType":"pro","configDirectory":"%s"}\n' "$CLAUDE_CONFIG_DIR" ;;
  *) exit 2 ;;
esac
FAKE
  chmod +x "$fake"
  claude_seat="$home/claude seat"
  printf '5\n\n\n%s\n\n' "$room_key" | EUREKA_CLAUDE_BIN="$fake" "$binary" setup --dir "$claude_seat" >"$log" 2>&1 || fail "Claude Code setup failed"
  tr -d '\r' <"$log" | grep -q 'No project: this seat stays chat only.' || fail "setup did not keep the seat chat only by default"
  tr -d '\r' <"$log" | grep -q 'Name: *Claude$' || fail "the Claude Code seat is not named Claude by default"
  [ -d "$claude_seat/claude-code/config" ] && [ -d "$claude_seat/claude-code/room" ] || fail "setup did not make the seat's Claude Code folders"
  [ ! -e "$home/.claude" ] || fail "setup touched ~/.claude"
  "$binary" start --dir "$claude_seat" >"$log" 2>&1 || fail "the Claude Code seat did not start"
  tr -d '\r' <"$log" | grep -q 'logged in with a Claude pro plan' || fail "start did not check the login"
  ANTHROPIC_API_KEY=not-a-key "$binary" doctor --dir "$claude_seat" >"$log" 2>&1 || fail "doctor found a problem with the Claude Code seat"
  tr -d '\r' <"$log" | grep -q 'ok    Claude Code: Claude Code 2.1.319, logged in with a Claude pro plan' || fail "doctor did not pass Claude Code"
  tr -d '\r' <"$log" | grep -q 'ANTHROPIC_API_KEY is set here; room turns never pass it on' || fail "doctor did not name the dropped API key"
  "$binary" stop --dir "$claude_seat" >"$log" 2>&1 || fail "the Claude Code seat did not stop"

  echo "== a Claude Code seat with a project for approved plans"
  project="$home/site"
  mkdir -p "$project" && (cd "$project" && git init -q && echo hi > a.txt && git add a.txt && git -c user.name=t -c user.email=t@t commit -qm init) || fail "cannot make a test repository"
  plan_seat="$home/plan seat"
  printf '5\n\n\n%s\n%s\n\n' "$room_key" "$project" | EUREKA_CLAUDE_BIN="$fake" "$binary" setup --dir "$plan_seat" >"$log" 2>&1 || fail "setup with a project failed"
  tr -d '\r' <"$log" | grep -q 'for room turns and approved plans' || fail "setup did not grant the room approved plans"
  grep -q '"project_name": "site"' "$plan_seat/seat.json" || fail "setup did not save the project"
  grep -q 'plan-run' "$plan_seat/trust.json" || fail "the trust file has no plan-run grant"
  "$binary" start --dir "$plan_seat" >"$log" 2>&1 || fail "the seat with a project did not start"
  tr -d '\r' <"$plan_seat/daemon.log" | grep -q 'offers: plan-run, plan-status, room-turn' || fail "the seat does not offer approved plans"
  tr -d '\r' <"$plan_seat/daemon.log" | grep -q 'approver none yet' || fail "the seat did not say no approver is pinned"
  "$binary" stop --dir "$plan_seat" >"$log" 2>&1 || fail "the seat with a project did not stop"
  [ -z "$(cd "$project" && git status --porcelain)" ] || fail "starting the seat changed the project"
fi

# The approver passkey: pinned, shown, refused twice, removed. Every platform; the test key from the vectors.
vectors="$(dirname "$0")/../../vectors/plans-v1.json"
credential=$(sed -n 's/^ *"credential_id": "\([A-Za-z0-9_-]*\)",$/\1/p' "$vectors" | head -1)
public_key=$(sed -n 's/^ *"public_key": "\([A-Za-z0-9_-]*\)",$/\1/p' "$vectors" | head -1)
fingerprint=$(sed -n 's/^ *"fingerprint": "\([0-9a-f ]*\)"$/\1/p' "$vectors" | head -1)
approver_seat="$home/approver seat"
"$binary" approver add "$credential" "$public_key" --dir "$approver_seat" >"$log" 2>&1 || fail "approver add failed"
tr -d '\r' <"$log" | grep -q "fingerprint  $fingerprint" || fail "approver add did not print the vectors' fingerprint"
"$binary" approver add "$credential" "$public_key" --dir "$approver_seat" >"$log" 2>&1 && fail "a second approver was accepted"
"$binary" approver show --dir "$approver_seat" >"$log" 2>&1 && tr -d '\r' <"$log" | grep -q "$fingerprint" || fail "approver show"
"$binary" approver remove --dir "$approver_seat" >"$log" 2>&1 || fail "approver remove failed"
[ ! -e "$approver_seat/approver.json" ] || fail "approver remove left the file"

echo "smoke: ok"
