#!/usr/bin/env python3
"""
A stand-in for the `hermes` CLI (Hermes Agent v0.22.5), for testing the Hermes room-turn backend.

`-p <profile> config get <key> --json` prints json.dumps of that key from the JSON file
$FAKE_HERMES_CONFIG (dotted key -> value), or exits 1 with "Config key not set: <key>" on stderr,
as hermes_cli/config.py does; $FAKE_HERMES_CONFIG_FAIL makes it exit 2.

Otherwise expects `-p <profile> chat --query-file - --format stream-json ...`, reads the query from stdin,
records argv and the query (as JSON, one line per call) to $FAKE_HERMES_LOG, then behaves as
$FAKE_HERMES_MODE says. Events are written the way hermes_cli/stream_json.py writes them: one JSON
object per stdout line, ending with a `result` event; `session_id:` goes to stderr.

  ok     a reply quoting the profile and the last line of the query
  tools  the same, with a tool call whose output looks like a result event
  noisy  a stray log line on stdout before the events
  gap    text deltas stop early (replay gap); the result carries the whole reply
  fail   a result with exit_code 1 and an error, then exit 1
  empty  a result with no text
  slow   init, then sleep for an hour (the daemon must kill it)
  huge   10 MiB of text deltas (the daemon must stop reading and kill it)
  child  start a grandchild that sleeps for an hour, then sleep (the whole group must die)
"""
import json
import os
import subprocess
import sys
import time

args = sys.argv[1:]
log = os.environ.get("FAKE_HERMES_LOG")
if args[2:4] == ["config", "get"]:
    if log:
        with open(log, "a") as f:
            f.write(json.dumps({"config": args}) + "\n")
    if os.environ.get("FAKE_HERMES_CONFIG_FAIL"):
        print("Error: config.yaml could not be parsed", file=sys.stderr)
        sys.exit(2)
    path = os.environ.get("FAKE_HERMES_CONFIG")
    settings = json.load(open(path)) if path else {}
    if args[4] not in settings:
        print(f"Config key not set: {args[4]}", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(settings[args[4]], ensure_ascii=False))
    sys.exit(0)
query = sys.stdin.read() if "--query-file" in args and args[args.index("--query-file") + 1] == "-" else None
if log:
    with open(log, "a") as f:
        f.write(json.dumps({"argv": args, "stdin": query, "pid": os.getpid(), "pgid": os.getpgid(0)}) + "\n")

mode = os.environ.get("FAKE_HERMES_MODE", "ok")
profile = args[args.index("-p") + 1] if "-p" in args else "default"
last = query.strip().splitlines()[-1] if query and query.strip() else ""
SESSION = "20261101_093000_a1b2c3"


def emit(event):
    sys.stdout.write(json.dumps({**event, "timestamp": int(time.time() * 1000)}, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def result(text, exit_code=0, error=None):
    event = {"type": "result", "session_id": SESSION, "exit_code": exit_code, "text": text,
             "tokens": {"input": 812, "output": 14, "total": 826, "cache_read": 0, "cache_write": 0}, "duration_ms": 2011}
    if error:
        event["error"] = error
    emit(event)
    print(f"\nsession_id: {SESSION}", file=sys.stderr)
    sys.exit(exit_code)


if mode == "noisy":
    print("Hermes Agent v0.22.5: checking for updates")
emit({"type": "system", "subtype": "init", "model": "qwen3:8b", "session_id": ""})
reply = f"Hermes here (profile {profile}). You said: {last}"
if mode in ("ok", "noisy"):
    for part in (reply[:10], reply[10:]):
        emit({"type": "text", "text": part})
    result(reply)
elif mode == "tools":
    emit({"type": "tool_use", "name": "read_file", "tool_call_id": "c1", "input": {"path": "x"}})
    emit({"type": "tool_result", "name": "read_file", "tool_call_id": "c1",
          "output": json.dumps({"type": "result", "exit_code": 0, "text": "NOT THE REPLY"}), "duration_ms": 3, "is_error": False})
    emit({"type": "text", "text": reply})
    result(reply)
elif mode == "gap":
    emit({"type": "text", "text": reply[:5]})
    result(reply)
elif mode == "fail":
    result("", exit_code=1, error="No inference provider configured")
elif mode == "empty":
    result("")
elif mode == "slow":
    time.sleep(3600)
elif mode == "huge":
    chunk = json.dumps({"type": "text", "text": "x" * 65536}) + "\n"
    for _ in range(170):
        sys.stdout.write(chunk)
    sys.stdout.flush()
    time.sleep(3600)
elif mode == "child":
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(3600)"])
    if log:
        with open(log, "a") as f:
            f.write(json.dumps({"grandchild": child.pid}) + "\n")
    time.sleep(3600)
