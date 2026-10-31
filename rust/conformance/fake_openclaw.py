#!/usr/bin/env python3
"""
A stand-in for the `openclaw` CLI, for testing the OpenClaw room-turn backend.

Records exactly the argv it was given (as JSON, one line per call) to
$FAKE_OPENCLAW_LOG, then behaves as $FAKE_OPENCLAW_MODE says:

  ok     print a reply that quotes the session and the last line of the message
  ansi   the same reply wrapped in colour codes
  slow   sleep for an hour (the daemon must kill it)
  huge   print 3 MiB (the daemon must stop reading and kill it)
  fail   print to stderr and exit 3
  empty  print nothing and exit 0
  child  start a grandchild that sleeps for an hour, then sleep (the whole group must die)
"""
import json
import os
import subprocess
import sys
import time

log = os.environ.get("FAKE_OPENCLAW_LOG")
if log:
    with open(log, "a") as f:
        f.write(json.dumps({"argv": sys.argv[1:], "pid": os.getpid(), "pgid": os.getpgid(0)}) + "\n")

mode = os.environ.get("FAKE_OPENCLAW_MODE", "ok")
args = sys.argv[1:]
session = args[args.index("--session-id") + 1] if "--session-id" in args else "?"
message = args[args.index("--message") + 1] if "--message" in args else ""
last = message.strip().splitlines()[-1] if message.strip() else ""

if mode == "ok":
    print(f"Antiochus here (session {session}). You said: {last}")
elif mode == "ansi":
    print(f"\x1b[1;32mAntiochus here (session {session}).\x1b[0m You said: {last}")
elif mode == "slow":
    time.sleep(3600)
elif mode == "huge":
    sys.stdout.write("x" * (3 * 1024 * 1024))
    sys.stdout.flush()
    time.sleep(3600)
elif mode == "fail":
    print("openclaw: gateway not reachable", file=sys.stderr)
    sys.exit(3)
elif mode == "empty":
    pass
elif mode == "child":
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(3600)"])
    if log:
        with open(log, "a") as f:
            f.write(json.dumps({"grandchild": child.pid}) + "\n")
    time.sleep(3600)
