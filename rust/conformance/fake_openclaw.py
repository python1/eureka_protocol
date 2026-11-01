#!/usr/bin/env python3
"""
A stand-in for the `openclaw` CLI, for testing the OpenClaw room-turn backend.

Records exactly the argv it was given (as JSON, one line per call) to
$FAKE_OPENCLAW_LOG, then behaves as $FAKE_OPENCLAW_MODE says. With --json,
replies are printed the way OpenClaw 2026.6.5 prints them: a result object
with the reply in result.payloads[].text, among run metadata.

  ok     reply quoting the session and the last line of the message
  ansi   the same reply wrapped in colour codes
  banner the terminal banner and a joke line, then the result
  error  a result with status "error"
  aborted a result marked aborted
  slow   sleep for an hour (the daemon must kill it)
  huge   print 10 MiB (the daemon must stop reading and kill it)
  long   a valid result whose reply is 12,005 characters
  fail   print to stderr and exit 3
  empty  print nothing and exit 0
  child  start a grandchild that sleeps for an hour, then sleep (the whole group must die)
"""
import json
import os
import uuid
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
as_json = "--json" in args
BANNER = "\u2502\n\u25c7  OpenClaw 2026.6.5 (5181e4f)\n\u2502\n\u2502  Why did the lobster refuse to share? It was a little shellfish.\n\u2502\n\u25c7\n"


def reply(text, status="ok", aborted=False):
    if not as_json:
        print(text)
        return
    print(json.dumps({"runId": str(uuid.uuid4()), "status": status, "summary": "completed" if status == "ok" else "failed",
                      "result": {"payloads": [{"text": text, "mediaUrl": None}],
                                 "meta": {"durationMs": 1603, "agentMeta": {"sessionId": session, "provider": "ollama",
                                                                            "model": "gemma4:26b", "usage": {"input": 25390, "output": 8, "total": 25398}},
                                          "aborted": aborted, "finalAssistantVisibleText": text, "stopReason": "stop",
                                          "systemPromptReport": {"systemPrompt": {"chars": 40980}, "tools": {"entries": ["x"] * 50}}}}}, indent=2))


text = f"Antiochus here (session {session}). You said: {last}"
if mode == "ok":
    reply(text)
elif mode == "ansi":
    reply(f"\x1b[1;32mAntiochus here (session {session}).\x1b[0m You said: {last}")
elif mode == "banner":
    sys.stdout.write(BANNER)
    reply(text)
elif mode == "error":
    reply("partial", status="error")
elif mode == "aborted":
    reply("partial", aborted=True)
elif mode == "slow":
    time.sleep(3600)
elif mode == "long":
    reply("\U0001F331" * 12_005)
elif mode == "huge":
    sys.stdout.write("x" * (10 * 1024 * 1024))
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
