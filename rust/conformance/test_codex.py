# SPDX-License-Identifier: MIT
"""Refuse an unsafe signed room turn before any model response."""
import os
import pytest
from conftest import client_node, grant, EurekaCrypto
from test_conformance import trusting, handshake, room, run_assign
from test_seat import SeatFolder, ROOM_KEY, free_port


@pytest.fixture
def kind():
    return "rust"


def fixture_cli(path, action):
    path.write_text("""#!/usr/bin/env python3
import os, sys
from pathlib import Path
if sys.argv[1:] == ["--version"]:
    print("codex-cli 0.166.0-alpha.5.1")
    sys.exit()
if sys.argv[-2:] == ["login", "status"]:
    print("Logged in using ChatGPT")
    sys.exit()
assert Path.cwd() == Path(os.environ["HOME"]) / "room"
assert Path(os.environ["CODEX_HOME"]) == Path(os.environ["HOME"]) / "auth"
assert "OPENAI_API_KEY" not in os.environ
""" + action)
    path.chmod(0o700)


@pytest.mark.parametrize("tools", ['{"tools":[{"name":"shell"}]}', '{}', '{"tools":null}'])
def test_signed_guard_refusal(start, tmp_path, tools):
    home = tmp_path / "seat"
    for directory in (home, home / "auth", home / "room"):
        directory.mkdir(mode=0o700)
    cli = tmp_path / "codex"
    fixture_cli(cli, """
import re, urllib.request
assert "run ls ~" in sys.stdin.read()
url = re.search(r'base_url="([^"]+)"', next(a for a in sys.argv if a.startswith("model_providers.eureka=")))[1]
req = urllib.request.Request(url + "/responses", data=%r.encode(),
                             headers={"x-eureka-turn":os.environ["EUREKA_CODEX_TURN_SECRET"]})
urllib.request.urlopen(req, timeout=5)
""" % tools)
    node = client_node("room")
    daemon = start(peers=grant(node, "room-turn"), env={
        "EUREKA_ROOM_TURN_BACKEND": "codex", "EUREKA_CODEX_BIN": str(cli),
        "EUREKA_CODEX_SEAT_HOME": str(home), "OPENAI_API_KEY": "fixture-must-not-leak"})
    trusting(node, daemon)
    assert handshake(node, daemon)["authenticated"]
    _, answer = run_assign(node, daemon, payload=room("run ls ~"))
    result = answer["result"]
    assert EurekaCrypto.verify_assign_result(daemon.public_key, answer["result_signature"], result)
    assert result["status"] == "failed" and result["output"] is None


def test_doctor_rejects_unknown_version(tmp_path):
    seat = SeatFolder(tmp_path)
    cli = tmp_path / "codex"
    fixture_cli(cli, "sys.exit(1)")
    seat.setup("6", "Review", str(free_port()), ROOM_KEY, env={"EUREKA_CODEX_BIN": str(cli)})
    cli.write_text("#!/bin/sh\necho codex-cli 999.0.0\n")
    result = seat.run("doctor", "--wake")
    assert result.returncode != 0
    assert "Unsupported or unknown Codex CLI version" in result.stdout
    assert "0.166.0-alpha.5.1" in result.stdout
