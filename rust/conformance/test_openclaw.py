"""
The OpenClaw room-turn backend (Rust build only), with fake_openclaw.py standing in for `openclaw`.
"""
import json
import os
import time
from pathlib import Path

import pytest

from conftest import HERE, client_node, grant
from test_conformance import handshake, room, run_assign, trusting

FAKE = str(HERE / "fake_openclaw.py")


@pytest.fixture
def kind():
    if os.environ.get("EUREKA_CONFORMANCE", "rust") != "rust":
        pytest.skip("the OpenClaw backend is in the Rust build only")
    return "rust"


@pytest.fixture
def claw(start, tmp_path):
    def _claw(mode="ok", **env):
        log = tmp_path / f"calls-{mode}.jsonl"
        node = client_node("room")
        daemon = start(peers=grant(node, "room-turn"), env={
            "EUREKA_ROOM_TURN_BACKEND": "openclaw", "EUREKA_OPENCLAW_BIN": FAKE,
            "FAKE_OPENCLAW_MODE": mode, "FAKE_OPENCLAW_LOG": str(log), **env})
        trusting(node, daemon)
        assert handshake(node, daemon)["authenticated"] is True
        return node, daemon, log
    return _claw


def calls(log: Path):
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def test_a_turn_runs_openclaw_agent_with_the_room_session_and_returns_stdout(claw, ollama):
    node, daemon, log = claw()
    answer = run_assign(node, daemon, payload=room("Plan the beds", "And the path; rm -rf / $(whoami) `id`"))[1]
    output = answer["result"]["output"]
    assert answer["result"]["status"] == "completed"
    # Only the reply: none of the run metadata OpenClaw prints around it.
    assert output == {"model": "openclaw", "text": "Antiochus here (session knights-circle). You said: And the path; rm -rf / $(whoami) `id`",
                      "chars": len(output["text"]), "truncated": False, "done_reason": "stop", "eval_count": 8}
    (call,) = calls(log)
    argv = call["argv"]
    # Exactly these arguments, the message as one argv entry, no shell anywhere.
    assert argv[:5] == ["agent", "--session-id", "knights-circle", "--json", "--message"] and len(argv) == 6
    assert argv[5].startswith("You are an external agent taking one turn in a Knights Circle room")
    assert "[system]\nYou are the Critic.\n\n[user]\nPlan the beds\n\n[user]\nAnd the path; rm -rf / $(whoami) `id`" in argv[5]
    assert call["pgid"] == call["pid"]  # its own process group
    assert ollama.requests == []
    assert "via OpenClaw" in daemon.output()


def test_the_session_id_is_configurable(claw):
    node, daemon, log = claw(EUREKA_OPENCLAW_SESSION="kc-test")
    run_assign(node, daemon)
    assert calls(log)[0]["argv"][2] == "kc-test"


def test_a_banner_printed_before_the_result_is_not_part_of_the_reply(claw):
    node, daemon, _ = claw("banner")
    text = run_assign(node, daemon)[1]["result"]["output"]["text"]
    assert text.startswith("Antiochus here") and "OpenClaw 2026.6.5" not in text and "shellfish" not in text and "\u2502" not in text


def test_colour_codes_are_removed(claw):
    node, daemon, _ = claw("ansi")
    assert "\x1b" not in run_assign(node, daemon)[1]["result"]["output"]["text"]


@pytest.mark.parametrize("mode", ["fail", "empty", "error", "aborted"])
def test_a_failing_or_silent_agent_is_upstream_error(claw, mode):
    node, daemon, _ = claw(mode)
    result = run_assign(node, daemon)[1]["result"]
    assert (result["status"], result["reason"], result["output"]) == ("failed", "upstream_error", None)


def test_a_slow_agent_is_killed_at_the_timeout(claw):
    node, daemon, log = claw("slow", EUREKA_OPENCLAW_TIMEOUT="2")
    began = time.time()
    result = run_assign(node, daemon)[1]["result"]
    assert result["reason"] == "timeout" and time.time() - began < 10
    time.sleep(0.5)
    assert not alive(calls(log)[0]["pid"])


def test_the_whole_process_group_dies_with_the_turn(claw):
    node, daemon, log = claw("child", EUREKA_OPENCLAW_TIMEOUT="2")
    assert run_assign(node, daemon)[1]["result"]["reason"] == "timeout"
    time.sleep(0.5)
    grandchild = next(c["grandchild"] for c in calls(log) if "grandchild" in c)
    assert not alive(grandchild)


def test_huge_output_is_refused_and_the_agent_stopped(claw):
    node, daemon, log = claw("huge")
    began = time.time()
    result = run_assign(node, daemon)[1]["result"]
    assert (result["status"], result["reason"]) == ("failed", "upstream_error") and time.time() - began < 15
    time.sleep(0.5)
    assert not alive(calls(log)[0]["pid"])


def test_a_long_reply_is_capped_in_characters_and_says_so(claw):
    node, daemon, _ = claw("long")
    output = run_assign(node, daemon)[1]["result"]["output"]
    assert output["truncated"] is True and output["chars"] == 12_000 and output["text"] == "\U0001F331" * 12_000


def test_payload_checks_still_apply_before_openclaw_runs(claw):
    node, daemon, log = claw()
    for payload, reason in [({"messages": []}, "invalid_payload"),
                            ({"messages": [{"role": "user", "content": "x" * 48_001}]}, "room_turn_too_long")]:
        assert run_assign(node, daemon, payload=payload)[1]["result"]["reason"] == reason
    assert calls(log) == []


@pytest.mark.parametrize("env,words", [
    ({"EUREKA_OPENCLAW_BIN": "/nonexistent/openclaw"}, "cannot find"),
    ({"EUREKA_OPENCLAW_SESSION": "--help"}, "EUREKA_OPENCLAW_SESSION"),
    ({"EUREKA_OPENCLAW_TIMEOUT": "0"}, "EUREKA_OPENCLAW_TIMEOUT"),
    ({"EUREKA_ROOM_TURN_BACKEND": "gpt"}, "use ollama, openclaw or hermes"),
])
def test_bad_settings_stop_the_daemon_at_startup(start, env, words):
    with pytest.raises(RuntimeError, match=words):
        start(env={"EUREKA_ROOM_TURN_BACKEND": "openclaw", "EUREKA_OPENCLAW_BIN": FAKE, **env})
