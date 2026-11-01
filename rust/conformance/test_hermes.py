"""
The Hermes Agent room-turn backend (Rust build only), with fake_hermes.py standing in for `hermes`.
"""
import json
import os
import time
from pathlib import Path

import pytest

from conftest import HERE, client_node, grant
from test_conformance import handshake, room, run_assign, trusting

FAKE = str(HERE / "fake_hermes.py")


@pytest.fixture
def kind():
    if os.environ.get("EUREKA_CONFORMANCE", "rust") != "rust":
        pytest.skip("the Hermes backend is in the Rust build only")
    return "rust"


@pytest.fixture
def hermes_home(tmp_path):
    home = tmp_path / "hermes-home"
    (home / "profiles" / "knights-circle").mkdir(parents=True)
    return home


@pytest.fixture
def hermes(start, tmp_path, hermes_home):
    def _hermes(mode="ok", **env):
        log = tmp_path / f"calls-{mode}.jsonl"
        node = client_node("room")
        daemon = start(peers=grant(node, "room-turn"), env={
            "EUREKA_ROOM_TURN_BACKEND": "hermes", "EUREKA_HERMES_BIN": FAKE, "HERMES_HOME": str(hermes_home),
            "FAKE_HERMES_MODE": mode, "FAKE_HERMES_LOG": str(log), **env})
        trusting(node, daemon)
        assert handshake(node, daemon)["authenticated"] is True
        return node, daemon, log
    return _hermes


def calls(log: Path):
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def test_a_turn_runs_hermes_in_its_profile_with_the_room_on_stdin(hermes, ollama):
    node, daemon, log = hermes()
    answer = run_assign(node, daemon, payload=room("Plan the beds", "And the path; rm -rf / $(whoami) `id`"))[1]
    result = answer["result"]
    assert (result["status"], result["reason"]) == ("completed", "ok")
    assert result["output"] == {"model": "hermes", "text": "Hermes here (profile knights-circle). You said: And the path; rm -rf / $(whoami) `id`",
                                "chars": len(result["output"]["text"]), "truncated": False, "done_reason": None, "eval_count": 14}
    (call,) = calls(log)
    # Exactly these arguments; the room's text is never in argv, only on stdin.
    assert call["argv"] == ["-p", "knights-circle", "chat", "--query-file", "-", "--format", "stream-json",
                            "--source", "tool", "--run-budget", "120"]
    assert call["stdin"].startswith("You are an external agent taking one turn in a Knights Circle room")
    assert "[system]\nYou are the Critic.\n\n[user]\nPlan the beds\n\n[user]\nAnd the path; rm -rf / $(whoami) `id`" in call["stdin"]
    assert call["pgid"] == call["pid"]
    assert ollama.requests == []
    assert "room-turn via Hermes Agent" in daemon.output() and "a new session each turn" in daemon.output()


def test_profile_session_and_time_limit_are_configurable(hermes, hermes_home):
    (hermes_home / "profiles" / "rooms").mkdir()
    node, daemon, log = hermes(EUREKA_HERMES_PROFILE="rooms", EUREKA_HERMES_SESSION="kc-thread", EUREKA_HERMES_TIMEOUT="45")
    run_assign(node, daemon)
    assert calls(log)[0]["argv"] == ["-p", "rooms", "chat", "--query-file", "-", "--format", "stream-json", "--source", "tool",
                                     "--run-budget", "45", "-c", "kc-thread", "--create-if-missing"]


@pytest.mark.parametrize("mode", ["tools", "noisy", "gap"])
def test_only_the_result_text_is_the_reply(hermes, mode):
    node, daemon, _ = hermes(mode)
    text = run_assign(node, daemon)[1]["result"]["output"]["text"]
    assert text.startswith("Hermes here (profile knights-circle).") and "NOT THE REPLY" not in text and "checking for updates" not in text


def test_a_long_room_goes_through_stdin_whole(hermes):
    node, daemon, log = hermes()
    big = "語" * 20_000  # 60 KB of UTF-8, near the daemon's 64 KiB request cap
    assert run_assign(node, daemon, payload=room(big))[1]["result"]["status"] == "completed"
    assert big in calls(log)[0]["stdin"]


@pytest.mark.parametrize("mode", ["fail", "empty"])
def test_a_failed_or_empty_run_is_upstream_error(hermes, mode):
    node, daemon, _ = hermes(mode)
    result = run_assign(node, daemon)[1]["result"]
    assert (result["status"], result["reason"], result["output"]) == ("failed", "upstream_error", None)


def test_a_slow_agent_is_killed_at_the_timeout(hermes):
    node, daemon, log = hermes("slow", EUREKA_HERMES_TIMEOUT="2")
    began = time.time()
    assert run_assign(node, daemon)[1]["result"]["reason"] == "timeout" and time.time() - began < 10
    time.sleep(0.5)
    assert not alive(calls(log)[0]["pid"])


def test_the_whole_process_group_dies_with_the_turn(hermes):
    node, daemon, log = hermes("child", EUREKA_HERMES_TIMEOUT="2")
    assert run_assign(node, daemon)[1]["result"]["reason"] == "timeout"
    time.sleep(0.5)
    assert not alive(next(c["grandchild"] for c in calls(log) if "grandchild" in c))


def test_huge_output_is_refused_and_the_agent_stopped(hermes):
    node, daemon, log = hermes("huge")
    began = time.time()
    result = run_assign(node, daemon)[1]["result"]
    assert (result["status"], result["reason"]) == ("failed", "upstream_error") and time.time() - began < 15
    time.sleep(0.5)
    assert not alive(calls(log)[0]["pid"])


def test_payload_checks_apply_before_hermes_runs(hermes):
    node, daemon, log = hermes()
    for payload, reason in [({"messages": []}, "invalid_payload"),
                            ({"messages": [{"role": "user", "content": "x" * 48_001}]}, "room_turn_too_long")]:
        assert run_assign(node, daemon, payload=payload)[1]["result"]["reason"] == reason
    assert calls(log) == []


@pytest.mark.parametrize("env,words", [
    ({"EUREKA_HERMES_BIN": "/nonexistent/hermes"}, "cannot find"),
    ({"EUREKA_HERMES_PROFILE": "missing"}, "hermes profile create missing --clone"),
    ({"EUREKA_HERMES_PROFILE": "Not-Valid"}, "EUREKA_HERMES_PROFILE"),
    ({"EUREKA_HERMES_SESSION": "--help"}, "EUREKA_HERMES_SESSION"),
    ({"EUREKA_HERMES_TIMEOUT": "0"}, "EUREKA_HERMES_TIMEOUT"),
])
def test_bad_settings_stop_the_daemon_at_startup(start, hermes_home, env, words):
    with pytest.raises(RuntimeError, match=words):
        start(env={"EUREKA_ROOM_TURN_BACKEND": "hermes", "EUREKA_HERMES_BIN": FAKE, "HERMES_HOME": str(hermes_home), **env})
