"""
Files and command line: existing identity keys and trust files keep working in
both directions, and the flags behave as server.py's do.
"""
import json
import os
import subprocess
import sys

import httpx
import pytest

from conftest import HERE, Daemon, client_node, free_port, grant, rust_binary
from test_conformance import handshake, run_assign, trusting


@pytest.fixture
def kind():
    return "rust"


def test_a_python_identity_key_is_the_same_node_in_rust_and_back(tmp_path, ollama):
    py = Daemon("python", tmp_path, ollama.url)
    py.stop()
    rs = Daemon("rust", tmp_path, ollama.url)  # same identity.key, same trust.json
    assert (rs.node_id, rs.public_key) == (py.node_id, py.public_key)
    rs.stop()
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    made_by_rust = Daemon("rust", fresh, ollama.url)
    made_by_rust.stop()
    assert oct(os.stat(made_by_rust.identity).st_mode & 0o777) == "0o600"
    loaded_by_python = Daemon("python", fresh, ollama.url)
    assert loaded_by_python.node_id == made_by_rust.node_id
    loaded_by_python.stop()


def test_a_python_written_trust_file_grants_the_same_in_rust(start, tmp_path):
    node = client_node("room")
    daemon = start(peers=grant(node, "room-turn"))
    trusting(node, daemon)
    assert handshake(node, daemon)["authenticated"] is True
    assert run_assign(node, daemon)[1]["result"]["status"] == "completed"


def test_trust_add_writes_exactly_what_the_knights_circle_python_command_writes(tmp_path):
    seed = {"version": 3, "algorithm": "ed25519",
            "peers": {"old": {"public_key": "ab" * 32, "capabilities": ["room-turn", "inference"]}},
            "revoked": [{"public_key": "cd" * 32, "reason": " lost "}, "12" * 32]}
    for name in ("py.json", "rust.json"):
        (tmp_path / name).write_text(json.dumps(seed))
    key = "EF" * 32
    subprocess.run([sys.executable, "-c", f"""
import json, os, sys
sys.path.insert(0, {str(HERE.parents[2])!r})
from pathlib import Path
from eureka_protocol.src.eureka_daemon.trust import TrustList
p = Path(os.environ['EUREKA_TRUST_PATH']).expanduser()
t = TrustList.load(p) if p.exists() else TrustList()
t.add('knights-circle-node_x', '{key}', ['room-turn'])
p.write_text(json.dumps(t.to_document(), indent=2) + '\\n'); p.chmod(0o600)
"""], env={**os.environ, "EUREKA_TRUST_PATH": str(tmp_path / "py.json")}, check=True)
    subprocess.run([str(rust_binary()), "trust", "add", "knights-circle-node_x", key, "room-turn"],
                   env={**os.environ, "EUREKA_TRUST_PATH": str(tmp_path / "rust.json")}, check=True, capture_output=True)
    assert (tmp_path / "rust.json").read_bytes() == (tmp_path / "py.json").read_bytes()
    refused = subprocess.run([str(rust_binary()), "trust", "add", "back", "cd" * 32, "room-turn"],
                             env={**os.environ, "EUREKA_TRUST_PATH": str(tmp_path / "rust.json")}, capture_output=True, text=True)
    assert refused.returncode == 1 and "revoked" in refused.stderr


def test_startup_lines_match_and_loopback_is_the_default(start):
    daemon = start(cors=["https://knights-circle.vercel.app"])
    out = daemon.output()
    assert f"Starting Eureka Daemon API as {daemon.node_id}" in out
    assert f"  public key: {daemon.public_key}" in out
    assert f"  listening on http://127.0.0.1:{daemon.port}" in out
    assert "  browser pages allowed to read replies: https://knights-circle.vercel.app" in out
    assert "  offers: inference, room-turn" in out
    with pytest.raises(httpx.HTTPError):
        httpx.get(f"http://[::1]:{daemon.port}/v1/manifest", timeout=1)


def run_binary(*args, env=None):
    return subprocess.run([str(rust_binary()), *args], capture_output=True, text=True, timeout=10,
                          env={"PATH": os.environ["PATH"], "HOME": "/nonexistent", **(env or {})})


@pytest.mark.parametrize("args,env,words", [
    (["--tls"], {}, "not in the Rust build"),
    (["--cors-origin", "*"], {}, "no wildcards"),
    (["--cors-origin", "http://example.com"], {}, "plain http is only allowed"),
    (["abc"], {}, "invalid int value"),
    (["--hos", "127.0.0.1", "--nope"], {}, "unrecognized arguments: --nope"),
    ([], {"EUREKA_ROOM_TURN": "maybe"}, "neither on nor off"),
    ([], {"EUREKA_ROOM_TURN": "1", "EUREKA_ROOM_TURN_MODEL": "a b"}, "not an Ollama model name"),
    ([], {"EUREKA_ROOM_TURN": "1", "EUREKA_OLLAMA_URL": "http://192.168.1.5:11434"}, "not loopback"),
])
def test_bad_flags_and_settings_stop_with_a_reason(args, env, words):
    result = run_binary(str(free_port()), *args, env=env) if args[:1] != ["abc"] else run_binary(*args, env=env)
    assert result.returncode != 0 and words in result.stderr


def test_help_names_every_flag():
    out = run_binary("--help").stdout
    for flag in ("--host", "--cors-origin", "--tls-port", "EUREKA_ROOM_TURN_BACKEND", "trust add"):
        assert flag in out
