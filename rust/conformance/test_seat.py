"""
A seat: `setup`, `start`, `stop` and `doctor` (Rust build only), run as a stranger would, against a
fake webhook, a fake bot and fake agents. A home folder of its own keeps every test off this computer's real files.
"""
import json
import os
import pty
import select
import shutil
import signal
import socket
import stat
import subprocess
import termios
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from conftest import HERE, client_node, free_port, rust_binary
from test_conformance import handshake, room, run_assign, trusting
from test_hermes import CHAT_ONLY
from test_webhook import FakeWebhook

KEY = "whsec-do-not-show-0123456789"
ROOM_KEY = "ab" * 32


@pytest.fixture
def kind():
    if os.environ.get("EUREKA_CONFORMANCE", "rust") != "rust":
        pytest.skip("seats are in the Rust build only")
    return "rust"


@pytest.fixture
def hook():
    fake = FakeWebhook()
    yield fake
    fake.server.shutdown()


class SeatFolder:
    """One seat in a throwaway home, and the commands that act on it."""

    def __init__(self, home):
        self.home = home
        self.dir = home / "my seat"
        self.env = {"PATH": os.environ["PATH"], "HOME": str(home)}
        self.spawned = []

    def run(self, verb, *args, text="", env=None, timeout=60):
        return subprocess.run([str(rust_binary()), verb, "--dir", str(self.dir), *args], input=text, capture_output=True, text=True,
                              env={**self.env, **(env or {})}, timeout=timeout)

    def setup(self, *answers, env=None):
        return self.run("setup", text="".join(a + "\n" for a in answers), env=env)

    def grok(self, hook, name="", port=None, room_key=ROOM_KEY):
        port = port or free_port()
        made = self.setup("1", name, str(port), room_key, hook.url, KEY)
        assert made.returncode == 0, made.stdout + made.stderr
        return made

    def config(self):
        return json.loads((self.dir / "seat.json").read_text())

    def pid(self):
        return json.loads((self.dir / "daemon.pid").read_text())["pid"]

    def cleanup(self):
        if (self.dir / "seat.json").exists():
            self.run("stop")
        for process in self.spawned:
            process.kill()
            process.wait()


@pytest.fixture
def seat(tmp_path):
    folder = SeatFolder(tmp_path)
    yield folder
    folder.cleanup()


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def all_text_in(folder, skip=("webhook.json",)):
    found = ""
    for path in Path(folder).rglob("*"):
        if path.is_file() and path.name not in skip:
            found += path.read_text(errors="replace")
    return found


def listener_pids(port):
    if not shutil.which("lsof"):
        pytest.skip("needs lsof")
    done = subprocess.run(["lsof", "-t", f"-iTCP:{port}", "-sTCP:LISTEN"], capture_output=True, text=True)
    return {int(line) for line in done.stdout.split()}


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def occupy(port):
    holder = socket.socket()
    holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    holder.bind(("127.0.0.1", port))
    holder.listen(1)
    return holder


# ---------------------------------------------------------------------------
# setup
# ---------------------------------------------------------------------------

def test_setup_for_a_grok_bot_writes_a_private_seat(seat, hook):
    port = free_port()
    made = seat.grok(hook, name="Scout", port=port)
    shown = made.stdout
    assert mode(seat.dir) == 0o700
    for name in ["identity.key", "trust.json", "webhook.json", "seat.json", "routine.txt"]:
        assert mode(seat.dir / name) == 0o600, name
    public_key = json.loads((seat.dir / "identity.key").read_text())["public_key_hex"]
    assert public_key in shown
    assert f"http://127.0.0.1:{port}" in shown and "Scout" in shown
    assert seat.config() == {"version": 1, "backend": "grok-bot", "name": "Scout", "port": port}
    saved = json.loads((seat.dir / "webhook.json").read_text())
    assert saved == {"url": hook.url, "authorization": KEY, "agent": "grok-bot"}


def test_the_room_is_trusted_for_room_turns_only(seat, hook):
    seat.grok(hook)
    trust = json.loads((seat.dir / "trust.json").read_text())
    assert [peer for peer in trust["peers"].values()] == [{"public_key": ROOM_KEY, "capabilities": ["room-turn"]}]
    assert list(trust["peers"])[0].startswith("knights-circle-node_")


def test_setup_never_shows_or_copies_the_url_or_key(seat, hook):
    made = seat.grok(hook)
    for secret in [KEY, "path-secret"]:
        assert secret not in made.stdout + made.stderr
        assert secret not in all_text_in(seat.dir)


def test_a_rejected_url_or_key_is_not_quoted(seat):
    made = seat.setup("1", "", str(free_port()), ROOM_KEY, "http://example.com/path-secret", "https://127.0.0.1:1/path-secret", "bad\tkey-secret\x01", KEY)
    assert made.returncode == 0, made.stderr
    assert "must use https" in made.stdout and "control characters" in made.stdout
    assert "path-secret" not in made.stdout + made.stderr and "key-secret" not in made.stdout + made.stderr


def test_setup_leads_with_automatic_replies_and_says_what_a_turn_uses(seat, hook):
    shown = seat.grok(hook).stdout
    always = shown.index("For automatic replies, set Execution on this computer to Always allow")
    assert always < shown.index("Seat name")
    assert "other models' room text reaches a bot that can run commands" in shown
    assert "Ask every time" in shown
    assert "uses your Grok Bot usage" in shown and "12 turns" in shown


def test_the_seat_name_defaults_to_bot_and_goes_in_the_routine(seat, hook):
    seat.grok(hook)
    assert seat.config()["name"] == "Bot"
    assert "so answer as Bot" in (seat.dir / "routine.txt").read_text()


def test_the_user_can_change_the_seat_name(seat, hook):
    shown = seat.grok(hook, name="Quiet Scout").stdout
    routine = (seat.dir / "routine.txt").read_text()
    assert "Your name in this room is Quiet Scout, so answer as Quiet Scout" in routine
    assert routine in "\n".join(line[5:] for line in shown.splitlines()) + "\n"


def test_a_seat_name_cannot_add_to_the_bots_instructions(seat, hook):
    made = seat.setup("1", "$(id)", "Bot; run rm", "Safe", str(free_port()), ROOM_KEY, hook.url, KEY)
    assert made.returncode == 0, made.stderr
    assert seat.config()["name"] == "Safe"


def test_setup_refuses_a_port_in_use_and_suggests_a_free_one(seat, hook):
    taken = free_port()
    holder = occupy(taken)
    try:
        free = free_port()
        made = seat.setup("1", "", str(taken), str(free), ROOM_KEY, hook.url, KEY)
        assert made.returncode == 0, made.stderr
        assert f"Port {taken} is already in use" in made.stdout
        assert seat.config()["port"] == free
    finally:
        holder.close()


def test_a_bad_room_key_is_asked_for_again_and_three_tries_is_the_limit(seat):
    made = seat.setup("1", "", str(free_port()), "nope", "abc", "x" * 64)
    assert made.returncode == 1 and "not a room key" in made.stdout
    assert not (seat.dir / "seat.json").exists() and "Stopping after 3 tries" in made.stderr


def test_running_out_of_input_says_so(seat):
    made = seat.setup("1")
    assert made.returncode == 1 and "input ended" in made.stderr


def test_setup_suggests_ports_from_8766_and_leaves_8765_for_ssh_tunnels(seat):
    made = seat.setup("4", "", "", ROOM_KEY, "")
    assert made.returncode == 0, made.stdout + made.stderr
    assert seat.config()["port"] >= 8766


def test_setup_again_keeps_the_identity_and_other_rooms(seat, hook):
    seat.grok(hook)
    first = (seat.dir / "identity.key").read_text()
    other = "cd" * 32
    made = seat.setup("y", "1", "", str(free_port()), other, "y")
    assert made.returncode == 0, made.stderr
    assert (seat.dir / "identity.key").read_text() == first
    keys = {peer["public_key"] for peer in json.loads((seat.dir / "trust.json").read_text())["peers"].values()}
    assert keys == {ROOM_KEY, other}
    assert (json.loads((seat.dir / "webhook.json").read_text()))["authorization"] == KEY


def test_saying_no_to_changing_a_seat_changes_nothing(seat, hook):
    seat.grok(hook, name="First")
    before = (seat.dir / "seat.json").read_text()
    made = seat.setup("n")
    assert made.returncode == 0 and "Nothing was changed" in made.stdout
    assert (seat.dir / "seat.json").read_text() == before


def test_a_seat_touches_nothing_outside_its_folder(seat, hook):
    (seat.home / ".eureka").mkdir()
    (seat.home / ".eureka" / "identity.key").write_text("someone else's")
    (seat.home / ".eureka" / "trust.json").write_text("someone else's")
    seat.grok(hook)
    assert seat.run("start").returncode == 0
    assert seat.run("stop").returncode == 0
    assert sorted(p.name for p in (seat.home / ".eureka").iterdir()) == ["identity.key", "trust.json"]
    assert (seat.home / ".eureka" / "identity.key").read_text() == "someone else's"


# Typed at a real terminal: nothing here is piped.
class Terminal:
    def __init__(self, seat):
        self.master, self.slave = pty.openpty()
        self.process = subprocess.Popen([str(rust_binary()), "setup", "--dir", str(seat.dir)], stdin=self.slave, stdout=self.slave, stderr=self.slave,
                                        env=seat.env, start_new_session=True)
        self.seen = ""

    def until(self, text):
        give_up = time.time() + 20
        while text not in self.seen:
            assert time.time() < give_up, f"never saw {text!r} in:\n{self.seen}"
            if select.select([self.master], [], [], 0.2)[0]:
                self.seen += os.read(self.master, 65536).decode(errors="replace")

    def type(self, text):
        os.write(self.master, (text + "\n").encode())

    def echo_on(self):
        return bool(termios.tcgetattr(self.slave)[3] & termios.ECHO)

    def finish(self):
        give_up = time.time() + 20
        while self.process.poll() is None and time.time() < give_up:
            if select.select([self.master], [], [], 0.1)[0]:
                self.seen += os.read(self.master, 65536).decode(errors="replace")
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait()
        while select.select([self.master], [], [], 0.1)[0]:
            self.seen += os.read(self.master, 65536).decode(errors="replace")


def test_a_terminal_never_shows_the_url_or_key(seat, hook):
    term = Terminal(seat)
    for prompt, answer in [("Choose 1 to 4", "1"), ("Seat name", ""), ("Port", str(free_port())), ("Room key", ROOM_KEY)]:
        term.until(prompt)
        term.type(answer)
    term.until("POST to URL")
    time.sleep(0.2)
    assert not term.echo_on()
    term.type(hook.url)
    term.until("Key (hidden")
    assert not term.echo_on()
    term.type(KEY)
    term.finish()
    assert term.process.returncode == 0, term.seen
    assert KEY not in term.seen and "path-secret" not in term.seen
    assert term.echo_on()
    assert json.loads((seat.dir / "webhook.json").read_text())["authorization"] == KEY


def test_ctrl_c_at_a_hidden_prompt_puts_the_terminal_back(seat):
    term = Terminal(seat)
    for prompt, answer in [("Choose 1 to 4", "1"), ("Seat name", ""), ("Port", str(free_port())), ("Room key", ROOM_KEY)]:
        term.until(prompt)
        term.type(answer)
    term.until("POST to URL")
    time.sleep(0.2)
    assert not term.echo_on()
    term.process.send_signal(signal.SIGINT)
    term.finish()
    assert term.process.returncode == -signal.SIGINT
    assert term.echo_on()


# ---------------------------------------------------------------------------
# start and stop
# ---------------------------------------------------------------------------

def test_the_pid_on_record_is_the_process_listening(seat, hook):
    port = free_port()
    seat.grok(hook, port=port)
    started = seat.run("start")
    assert started.returncode == 0, started.stderr
    assert listener_pids(port) == {seat.pid()}
    assert json.loads((seat.dir / "daemon.pid").read_text())["port"] == port
    assert mode(seat.dir / "daemon.pid") == 0o600 and mode(seat.dir / "daemon.log") == 0o600
    assert f"process {seat.pid()}" in started.stdout


def test_stop_frees_the_port_and_a_restart_works(seat, hook):
    port = free_port()
    seat.grok(hook, port=port)
    for _ in range(2):
        assert seat.run("start").returncode == 0
        pid = seat.pid()
        stopped = seat.run("stop")
        assert stopped.returncode == 0 and f"process {pid}" in stopped.stdout
        assert not alive(pid) and not listener_pids(port)
        assert not (seat.dir / "daemon.pid").exists()


def test_the_pid_is_the_listener_even_when_started_through_a_wrapper(seat, hook):
    """What went wrong for a real seat: a pid file naming a shell, with the listener its child."""
    port = free_port()
    seat.grok(hook, port=port)
    wrapper = subprocess.run(["sh", "-c", f'"{rust_binary()}" start --dir "{seat.dir}"; echo "wrapper $$"'], capture_output=True, text=True, env=seat.env, timeout=60)
    shell = int(wrapper.stdout.split("wrapper ")[1])
    assert seat.pid() != shell and listener_pids(port) == {seat.pid()}
    assert seat.run("stop").returncode == 0
    assert seat.run("start").returncode == 0


def test_start_refuses_a_port_in_use_clearly_and_stops_nothing(seat, hook):
    port = free_port()
    seat.grok(hook, port=port)
    holder = occupy(port)
    try:
        started = seat.run("start")
        assert started.returncode == 1
        assert f"port {port} is already in use by another program" in started.stderr
        assert "nothing was stopped" in started.stderr and "choose another port" in started.stderr
        assert not (seat.dir / "daemon.pid").exists()
    finally:
        holder.close()


def test_starting_twice_is_harmless(seat, hook):
    seat.grok(hook)
    assert seat.run("start").returncode == 0
    pid = seat.pid()
    again = seat.run("start")
    assert again.returncode == 0 and "already running" in again.stdout and seat.pid() == pid


def test_stop_with_nothing_running_is_harmless(seat, hook):
    seat.grok(hook)
    stopped = seat.run("stop")
    assert stopped.returncode == 0 and "not running" in stopped.stdout


def test_a_stale_pid_record_is_cleared_and_kills_nothing(seat, hook):
    seat.grok(hook)
    gone = subprocess.Popen(["true"])
    gone.wait()
    (seat.dir / "daemon.pid").write_text(json.dumps({"pid": gone.pid, "port": seat.config()["port"]}))
    stopped = seat.run("stop")
    assert stopped.returncode == 0 and "not running" in stopped.stdout
    assert not (seat.dir / "daemon.pid").exists()


def test_stop_never_signals_a_process_that_is_not_this_seat(seat, hook):
    """A reused pid, or a hand-edited record: the process must prove it is this seat first."""
    seat.grok(hook)
    bystander = subprocess.Popen(["sleep", "60"])
    seat.spawned.append(bystander)
    (seat.dir / "daemon.pid").write_text(json.dumps({"pid": bystander.pid, "port": seat.config()["port"]}))
    stopped = seat.run("stop")
    assert stopped.returncode == 1 and "was not stopped" in stopped.stderr
    assert bystander.poll() is None


def test_another_daemon_on_the_port_is_not_taken_for_this_seat(seat, hook, tmp_path):
    """Another real eureka-daemon, with its own identity, holding this seat's port."""
    seat.grok(hook)
    port = seat.config()["port"]
    other_home = tmp_path / "other"
    other_home.mkdir()
    other = subprocess.Popen([str(rust_binary()), str(port)], env={"PATH": os.environ["PATH"], "HOME": str(other_home)},
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    seat.spawned.append(other)
    give_up = time.time() + 10
    while not listener_pids(port):
        assert time.time() < give_up
        time.sleep(0.05)
    (seat.dir / "daemon.pid").write_text(json.dumps({"pid": other.pid, "port": port}))
    assert seat.run("stop").returncode == 1
    assert other.poll() is None
    (seat.dir / "daemon.pid").unlink()
    started = seat.run("start")
    assert started.returncode == 1 and "already in use by another program" in started.stderr
    assert other.poll() is None
    assert "in use by another program" in seat.run("doctor").stdout


def test_the_daemon_outlives_the_command_that_started_it_and_its_terminal(seat, hook):
    seat.grok(hook)
    assert seat.run("start").returncode == 0
    assert os.getsid(seat.pid()) == seat.pid()


def test_shell_settings_cannot_redirect_a_seat(seat, hook, tmp_path):
    seat.grok(hook)
    stray = tmp_path / "stray"
    env = {"EUREKA_IDENTITY_PATH": str(stray / "identity.key"), "EUREKA_TRUST_PATH": str(stray / "trust.json"), "EUREKA_TURN_DIR": str(stray / "turns"),
           "EUREKA_WEBHOOK_CONFIG": str(stray / "webhook.json"), "EUREKA_ROOM_TURN_BACKEND": "queue", "EUREKA_INFERENCE": "1", "EUREKA_CORS_ORIGINS": "https://evil.example"}
    started = seat.run("start", env=env)
    assert started.returncode == 0, started.stderr
    assert not stray.exists()
    assert "offers: room-turn" in started.stdout and "evil.example" not in started.stdout


def test_a_room_turn_works_through_a_started_seat(seat, hook):
    node = client_node("room")
    seat.grok(hook, room_key=node.public_key_hex, name="Scout")
    assert seat.run("start").returncode == 0
    port = seat.config()["port"]
    routine = (seat.dir / "routine.txt").read_text()
    show = next(line.strip() for line in routine.splitlines() if "turn show" in line)
    bot_env = {"PATH": os.environ["PATH"], "HOME": str(seat.home)}

    def bot():
        shown = subprocess.run(show + " --json", shell=True, capture_output=True, text=True, env=bot_env, timeout=30)
        turn = json.loads(shown.stdout)["turn"]
        subprocess.run(turn["answer_command"], shell=True, input="Hello from the seat.", capture_output=True, text=True, env=bot_env, timeout=30)

    hook.on_wake = bot
    daemon = SimpleNamespace(base=f"http://127.0.0.1:{port}", port=port, public_key=json.loads((seat.dir / "identity.key").read_text())["public_key_hex"],
                             node_id=httpx.get(f"http://127.0.0.1:{port}/v1/manifest").json()["node_id"])
    trusting(node, daemon)
    assert handshake(node, daemon)["authenticated"] is True
    result = run_assign(node, daemon, payload=room("Plan the beds"))[1]["result"]
    assert (result["status"], result["output"]["text"]) == ("completed", "Hello from the seat.")
    assert hook.calls and KEY in hook.calls[0]["headers"]["authorization"]
    assert KEY not in (seat.dir / "daemon.log").read_text() and "path-secret" not in (seat.dir / "daemon.log").read_text()
    assert os.listdir(seat.dir / "turns") == []


def openclaw_seat(seat, config=None):
    fake = HERE / "fake_openclaw.py"
    path = seat.home / "openclaw.json"
    path.write_text(json.dumps(config or {}))
    env = {"EUREKA_OPENCLAW_BIN": str(fake), "FAKE_OPENCLAW_CONFIG": str(path)}
    return seat.setup("2", "", str(free_port()), ROOM_KEY, "", env=env), env


def hermes_seat(seat, config):
    home = seat.home / "hermes"
    (home / "profiles" / "knights-circle").mkdir(parents=True)
    path = seat.home / "hermes.json"
    path.write_text(json.dumps(config))
    env = {"EUREKA_HERMES_BIN": str(HERE / "fake_hermes.py"), "HERMES_HOME": str(home), "FAKE_HERMES_CONFIG": str(path)}
    return seat.setup("3", "", str(free_port()), ROOM_KEY, "", env=env), env


OPENCLAW_LOCKED = {"agents.entries.knights-circle.tools": {"profile": "minimal", "deny": [
    "group:runtime", "group:fs", "group:ui", "group:automation", "group:nodes", "group:plugins", "group:agents", "group:web", "group:messaging", "group:media", "group:memory"]}}


def test_a_chat_only_openclaw_agent_starts_and_doctor_agrees(seat):
    made, env = openclaw_seat(seat, OPENCLAW_LOCKED)
    assert made.returncode == 0 and "must be fixed" not in made.stdout, made.stdout + made.stderr
    assert seat.run("start", env=env).returncode == 0
    checked = seat.run("doctor", env=env)
    assert checked.returncode == 0 and "locked down to chat only" in checked.stdout, checked.stdout


def test_start_is_a_hard_stop_for_an_unsafe_openclaw_agent(seat):
    made, env = openclaw_seat(seat)
    assert made.returncode == 0 and "must be fixed before the seat can start" in made.stdout
    started = seat.run("start", env=env)
    assert started.returncode == 1 and "did not start" in started.stderr and "not chat only" in started.stderr
    assert not (seat.dir / "daemon.pid").exists()


def test_start_is_a_hard_stop_for_an_unsafe_hermes_profile(seat):
    made, env = hermes_seat(seat, {})
    assert made.returncode == 0 and "must be fixed before the seat can start" in made.stdout
    started = seat.run("start", env=env)
    assert started.returncode == 1 and "can run commands or touch files" in started.stderr
    assert not (seat.dir / "daemon.pid").exists()


def test_a_chat_only_hermes_profile_starts_and_doctor_agrees(seat):
    made, env = hermes_seat(seat, CHAT_ONLY)
    assert made.returncode == 0, made.stderr
    assert "must be fixed" not in made.stdout
    assert seat.run("start", env=env).returncode == 0
    checked = seat.run("doctor", env=env)
    assert checked.returncode == 0 and "locked down to chat only" in checked.stdout, checked.stdout


def test_doctor_explains_an_unsafe_openclaw_agent(seat):
    _, env = openclaw_seat(seat)
    checked = seat.run("doctor", env=env)
    assert checked.returncode == 1 and "failed the chat-only check" in checked.stdout and "openclaw config set" in checked.stdout


def test_a_missing_agent_program_stops_setup_with_a_reason(seat):
    made = seat.setup("3", "", str(free_port()), ROOM_KEY, env={"EUREKA_HERMES_BIN": "/nothing/here"})
    assert made.returncode == 1 and "cannot find" in made.stderr
    assert not (seat.dir / "seat.json").exists()


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------

def test_doctor_on_a_healthy_seat(seat, hook):
    seat.grok(hook)
    assert seat.run("start").returncode == 0
    checked = seat.run("doctor")
    assert checked.returncode == 0, checked.stdout
    assert "ok    identity" in checked.stdout and "ok    trust file" in checked.stdout and f"process {seat.pid()}" in checked.stdout
    assert "ok    webhook: 127.0.0.1" in checked.stdout and "No problems found" in checked.stdout


def test_doctor_does_not_wake_the_bot_unless_asked(seat, hook):
    seat.grok(hook)
    checked = seat.run("doctor")
    assert hook.calls == []
    assert "bot: not tested" in checked.stdout and "--wake" in checked.stdout


def test_doctor_with_no_seat_says_to_run_setup(seat):
    checked = seat.run("doctor")
    assert checked.returncode == 1 and "there is no seat" in checked.stderr and "setup" in checked.stderr


def test_doctor_finds_a_stale_grant_and_says_how_to_fix_it(seat, hook):
    seat.grok(hook)
    trust = json.loads((seat.dir / "trust.json").read_text())
    next(iter(trust["peers"].values()))["capabilities"].append("inference")
    (seat.dir / "trust.json").write_text(json.dumps(trust))
    checked = seat.run("doctor")
    assert checked.returncode == 1
    assert "FAIL  trust file" in checked.stdout and "inference" in checked.stdout and "trust revoke" in checked.stdout
    assert "EUREKA_TRUST_PATH=" in checked.stdout
    started = seat.run("start")
    assert started.returncode == 1 and "inference" in started.stderr


def test_doctor_finds_a_trust_file_with_no_room(seat, hook):
    seat.grok(hook)
    (seat.dir / "trust.json").write_text(json.dumps({"version": 3, "algorithm": "ed25519", "peers": {}}))
    checked = seat.run("doctor")
    assert checked.returncode == 1 and "no room may use this seat" in checked.stdout


def test_doctor_finds_a_key_file_others_can_read(seat, hook):
    seat.grok(hook)
    os.chmod(seat.dir / "identity.key", 0o644)
    checked = seat.run("doctor")
    assert checked.returncode == 1 and "FAIL  identity" in checked.stdout


def test_doctor_finds_webhook_not_set(seat, hook):
    seat.grok(hook)
    (seat.dir / "webhook.json").unlink()
    checked = seat.run("doctor", "--wake")
    assert checked.returncode == 1 and "Webhook not set" in checked.stdout and hook.calls == []


def test_doctor_finds_a_webhook_file_others_can_read_and_never_shows_it(seat, hook):
    seat.grok(hook)
    os.chmod(seat.dir / "webhook.json", 0o644)
    checked = seat.run("doctor")
    assert checked.returncode == 1 and "private to this user" in checked.stdout
    assert KEY not in checked.stdout + checked.stderr and "path-secret" not in checked.stdout + checked.stderr


def test_doctor_finds_an_unreachable_webhook(seat, hook):
    seat.grok(hook)
    fields = json.loads((seat.dir / "webhook.json").read_text())
    fields["url"] = f"http://127.0.0.1:{free_port()}/hook"
    (seat.dir / "webhook.json").write_text(json.dumps(fields))
    checked = seat.run("doctor")
    assert checked.returncode == 1 and "cannot reach 127.0.0.1" in checked.stdout


def test_doctor_finds_ollama_missing_or_without_the_model(seat, ollama_tags):
    url = ollama_tags(["other:1"])
    env = {"EUREKA_OLLAMA_URL": url}
    made = seat.setup("4", "", str(free_port()), ROOM_KEY, "wanted:1", env=env)
    assert made.returncode == 0 and "ollama pull wanted:1" in made.stdout
    assert "ollama pull wanted:1" in seat.run("doctor", env=env).stdout
    ok = seat.run("doctor", env={"EUREKA_OLLAMA_URL": ollama_tags(["wanted:1"])})
    assert ok.returncode == 0 and "has the model" in ok.stdout
    down = seat.run("doctor", env={"EUREKA_OLLAMA_URL": f"http://127.0.0.1:{free_port()}"})
    assert down.returncode == 1 and "ollama serve" in down.stdout


@pytest.fixture
def ollama_tags():
    servers = []

    def serve(models):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                data = json.dumps({"models": [{"name": name} for name in models]}).encode()
                self.send_response(200)
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}"

    yield serve
    for server in servers:
        server.shutdown()


def fake_bot(seat, reply="Hello.", answer=True):
    routine = (seat.dir / "routine.txt").read_text()
    show = next(line.strip() for line in routine.splitlines() if "turn show" in line)
    env = {"PATH": os.environ["PATH"], "HOME": str(seat.home)}

    def run():
        shown = subprocess.run(show + " --json", shell=True, capture_output=True, text=True, env=env, timeout=30)
        turn = json.loads(shown.stdout)["turn"]
        assert "connection test" in turn["message"]
        if answer:
            subprocess.run(turn["answer_command"], shell=True, input=reply, capture_output=True, text=True, env=env, timeout=30)
    return run


def test_doctor_wake_sees_a_bot_that_answers(seat, hook):
    seat.grok(hook)
    hook.on_wake = fake_bot(seat)
    checked = seat.run("doctor", "--wake", env={"EUREKA_TURN_WAIT": "10"})
    assert checked.returncode == 0, checked.stdout
    assert "woken, read the test turn and answered" in checked.stdout
    assert len(hook.calls) == 1 and os.listdir(seat.dir / "turns") == []


def test_doctor_wake_works_while_the_daemon_runs_and_leaves_it_running(seat, hook):
    seat.grok(hook)
    assert seat.run("start").returncode == 0
    pid = seat.pid()
    hook.on_wake = fake_bot(seat)
    checked = seat.run("doctor", "--wake", env={"EUREKA_TURN_WAIT": "10"})
    assert checked.returncode == 0, checked.stdout
    assert alive(pid) and seat.pid() == pid


def test_doctor_wake_names_the_causes_when_the_bot_never_reads(seat, hook):
    seat.grok(hook)
    checked = seat.run("doctor", "--wake", env={"EUREKA_TURN_WAIT": "2"})
    assert checked.returncode == 1
    out = checked.stdout
    assert "woken, but did not read the test turn in 2 seconds" in out
    assert "Desktop app closed" in out and "Ask every time" in out and "Always allow" in out and "routine.txt" in out
    assert os.listdir(seat.dir / "turns") == []


def test_doctor_wake_names_the_cause_when_the_bot_reads_but_never_answers(seat, hook):
    seat.grok(hook)
    hook.on_wake = fake_bot(seat, answer=False)
    checked = seat.run("doctor", "--wake", env={"EUREKA_TURN_WAIT": "2"})
    assert checked.returncode == 1
    assert "read the test turn, but did not answer in 2 seconds" in checked.stdout and "Ask every time" in checked.stdout


@pytest.mark.parametrize("status", [401, 404])
def test_doctor_wake_says_webhook_not_set_when_the_webhook_refuses(seat, hook, status):
    seat.grok(hook)
    hook.statuses = [status]
    checked = seat.run("doctor", "--wake", env={"EUREKA_TURN_WAIT": "2"})
    assert checked.returncode == 1
    assert f"HTTP {status}" in checked.stdout and "Webhook not set" in checked.stdout and "paused" in checked.stdout
    assert KEY not in checked.stdout and "path-secret" not in checked.stdout
    assert os.listdir(seat.dir / "turns") == []


def test_doctor_wake_stands_aside_for_a_real_turn(seat, hook):
    seat.grok(hook)
    turns = seat.dir / "turns"
    turns.mkdir(mode=0o700)
    live = "a" * 32
    (turns / f"{live}.turn.json").write_text(json.dumps({"version": 1, "id": live, "expires_at": time.time() + 60, "message": "real"}))
    os.chmod(turns / f"{live}.turn.json", 0o600)
    checked = seat.run("doctor", "--wake")
    assert "a room turn is waiting" in checked.stdout and hook.calls == []
    assert (turns / f"{live}.turn.json").exists()


def test_turn_commands_take_the_queue_as_a_flag(seat):
    queue = seat.home / "q"
    queue.mkdir(mode=0o700)
    done = subprocess.run([str(rust_binary()), "turn", "show", "--queue", str(queue)], capture_output=True, text=True, env=seat.env, timeout=30)
    assert done.returncode == 0 and "No turn is waiting" in done.stdout
    assert subprocess.run([str(rust_binary()), "turn", "show", "--queue"], capture_output=True, text=True, env=seat.env, timeout=30).returncode == 2
