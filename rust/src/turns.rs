//! The turn queue: how a room turn reaches an agent that can run a local command, and how its
//! reply comes back. The daemon writes one turn into a private directory and waits; the agent runs
//! `eureka-daemon turn show` and `eureka-daemon turn answer`, and needs no other access.
//!
//! Each turn is a few files named after its random id: `<id>.turn.json` (written by the daemon),
//! `<id>.read` (left by `turn show`, so the daemon can tell a bot that never looked from one that
//! never answered) and `<id>.reply.json` (written by `turn answer`). The daemon removes them when
//! the turn ends, whichever way it ends.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use crate::crypto;
use crate::handlers::strip_ansi;
use crate::pyjson::{self, object, py_strip, Value};

pub const TURN_DIR_ENV: &str = "EUREKA_TURN_DIR";
/// What a reply file or `turn answer` input may hold. The room gets at most 12,000 characters of it.
pub const MAX_REPLY_BYTES: usize = 256 * 1024;
const MAX_TURN_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_WAIT_SECONDS: u64 = 170;
const POLL: Duration = Duration::from_millis(200);
/// How long `turn answer` waits for the daemon to take the reply.
const PICKUP_WAIT: Duration = Duration::from_secs(5);

const USAGE: &str = "usage: eureka-daemon turn show [--wait SECONDS] [--json] [--queue DIR]
       eureka-daemon turn answer ID [--text-file PATH] [--queue DIR]

For an agent answering room turns (EUREKA_ROOM_TURN_BACKEND=webhook or queue).
  show    prints the waiting turn and the exact command to answer it
  answer  takes the reply on stdin, or from --text-file
The queue is --queue, or EUREKA_TURN_DIR (default ~/.eureka/turns).";

pub fn resolve_turn_dir() -> PathBuf {
    match std::env::var(TURN_DIR_ENV) {
        Ok(p) if !p.trim().is_empty() => crypto::expand_user(p.trim()),
        _ => crypto::default_eureka_dir().join("turns"),
    }
}

fn valid_turn_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn turn_file(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.turn.json"))
}
fn read_file(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.read"))
}
fn reply_file(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.reply.json"))
}

fn now_seconds() -> f64 {
    crate::isotime::now_micros() as f64 / 1_000_000.0
}

/// Why this directory cannot be trusted to hold turns: another account could plant one.
pub fn dir_problem(dir: &Path) -> Option<String> {
    match crypto::private_file_problem(dir) {
        Ok(None) => None,
        Ok(Some(_)) => Some(format!("turn directory {} can be reached by other accounts; make it private to this user", dir.display())),
        Err(e) => Some(format!("cannot check turn directory {}: {e}", dir.display())),
    }
}

/// The reply as the room should get it: no terminal sequences, no surrounding space.
pub fn clean_reply(text: &str) -> String {
    py_strip(&strip_ansi(text)).to_string()
}

fn remove_turn_files(dir: &Path, id: &str) {
    for path in [turn_file(dir, id), read_file(dir, id), reply_file(dir, id)] {
        let _ = std::fs::remove_file(path);
    }
}

pub struct Queue {
    dir: PathBuf,
}

/// A turn on the queue; dropping it removes its files, so a failed or abandoned turn leaves nothing.
pub struct PostedTurn<'a> {
    dir: &'a Path,
    pub id: String,
}

impl Drop for PostedTurn<'_> {
    fn drop(&mut self) {
        remove_turn_files(self.dir, &self.id);
    }
}

impl Queue {
    /// Open the directory for a daemon starting up, creating it private, and clear what a stopped
    /// daemon left. One daemon uses one directory, so nothing here belongs to a live turn.
    pub fn open(dir: PathBuf) -> Result<Queue, String> {
        crypto::create_private_dir(&dir).map_err(|e| format!("cannot create turn directory {}: {e}", dir.display()))?;
        if let Some(problem) = dir_problem(&dir) {
            return Err(problem);
        }
        let entries = std::fs::read_dir(&dir).map_err(|e| format!("cannot read turn directory {}: {e}", dir.display()))?;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let id = name.split('.').next().unwrap_or("");
            let ours = valid_turn_id(id) && [".turn.json", ".read", ".reply.json"].iter().any(|ending| name.len() == id.len() + ending.len() && name.ends_with(ending));
            if ours {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        Ok(Queue { dir })
    }

    /// The directory without clearing it, for a test turn beside a daemon that may be using it.
    pub fn existing(dir: PathBuf) -> Result<Queue, String> {
        crypto::create_private_dir(&dir).map_err(|e| format!("cannot create turn directory {}: {e}", dir.display()))?;
        match dir_problem(&dir) {
            Some(problem) => Err(problem),
            None => Ok(Queue { dir }),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn post(&self, id: &str, message: &str, expires_at: f64) -> std::io::Result<PostedTurn<'_>> {
        let posted = PostedTurn { dir: &self.dir, id: id.to_string() };
        let document = object([
            ("version", Value::int(1)),
            ("id", Value::str(id)),
            ("expires_at", Value::Float(expires_at)),
            ("message", Value::str(message)),
        ]);
        let text = pyjson::response(&document).expect("finite");
        crypto::write_private_file(&turn_file(&self.dir, id), text.as_bytes())?;
        Ok(posted)
    }

    pub fn was_read(&self, id: &str) -> bool {
        read_file(&self.dir, id).exists()
    }

    /// The agent's reply, if there is one yet. Err when a reply is there but unusable.
    pub fn take_reply(&self, id: &str) -> Result<Option<String>, &'static str> {
        let path = reply_file(&self.dir, id);
        let Ok(meta) = std::fs::symlink_metadata(&path) else { return Ok(None) };
        if !meta.is_file() || meta.len() > MAX_REPLY_BYTES as u64 * 2 {
            return Err("the reply file is not a file of a usable size");
        }
        let bytes = std::fs::read(&path).map_err(|_| "the reply file cannot be read")?;
        let document = pyjson::loads(&bytes).map_err(|_| "the reply file is not JSON")?;
        let fields = document.as_object().ok_or("the reply file is not an object")?;
        if !fields.get("id").is_some_and(|v| v.is_str(id)) {
            return Err("the reply file is for another turn");
        }
        let text = fields.get("text").and_then(Value::as_str).ok_or("the reply file has no text")?;
        let text = clean_reply(text);
        if text.is_empty() {
            return Err("the reply is empty");
        }
        Ok(Some(text))
    }
}

struct WaitingTurn {
    id: String,
    message: String,
    expires_at: f64,
}

/// The turn waiting now, if any. Files whose time has passed are ignored: their daemon has gone.
fn waiting_turn(dir: &Path) -> Option<WaitingTurn> {
    let now = now_seconds();
    let mut found: Option<WaitingTurn> = None;
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let name = entry.file_name();
        let Some(id) = name.to_str().and_then(|n| n.strip_suffix(".turn.json")) else { continue };
        if !valid_turn_id(id) || entry.path().symlink_metadata().map_or(true, |m| !m.is_file() || m.len() > MAX_TURN_BYTES) {
            continue;
        }
        let Some(turn) = read_turn(&entry.path(), id) else { continue };
        if turn.expires_at > now && found.as_ref().map_or(true, |f| turn.expires_at < f.expires_at) {
            found = Some(turn);
        }
    }
    found
}

pub fn turn_waiting(dir: &Path) -> bool {
    waiting_turn(dir).is_some()
}

fn read_turn(path: &Path, id: &str) -> Option<WaitingTurn> {
    let document = pyjson::loads(&std::fs::read(path).ok()?).ok()?;
    let fields = document.as_object()?;
    if !fields.get("id")?.is_str(id) {
        return None;
    }
    Some(WaitingTurn { id: id.to_string(), message: fields.get("message")?.as_str()?.to_string(), expires_at: fields.get("expires_at")?.as_number()? })
}

/// Quote a word for a POSIX shell, leaving plain ones as they are.
fn shell_quote(word: &str) -> String {
    if !word.is_empty() && word.chars().all(|c| c.is_ascii_alphanumeric() || "_-./:=@%+".contains(c)) {
        return word.to_string();
    }
    format!("'{}'", word.replace('\'', "'\\''"))
}

/// A word as it goes in a command printed for someone to run on this computer.
pub fn quote_for_command(word: &str) -> String {
    if cfg!(windows) {
        format!("\"{word}\"")
    } else {
        shell_quote(word)
    }
}

/// The command that answers this turn, naming this program by its path and the queue if it was set.
fn answer_command(id: &str) -> String {
    let program = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "eureka-daemon".to_string());
    let queue = match std::env::var(TURN_DIR_ENV) {
        Ok(p) if !p.trim().is_empty() => format!(" --queue {}", quote_for_command(p.trim())),
        _ => String::new(),
    };
    format!("{} turn answer {id}{queue}", quote_for_command(&program))
}

fn print_turn(turn: &WaitingTurn, json: bool) {
    let seconds = (turn.expires_at - now_seconds()).max(0.0).round() as i64;
    let command = answer_command(&turn.id);
    if json {
        let document = object([(
            "turn",
            object([
                ("id", Value::str(turn.id.clone())),
                ("expires_in_seconds", Value::int(seconds)),
                ("message", Value::str(turn.message.clone())),
                ("answer_command", Value::str(command)),
            ]),
        )]);
        println!("{}", pyjson::response(&document).expect("finite"));
        return;
    }
    println!("Turn {} (answer within {seconds} seconds)\n\n{}\n", turn.id, turn.message);
    if cfg!(windows) {
        println!("To answer, save your reply in a file and run exactly this. Run nothing else for this turn.\n\n{command} --text-file <reply file>");
    } else {
        // Chosen after the room's text was fixed, so nothing in the room can end the block early.
        let delimiter = format!("EUREKA_REPLY_{}", &crypto::token_hex16()[..16]);
        println!("To answer, run exactly this, with your reply between the two {delimiter} lines. Run nothing else for this turn.\n\n{command} <<'{delimiter}'\n<your reply>\n{delimiter}");
    }
}

fn show(args: &[String]) -> ExitCode {
    let mut json = false;
    let mut wait = 0u64;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => json = true,
            "--wait" => match args.next().and_then(|v| v.parse().ok()) {
                Some(seconds) if seconds <= MAX_WAIT_SECONDS => wait = seconds,
                _ => return usage_error(&format!("--wait takes 0 to {MAX_WAIT_SECONDS} seconds")),
            },
            other => return usage_error(&format!("unknown argument {other:?}")),
        }
    }
    let dir = resolve_turn_dir();
    let give_up = Instant::now() + Duration::from_secs(wait);
    loop {
        if dir.exists() {
            if let Some(problem) = dir_problem(&dir) {
                return refuse(&problem);
            }
            if let Some(turn) = waiting_turn(&dir) {
                // Tells the daemon this turn was picked up, so a later stall is reported as such.
                if let Err(e) = crypto::write_private_file(&read_file(&dir, &turn.id), b"") {
                    return refuse(&format!("cannot mark the turn as read: {e}"));
                }
                print_turn(&turn, json);
                return ExitCode::SUCCESS;
            }
        }
        if Instant::now() >= give_up {
            break;
        }
        std::thread::sleep(POLL);
    }
    if json {
        println!("{{\"turn\": null}}");
    } else {
        println!("No turn is waiting. Nothing to do.");
    }
    ExitCode::SUCCESS
}

fn read_limited(mut input: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    input.by_ref().take(MAX_REPLY_BYTES as u64 + 1).read_to_end(&mut bytes).map_err(|e| format!("cannot read the reply: {e}"))?;
    if bytes.len() > MAX_REPLY_BYTES {
        return Err(format!("the reply is over {MAX_REPLY_BYTES} bytes"));
    }
    Ok(bytes)
}

fn answer(args: &[String]) -> ExitCode {
    let (id, text_file) = match args {
        [id] => (id, None),
        [id, flag, path] if flag == "--text-file" => (id, Some(path)),
        _ if args.iter().any(|a| a == "--text") => {
            // A reply on a command line would pass room-influenced text through a shell.
            return usage_error("there is no --text; give the reply on stdin or with --text-file");
        }
        _ => return usage_error("turn answer takes a turn id"),
    };
    if !valid_turn_id(id) {
        return usage_error(&format!("{id:?} is not a turn id; use the one `turn show` printed"));
    }
    let bytes = match text_file {
        Some(path) => std::fs::File::open(path).map_err(|e| format!("cannot open {path}: {e}")).and_then(read_limited),
        None => read_limited(std::io::stdin()),
    };
    let bytes = match bytes {
        Ok(bytes) => bytes,
        Err(why) => return refuse(&why),
    };
    let Ok(text) = String::from_utf8(bytes) else { return refuse("the reply is not UTF-8 text") };
    let text = clean_reply(&text);
    if text.is_empty() {
        return refuse("the reply is empty");
    }
    let dir = resolve_turn_dir();
    if dir.exists() {
        if let Some(problem) = dir_problem(&dir) {
            return refuse(&problem);
        }
    }
    let turn_path = turn_file(&dir, id);
    if read_turn(&turn_path, id).map_or(true, |turn| turn.expires_at <= now_seconds()) {
        return refuse("that turn is over, so this reply was not sent. The room has been told; a retry there starts a new turn.");
    }
    let reply_path = reply_file(&dir, id);
    if reply_path.exists() {
        return refuse("that turn already has a reply");
    }
    let document = object([("id", Value::str(id.clone())), ("text", Value::str(text))]);
    if let Err(e) = crypto::write_private_file(&reply_path, pyjson::response(&document).expect("finite").as_bytes()) {
        return refuse(&format!("cannot save the reply: {e}"));
    }
    let give_up = Instant::now() + PICKUP_WAIT;
    while Instant::now() < give_up {
        if !turn_path.exists() {
            println!("The daemon took the reply. Nothing more to do for this turn.");
            return ExitCode::SUCCESS;
        }
        std::thread::sleep(POLL);
    }
    refuse("the reply is saved but the daemon has not taken it; check that it is running")
}

fn refuse(why: &str) -> ExitCode {
    eprintln!("eureka-daemon turn: {why}");
    ExitCode::from(1)
}

fn usage_error(why: &str) -> ExitCode {
    eprintln!("eureka-daemon turn: {why}\n{USAGE}");
    ExitCode::from(2)
}

pub fn command(args: &[String]) -> ExitCode {
    let mut args = args.to_vec();
    if let Some(at) = args.iter().position(|a| a == "--queue") {
        let Some(dir) = args.get(at + 1).cloned() else { return usage_error("--queue takes a folder") };
        // Nothing else is running yet: this command has started no threads of its own.
        std::env::set_var(TURN_DIR_ENV, dir);
        args.drain(at..=at + 1);
    }
    match args.as_slice() {
        [verb, rest @ ..] if verb == "show" => show(rest),
        [verb, rest @ ..] if verb == "answer" => answer(rest),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef";

    fn queue() -> Queue {
        Queue::open(std::env::temp_dir().join(format!("eureka-turns-{}", crypto::token_hex16()))).unwrap()
    }

    #[test]
    fn turn_ids_cannot_leave_the_directory() {
        assert!(valid_turn_id(ID));
        for bad in ["", "../../etc/passwd", "0123456789ABCDEF0123456789ABCDEF", "0123456789abcdef0123456789abcde/", "0123456789abcdef"] {
            assert!(!valid_turn_id(bad), "{bad}");
        }
    }

    #[test]
    fn a_turn_leaves_nothing_behind() {
        let queue = queue();
        {
            let _turn = queue.post(ID, "hello", now_seconds() + 60.0).unwrap();
            crypto::write_private_file(&read_file(queue.dir(), ID), b"").unwrap();
            assert!(queue.was_read(ID));
            assert_eq!(waiting_turn(queue.dir()).unwrap().message, "hello");
        }
        assert_eq!(std::fs::read_dir(queue.dir()).unwrap().count(), 0);
        std::fs::remove_dir_all(queue.dir()).unwrap();
    }

    #[test]
    fn an_expired_turn_is_not_waiting_and_startup_clears_it() {
        let queue = queue();
        let turn = queue.post(ID, "old", now_seconds() - 1.0).unwrap();
        assert!(waiting_turn(queue.dir()).is_none());
        std::mem::forget(turn);
        std::fs::write(queue.dir().join("keep-me.txt"), "not ours").unwrap();
        let reopened = Queue::open(queue.dir().to_path_buf()).unwrap();
        let left: Vec<String> = std::fs::read_dir(reopened.dir()).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(left, ["keep-me.txt"]);
        std::fs::remove_dir_all(reopened.dir()).unwrap();
    }

    #[test]
    fn replies_are_checked_and_cleaned() {
        let queue = queue();
        let reply = |text: &str| std::fs::write(reply_file(queue.dir(), ID), text).unwrap();
        assert_eq!(queue.take_reply(ID), Ok(None));
        reply(&format!(r#"{{"id": "{ID}", "text": "  \u001b[31mhi\u001b[0m\n"}}"#));
        assert_eq!(queue.take_reply(ID), Ok(Some("hi".to_string())));
        reply(r#"{"id": "someone-else", "text": "hi"}"#);
        assert_eq!(queue.take_reply(ID), Err("the reply file is for another turn"));
        reply(&format!(r#"{{"id": "{ID}", "text": "  "}}"#));
        assert_eq!(queue.take_reply(ID), Err("the reply is empty"));
        reply("not json");
        assert_eq!(queue.take_reply(ID), Err("the reply file is not JSON"));
        std::fs::remove_dir_all(queue.dir()).unwrap();
    }

    #[test]
    fn words_are_quoted_for_the_shell() {
        assert_eq!(shell_quote("/usr/local/bin/eureka-daemon"), "/usr/local/bin/eureka-daemon");
        assert_eq!(shell_quote("/a b/it's"), r"'/a b/it'\''s'");
        assert_eq!(shell_quote("$(x)"), "'$(x)'");
    }
}
