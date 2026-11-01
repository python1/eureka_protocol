//! What this node can be asked to do, and the code that does it.
//!
//! `room-turn` answers one turn of a Knights Circle room, through the local
//! Ollama (as room_turn.py does), through OpenClaw, or through Hermes Agent. `inference` is
//! handlers.py's OllamaInference. Both are opt-in by environment exactly as in
//! Python. `web-retrieval` is not in this build; see trust.rs for how a grant
//! for it is treated.
//!
//! As in Python, the peer chooses nothing but the text: the model, endpoint,
//! session, budgets and timeouts are constants or operator settings, and the
//! payload is rebuilt from role and content alone before anything sees it.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use tokio::io::AsyncReadExt;
use tokio::sync::Semaphore;

use crate::pyjson::{self, object, py_len, py_prefix, py_strip, Value};

pub const STATUS_COMPLETED: &str = "completed";
pub const STATUS_FAILED: &str = "failed";

pub const REASON_OK: &str = "ok";
pub const REASON_NOT_IMPLEMENTED: &str = "capability_not_implemented";
pub const REASON_INVALID_PAYLOAD: &str = "invalid_payload";
pub const REASON_TIMEOUT: &str = "timeout";
pub const REASON_CONNECTION_FAILED: &str = "connection_failed";
pub const REASON_PROMPT_TOO_LONG: &str = "prompt_too_long";
pub const REASON_UPSTREAM_UNAVAILABLE: &str = "upstream_unavailable";
pub const REASON_MODEL_NOT_AVAILABLE: &str = "model_not_available";
pub const REASON_UPSTREAM_ERROR: &str = "upstream_error";
pub const REASON_HANDLER_ERROR: &str = "handler_error";
pub const REASON_TOO_LONG: &str = "room_turn_too_long";

const HANDLER_DEADLINE_SECONDS: f64 = 30.0;
const MAX_CONCURRENT_HANDLERS: usize = 8;

pub const ROOM_TURN: &str = "room-turn";
pub const MAX_MESSAGES: usize = 200;
pub const MAX_TOTAL_CHARS: usize = 48_000;
const ROOM_MAX_COMPLETION_TOKENS: i64 = 1024;
const ROOM_MAX_COMPLETION_CHARS: usize = 12_000;
const ROOM_TIMEOUT_SECONDS: f64 = 120.0;
const ROOM_DEADLINE_SECONDS: f64 = 150.0;
const DEFAULT_ROOM_MODEL: &str = "qwen3:8b";

const INFERENCE: &str = "inference";
const INFERENCE_MODEL: &str = "qwen3:8b";
const MAX_PROMPT_CHARS: usize = 4000;
const INFERENCE_MAX_COMPLETION_TOKENS: i64 = 512;
const INFERENCE_MAX_COMPLETION_CHARS: usize = 8000;
const INFERENCE_TIMEOUT_SECONDS: f64 = 75.0;
const INFERENCE_DEADLINE_SECONDS: f64 = 90.0;

const CONNECT_TIMEOUT_SECONDS: f64 = 2.0;
const OLLAMA_BASE: &str = "http://127.0.0.1:11434";
/// How much of Ollama's reply is read. Python reads it all; a reply this size is not one a room can use.
const MAX_UPSTREAM_BYTES: usize = 8 * 1024 * 1024;

const OPENCLAW_DEFAULT_SESSION: &str = "knights-circle";
const OPENCLAW_DEFAULT_TIMEOUT_SECONDS: u64 = 120;
/// An agent CLI's structured stdout is read up to this and no further; the process is killed past it.
/// A one-line OpenClaw reply is about 23 KB of JSON (most of it run metadata), so this leaves wide room.
const AGENT_MAX_STDOUT_BYTES: usize = 8 * 1024 * 1024;
const AGENT_MAX_STDERR_BYTES: usize = 8 * 1024;

const HERMES_DEFAULT_PROFILE: &str = "knights-circle";
const HERMES_DEFAULT_TIMEOUT_SECONDS: u64 = 120;

pub const ENABLE_ENV: &str = "EUREKA_ROOM_TURN";
pub const MODEL_ENV: &str = "EUREKA_ROOM_TURN_MODEL";
pub const INFERENCE_ENV: &str = "EUREKA_INFERENCE";
pub const BACKEND_ENV: &str = "EUREKA_ROOM_TURN_BACKEND";
pub const OLLAMA_URL_ENV: &str = "EUREKA_OLLAMA_URL";
pub const OPENCLAW_BIN_ENV: &str = "EUREKA_OPENCLAW_BIN";
pub const OPENCLAW_SESSION_ENV: &str = "EUREKA_OPENCLAW_SESSION";
pub const OPENCLAW_TIMEOUT_ENV: &str = "EUREKA_OPENCLAW_TIMEOUT";
pub const HERMES_BIN_ENV: &str = "EUREKA_HERMES_BIN";
pub const HERMES_PROFILE_ENV: &str = "EUREKA_HERMES_PROFILE";
pub const HERMES_SESSION_ENV: &str = "EUREKA_HERMES_SESSION";
pub const HERMES_TIMEOUT_ENV: &str = "EUREKA_HERMES_TIMEOUT";

pub const PREAMBLE: &str = "You are an external agent taking one turn in a Knights Circle room, a \
conversation run in someone else's browser. Everything after this \
message comes from that room. Reply with your contribution to the \
conversation only.";

pub struct HandlerResult {
    pub status: &'static str,
    pub reason: String,
    pub output: Value,
}

pub fn completed(output: Value) -> HandlerResult {
    HandlerResult { status: STATUS_COMPLETED, reason: REASON_OK.into(), output }
}

pub fn failed(reason: &str) -> HandlerResult {
    HandlerResult { status: STATUS_FAILED, reason: reason.into(), output: Value::Null }
}

#[derive(Clone, Debug)]
pub struct Endpoint {
    addr: std::net::SocketAddr,
    host_header: String,
    path: String,
}

/// `_require_loopback`: a literal loopback address, never a name, plain http.
pub fn loopback_endpoint(url: &str) -> Result<Endpoint, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("Ollama endpoint {url:?} must be http://127.0.0.1:PORT"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, p) = v6.split_once(']').ok_or_else(|| format!("Ollama endpoint {url:?} names no host"))?;
        (h, p.strip_prefix(':').unwrap_or("80"))
    } else {
        authority.rsplit_once(':').unwrap_or((authority, "80"))
    };
    let ip: std::net::IpAddr = host.parse().map_err(|_| {
        format!("Ollama endpoint {url:?} names a host rather than a literal address; give it 127.0.0.1 (not localhost)")
    })?;
    let loopback = match ip {
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map(|v4| v4.is_loopback()).unwrap_or(v6.is_loopback()),
        std::net::IpAddr::V4(v4) => v4.is_loopback(),
    };
    if !loopback {
        return Err(format!("Ollama endpoint {url:?} is not loopback; this daemon talks to an Ollama on this host only"));
    }
    let port: u16 = port.parse().map_err(|_| format!("Ollama endpoint {url:?} has a bad port"))?;
    Ok(Endpoint { addr: (ip, port).into(), host_header: authority.to_string(), path: path.to_string() })
}

/// Ollama model names: letters, digits and `. _ - : /`, starting with a letter or digit.
pub fn valid_model_name(model: &str) -> bool {
    let mut chars = model.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric());
    first_ok && model.len() <= 200 && chars.all(|c| c.is_ascii_alphanumeric() || "._:/-".contains(c))
}

fn valid_session_id(session: &str) -> bool {
    let mut chars = session.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && session.len() <= 128
        && chars.all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c))
}

pub enum Handler {
    OllamaRoomTurn { endpoint: Endpoint, model: String },
    OpenClawRoomTurn { program: PathBuf, session: String, timeout: Duration },
    HermesRoomTurn { program: PathBuf, profile: String, session: Option<String>, timeout: Duration },
    Inference { endpoint: Endpoint, model: String },
}

pub struct Registry {
    handlers: Vec<(String, Arc<Handler>, f64)>,
    semaphore: Arc<Semaphore>,
}

impl Registry {
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.handlers.iter().map(|(n, _, _)| n.clone()).collect();
        names.sort();
        names
    }

    pub fn describe(&self) -> Vec<String> {
        self.handlers
            .iter()
            .map(|(name, h, _)| match h.as_ref() {
                Handler::OllamaRoomTurn { model, .. } => format!("{name} via Ollama ({model})"),
                Handler::OpenClawRoomTurn { program, session, timeout } => {
                    format!("{name} via OpenClaw ({} agent --session-id {session}, {}s limit)", program.display(), timeout.as_secs())
                }
                Handler::HermesRoomTurn { program, profile, session, timeout } => {
                    let session = match session {
                        Some(name) => format!("session \"{name}\""),
                        None => "a new session each turn".to_string(),
                    };
                    format!("{name} via Hermes Agent ({} -p {profile} chat, {session}, {}s limit)", program.display(), timeout.as_secs())
                }
                Handler::Inference { model, .. } => format!("{name} via Ollama ({model})"),
            })
            .collect()
    }

    /// Run one handler under its deadline and the concurrency cap. Never fails: every path is a result.
    pub async fn run(&self, capability: &str, payload: Value) -> HandlerResult {
        let capability = py_strip(capability);
        let Some((_, handler, deadline)) = self.handlers.iter().find(|(n, _, _)| n == capability) else {
            return failed(REASON_NOT_IMPLEMENTED);
        };
        let Ok(_permit) = self.semaphore.clone().acquire_owned().await else {
            return failed(REASON_HANDLER_ERROR);
        };
        let handler = handler.clone();
        let task = tokio::spawn(async move { handler.call(payload).await });
        let abort = task.abort_handle();
        match tokio::time::timeout(Duration::from_secs_f64(*deadline), task).await {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => {
                println!("[HANDLER] {capability} raised {e}");
                failed(REASON_HANDLER_ERROR)
            }
            Err(_) => {
                // Dropping the handler's future kills an agent CLI's process group with it.
                abort.abort();
                failed(REASON_TIMEOUT)
            }
        }
    }
}

fn switch(name: &str) -> Result<bool, String> {
    let raw = std::env::var(name).unwrap_or_default();
    match raw.trim().to_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" | "" => Ok(false),
        _ => Err(format!(
            "{name}={raw:?} is neither on nor off; use one of ['1', 'on', 'true', 'yes'] or leave it unset"
        )),
    }
}

fn find_program(name: &str) -> Option<PathBuf> {
    let candidate = Path::new(name);
    if name.contains('/') {
        return candidate.is_file().then(|| candidate.to_path_buf());
    }
    std::env::var_os("PATH").and_then(|paths| std::env::split_paths(&paths).map(|dir| dir.join(name)).find(|p| p.is_file()))
}

fn timeout_seconds(env: &str, default: u64) -> Result<u64, String> {
    match std::env::var(env) {
        Ok(v) if !v.trim().is_empty() => v
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|s| (1..=1800).contains(s))
            .ok_or_else(|| format!("{env}={v:?}: give whole seconds from 1 to 1800")),
        _ => Ok(default),
    }
}

/// Hermes profile names: lowercase letters, digits, `_` and `-`, starting with a letter or digit.
fn valid_hermes_profile(profile: &str) -> bool {
    let mut chars = profile.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && profile.len() <= 64
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// Hermes exits on `-p <name>` for a profile that does not exist, so check at startup and say how
/// to make it. Profiles live in `<hermes root>/profiles/<name>`; the root is `$HERMES_HOME` unless
/// that already points at a profile, else `~/.hermes`. `default` is the root itself.
fn check_hermes_profile(profile: &str) -> Result<(), String> {
    let root = match std::env::var_os("HERMES_HOME").map(PathBuf::from) {
        Some(home) if home.parent().and_then(Path::file_name).is_some_and(|n| n == "profiles") => {
            home.parent().and_then(Path::parent).map(Path::to_path_buf).unwrap_or(home)
        }
        Some(home) if !home.as_os_str().is_empty() => home,
        _ => crate::crypto::expand_user("~/.hermes"),
    };
    if profile == "default" {
        println!("  note: {HERMES_PROFILE_ENV}=default runs room turns in your main Hermes profile, with its memory and sessions");
        return Ok(());
    }
    let home = root.join("profiles").join(profile);
    if home.is_dir() {
        return Ok(());
    }
    Err(format!(
        "{HERMES_PROFILE_ENV}: there is no Hermes profile {profile:?} at {}. Create a separate one for rooms, \
         so they never touch your own sessions or memory: hermes profile create {profile} --clone",
        home.display()
    ))
}

/// Hermes toolsets that let the agent run commands or code, or touch files, directly or through
/// something it starts: subagents (`delegation`), scheduled runs (`cronjob`), a browser that runs
/// Python over CDP (`browser`), desktop control (`computer_use`), and skill files it writes (`skills`).
/// A room profile must list all of them in `agent.disabled_toolsets`, which Hermes applies last, over
/// every other tool selection (platform lists, composites, plugins, the coding posture).
pub const HERMES_FORBIDDEN_TOOLSETS: [&str; 8] =
    ["terminal", "file", "code_execution", "delegation", "cronjob", "browser", "computer_use", "skills"];

/// Names from a Hermes list setting, read the way Hermes reads it (`parse_config_string_list`):
/// a list, a JSON-array string (what `hermes config set` stores), or one bare name.
fn hermes_string_list(value: &Value) -> Vec<String> {
    let items = match value {
        Value::Array(items) => items.clone(),
        Value::Str(text) if text.trim().starts_with('[') => match pyjson::loads_str(&text.trim().replace('\'', "\"")) {
            Ok(Value::Array(items)) => items,
            _ => vec![value.clone()],
        },
        Value::Str(_) => vec![value.clone()],
        _ => vec![],
    };
    items.iter().filter_map(Value::as_str).map(|name| name.trim().to_string()).filter(|n| !n.is_empty()).collect()
}

/// Why a profile's tool settings are not chat-only: forbidden toolsets missing from
/// `agent.disabled_toolsets`, and MCP servers that are on (their tools can do anything).
/// Each argument is what `hermes config get <key> --json` printed, or Null when the key is not set.
pub fn hermes_tool_problems(disabled_toolsets: &Value, mcp_servers: &Value) -> Vec<String> {
    let disabled = hermes_string_list(disabled_toolsets);
    let mut problems = Vec::new();
    let missing: Vec<&str> = HERMES_FORBIDDEN_TOOLSETS.iter().copied().filter(|t| !disabled.iter().any(|d| d == t)).collect();
    if !missing.is_empty() {
        problems.push(format!("agent.disabled_toolsets does not include {}", missing.join(", ")));
    }
    let off = |v: &Value| match v {
        Value::Bool(b) => !b,
        Value::Int(i) => i == "0",
        Value::Str(t) => matches!(t.trim().to_ascii_lowercase().as_str(), "false" | "no" | "off" | "0"),
        _ => false,
    };
    let on: Vec<&str> = match mcp_servers {
        Value::Object(servers) => servers
            .iter()
            .filter(|(_, server)| !server.as_object().and_then(|s| s.get("enabled")).is_some_and(off))
            .map(|(name, _)| name.as_str())
            .collect(),
        _ => vec![],
    };
    if !on.is_empty() {
        problems.push(format!("MCP servers are on ({})", on.join(", ")));
    }
    problems
}

/// `hermes -p <profile> config get <key> --json`: the value, or Null when the key is not set.
fn hermes_config(program: &Path, profile: &str, key: &str) -> Result<Value, String> {
    let child = std::process::Command::new(program)
        .args(["-p", profile, "config", "get", key, "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("NO_COLOR", "1")
        .env("FORCE_COLOR", "0")
        .spawn()
        .map_err(|e| format!("cannot run {} to read profile {profile:?}: {e}", program.display()))?;
    let pid = child.id() as i32;
    let (done, result) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = done.send(child.wait_with_output());
    });
    let output = match result.recv_timeout(Duration::from_secs(30)) {
        Ok(output) => output.map_err(|e| format!("reading Hermes setting {key}: {e}"))?,
        Err(_) => {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            return Err(format!("hermes -p {profile} config get {key} did not answer in 30s"));
        }
    };
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        if output.status.code() == Some(1) && stderr.contains("Config key not set") {
            return Ok(Value::Null);
        }
        let first = stderr.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("no message");
        return Err(format!("hermes -p {profile} config get {key} failed: {first}"));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().rev().map(str::trim).find(|l| !l.is_empty()).unwrap_or("null");
    pyjson::loads_str(line).map_err(|_| format!("hermes -p {profile} config get {key} --json did not print JSON"))
}

/// Room text includes other models' replies, so the room profile must be chat only: no tool
/// that runs commands or code or touches files. Asked of Hermes itself (`config get`, its
/// documented, machine-readable setting reader) at startup; anything else stops the daemon.
fn check_hermes_tools(program: &Path, profile: &str) -> Result<(), String> {
    let disabled = hermes_config(program, profile, "agent.disabled_toolsets")?;
    let mcp = hermes_config(program, profile, "mcp_servers")?;
    let problems = hermes_tool_problems(&disabled, &mcp);
    if problems.is_empty() {
        return Ok(());
    }
    Err(format!(
        "WARNING: Hermes profile {profile:?} can run commands or touch files ({}). Room text includes \
         other models' replies, so the room profile must be chat only. Run:\n  \
         hermes -p {profile} config set agent.disabled_toolsets '[{}]'\n  \
         hermes -p {profile} config set platform_toolsets.cli '[]'\n\
         and remove or disable its MCP servers (hermes -p {profile} mcp list). See rust/README.md, The Hermes Agent backend.",
        problems.join("; "),
        HERMES_FORBIDDEN_TOOLSETS.map(|t| format!("\"{t}\"")).join(", "),
    ))
}

/// `default_registry()`, read from the environment at startup. An unusable setting stops the daemon.
pub fn registry_from_environment() -> Result<Registry, String> {
    let base = std::env::var(OLLAMA_URL_ENV).ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| OLLAMA_BASE.into());
    let base = base.trim().trim_end_matches('/').to_string();
    let mut handlers = Vec::new();
    if switch(INFERENCE_ENV)? {
        let endpoint = loopback_endpoint(&format!("{base}/api/generate"))?;
        handlers.push((INFERENCE.to_string(), Arc::new(Handler::Inference { endpoint, model: INFERENCE_MODEL.into() }), INFERENCE_DEADLINE_SECONDS));
    }
    if switch(ENABLE_ENV)? {
        let backend = std::env::var(BACKEND_ENV).unwrap_or_default().trim().to_lowercase();
        let (handler, deadline) = match backend.as_str() {
            "" | "ollama" => {
                let model = std::env::var(MODEL_ENV).unwrap_or_default();
                let model = if model.trim().is_empty() { DEFAULT_ROOM_MODEL.to_string() } else { model.trim().to_string() };
                if !valid_model_name(&model) {
                    return Err(format!("{MODEL_ENV}={model:?} is not an Ollama model name"));
                }
                let endpoint = loopback_endpoint(&format!("{base}/api/chat"))?;
                (Handler::OllamaRoomTurn { endpoint, model }, ROOM_DEADLINE_SECONDS)
            }
            "openclaw" => {
                let name = std::env::var(OPENCLAW_BIN_ENV).ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| "openclaw".into());
                let program = find_program(name.trim())
                    .ok_or_else(|| format!("{OPENCLAW_BIN_ENV}: cannot find {:?} (set it to the openclaw executable's path)", name.trim()))?;
                let session = std::env::var(OPENCLAW_SESSION_ENV).ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| OPENCLAW_DEFAULT_SESSION.into());
                let session = session.trim().to_string();
                if !valid_session_id(&session) {
                    return Err(format!("{OPENCLAW_SESSION_ENV}={session:?}: use letters, digits and . _ : - (up to 128)"));
                }
                let timeout = timeout_seconds(OPENCLAW_TIMEOUT_ENV, OPENCLAW_DEFAULT_TIMEOUT_SECONDS)?;
                // The registry's deadline sits above the process timeout, so the handler loses first and says why.
                (Handler::OpenClawRoomTurn { program, session, timeout: Duration::from_secs(timeout) }, timeout as f64 + 30.0)
            }
            "hermes" => {
                let name = std::env::var(HERMES_BIN_ENV).ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| "hermes".into());
                let program = find_program(name.trim())
                    .ok_or_else(|| format!("{HERMES_BIN_ENV}: cannot find {:?} (set it to the hermes executable's path)", name.trim()))?;
                let profile = std::env::var(HERMES_PROFILE_ENV).ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| HERMES_DEFAULT_PROFILE.into());
                let profile = profile.trim().to_string();
                if !valid_hermes_profile(&profile) {
                    return Err(format!("{HERMES_PROFILE_ENV}={profile:?}: use lowercase letters, digits, _ and - (up to 64)"));
                }
                check_hermes_profile(&profile)?;
                check_hermes_tools(&program, &profile)?;
                let session = match std::env::var(HERMES_SESSION_ENV) {
                    Ok(v) if !v.trim().is_empty() => {
                        let v = v.trim().to_string();
                        if !valid_session_id(&v) {
                            return Err(format!("{HERMES_SESSION_ENV}={v:?}: use letters, digits and . _ : - (up to 128)"));
                        }
                        Some(v)
                    }
                    _ => None,
                };
                let timeout = timeout_seconds(HERMES_TIMEOUT_ENV, HERMES_DEFAULT_TIMEOUT_SECONDS)?;
                (Handler::HermesRoomTurn { program, profile, session, timeout: Duration::from_secs(timeout) }, timeout as f64 + 30.0)
            }
            other => return Err(format!("{BACKEND_ENV}={other:?}: use ollama, openclaw or hermes")),
        };
        handlers.push((ROOM_TURN.to_string(), Arc::new(handler), deadline));
    }
    let _ = HANDLER_DEADLINE_SECONDS;
    Ok(Registry { handlers, semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_HANDLERS)) })
}

/// The payload's messages, rebuilt from role and content, or None.
pub fn room_messages(payload: &Value) -> Option<Vec<(String, String)>> {
    let raw = payload.as_object()?.get("messages")?.as_array()?;
    if raw.is_empty() || raw.len() > MAX_MESSAGES {
        return None;
    }
    let mut out = Vec::with_capacity(raw.len());
    for message in raw {
        let m = message.as_object()?;
        let role = m.get("role")?.as_str()?;
        let content = m.get("content")?.as_str()?;
        if !["system", "user", "assistant"].contains(&role) {
            return None;
        }
        out.push((role.to_string(), content.to_string()));
    }
    out.iter().any(|(role, content)| role != "system" && !py_strip(content).is_empty()).then_some(out)
}

/// What an agent CLI (OpenClaw, Hermes) is sent as its one message: the preamble, then the room's messages labelled by role.
pub fn agent_message(messages: &[(String, String)]) -> String {
    let mut text = String::from(PREAMBLE);
    for (role, content) in messages {
        text.push_str(&format!("\n\n[{role}]\n{content}"));
    }
    text
}

impl Handler {
    async fn call(&self, payload: Value) -> HandlerResult {
        match self {
            Handler::OllamaRoomTurn { endpoint, model } => {
                let Some(messages) = room_messages(&payload) else { return failed(REASON_INVALID_PAYLOAD) };
                if messages.iter().map(|(_, c)| py_len(c)).sum::<usize>() > MAX_TOTAL_CHARS {
                    return failed(REASON_TOO_LONG);
                }
                let mut chat = vec![object([("role", Value::str("system")), ("content", Value::str(PREAMBLE))])];
                chat.extend(messages.into_iter().map(|(r, c)| object([("role", Value::str(r)), ("content", Value::str(c))])));
                let body = object([
                    ("model", Value::str(model.clone())),
                    ("messages", Value::Array(chat)),
                    ("stream", Value::Bool(false)),
                    ("think", Value::Bool(false)),
                    ("options", object([("num_predict", Value::int(ROOM_MAX_COMPLETION_TOKENS))])),
                ]);
                ollama(endpoint, &body, ROOM_TIMEOUT_SECONDS, |data| {
                    let text = data.get("message")?.as_object()?.get("content")?.as_str()?.to_string();
                    Some(describe(model, "text", &text, ROOM_MAX_COMPLETION_CHARS, data))
                })
                .await
            }
            Handler::Inference { endpoint, model } => {
                let prompt = payload.as_object().and_then(|p| p.get("prompt")).and_then(Value::as_str).map(py_strip).unwrap_or_default();
                if prompt.is_empty() {
                    return failed(REASON_INVALID_PAYLOAD);
                }
                if py_len(prompt) > MAX_PROMPT_CHARS {
                    return failed(REASON_PROMPT_TOO_LONG);
                }
                let body = object([
                    ("model", Value::str(model.clone())),
                    ("prompt", Value::str(prompt)),
                    ("stream", Value::Bool(false)),
                    ("think", Value::Bool(false)),
                    ("options", object([("num_predict", Value::int(INFERENCE_MAX_COMPLETION_TOKENS))])),
                ]);
                ollama(endpoint, &body, INFERENCE_TIMEOUT_SECONDS, |data| {
                    let text = data.get("response")?.as_str()?.to_string();
                    Some(describe(model, "completion", &text, INFERENCE_MAX_COMPLETION_CHARS, data))
                })
                .await
            }
            Handler::OpenClawRoomTurn { program, session, timeout } => {
                let Some(messages) = room_messages(&payload) else { return failed(REASON_INVALID_PAYLOAD) };
                if messages.iter().map(|(_, c)| py_len(c)).sum::<usize>() > MAX_TOTAL_CHARS {
                    return failed(REASON_TOO_LONG);
                }
                let args = ["agent", "--session-id", session, "--json", "--message", &agent_message(&messages)].map(String::from);
                run_agent_cli("openclaw", program, &args, None, *timeout, openclaw_reply).await
            }
            Handler::HermesRoomTurn { program, profile, session, timeout } => {
                let Some(messages) = room_messages(&payload) else { return failed(REASON_INVALID_PAYLOAD) };
                if messages.iter().map(|(_, c)| py_len(c)).sum::<usize>() > MAX_TOTAL_CHARS {
                    return failed(REASON_TOO_LONG);
                }
                run_agent_cli("hermes", program, &hermes_args(profile, session.as_deref(), *timeout), Some(agent_message(&messages)), *timeout, hermes_reply).await
            }
        }
    }
}

/// The output Python builds: typed fields only, the text capped in characters.
fn describe(model: &str, field: &str, text: &str, cap: usize, data: &pyjson::Map) -> Value {
    let truncated = py_len(text) > cap;
    let text = if truncated { py_prefix(text, cap) } else { text };
    let done_reason = match data.get("done_reason") {
        Some(Value::Str(s)) => Value::str(s.clone()),
        _ => Value::Null,
    };
    let eval_count = match data.get("eval_count") {
        Some(v) if v.is_python_int() => v.clone(),
        _ => Value::Null,
    };
    object([
        ("model", Value::str(model)),
        (field, Value::str(text)),
        ("chars", Value::int(py_len(text) as i64)),
        ("truncated", Value::Bool(truncated)),
        ("done_reason", done_reason),
        ("eval_count", eval_count),
    ])
}

enum PostError {
    Timeout,
    Connect,
    Other,
}

async fn post_json(endpoint: &Endpoint, body: String, timeout: f64) -> Result<(u16, Bytes), PostError> {
    let stream = match tokio::time::timeout(Duration::from_secs_f64(CONNECT_TIMEOUT_SECONDS), tokio::net::TcpStream::connect(endpoint.addr)).await {
        Err(_) => return Err(PostError::Timeout),
        Ok(Err(_)) => return Err(PostError::Connect),
        Ok(Ok(s)) => s,
    };
    let exchange = async {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|_| PostError::Other)?;
        tokio::spawn(conn);
        let request = hyper::Request::post(endpoint.path.as_str())
            .header("host", endpoint.host_header.as_str())
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| PostError::Other)?;
        let response = sender.send_request(request).await.map_err(|_| PostError::Other)?;
        let status = response.status().as_u16();
        let limited = http_body_util::Limited::new(response.into_body(), MAX_UPSTREAM_BYTES);
        let bytes = limited.collect().await.map_err(|_| PostError::Other)?.to_bytes();
        Ok((status, bytes))
    };
    match tokio::time::timeout(Duration::from_secs_f64(timeout), exchange).await {
        Err(_) => Err(PostError::Timeout),
        Ok(result) => result,
    }
}

async fn ollama(endpoint: &Endpoint, body: &Value, timeout: f64, read: impl Fn(&pyjson::Map) -> Option<Value>) -> HandlerResult {
    let body = pyjson::response(body).expect("request bodies are finite");
    let (status, bytes) = match post_json(endpoint, body, timeout).await {
        Ok(ok) => ok,
        Err(PostError::Timeout) => return failed(REASON_TIMEOUT),
        Err(PostError::Connect) => return failed(REASON_UPSTREAM_UNAVAILABLE),
        Err(PostError::Other) => return failed(REASON_CONNECTION_FAILED),
    };
    if status == 404 {
        return failed(REASON_MODEL_NOT_AVAILABLE);
    }
    if status != 200 {
        return failed(REASON_UPSTREAM_ERROR);
    }
    let Ok(Value::Object(data)) = pyjson::loads(&bytes) else { return failed(REASON_UPSTREAM_ERROR) };
    match read(&data) {
        Some(output) => completed(output),
        None => failed(REASON_UPSTREAM_ERROR),
    }
}

/// Kills an agent CLI's process group when the turn ends for any reason, timeout and deadline included.
struct GroupKill(Option<i32>);

impl Drop for GroupKill {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            // SAFETY: killpg on a process group this daemon created; failure (already gone) is harmless.
            unsafe {
                libc::killpg(pid, libc::SIGKILL);
            }
        }
    }
}

/// Remove terminal colour and cursor sequences, in case the CLI ignores NO_COLOR.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(n) = chars.next() {
                    if ('\u{40}'..='\u{7e}').contains(&n) {
                        break;
                    }
                }
            } else {
                chars.next();
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// An agent CLI's reply, taken from its structured output: the text and, when given, why it stopped and its output tokens.
#[derive(Debug)]
pub struct AgentReply {
    pub text: String,
    pub stop_reason: Option<String>,
    pub output_tokens: Option<Value>,
}

/// Find the JSON result in OpenClaw's stdout. It is normally the whole of it,
/// but anything printed first (the banner and tagline OpenClaw shows on a
/// terminal, a plugin's log line) is skipped: the result is the first line
/// starting with `{` from which the rest parses as one JSON object.
fn openclaw_result(stdout: &str) -> Option<pyjson::Map> {
    let mut starts = vec![0];
    starts.extend(stdout.match_indices('\n').map(|(i, _)| i + 1));
    starts.into_iter().filter(|&i| stdout[i..].trim_start().starts_with('{')).find_map(|i| match pyjson::loads(stdout[i..].as_bytes()) {
        Ok(Value::Object(map)) => Some(map),
        _ => None,
    })
}

/// Only the agent's reply: `result.payloads[].text`, joined, or the run's final
/// visible text if it sent no payloads. A run that is not `status: "ok"`, or was
/// aborted, has no reply. The run metadata (prompt reports, traces, usage) is dropped.
pub fn openclaw_reply(stdout: &str) -> Result<AgentReply, &'static str> {
    let doc = openclaw_result(stdout).ok_or("no JSON result in its output")?;
    if !doc.get("status").is_some_and(|s| s.is_str("ok")) {
        return Err("its result status is not ok");
    }
    let result = doc.get("result").and_then(Value::as_object).ok_or("its result has no 'result'")?;
    let meta = result.get("meta").and_then(Value::as_object);
    if meta.and_then(|m| m.get("aborted")).is_some_and(|a| matches!(a, Value::Bool(true))) {
        return Err("the run was aborted");
    }
    let payloads: Vec<String> = result
        .get("payloads")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(|p| p.as_object()?.get("text")?.as_str()).map(|t| strip_ansi(t).trim().to_string()).filter(|t| !t.is_empty()).collect())
        .unwrap_or_default();
    let text = if payloads.is_empty() {
        meta.and_then(|m| m.get("finalAssistantVisibleText")).and_then(Value::as_str).map(|t| strip_ansi(t).trim().to_string()).unwrap_or_default()
    } else {
        payloads.join("\n\n")
    };
    if text.is_empty() {
        return Err("its result has no reply text");
    }
    let stop_reason = meta.and_then(|m| m.get("stopReason")).and_then(Value::as_str).map(str::to_string);
    let output_tokens = meta
        .and_then(|m| m.get("agentMeta")?.as_object()?.get("usage")?.as_object()?.get("output"))
        .filter(|v| v.is_python_int())
        .cloned();
    Ok(AgentReply { text, stop_reason, output_tokens })
}

/// `hermes -p <profile> chat --query-file - --format stream-json --source tool --run-budget <s> [-c <session> --create-if-missing]`.
///
/// The room's message goes on stdin (`--query-file -`), never in argv, so the
/// room's text does not show in `ps` and can never be read as a flag. The
/// profile is a Hermes home of its own (sessions, memory, config), so rooms
/// never touch the user's own sessions or memory. Without a session name each
/// turn is a fresh session, since every turn already carries the whole room;
/// `--source tool` keeps those out of Hermes' session pickers. `--run-budget`
/// gives Hermes the same time limit, so the agent wraps up before it is stopped.
pub fn hermes_args(profile: &str, session: Option<&str>, timeout: Duration) -> Vec<String> {
    let mut args = ["-p", profile, "chat", "--query-file", "-", "--format", "stream-json", "--source", "tool", "--run-budget"]
        .map(String::from)
        .to_vec();
    args.push(timeout.as_secs().to_string());
    if let Some(name) = session {
        args.extend(["-c", name, "--create-if-missing"].map(String::from));
    }
    args
}

/// Only the agent's reply from `hermes chat --format stream-json`: the `text` of
/// the terminal `{"type":"result"}` event, which is the whole reply (the `text`
/// deltas before it can stop early on a replay gap). Tool calls, tool output and
/// anything not JSON (a stray log line) are ignored. A result whose `exit_code`
/// is not 0, or with no text, has no reply.
pub fn hermes_reply(stdout: &str) -> Result<AgentReply, &'static str> {
    let result = stdout
        .lines()
        .filter(|line| line.trim_start().starts_with('{'))
        .filter_map(|line| match pyjson::loads(line.as_bytes()) {
            Ok(Value::Object(event)) if event.get("type").is_some_and(|t| t.is_str("result")) => Some(event),
            _ => None,
        })
        .next_back()
        .ok_or("no result event in its output")?;
    if !result.get("exit_code").is_some_and(|c| pyjson::canonical(c) == "0") {
        return Err("its result exit_code is not 0");
    }
    let text = result.get("text").and_then(Value::as_str).map(|t| strip_ansi(t).trim().to_string()).unwrap_or_default();
    if text.is_empty() {
        return Err("its result has no reply text");
    }
    let output_tokens = result
        .get("tokens")
        .and_then(Value::as_object)
        .and_then(|t| t.get("output"))
        .filter(|v| v.is_python_int())
        .cloned();
    Ok(AgentReply { text, stop_reason: None, output_tokens })
}

/// One room turn through an agent's CLI (OpenClaw, Hermes).
///
/// Arguments go straight to the program, never through a shell; `stdin` is the
/// message when the CLI reads it there, else stdin is closed. Each CLI is run in
/// its structured-output mode, and `parse` takes only the reply from it, never
/// banners or run metadata. stdout is read up to a limit, the whole run is under
/// a timeout, and the process group is killed if either is passed or the turn is
/// abandoned.
async fn run_agent_cli(
    label: &'static str,
    program: &Path,
    args: &[String],
    stdin: Option<String>,
    timeout: Duration,
    parse: fn(&str) -> Result<AgentReply, &'static str>,
) -> HandlerResult {
    let mut command = tokio::process::Command::new(program);
    command
        .args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("NO_COLOR", "1")
        .env("FORCE_COLOR", "0")
        .kill_on_drop(true)
        .process_group(0);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            println!("[HANDLER] room-turn: cannot start {}: {e}", program.display());
            return failed(REASON_UPSTREAM_UNAVAILABLE);
        }
    };
    let pid = child.id().map(|pid| pid as i32);
    let _group = GroupKill(pid);
    // Written while stdout is read, so a long message never waits on a full pipe; closed when done.
    let feed = stdin.zip(child.stdin.take()).map(|(text, mut pipe)| async move {
        use tokio::io::AsyncWriteExt;
        let _ = pipe.write_all(text.as_bytes()).await;
        let _ = pipe.shutdown().await;
    });
    let mut stdout = child.stdout.take().expect("piped");
    let mut stderr = child.stderr.take().expect("piped");

    let run = async {
        let read_out = async {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                let n = stdout.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    return (buf, false);
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > AGENT_MAX_STDOUT_BYTES {
                    buf.truncate(AGENT_MAX_STDOUT_BYTES);
                    // Stop the agent now, so its stderr closes and nobody waits for an answer nobody will read.
                    if let Some(pid) = pid {
                        // SAFETY: as in GroupKill.
                        unsafe {
                            libc::killpg(pid, libc::SIGKILL);
                        }
                    }
                    return (buf, true);
                }
            }
        };
        let read_err = async {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = stderr.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    return buf;
                }
                if buf.len() < AGENT_MAX_STDERR_BYTES {
                    buf.extend_from_slice(&chunk[..n.min(AGENT_MAX_STDERR_BYTES - buf.len())]);
                }
            }
        };
        let write_in = async {
            if let Some(feed) = feed {
                feed.await;
            }
        };
        let ((out, overflowed), err, ()) = tokio::join!(read_out, read_err, write_in);
        (out, overflowed, err)
    };
    let (out, overflowed, err) = match tokio::time::timeout(timeout, run).await {
        Ok(read) => read,
        Err(_) => {
            println!("[HANDLER] room-turn: {label} passed its {}s limit; stopped", timeout.as_secs());
            return failed(REASON_TIMEOUT);
        }
    };
    let status = match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
        Ok(Ok(status)) => Some(status),
        _ => None,
    };
    if overflowed {
        println!("[HANDLER] room-turn: {label} printed over {AGENT_MAX_STDOUT_BYTES} bytes; stopped");
        return failed(REASON_UPSTREAM_ERROR);
    }
    if !status.is_some_and(|s| s.success()) {
        let first = String::from_utf8_lossy(&err).lines().find(|l| !l.trim().is_empty()).unwrap_or("").chars().take(200).collect::<String>();
        println!("[HANDLER] room-turn: {label} exited with {status:?}: {first}");
        return failed(REASON_UPSTREAM_ERROR);
    }
    let reply = match parse(&String::from_utf8_lossy(&out)) {
        Ok(reply) => reply,
        Err(why) => {
            println!("[HANDLER] room-turn: {label} gave no usable reply: {why}");
            return failed(REASON_UPSTREAM_ERROR);
        }
    };
    let truncated = py_len(&reply.text) > ROOM_MAX_COMPLETION_CHARS;
    let text = py_prefix(&reply.text, ROOM_MAX_COMPLETION_CHARS);
    completed(object([
        ("model", Value::str(label)),
        ("text", Value::str(text)),
        ("chars", Value::int(py_len(text) as i64)),
        ("truncated", Value::Bool(truncated)),
        ("done_reason", reply.stop_reason.map(Value::str).unwrap_or(Value::Null)),
        ("eval_count", reply.output_tokens.unwrap_or(Value::Null)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_literal_loopback_endpoints() {
        assert!(loopback_endpoint("http://127.0.0.1:11434/api/chat").is_ok());
        assert!(loopback_endpoint("http://[::1]:11434/api/chat").is_ok());
        assert!(loopback_endpoint("http://localhost:11434/api/chat").is_err());
        assert!(loopback_endpoint("http://192.168.1.5:11434/api/chat").is_err());
        assert!(loopback_endpoint("https://127.0.0.1:11434/api/chat").is_err());
    }

    #[test]
    fn model_and_session_names() {
        assert!(valid_model_name("qwen3.5:4b") && valid_model_name("library/llama3:8b"));
        assert!(!valid_model_name("-x") && !valid_model_name("a b") && !valid_model_name(""));
        assert!(valid_session_id("knights-circle") && !valid_session_id("--help") && !valid_session_id("a/b"));
    }

    #[test]
    fn room_payloads_are_rebuilt_and_checked() {
        let ok = pyjson::loads(br#"{"messages":[{"role":"system","content":"s","images":[1]},{"role":"user","content":"hi"}]}"#).unwrap();
        assert_eq!(room_messages(&ok).unwrap().len(), 2);
        for bad in [r#"{"messages":[]}"#, r#"{"messages":[{"role":"system","content":"only"}]}"#, r#"{"messages":[{"role":"tool","content":"x"}]}"#, r#"{"messages":[{"role":"user","content":"   "}]}"#, r#"[]"#] {
            assert!(room_messages(&pyjson::loads(bad.as_bytes()).unwrap()).is_none(), "{bad}");
        }
    }

    const REAL_JSON: &str = include_str!("../tests/fixtures/openclaw-agent-json.json");

    #[test]
    fn the_reply_is_taken_from_real_openclaw_json_output() {
        let reply = openclaw_reply(REAL_JSON).unwrap();
        assert_eq!(reply.text, "Hello there, how are you?");
        assert_eq!(reply.stop_reason.as_deref(), Some("stop"));
        assert_eq!(reply.output_tokens.map(|v| pyjson::canonical(&v)).as_deref(), Some("8"));
    }

    #[test]
    fn a_terminal_banner_before_the_json_is_skipped() {
        // What OpenClaw 2026.6.5 shows before the result when it believes it is on a terminal.
        let banner = "\u{1b}[2m│\u{1b}[0m\n◇  OpenClaw 2026.6.5 (5181e4f)\n│\n│  Why did the lobster refuse to share? It was a little shellfish.\n│\n◇\n";
        let reply = openclaw_reply(&format!("{banner}{REAL_JSON}")).unwrap();
        assert_eq!(reply.text, "Hello there, how are you?");
        assert!(!reply.text.contains("OpenClaw 2026.6.5") && !reply.text.contains('│'));
    }

    #[test]
    fn payloads_are_joined_and_failures_have_no_reply() {
        let two = r#"{"status":"ok","result":{"payloads":[{"text":"First."},{"text":"  "},{"mediaUrl":"x"},{"text":"Second."}],"meta":{}}}"#;
        assert_eq!(openclaw_reply(two).unwrap().text, "First.\n\nSecond.");
        let fallback = r#"{"status":"ok","result":{"payloads":[],"meta":{"finalAssistantVisibleText":"From meta."}}}"#;
        assert_eq!(openclaw_reply(fallback).unwrap().text, "From meta.");
        for bad in [
            "Hello there, how are you?",
            r#"{"status":"error","summary":"gateway unreachable","result":{"payloads":[{"text":"x"}]}}"#,
            r#"{"status":"ok","result":{"payloads":[{"text":"partial"}],"meta":{"aborted":true}}}"#,
            r#"{"status":"ok","result":{"payloads":[],"meta":{}}}"#,
            r#"{"status":"ok","result":{"payloads":[{"text":"cut off"#,
        ] {
            assert!(openclaw_reply(bad).is_err(), "{bad}");
        }
    }

    // Written field for field as Hermes v0.22.5's StreamJsonEmitter writes them (hermes_cli/stream_json.py).
    const HERMES_STREAM: &str = include_str!("../tests/fixtures/hermes-stream-json.jsonl");

    #[test]
    fn hermes_reply_is_the_result_events_text_only() {
        let reply = hermes_reply(HERMES_STREAM).unwrap();
        assert_eq!(reply.text, "Start with Python, then build one small project.");
        assert_eq!(reply.output_tokens.map(|v| pyjson::canonical(&v)).as_deref(), Some("14"));
        assert!(reply.stop_reason.is_none());
        // Tool output, even one shaped like a result, is never the reply; nor are stray non-JSON lines.
        let noisy = format!("Hermes Agent v0.22.5\nwarning: something\n{HERMES_STREAM}");
        assert_eq!(hermes_reply(&noisy).unwrap().text, reply.text);
    }

    #[test]
    fn hermes_failures_have_no_reply() {
        for bad in [
            "",
            "Start with Python.",
            r#"{"type": "system", "subtype": "init", "model": "m", "session_id": ""}"#,
            r#"{"type": "result", "session_id": "", "exit_code": 1, "text": "", "error": "No inference provider configured"}"#,
            r#"{"type": "result", "session_id": "s", "exit_code": 130, "text": "partial"}"#,
            r#"{"type": "result", "session_id": "s", "exit_code": 0, "text": "   "}"#,
            r#"{"type": "result", "session_id": "s", "exit_code": 0, "text": "cut off"#,
        ] {
            assert!(hermes_reply(bad).is_err(), "{bad}");
        }
        // A replay gap: the deltas stopped early, the result carries the whole reply.
        let gap = "{\"type\": \"text\", \"text\": \"Sta\"}\n{\"type\": \"result\", \"exit_code\": 0, \"text\": \"Start here.\", \"replay_gap\": true}\n";
        assert_eq!(hermes_reply(gap).unwrap().text, "Start here.");
    }

    #[test]
    fn hermes_is_run_in_its_own_profile_with_the_message_on_stdin() {
        let args = hermes_args("knights-circle", None, Duration::from_secs(120));
        assert_eq!(args, ["-p", "knights-circle", "chat", "--query-file", "-", "--format", "stream-json", "--source", "tool", "--run-budget", "120"]);
        let pinned = hermes_args("kc", Some("room-thread"), Duration::from_secs(60));
        assert_eq!(&pinned[pinned.len() - 3..], ["-c", "room-thread", "--create-if-missing"]);
        assert!(valid_hermes_profile("knights-circle") && valid_hermes_profile("kc_2"));
        assert!(!valid_hermes_profile("-p") && !valid_hermes_profile("Knights") && !valid_hermes_profile("a/b") && !valid_hermes_profile(""));
    }

    #[test]
    fn a_room_profile_must_disable_every_tool_that_runs_commands_or_touches_files() {
        let all = Value::Array(HERMES_FORBIDDEN_TOOLSETS.iter().map(|t| Value::str(*t)).collect());
        assert!(hermes_tool_problems(&all, &Value::Null).is_empty());
        // `hermes config set` stores a list as a JSON (or Python-literal) string; Hermes reads both.
        let as_set = Value::str(format!("[{}]", HERMES_FORBIDDEN_TOOLSETS.map(|t| format!("'{t}'")).join(", ")));
        assert!(hermes_tool_problems(&as_set, &pyjson::loads_str("{}").unwrap()).is_empty());
        let problems = hermes_tool_problems(&Value::Null, &Value::Null);
        assert_eq!(problems, ["agent.disabled_toolsets does not include terminal, file, code_execution, delegation, cronjob, browser, computer_use, skills"]);
        let some = pyjson::loads_str(r#"["memory", "terminal", "file"]"#).unwrap();
        assert_eq!(hermes_tool_problems(&some, &Value::Null)[0], "agent.disabled_toolsets does not include code_execution, delegation, cronjob, browser, computer_use, skills");
        assert!(!hermes_tool_problems(&Value::str("terminal"), &Value::Null).is_empty());
        let mcp = pyjson::loads_str(r#"{"github": {"command": "npx"}, "off": {"command": "x", "enabled": false}, "no": {"enabled": "no"}, "on": {"enabled": true}}"#).unwrap();
        assert_eq!(hermes_tool_problems(&all, &mcp), ["MCP servers are on (github, on)"]);
    }

    #[test]
    fn ansi_is_removed() {
        assert_eq!(strip_ansi("\u{1b}[1;32mhello\u{1b}[0m"), "hello");
    }
}
