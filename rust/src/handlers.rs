//! What this node can be asked to do, and the code that does it.
//!
//! `room-turn` answers one turn of a Knights Circle room, through the local
//! Ollama (as room_turn.py does) or through OpenClaw. `inference` is
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
/// OpenClaw's stdout is read up to this and no further; the process is killed past it.
const OPENCLAW_MAX_STDOUT_BYTES: usize = 1024 * 1024;
const OPENCLAW_MAX_STDERR_BYTES: usize = 8 * 1024;

pub const ENABLE_ENV: &str = "EUREKA_ROOM_TURN";
pub const MODEL_ENV: &str = "EUREKA_ROOM_TURN_MODEL";
pub const INFERENCE_ENV: &str = "EUREKA_INFERENCE";
pub const BACKEND_ENV: &str = "EUREKA_ROOM_TURN_BACKEND";
pub const OLLAMA_URL_ENV: &str = "EUREKA_OLLAMA_URL";
pub const OPENCLAW_BIN_ENV: &str = "EUREKA_OPENCLAW_BIN";
pub const OPENCLAW_SESSION_ENV: &str = "EUREKA_OPENCLAW_SESSION";
pub const OPENCLAW_TIMEOUT_ENV: &str = "EUREKA_OPENCLAW_TIMEOUT";

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
                // Dropping the handler's future kills an OpenClaw process group with it.
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
                let timeout = match std::env::var(OPENCLAW_TIMEOUT_ENV) {
                    Ok(v) if !v.trim().is_empty() => v
                        .trim()
                        .parse::<u64>()
                        .ok()
                        .filter(|s| (1..=1800).contains(s))
                        .ok_or_else(|| format!("{OPENCLAW_TIMEOUT_ENV}={v:?}: give whole seconds from 1 to 1800"))?,
                    _ => OPENCLAW_DEFAULT_TIMEOUT_SECONDS,
                };
                // The registry's deadline sits above the process timeout, so the handler loses first and says why.
                (Handler::OpenClawRoomTurn { program, session, timeout: Duration::from_secs(timeout) }, timeout as f64 + 30.0)
            }
            other => return Err(format!("{BACKEND_ENV}={other:?}: use ollama or openclaw")),
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

/// What OpenClaw is sent as its one message: the preamble, then the room's messages labelled by role.
pub fn openclaw_message(messages: &[(String, String)]) -> String {
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
                openclaw(program, session, *timeout, &openclaw_message(&messages)).await
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

/// Kills the OpenClaw process group when the turn ends for any reason, timeout and deadline included.
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

/// One turn through `openclaw agent --session-id <id> --message <text>`.
///
/// Arguments go straight to the program, never through a shell. The session id
/// is the operator's (default "knights-circle"), so the agent's main
/// conversation is never the one a room writes into. stdout is read up to a
/// limit, the whole run is under a timeout, and the process group is killed if
/// either is passed or the turn is abandoned.
async fn openclaw(program: &Path, session: &str, timeout: Duration, message: &str) -> HandlerResult {
    let mut command = tokio::process::Command::new(program);
    command
        .arg("agent")
        .arg("--session-id")
        .arg(session)
        .arg("--message")
        .arg(message)
        .stdin(Stdio::null())
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
                if buf.len() > OPENCLAW_MAX_STDOUT_BYTES {
                    buf.truncate(OPENCLAW_MAX_STDOUT_BYTES);
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
                if buf.len() < OPENCLAW_MAX_STDERR_BYTES {
                    buf.extend_from_slice(&chunk[..n.min(OPENCLAW_MAX_STDERR_BYTES - buf.len())]);
                }
            }
        };
        let ((out, overflowed), err) = tokio::join!(read_out, read_err);
        (out, overflowed, err)
    };
    let (out, overflowed, err) = match tokio::time::timeout(timeout, run).await {
        Ok(read) => read,
        Err(_) => {
            println!("[HANDLER] room-turn: openclaw passed its {}s limit; stopped", timeout.as_secs());
            return failed(REASON_TIMEOUT);
        }
    };
    let status = match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
        Ok(Ok(status)) => Some(status),
        _ => None,
    };
    if !overflowed && !status.is_some_and(|s| s.success()) {
        let first = String::from_utf8_lossy(&err).lines().find(|l| !l.trim().is_empty()).unwrap_or("").chars().take(200).collect::<String>();
        println!("[HANDLER] room-turn: openclaw exited with {status:?}: {first}");
        return failed(REASON_UPSTREAM_ERROR);
    }
    let text = strip_ansi(&String::from_utf8_lossy(&out));
    let text = text.trim();
    if text.is_empty() {
        println!("[HANDLER] room-turn: openclaw printed nothing");
        return failed(REASON_UPSTREAM_ERROR);
    }
    let truncated = overflowed || py_len(text) > ROOM_MAX_COMPLETION_CHARS;
    let text = py_prefix(text, ROOM_MAX_COMPLETION_CHARS);
    completed(object([
        ("model", Value::str("openclaw")),
        ("text", Value::str(text)),
        ("chars", Value::int(py_len(text) as i64)),
        ("truncated", Value::Bool(truncated)),
        ("done_reason", Value::Null),
        ("eval_count", Value::Null),
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

    #[test]
    fn ansi_is_removed() {
        assert_eq!(strip_ansi("\u{1b}[1;32mhello\u{1b}[0m"), "hello");
    }
}
