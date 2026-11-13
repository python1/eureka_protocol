// SPDX-License-Identifier: AGPL-3.0-only
//! A single-use Responses endpoint for a single CLI invocation. Inspect the actual
//! serialized request before opening the upstream connection. No request body,
//! access token, model output or account header belongs in a diagnostic.
use crate::pyjson;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{body::Incoming, Request, Response};
use hyper_util::rt::TokioIo;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::TcpListener;

const UPSTREAM: &str = "chatgpt.com";
const PATH: &str = "/backend-api/codex/responses";
type GuardError = &'static str;
type ForwardRequest = Request<Full<Bytes>>;

pub struct Guard {
    listener: TcpListener,
    pub base: String,
    pub secret: String,
    /// True only after the inspected request received a successful upstream response.
    pub admitted: AtomicBool,
}

impl Guard {
    pub async fn bind() -> Result<Self, GuardError> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|_| "cannot bind the local tool guard")?;
        let base = format!(
            "http://{}/v1",
            listener
                .local_addr()
                .map_err(|_| "cannot inspect guard address")?
        );
        Ok(Self {
            listener,
            base,
            secret: crate::crypto::token_hex16(),
            admitted: AtomicBool::new(false),
        })
    }

    pub async fn serve(&self, home: &std::path::Path) -> Result<(), GuardError> {
        self.serve_with(|mut req| async {
            attach_seat_login(&mut req, home)?;
            forward(req).await
        })
        .await
    }

    async fn serve_with<F, Fut, B>(&self, send: F) -> Result<(), GuardError>
    where
        F: Fn(ForwardRequest) -> Fut,
        Fut: Future<Output = Result<Response<B>, GuardError>>,
        B: hyper::body::Body + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let (stream, _) = self
            .listener
            .accept()
            .await
            .map_err(|_| "cannot accept the Codex request")?;
        let service = hyper::service::service_fn(|request| async {
            let checked = inspect(request, &self.secret)
                .await
                .inspect_err(|why| eprintln!("[HANDLER] Codex: {why}"))?;
            let response = send(checked).await?;
            if !response.status().is_success() {
                return Err(
                    "ChatGPT refused the guarded request; check the seat login and model access",
                );
            }
            self.admitted.store(true, Ordering::Release);
            Ok::<_, GuardError>(response)
        });
        hyper::server::conn::http1::Builder::new()
            .keep_alive(false)
            .serve_connection(TokioIo::new(stream), service)
            .await
            .map_err(|_| "tool guard refused the request or the upstream connection failed")
    }
}

async fn inspect(request: Request<Incoming>, secret: &str) -> Result<ForwardRequest, GuardError> {
    if request.method() != hyper::Method::POST
        || request.uri().path_and_query().map(|p| p.as_str()) != Some("/v1/responses")
        || request.headers().get("x-eureka-turn").map(|v| v.as_bytes()) != Some(secret.as_bytes())
        || request.headers().contains_key("content-encoding")
    {
        return Err("unexpected Codex request");
    }
    let (parts, body) = request.into_parts();
    let bytes = Limited::new(body, 2 * 1024 * 1024)
        .collect()
        .await
        .map_err(|_| "invalid request body")?
        .to_bytes();
    let pyjson::Value::Object(mut fields) =
        pyjson::loads(&bytes).map_err(|_| "invalid request JSON")?
    else {
        return Err("invalid request shape");
    };
    // This pinned build omits tools for an empty inventory. Accept that encoding
    // only for a complete standalone request. Never inherit tools from a prior response.
    let known = [
        "model",
        "stream",
        "input",
        "tool_choice",
        "parallel_tool_calls",
        "tools",
        "reasoning",
        "store",
        "include",
        "prompt_cache_key",
        "text",
        "client_metadata",
        "instructions",
        "service_tier",
        "metadata",
        "temperature",
        "top_p",
        "max_output_tokens",
        "truncation",
    ];
    if fields.keys().any(|k| !known.contains(&k.as_str()))
        || !fields.get("input").is_some_and(|v| v.as_array().is_some())
        || !matches!(fields.get("stream"), Some(pyjson::Value::Bool(true)))
        || !fields
            .get("model")
            .is_some_and(|v| v.as_str().is_some_and(|m| !m.is_empty()))
        || !fields
            .get("tool_choice")
            .is_some_and(|v| v.is_str("auto") || v.is_str("none"))
    {
        return Err("unrecognized standalone Codex request");
    }
    if fields
        .get("tools")
        .is_some_and(|v| !v.as_array().is_some_and(|tools| tools.is_empty()))
    {
        return Err("Codex advertised tools or supplied an invalid inventory");
    }
    fields.insert("tools".into(), pyjson::Value::Array(vec![]));
    fields.insert("tool_choice".into(), pyjson::Value::str("none"));
    let body = pyjson::response(&pyjson::Value::Object(fields)).ok_or("invalid request values")?;
    let mut out = Request::post(PATH)
        .header("host", UPSTREAM)
        .header("content-type", "application/json");
    for name in [
        "openai-beta",
        "originator",
        "user-agent",
        "session_id",
        "version",
        "accept",
    ] {
        if let Some(value) = parts.headers.get(name) {
            out = out.header(name, value);
        }
    }
    out.body(Full::new(Bytes::from(body)))
        .map_err(|_| "invalid request headers")
}

// The CLI may withhold first-party authorization from a custom loopback provider.
// Load only this seat's file login, after inspecting the request. The host/path
// are compiled in and HTTPS redirects are never followed.
fn attach_seat_login(req: &mut ForwardRequest, home: &std::path::Path) -> Result<(), GuardError> {
    let path = home.join("auth/auth.json");
    if !matches!(crate::crypto::private_file_problem(&path), Ok(None))
        || !std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file() && m.len() < 1024 * 1024)
    {
        return Err("seat auth.json must be a private regular file");
    }
    let bytes = std::fs::read(path).map_err(|_| "cannot read seat login")?;
    let login = pyjson::loads(&bytes).map_err(|_| "invalid seat login")?;
    let fields = login.as_object().ok_or("invalid seat login")?;
    if !fields.get("auth_mode").is_some_and(|v| v.is_str("chatgpt")) {
        return Err("seat requires a ChatGPT file login");
    }
    let tokens = fields
        .get("tokens")
        .and_then(|v| v.as_object())
        .ok_or("missing seat login tokens")?;
    for (key, name) in [
        ("access_token", "authorization"),
        ("account_id", "chatgpt-account-id"),
    ] {
        let value = tokens
            .get(key)
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .ok_or("incomplete seat login")?;
        let value = if key == "access_token" {
            format!("Bearer {value}")
        } else {
            value.to_owned()
        };
        let mut header =
            hyper::header::HeaderValue::from_str(&value).map_err(|_| "invalid seat credential")?;
        header.set_sensitive(true);
        req.headers_mut().insert(name, header);
    }
    Ok(())
}

#[cfg(feature = "tls")]
async fn forward(request: ForwardRequest) -> Result<Response<Incoming>, GuardError> {
    let tcp = tokio::net::TcpStream::connect((UPSTREAM, 443))
        .await
        .map_err(|_| "ChatGPT unreachable")?;
    let tls = crate::webhook::tls_stream(UPSTREAM, tcp)
        .await
        .map_err(|_| "ChatGPT TLS connection failed")?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(|_| "upstream handshake failed")?;
    let connection = tokio::spawn(connection);
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| "upstream request failed");
    drop(sender);
    // Dropping the response body cancels its stream; the connection driver then exits.
    drop(connection);
    response
}

#[cfg(not(feature = "tls"))]
async fn forward(_: ForwardRequest) -> Result<Response<Incoming>, GuardError> {
    Err("Codex requires a TLS build")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn only_verified_empty_tools_reach_the_upstream() {
        for (body, pass) in [
            (r#"{"tools":[]}"#, true),
            ("{}", false),
            (r#"{"tools":null}"#, false),
            (r#"{"tools":[{"type":"function","name":"exec"}]}"#, false),
        ] {
            let guard = Guard::bind().await.unwrap();
            let called = AtomicBool::new(false);
            let serve = guard.serve_with(|req| {
                assert!(req.headers().get("x-eureka-turn").is_none());
                called.store(true, Ordering::Relaxed);
                async { Ok(Response::new(Full::new(Bytes::from_static(b"ok")))) }
            });
            let client = async {
                let stream = tokio::net::TcpStream::connect(guard.listener.local_addr().unwrap())
                    .await
                    .unwrap();
                let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
                    .await
                    .unwrap();
                tokio::spawn(conn);
                let mut fields = pyjson::loads_str(body)
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .clone();
                if body != "{}" {
                    for (k, v) in pyjson::loads_str(
                        r#"{"model":"test","stream":true,"input":[],"tool_choice":"auto"}"#,
                    )
                    .unwrap()
                    .as_object()
                    .unwrap()
                    {
                        fields.insert(k.clone(), v.clone());
                    }
                }
                let body = pyjson::canonical(&pyjson::Value::Object(fields));
                let req = Request::post("/v1/responses")
                    .header("x-eureka-turn", &guard.secret)
                    .body(Full::new(Bytes::from(body)))
                    .unwrap();
                tx.send_request(req).await.is_ok()
            };
            let (server, client) = tokio::join!(serve, client);
            assert_eq!(
                (server.is_ok(), client, called.load(Ordering::Relaxed)),
                (pass, pass, pass)
            );
        }
    }

    /// Exercise the production CLI flags and guard with an isolated synthetic
    /// ChatGPT login and model. Opt in by setting EUREKA_TEST_CODEX_BIN.
    #[cfg(unix)]
    #[tokio::test]
    async fn installed_cli_through_guard() {
        let Some(bin) = std::env::var_os("EUREKA_TEST_CODEX_BIN") else {
            return;
        };
        let home =
            std::env::temp_dir().join(format!("eureka-codex-{}", crate::crypto::token_hex16()));
        crate::codex::prepare(&home).unwrap();
        let seat = crate::codex::CodexSeat::new(bin.as_ref(), &home).unwrap();
        seat.check_version().unwrap();
        // Dummy file auth restricted to this disposable HOME. Never load a real account.
        let auth = r#"{"auth_mode":"chatgpt","tokens":{"id_token":"eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.","access_token":"offline-fixture","refresh_token":"offline-fixture","account_id":"fixture"},"last_refresh":"2099-01-01T00:00:00Z"}"#;
        std::fs::write(home.join("auth/auth.json"), auth).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            home.join("auth/auth.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        for enable_shell in [false, true] {
            let guard = Guard::bind().await.unwrap();
            let server = guard.serve_with(|mut req| {
            let home = &home;
            async move {
            assert!(!enable_shell, "unsafe inventory reached upstream");
            attach_seat_login(&mut req, home)?;
            assert_eq!(req.headers()["authorization"], "Bearer offline-fixture");
            let data = req.into_body().collect().await.unwrap().to_bytes();
            let request = pyjson::loads(&data).unwrap();
            assert!(request.as_object().unwrap()["tools"].as_array().unwrap().is_empty());
            let sse = concat!("event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"r\"}}\n\n",
                "event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"message\",\"id\":\"m\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"awake\"}]}}\n\n",
                "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"status\":\"completed\",\"output\":[]}}\n\n");
            Ok(Response::builder().header("content-type","text/event-stream").body(Full::new(Bytes::from_static(sse.as_bytes()))).unwrap())
        } });
            let mut args = crate::codex::args(&guard.base);
            if enable_shell {
                for flag in ["shell_tool", "unified_exec", "goals", "view_image"] {
                    let index = args.iter().position(|arg| arg == flag).unwrap();
                    args[index - 1] = "--enable".into();
                }
                args.splice(
                    args.len() - 1..args.len() - 1,
                    [
                        "-m".into(),
                        "gpt-5.4".into(),
                        "-c".into(),
                        "web_search=\"live\"".into(),
                    ],
                );
            }
            *args.last_mut().unwrap() = "Say awake.".into();
            let child = tokio::process::Command::new(&seat.program)
                .args(args)
                .env_clear()
                .envs(seat.environment())
                .env("EUREKA_CODEX_TURN_SECRET", &guard.secret)
                .current_dir(home.join("room"))
                .kill_on_drop(true)
                .output();
            tokio::pin!(child);
            let output = tokio::time::timeout(std::time::Duration::from_secs(40), async {
            tokio::select! {
                result = server => { assert_eq!(result.is_ok(), !enable_shell); child.await.unwrap() },
                result = &mut child => result.unwrap(),
            }
        })
        .await
        .unwrap();
            if enable_shell {
                assert!(!guard.admitted.load(Ordering::Acquire));
                continue;
            }
            assert_eq!(
                crate::codex::reply(&output.stdout).as_deref(),
                Some("awake"),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(guard.admitted.load(Ordering::Acquire));
        }
        std::fs::remove_dir_all(home).unwrap();
    }
}
