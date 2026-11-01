//! The HTTP surface, matching what FastAPI, Starlette and uvicorn serve for
//! api.py: the same routes, the same 64 KiB body cap and refusals, the same
//! 404/405/307 answers, and CORS headers identical to Starlette's
//! CORSMiddleware for the origins named with --cors-origin.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};

use crate::handlers::Registry;
use crate::node::{AssignDecision, Node, LOGS_EVENT, MANIFEST_EVENT, PEERS_EVENT, REASON_MALFORMED};
use crate::pyjson::{self, object, Value};

pub const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;

pub struct App {
    pub node: Mutex<Node>,
    pub registry: Registry,
    pub cors_origins: Vec<String>,
}

type Reply = Response<Full<Bytes>>;

fn json(status: StatusCode, v: &Value) -> Reply {
    let body = pyjson::response(v).expect("answers are built from finite values");
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn text(status: StatusCode, body: String) -> Reply {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// The transport-level refusal api.py builds for a body it never parsed.
fn handshake_transport_rejection() -> Value {
    object([
        ("event", Value::str("handshake_rejected")),
        ("authenticated", Value::Bool(false)),
        ("reason", Value::str(REASON_MALFORMED)),
        ("peer_id", Value::Null),
        ("auth_type", Value::str("Ed25519")),
    ])
}

enum BodyError {
    TooLarge,
    Bad,
}

/// Read the body under the cap and parse it; refused before buffering once past the cap.
async fn read_json(req: Request<Incoming>) -> Result<Value, BodyError> {
    if let Some(declared) = req.headers().get("content-length") {
        let declared: u64 = declared.to_str().ok().and_then(|s| s.trim().parse().ok()).ok_or(BodyError::Bad)?;
        if declared > MAX_REQUEST_BODY_BYTES as u64 {
            return Err(BodyError::TooLarge);
        }
    }
    let mut body = req.into_body();
    let mut buf = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| BodyError::Bad)?;
        if let Ok(data) = frame.into_data() {
            buf.extend_from_slice(&data);
            if buf.len() > MAX_REQUEST_BODY_BYTES {
                return Err(BodyError::TooLarge);
            }
        }
    }
    pyjson::loads(&buf).map_err(|_| BodyError::Bad)
}

fn status_of(e: &BodyError) -> StatusCode {
    match e {
        BodyError::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        BodyError::Bad => StatusCode::BAD_REQUEST,
    }
}

/// An answer that cannot be rendered (a NaN echoed back) becomes the endpoint's own refusal, as in api.py.
fn render_or(status: StatusCode, v: Value, fallback: impl FnOnce() -> Value) -> Reply {
    if pyjson::response(&v).is_some() {
        json(status, &v)
    } else {
        json(StatusCode::OK, &fallback())
    }
}

const ROUTES: &[(&str, &[&str])] = &[
    ("/v1/manifest", &["GET", "POST"]),
    ("/v1/handshake/offer", &["POST"]),
    ("/v1/handshake/confirm", &["POST"]),
    ("/v1/discovery/addresses", &["POST"]),
    ("/v1/peers", &["POST"]),
    ("/v1/logs", &["POST"]),
    ("/v1/assign", &["POST"]),
];

fn percent_decode(path: &str) -> String {
    let b = path.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = ((b[i + 1] as char).to_digit(16), (b[i + 2] as char).to_digit(16)) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn route(app: Arc<App>, req: Request<Incoming>) -> Reply {
    let path = percent_decode(req.uri().path());
    let method = req.method().clone();
    let Some((route, methods)) = ROUTES.iter().find(|(p, _)| *p == path) else {
        // redirect_slashes: a known path with trailing slashes is redirected to it.
        let trimmed = path.trim_end_matches('/');
        if path.ends_with('/') && ROUTES.iter().any(|(p, _)| *p == trimmed) {
            let host = req.headers().get("host").and_then(|h| h.to_str().ok()).unwrap_or("127.0.0.1");
            let query = req.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
            return Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header("location", format!("http://{host}{trimmed}{query}"))
                .body(Full::new(Bytes::new()))
                .unwrap();
        }
        return json(StatusCode::NOT_FOUND, &object([("detail", Value::str("Not Found"))]));
    };
    let wanted = if method == Method::HEAD { "GET" } else { method.as_str() };
    if !methods.contains(&wanted) {
        let mut reply = json(StatusCode::METHOD_NOT_ALLOWED, &object([("detail", Value::str("Method Not Allowed"))]));
        // Starlette names the first matching route's methods only.
        reply.headers_mut().insert("allow", HeaderValue::from_static(methods[0]));
        return reply;
    }
    match (*route, wanted) {
        ("/v1/manifest", "GET") => {
            let node = app.node.lock().unwrap();
            json(StatusCode::OK, &object([("node_id", Value::str(node.node_id.clone())), ("runtime", Value::str("eureka-daemon-mvd"))]))
        }
        ("/v1/handshake/offer", _) => match read_json(req).await {
            Err(e) => json(status_of(&e), &handshake_transport_rejection()),
            Ok(doc) => {
                let answer = app.node.lock().unwrap().answer_handshake_offer(&doc);
                render_or(StatusCode::OK, answer, handshake_transport_rejection)
            }
        },
        ("/v1/handshake/confirm", _) => match read_json(req).await {
            Err(e) => json(status_of(&e), &handshake_transport_rejection()),
            Ok(doc) => {
                let answer = app.node.lock().unwrap().complete_mutual_handshake(&doc);
                render_or(StatusCode::OK, answer, handshake_transport_rejection)
            }
        },
        ("/v1/discovery/addresses", _) => match read_json(req).await {
            Err(e) => json(status_of(&e), &handshake_transport_rejection()),
            Ok(doc) => json(StatusCode::OK, &app.node.lock().unwrap().answer_discovery(&doc)),
        },
        (path, _) if path != "/v1/assign" => {
            let event = match path {
                "/v1/peers" => PEERS_EVENT,
                "/v1/logs" => LOGS_EVENT,
                _ => MANIFEST_EVENT,
            };
            match read_json(req).await {
                Err(e) => json(status_of(&e), &Node::read_rejected(event, REASON_MALFORMED)),
                Ok(doc) => {
                    let answer = app.node.lock().unwrap().answer_read(event, &doc);
                    render_or(StatusCode::OK, answer, || Node::read_rejected(event, REASON_MALFORMED))
                }
            }
        }
        _ => match read_json(req).await {
            Err(e) => json(status_of(&e), &Node::assign_rejected(REASON_MALFORMED)),
            Ok(doc) => {
                let decision = app.node.lock().unwrap().decide_assign(&doc);
                match decision {
                    AssignDecision::Refused(answer) => json(StatusCode::OK, &answer),
                    AssignDecision::Dispatch { capability, task_name, nonce, peer_id, payload } => {
                        let outcome = app.registry.run(&capability, payload).await;
                        let answer = app.node.lock().unwrap().finish_assign(&capability, &task_name, &nonce, &peer_id, outcome);
                        render_or(StatusCode::OK, answer, || Node::assign_rejected(REASON_MALFORMED))
                    }
                }
            }
        },
    }
}

const PREFLIGHT_VARY: &str = "Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network";
const ALLOW_HEADERS: &str = "Accept, Accept-Language, Content-Language, Content-Type, content-type";
const ALLOWED_REQUEST_HEADERS: [&str; 4] = ["accept", "accept-language", "content-language", "content-type"];

fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

/// Starlette's CORSMiddleware preflight, for an explicit origin list.
fn preflight(app: &App, h: &HeaderMap) -> Reply {
    let origin = header(h, "origin").unwrap_or_default();
    let mut failures = Vec::new();
    let allowed = app.cors_origins.iter().any(|o| o == origin);
    if !allowed {
        failures.push("origin");
    }
    if !["GET", "POST"].contains(&header(h, "access-control-request-method").unwrap_or_default()) {
        failures.push("method");
    }
    if let Some(requested) = header(h, "access-control-request-headers") {
        if requested.split(',').any(|x| !ALLOWED_REQUEST_HEADERS.contains(&x.to_lowercase().trim())) {
            failures.push("headers");
        }
    }
    // Private network access is not granted, exactly as the Python daemon does not grant it.
    if h.contains_key("access-control-request-private-network") {
        failures.push("private-network");
    }
    let mut reply = if failures.is_empty() {
        text(StatusCode::OK, "OK".into())
    } else {
        text(StatusCode::BAD_REQUEST, format!("Disallowed CORS {}", failures.join(", ")))
    };
    let headers = reply.headers_mut();
    headers.insert("vary", HeaderValue::from_static(PREFLIGHT_VARY));
    headers.insert("access-control-allow-methods", HeaderValue::from_static("GET, POST"));
    headers.insert("access-control-max-age", HeaderValue::from_static("600"));
    headers.insert("access-control-allow-headers", HeaderValue::from_static(ALLOW_HEADERS));
    if allowed {
        headers.insert("access-control-allow-origin", HeaderValue::from_str(origin).unwrap());
    }
    reply
}

pub async fn serve(app: Arc<App>, req: Request<Incoming>) -> Result<Reply, Infallible> {
    let cors = !app.cors_origins.is_empty();
    let headers = req.headers().clone();
    let origin = header(&headers, "origin").map(str::to_string);
    if cors && origin.is_some() && req.method() == Method::OPTIONS && headers.contains_key("access-control-request-method") {
        return Ok(preflight(&app, &headers));
    }
    let mut reply = route(app.clone(), req).await;
    if cors {
        let h = reply.headers_mut();
        let vary = |h: &mut HeaderMap| {
            let existing: Vec<String> = h.get_all("vary").iter().filter_map(|v| v.to_str().ok().map(str::to_string)).collect();
            let joined = existing.into_iter().chain(["Origin".to_string()]).collect::<Vec<_>>().join(", ");
            h.insert("vary", HeaderValue::from_str(&joined).unwrap());
        };
        match origin {
            Some(o) if app.cors_origins.contains(&o) => {
                h.insert("access-control-allow-origin", HeaderValue::from_str(&o).unwrap());
                vary(h);
            }
            _ => vary(h),
        }
    }
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_percent_decoded() {
        assert_eq!(percent_decode("/v1/%61ssign"), "/v1/assign");
        assert_eq!(percent_decode("/v1/a%"), "/v1/a%");
        assert_eq!(percent_decode("/v1/a%4"), "/v1/a%4");
    }
}
