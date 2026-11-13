// SPDX-License-Identifier: AGPL-3.0-only
//! Waking an agent by webhook. Only the fact of a turn goes out, as `{event, id, ts}`: never the
//! room's text, which the agent reads from the local queue (turns.rs).
//!
//! The URL and key live in `webhook.json`, private to this user, and nowhere else: not in
//! arguments or the environment, and only the host is ever logged. HTTPS only (plain http to a
//! literal loopback address, for an agent on this machine), redirects are not followed, and a
//! refusal (4xx) is not retried.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper_util::rt::TokioIo;

use crate::pyjson::{self, object, Value};

pub const WEBHOOK_CONFIG_ENV: &str = "EUREKA_WEBHOOK_CONFIG";
const DEFAULT_EVENT: &str = "eureka_room_turn";
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);
/// Pauses before the second and third attempts, for an unreachable host or a 5xx.
const RETRY_DELAYS: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(3)];

/// Who is being woken, which decides how the room is told about a stall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentKind {
    GrokBot,
    Generic,
}

/// Why a wake did not start a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeFailure {
    Refused(u16),
    Unreachable,
}

/// Deliberately not `Debug`: it holds the key.
pub struct Webhook {
    target: Target,
    authorization: Option<String>,
    event: String,
    pub agent: AgentKind,
}

#[derive(Debug, PartialEq, Eq)]
struct Target {
    tls: bool,
    host: String,
    port: u16,
    host_header: String,
    path: String,
}

pub fn resolve_config_path() -> PathBuf {
    match std::env::var(WEBHOOK_CONFIG_ENV) {
        Ok(p) if !p.trim().is_empty() => crate::crypto::expand_user(p.trim()),
        _ => crate::crypto::default_eureka_dir().join("webhook.json"),
    }
}

fn parse_url(url: &str) -> Result<Target, String> {
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) || url.contains('#') {
        return Err("the url has spaces or a fragment".into());
    }
    let (tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err("the url must start with https://".into());
    };
    let split = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(split);
    if authority.contains('@') {
        return Err("the url must not hold a name or password; put the key in \"authorization\"".into());
    }
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (host, after) = v6.split_once(']').ok_or("the url has a bad host")?;
        (host, after.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return Err("the url has no host".into());
    }
    let port: u16 = match port {
        Some(text) => text.parse().map_err(|_| "the url has a bad port")?,
        None if tls => 443,
        None => 80,
    };
    if !tls && !host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()) {
        return Err("the url must use https (plain http is only for a literal loopback address such as 127.0.0.1)".into());
    }
    if tls && !cfg!(feature = "tls") {
        return Err("this build has no HTTPS (built with --no-default-features); use a default build".into());
    }
    let path = match path {
        "" => "/".to_string(),
        p if p.starts_with('?') => format!("/{p}"),
        p => p.to_string(),
    };
    Ok(Target { tls, host: host.to_string(), port, host_header: authority.to_string(), path })
}

/// The header value, from whatever the user copied: the key, `Bearer <key>`, or the whole header.
fn authorization_value(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    let value = match raw.split_once(':') {
        Some((name, value)) if name.trim().eq_ignore_ascii_case("authorization") => value.trim(),
        _ => raw,
    };
    if value.is_empty() || value.chars().any(|c| c.is_control()) {
        // The value is a secret, so the message never quotes it.
        return Err("\"authorization\" is empty or has control characters".into());
    }
    Ok(if value.contains(' ') { value.to_string() } else { format!("Bearer {value}") })
}

/// Whether this URL could be used. The message never quotes it, since a URL may hold a token.
pub fn check_url(url: &str) -> Result<(), String> {
    parse_url(url.trim()).map(|_| ()).map_err(|why| format!("That was not saved: {why}."))
}

pub fn parse_config(text: &[u8]) -> Result<Webhook, String> {
    let document = pyjson::loads(text).map_err(|_| "it is not valid JSON".to_string())?;
    let fields = document.as_object().ok_or("it is not a JSON object")?;
    if let Some(unknown) = fields.keys().find(|k| !["url", "authorization", "event", "agent"].contains(&k.as_str())) {
        return Err(format!("unknown field {unknown:?}; use url, authorization, event and agent"));
    }
    let text_field = |name: &str| -> Result<Option<&str>, String> {
        match fields.get(name) {
            None => Ok(None),
            Some(value) => value.as_str().map(Some).ok_or_else(|| format!("{name:?} must be a string")),
        }
    };
    let target = parse_url(text_field("url")?.ok_or("it has no \"url\"")?.trim())?;
    let authorization = text_field("authorization")?.map(authorization_value).transpose()?;
    let event = text_field("event")?.unwrap_or(DEFAULT_EVENT).to_string();
    if event.is_empty() || event.len() > 64 || !event.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) {
        return Err("\"event\" must be letters, digits and . _ - (up to 64)".into());
    }
    let agent = match text_field("agent")? {
        None | Some("generic") => AgentKind::Generic,
        Some("grok-bot") => AgentKind::GrokBot,
        Some(other) => return Err(format!("\"agent\" is {other:?}; use grok-bot or generic")),
    };
    if agent == AgentKind::GrokBot && authorization.is_none() {
        return Err("it has no \"authorization\", which a Grok Bot routine requires".into());
    }
    Ok(Webhook { target, authorization, event, agent })
}

impl Webhook {
    /// Load `webhook.json`, refusing a file other accounts can read. Errors never quote the key.
    pub fn load(path: &Path) -> Result<Webhook, String> {
        let shown = path.display();
        match crate::crypto::private_file_problem(path) {
            Ok(None) => {}
            Ok(Some(problem)) => return Err(format!("webhook config {shown} {problem}. It holds a secret; make it private to this user")),
            Err(e) => {
                return Err(format!(
                    "cannot read webhook config {shown}: {e}. Create it, private to this user, with {{\"url\": \"https://...\", \"authorization\": \"Bearer ...\"}}, or use the queue backend, which wakes nothing"
                ))
            }
        }
        let text = std::fs::read(path).map_err(|e| format!("cannot read webhook config {shown}: {e}"))?;
        parse_config(&text).map_err(|why| format!("webhook config {shown}: {why}"))
    }

    pub fn host(&self) -> &str {
        &self.target.host
    }

    /// The forms of the key a reply must never contain.
    pub fn secret_forms(&self) -> Vec<String> {
        let Some(value) = &self.authorization else { return vec![] };
        let mut forms = vec![value.clone()];
        if let Some((_, key)) = value.split_once(' ') {
            forms.push(key.trim().to_string());
        }
        forms
    }

    /// Whether a connection can be made, and verified if it is HTTPS. Nothing is sent, so no run starts.
    pub async fn reachable(&self) -> bool {
        let check = async {
            let stream = tokio::net::TcpStream::connect((self.target.host.as_str(), self.target.port)).await.map_err(|_| ())?;
            if self.target.tls {
                self.connect_tls(stream).await.map(|_| ())
            } else {
                Ok(())
            }
        };
        matches!(tokio::time::timeout(ATTEMPT_TIMEOUT, check).await, Ok(Ok(())))
    }

    /// POST `{event, id, ts}`, retrying only what might work a moment later.
    pub async fn wake(&self, id: &str) -> Result<(), WakeFailure> {
        let body = object([("event", Value::str(self.event.clone())), ("id", Value::str(id)), ("ts", Value::str(crate::isotime::now_iso()))]);
        let body = pyjson::response(&body).expect("strings only");
        let mut delays = RETRY_DELAYS.iter();
        loop {
            let failure = match tokio::time::timeout(ATTEMPT_TIMEOUT, self.attempt(body.clone())).await {
                Ok(Ok(status)) if (200..300).contains(&status) => return Ok(()),
                Ok(Ok(status)) if status < 500 => return Err(WakeFailure::Refused(status)),
                Ok(Ok(status)) => WakeFailure::Refused(status),
                _ => WakeFailure::Unreachable,
            };
            match delays.next() {
                Some(delay) => tokio::time::sleep(*delay).await,
                None => return Err(failure),
            }
        }
    }

    async fn attempt(&self, body: String) -> Result<u16, ()> {
        let stream = tokio::net::TcpStream::connect((self.target.host.as_str(), self.target.port)).await.map_err(|_| ())?;
        if self.target.tls {
            self.over_tls(stream, body).await
        } else {
            self.exchange(stream, body).await
        }
    }

    #[cfg(feature = "tls")]
    async fn over_tls(&self, stream: tokio::net::TcpStream, body: String) -> Result<u16, ()> {
        let stream = self.connect_tls(stream).await?;
        self.exchange(stream, body).await
    }

    #[cfg(feature = "tls")]
    async fn connect_tls(&self, stream: tokio::net::TcpStream) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, ()> {
        tls_stream(&self.target.host, stream).await
    }

    #[cfg(not(feature = "tls"))]
    async fn over_tls(&self, _stream: tokio::net::TcpStream, _body: String) -> Result<u16, ()> {
        Err(())
    }

    #[cfg(not(feature = "tls"))]
    async fn connect_tls(&self, _stream: tokio::net::TcpStream) -> Result<(), ()> {
        Err(())
    }

    async fn exchange<S>(&self, stream: S, body: String) -> Result<u16, ()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|_| ())?;
        tokio::spawn(connection);
        let mut request = hyper::Request::post(self.target.path.as_str())
            .header("host", self.target.host_header.as_str())
            .header("content-type", "application/json")
            .header("user-agent", concat!("eureka-daemon/", env!("CARGO_PKG_VERSION")));
        if let Some(value) = &self.authorization {
            let mut value = hyper::header::HeaderValue::from_str(value).map_err(|_| ())?;
            value.set_sensitive(true);
            request = request.header("authorization", value);
        }
        let request = request.body(Full::new(Bytes::from(body))).map_err(|_| ())?;
        let response = sender.send_request(request).await.map_err(|_| ())?;
        Ok(response.status().as_u16())
    }
}

#[cfg(feature = "tls")]
pub(crate) async fn tls_stream(host: &str, stream: tokio::net::TcpStream) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, ()> {
    use tokio_rustls::rustls;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| ())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|_| ())?;
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(config)).connect(name, stream).await.map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(text: &str) -> Result<Webhook, String> {
        parse_config(text.as_bytes())
    }

    #[test]
    fn only_https_or_literal_loopback_http_is_a_webhook() {
        #[cfg(feature = "tls")]
        {
            let t = parse_url("https://hooks.example.com/a/b?c=d").unwrap();
            assert_eq!((t.tls, t.host.as_str(), t.port, t.host_header.as_str(), t.path.as_str()), (true, "hooks.example.com", 443, "hooks.example.com", "/a/b?c=d"));
            assert_eq!(parse_url("https://h.example:8443").unwrap().path, "/");
            assert_eq!(parse_url("https://h.example?x=1").unwrap().path, "/?x=1");
        }
        #[cfg(not(feature = "tls"))]
        assert!(parse_url("https://hooks.example.com/").unwrap_err().contains("no HTTPS"));
        let local = parse_url("http://127.0.0.1:9000/wake").unwrap();
        assert_eq!((local.tls, local.port, local.path.as_str()), (false, 9000, "/wake"));
        assert!(parse_url("http://[::1]:9000/").is_ok());
        for bad in ["http://hooks.example.com/", "http://localhost:9000/", "http://192.168.0.5/", "ftp://x/", "hooks.example.com",
                    "https://user:pw@h.example/", "https:///x", "https://h.example:port/", "https://h example/", "https://h.example/#f"] {
            assert!(parse_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_key_is_accepted_however_it_was_copied() {
        for raw in ["abc123", "Bearer abc123", "Authorization: Bearer abc123", " authorization:Bearer abc123 "] {
            assert_eq!(authorization_value(raw).unwrap(), "Bearer abc123", "{raw}");
        }
        assert_eq!(authorization_value("Basic dXNlcg==").unwrap(), "Basic dXNlcg==");
        assert!(authorization_value("  ").is_err());
        let refused = authorization_value("Bearer sec\nret").unwrap_err();
        assert!(!refused.contains("sec"), "{refused}");
    }

    #[test]
    fn a_config_is_checked_and_its_errors_never_quote_the_key() {
        let hook = config(r#"{"url": "http://127.0.0.1:9/w", "authorization": "Bearer topsecret", "agent": "grok-bot"}"#).unwrap();
        assert_eq!(hook.agent, AgentKind::GrokBot);
        assert_eq!(hook.event, "eureka_room_turn");
        assert_eq!(hook.secret_forms(), ["Bearer topsecret", "topsecret"]);
        assert!(config(r#"{"url": "http://127.0.0.1:9/w"}"#).unwrap().secret_forms().is_empty());
        for (bad, words) in [
            (r#"{"authorization": "k"}"#, "no \"url\""),
            (r#"{"url": "http://127.0.0.1:9/", "secret": "k"}"#, "unknown field"),
            (r#"{"url": "http://127.0.0.1:9/", "agent": "grok"}"#, "use grok-bot or generic"),
            (r#"{"url": "http://127.0.0.1:9/", "agent": "grok-bot"}"#, "requires"),
            (r#"{"url": "http://127.0.0.1:9/", "event": "a b"}"#, "event"),
            (r#"{"url": "http://example.com/", "authorization": "topsecret"}"#, "must use https"),
            ("not json topsecret", "not valid JSON"),
        ] {
            let why = config(bad).err().unwrap_or_else(|| panic!("{bad}"));
            assert!(why.contains(words), "{why}");
            assert!(!why.contains("topsecret"), "{why}");
        }
    }
}
