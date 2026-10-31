//! eureka-daemon: the Eureka Protocol daemon as one self-contained binary.
//!
//! A drop-in for `python -m eureka_protocol.src.eureka_daemon.server`: the same
//! command line, environment, identity and trust files, wire protocol and
//! answers. See rust/README.md for what is and is not in this build.

mod crypto;
mod handlers;
mod http;
mod isotime;
mod node;
mod pyjson;
mod trust;
#[cfg(test)]
mod differential;
#[cfg(test)]
mod vectors;

use std::net::IpAddr;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;

const DEFAULT_HOST: &str = "127.0.0.1";
const ORIGINS_ENV: &str = "EUREKA_CORS_ORIGINS";

const USAGE: &str = "usage: eureka-daemon [-h] [--tls-port TLS_PORT] [--no-plain] [--tls] [--tls-dir TLS_DIR] [--host HOST] [--cors-origin ORIGIN] [port]";

const HELP: &str = "Eureka Protocol daemon

positional arguments:
  port                  plaintext port (default 8000)

options:
  -h, --help            show this help message and exit
  --tls-port TLS_PORT   also serve TLS on this port (not in this build; use the Python daemon)
  --no-plain            do not serve plaintext (requires --tls-port)
  --tls                 serve TLS on the main port and nothing else
  --tls-dir TLS_DIR     where to write the certificate and key
  --host HOST           address every listener binds (default 127.0.0.1, this machine only);
                        pass 0.0.0.0 or a LAN address to accept peers on the network
  --cors-origin ORIGIN  let a web page at this exact origin read replies
                        (e.g. https://knights-circle.vercel.app); repeatable, also read from
                        EUREKA_CORS_ORIGINS. Grants nothing: every request is still authenticated

environment:
  EUREKA_IDENTITY_PATH, EUREKA_TRUST_PATH, EUREKA_CORS_ORIGINS,
  EUREKA_ROOM_TURN, EUREKA_ROOM_TURN_MODEL, EUREKA_INFERENCE,
  EUREKA_ROOM_TURN_BACKEND (ollama | openclaw), EUREKA_OPENCLAW_BIN,
  EUREKA_OPENCLAW_SESSION, EUREKA_OPENCLAW_TIMEOUT, EUREKA_OLLAMA_URL

trust file:
  eureka-daemon trust add NAME PUBLIC_KEY [CAPABILITY ...]
  eureka-daemon trust list";

struct Arguments {
    port: u16,
    host: String,
    cors_origins: Vec<String>,
}

fn usage_error(message: &str) -> ! {
    eprintln!("{USAGE}\neureka-daemon: error: {message}");
    std::process::exit(2);
}

fn is_loopback_host(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(IpAddr::V6(v6)) => v6.to_ipv4_mapped().map(|v4| v4.is_loopback()).unwrap_or(v6.is_loopback()),
        Err(_) => false,
    }
}

/// cors.normalise_origin: one exact origin, in the form a browser sends it.
fn normalise_origin(value: &str) -> Result<String, String> {
    let text = value.trim();
    let shown = format!("'{value}'");
    if text.is_empty() || text.contains('*') {
        return Err(format!("CORS origin {shown}: give one exact origin, no wildcards"));
    }
    let not_origin = || Err(format!("CORS origin {shown} must look like https://host"));
    let Some((scheme, rest)) = text.split_once(':') else { return not_origin() };
    let scheme = scheme.to_lowercase();
    if !["https", "http"].contains(&scheme.as_str()) {
        return not_origin();
    }
    let Some(rest) = rest.strip_prefix("//") else { return not_origin() };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (netloc, tail) = rest.split_at(end);
    if !(tail.is_empty() || tail == "/") || netloc.contains('@') {
        return Err(format!("CORS origin {shown} is an origin, not a URL: drop the path"));
    }
    let (host, port) = if let Some(v6) = netloc.strip_prefix('[') {
        let Some((h, after)) = v6.split_once(']') else { return not_origin() };
        (h.to_string(), after.strip_prefix(':'))
    } else {
        match netloc.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p)),
            None => (netloc.to_string(), None),
        }
    };
    let host = host.to_lowercase();
    if host.is_empty() {
        return not_origin();
    }
    let port = match port {
        None | Some("") => None,
        Some(p) => match p.parse::<u32>() {
            Ok(n) if n <= 65535 && p.bytes().all(|b| b.is_ascii_digit()) => Some(n),
            _ => return Err(format!("Port could not be cast to integer value as '{p}'")),
        },
    };
    if scheme == "http" && !is_loopback_host(&host) {
        return Err(format!("CORS origin {shown}: plain http is only allowed for a page on loopback"));
    }
    let shown_host = if host.contains(':') { format!("[{host}]") } else { host };
    let default = if scheme == "https" { 443 } else { 80 };
    Ok(match port {
        Some(p) if p != 0 && p != default => format!("{scheme}://{shown_host}:{p}"),
        _ => format!("{scheme}://{shown_host}"),
    })
}

/// The command line, as argparse reads server.py's: `--opt value`, `--opt=value`, unambiguous prefixes.
fn parse_arguments() -> Arguments {
    const OPTIONS: [(&str, bool); 7] = [
        ("--tls-port", true),
        ("--no-plain", false),
        ("--tls", false),
        ("--tls-dir", true),
        ("--host", true),
        ("--cors-origin", true),
        ("--help", false),
    ];
    let mut args = std::env::args().skip(1);
    let (mut port, mut host, mut origins, mut tls) = (None::<String>, DEFAULT_HOST.to_string(), Vec::new(), false);
    while let Some(arg) = args.next() {
        if arg == "-h" {
            println!("{USAGE}\n\n{HELP}");
            std::process::exit(0);
        }
        if arg.starts_with("--") {
            let (name, inline) = match arg.split_once('=') {
                Some((n, v)) => (n.to_string(), Some(v.to_string())),
                None => (arg.clone(), None),
            };
            let exact = OPTIONS.iter().find(|(o, _)| *o == name);
            let matches: Vec<_> = OPTIONS.iter().filter(|(o, _)| o.starts_with(name.as_str())).collect();
            let (option, takes_value) = match (exact, matches.as_slice()) {
                (Some(o), _) => *o,
                (None, [one]) => **one,
                (None, []) => usage_error(&format!("unrecognized arguments: {arg}")),
                (None, many) => usage_error(&format!(
                    "ambiguous option: {name} could match {}",
                    many.iter().map(|(o, _)| *o).collect::<Vec<_>>().join(", ")
                )),
            };
            let value = if takes_value {
                Some(inline.or_else(|| args.next()).unwrap_or_else(|| usage_error(&format!("argument {option}: expected one argument"))))
            } else {
                if inline.is_some() {
                    usage_error(&format!("argument {option}: ignored explicit argument"));
                }
                None
            };
            match option {
                "--help" => {
                    println!("{USAGE}\n\n{HELP}");
                    std::process::exit(0);
                }
                "--host" => host = value.unwrap(),
                "--cors-origin" => origins.push(value.unwrap()),
                _ => tls = true,
            }
        } else if port.is_none() {
            port = Some(arg);
        } else {
            usage_error(&format!("unrecognized arguments: {arg}"));
        }
    }
    if tls {
        usage_error("TLS listeners (--tls, --tls-port, --tls-dir, --no-plain) are not in the Rust build yet; serve plaintext on loopback, or use the Python daemon for TLS");
    }
    let port = match port {
        None => 8000,
        Some(p) => match p.trim().parse::<u16>() {
            Ok(n) => n,
            Err(_) => usage_error(&format!("argument port: invalid int value: '{p}'")),
        },
    };
    if host.trim().is_empty() {
        usage_error("--host needs an address; leave it out for loopback");
    }
    let env_origins = std::env::var(ORIGINS_ENV).unwrap_or_default();
    let mut cors_origins = Vec::new();
    for value in origins.iter().map(String::as_str).chain(env_origins.split(',').filter(|v| !v.trim().is_empty())) {
        match normalise_origin(value) {
            Ok(origin) if !cors_origins.contains(&origin) => cors_origins.push(origin),
            Ok(_) => {}
            Err(e) => usage_error(&e),
        }
    }
    Arguments { port, host, cors_origins }
}

const TRUST_USAGE: &str = "usage: eureka-daemon trust add NAME PUBLIC_KEY [CAPABILITY ...]
       eureka-daemon trust list

Edits the trust file (EUREKA_TRUST_PATH, default ~/.eureka/trust.json) the way
the Python TrustList.add + to_document does. For a Knights Circle room key:

  eureka-daemon trust add knights-circle-node_xxxxxxxx <room key> room-turn

Restart the daemon afterwards: it reads the file at startup.";

/// Every capability either build knows, so editing the file never rejects a grant the other build serves.
const KNOWN_CAPABILITIES: [&str; 3] = ["room-turn", "inference", "web-retrieval"];

fn trust_command(args: &[String]) -> ExitCode {
    let path = trust::resolve_trust_path();
    let known: Vec<String> = KNOWN_CAPABILITIES.iter().map(|s| s.to_string()).collect();
    let fail = |e: &dyn std::fmt::Display| {
        eprintln!("eureka-daemon trust: {e}");
        ExitCode::from(1)
    };
    let mut list = match trust::TrustList::load_or_empty(&path, &known) {
        Ok((list, _)) => list,
        Err(e) => return fail(&e),
    };
    match args {
        [verb, name, key, caps @ ..] if verb == "add" => {
            if let Some(unknown) = caps.iter().find(|c| !KNOWN_CAPABILITIES.contains(&c.trim())) {
                return fail(&format!("unknown capability {unknown:?}; use room-turn, inference or web-retrieval"));
            }
            if let Err(e) = list.add_peer(name, key, caps) {
                return fail(&e);
            }
            if let Err(e) = list.save(&path) {
                return fail(&format!("cannot write {}: {e}", path.display()));
            }
            let granted = if caps.is_empty() { "nothing".to_string() } else { caps.join(", ") };
            println!("trusted {name} with {granted} in {}", path.display());
            ExitCode::SUCCESS
        }
        [verb] if verb == "list" => {
            println!("{} ({} trusted, {} revoked)", path.display(), list.len(), list.revoked_count());
            for (name, key, caps) in list.names() {
                println!("  {name}  {key}  {}", if caps.is_empty() { "-".to_string() } else { caps.join(",") });
            }
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{TRUST_USAGE}");
            ExitCode::from(2)
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.first().is_some_and(|a| a == "trust") {
        return trust_command(&raw[1..]);
    }
    let arguments = parse_arguments();

    let registry = match handlers::registry_from_environment() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("eureka-daemon: {e}");
            return ExitCode::from(1);
        }
    };
    let identity_path = crypto::resolve_identity_path();
    let identity = match crypto::Identity::load_or_create(&identity_path) {
        Ok(identity) => identity,
        Err(e) => {
            eprintln!("eureka-daemon: {e}");
            return ExitCode::from(1);
        }
    };
    let capabilities = registry.names();
    let trust_path = trust::resolve_trust_path();
    let trust = match trust::TrustList::load_or_empty(&trust_path, &capabilities) {
        Ok((trust, warnings)) => {
            for warning in warnings {
                println!("  note: {warning}");
            }
            trust
        }
        Err(e) => {
            eprintln!("eureka-daemon: {e}");
            return ExitCode::from(1);
        }
    };

    let listener = match tokio::net::TcpListener::bind((arguments.host.as_str(), arguments.port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("eureka-daemon: cannot listen on {}:{}: {e}", arguments.host, arguments.port);
            return ExitCode::from(1);
        }
    };
    let bound_port = listener.local_addr().map(|a| a.port()).unwrap_or(arguments.port);

    let node = node::Node::new(identity, capabilities.clone(), trust);
    println!("Starting Eureka Daemon API as {}", node.node_id);
    println!("  public key: {}", node.identity.public_key_hex);
    println!("  listening on http://{}:{}", arguments.host, bound_port);
    for origin in &arguments.cors_origins {
        println!("  browser pages allowed to read replies: {origin}");
    }
    println!("  offers: {}", if capabilities.is_empty() { "nothing".to_string() } else { capabilities.join(", ") });
    for line in registry.describe() {
        println!("  {line}");
    }
    println!("  trusted peers: {} ({} revoked) from {}", node.trust.len(), node.trust.revoked_count(), trust_path.display());

    let app = Arc::new(http::App { node: Mutex::new(node), registry, cors_origins: arguments.cors_origins });

    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal handler");
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                let app = app.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req| http::serve(app.clone(), req));
                    let _ = http1::Builder::new().serve_connection(TokioIo::new(stream), service).await;
                });
            }
            _ = tokio::signal::ctrl_c() => break,
            _ = terminate.recv() => break,
        }
    }
    println!("Shutting down");
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_are_exact_and_normalised() {
        assert_eq!(normalise_origin("https://Knights-Circle.vercel.app/").unwrap(), "https://knights-circle.vercel.app");
        assert_eq!(normalise_origin("https://x.example:443").unwrap(), "https://x.example");
        assert_eq!(normalise_origin("http://127.0.0.1:4173").unwrap(), "http://127.0.0.1:4173");
        assert_eq!(normalise_origin("http://[::1]:4173").unwrap(), "http://[::1]:4173");
        for bad in ["*", "https://*.vercel.app", "knights-circle.vercel.app", "http://example.com", "https://x.example/path", "ftp://x", "https://u@x.example", "https://x.example:99999"] {
            assert!(normalise_origin(bad).is_err(), "{bad}");
        }
    }
}
