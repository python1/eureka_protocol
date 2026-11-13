// SPDX-License-Identifier: AGPL-3.0-only
//! A fresh Codex CLI conversation for each authenticated room turn.
use crate::{crypto, handlers, pyjson, turns};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const TIMEOUT_SECS: u64 = 120;
pub const VERSION: &str = "0.166.0-alpha.5.1";
pub const BIN: &str = "EUREKA_CODEX_BIN";
pub const HOME: &str = "EUREKA_CODEX_SEAT_HOME";

pub struct CodexSeat {
    pub program: PathBuf,
    pub home: PathBuf,
}

impl CodexSeat {
    pub fn new(program: &Path, home: &Path) -> Result<Self, String> {
        handlers::refuse_on_native_windows("codex")?;
        let program = program
            .canonicalize()
            .map_err(|_| "Codex executable missing; run setup again")?;
        let home = home
            .canonicalize()
            .map_err(|_| "Codex seat folder missing; run setup again")?;
        for dir in [home.clone(), home.join("auth"), home.join("room")] {
            if let Some(problem) = turns::dir_problem(&dir) {
                return Err(problem);
            }
        }
        if home
            .join("room")
            .read_dir()
            .map_err(|e| e.to_string())?
            .next()
            .is_some()
        {
            return Err("Codex seat needs an empty room directory".into());
        }
        Ok(Self { program, home })
    }

    pub fn environment(&self) -> Vec<(String, String)> {
        let mut env: Vec<_> = [
            "PATH",
            "LANG",
            "LC_ALL",
            "TMPDIR",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        ]
        .into_iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| (k.into(), v)))
        .collect();
        env.push(("HOME".into(), self.home.display().to_string()));
        env.push((
            "CODEX_HOME".into(),
            self.home.join("auth").display().to_string(),
        ));
        env
    }

    fn diagnostic(&self, args: &[&str]) -> Result<std::process::Output, String> {
        let child = Command::new(&self.program)
            .args(args)
            .env_clear()
            .envs(self.environment())
            .current_dir(self.home.join("room"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        let pid = child.id() as i32;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(child.wait_with_output());
        });
        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(output) => output.map_err(|e| e.to_string()),
            Err(_) => {
                crate::handlers::kill_process(pid);
                Err("Codex diagnostic did not answer within five seconds".into())
            }
        }
    }

    pub fn check_version(&self) -> Result<(), String> {
        let output = self.diagnostic(&["--version"]).map_err(|_| {
            format!("Cannot run Codex CLI --version. Install the supported build {VERSION}.")
        })?;
        let shown = std::str::from_utf8(&output.stdout).unwrap_or("").trim();
        if output.status.success() && shown == format!("codex-cli {VERSION}") {
            return Ok(());
        }
        let shown: String = shown
            .chars()
            .filter(|c| c.is_ascii_graphic() || *c == ' ')
            .take(80)
            .collect();
        Err(format!("Unsupported or unknown Codex CLI version ({shown:?}). Install exactly {VERSION} or set EUREKA_CODEX_BIN and rerun setup."))
    }

    pub fn check_login(&self) -> Result<(), String> {
        self.check_version()?;
        if !cfg!(feature = "tls") {
            return Err("Codex requires a daemon built with HTTPS support.".into());
        }
        let status = self.diagnostic(&[
            "-c",
            r#"cli_auth_credentials_store="file""#,
            "login",
            "status",
        ])?;
        let chatgpt_login = [&status.stdout, &status.stderr].iter().any(|out| {
            String::from_utf8_lossy(out)
                .lines()
                .any(|line| line.trim().eq_ignore_ascii_case("Logged in using ChatGPT"))
        });
        if status.status.success() && chatgpt_login {
            Ok(())
        } else {
            Err("Sign in using ChatGPT with the seat-specific HOME and CODEX_HOME printed during setup.".into())
        }
    }
}

pub fn prepare(home: &Path) -> Result<(), String> {
    for dir in [home.to_owned(), home.join("auth"), home.join("room")] {
        crypto::create_private_dir(&dir).map_err(|e| e.to_string())?;
        if let Some(problem) = turns::dir_problem(&dir) {
            return Err(problem);
        }
    }
    Ok(())
}

pub fn args(base: &str) -> Vec<String> {
    let mut args: Vec<String> = [
        "-a",
        "never",
        "exec",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "--skip-git-repo-check",
        "--json",
        "-c",
        "default_permissions=\"eureka-room\"",
        "-c",
        "permissions.eureka-room.filesystem={\":root\"=\"deny\",\":minimal\"=\"read\"}",
        "-c",
        "permissions.eureka-room.network.enabled=false",
        "-c",
        "web_search=\"disabled\"",
        "-c",
        "project_doc_max_bytes=0",
        "--disable",
        "shell_tool",
        "--disable",
        "unified_exec",
        "--disable",
        "multi_agent",
        "--disable",
        "apps",
        "--disable",
        "hooks",
        "--disable",
        "in_app_browser",
        "--disable",
        "view_image",
        "--disable",
        "goals",
        "--disable",
        "browser_use",
        "--disable",
        "computer_use",
        "--disable",
        "plugins",
        "--disable",
        "image_generation",
        "-c",
        "tools.experimental_request_user_input.enabled=false",
        "-c",
        "cli_auth_credentials_store=\"file\"",
        "-c",
        "features.enable_request_compression=false",
        "-c",
        "model_provider=\"eureka\"",
    ]
    .map(str::to_owned)
    .into();
    args.extend(["-c".into(), format!(r#"model_providers.eureka={{name="Eureka",base_url="{base}",wire_api="responses",requires_openai_auth=true,supports_websockets=false,request_max_retries=0,stream_max_retries=0,env_http_headers={{x-eureka-turn="EUREKA_CODEX_TURN_SECRET"}}}}"#), "-".into()]);
    args
}

/// Accept only a completed turn with an assistant message, never CLI logs or tool output.
pub fn reply(out: &[u8]) -> Option<String> {
    let mut last = None;
    let mut completed = false;
    let mut started = false;
    for line in std::str::from_utf8(out)
        .ok()?
        .lines()
        .filter(|s| !s.is_empty())
    {
        let value = pyjson::loads(line.as_bytes()).ok()?;
        let event = value.as_object()?;
        if completed {
            return None;
        }
        match event.get("type")?.as_str()? {
            "thread.started" if !started => (),
            "turn.started" if !started => started = true,
            "item.started" | "item.completed" => {
                let item = event.get("item")?.as_object()?;
                match item.get("type")?.as_str()? {
                    "error" if !started => (), // CLI startup diagnostics, excluded from the reply.
                    "agent_message"
                        if started && event["type"].as_str() == Some("item.completed") =>
                    {
                        last = Some(item.get("text")?.as_str()?.to_owned());
                    }
                    "agent_message" | "reasoning" => (),
                    _ => return None,
                }
            }
            "turn.completed" if started => completed = true,
            _ => return None,
        }
    }
    last.filter(|text| completed && !text.trim().is_empty())
}
