//! Argument-safe process execution. No shell, cleared environment, fixed PATH,
//! timeouts, and stderr redaction before anything is logged or returned.

use alizy_core::sysprobe::{find_exe, SAFE_PATH};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

const TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("required program `{0}` is not installed")]
    NotFound(String),
    #[error("`{cmd}` failed: {stderr}")]
    Failed {
        cmd: String,
        stderr: String,
        code: Option<i32>,
    },
    #[error("`{0}` timed out")]
    Timeout(String),
    #[error("could not run `{cmd}`: {err}")]
    Spawn { cmd: String, err: String },
}

impl ExecError {
    pub fn stderr_contains(&self, needle: &str) -> bool {
        matches!(self, ExecError::Failed { stderr, .. } if stderr.contains(needle))
    }
}

/// Short description safe for logs: program + first two args (never stdin).
fn describe(argv: &[String]) -> String {
    argv.iter().take(3).cloned().collect::<Vec<_>>().join(" ")
}

pub async fn run(argv: &[String], stdin: Option<&[u8]>) -> Result<String, ExecError> {
    let (prog, args) = argv.split_first().expect("argv must not be empty");
    let path = find_exe(prog).ok_or_else(|| ExecError::NotFound(prog.clone()))?;
    let mut cmd = Command::new(path);
    cmd.args(args)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .env("LC_ALL", "C")
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let desc = describe(argv);
    let mut child = cmd.spawn().map_err(|e| ExecError::Spawn {
        cmd: desc.clone(),
        err: e.to_string(),
    })?;
    if let Some(data) = stdin {
        let mut si = child.stdin.take().expect("stdin piped");
        si.write_all(data).await.map_err(|e| ExecError::Spawn {
            cmd: desc.clone(),
            err: e.to_string(),
        })?;
        drop(si);
    }
    let out = tokio::time::timeout(TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| ExecError::Timeout(desc.clone()))?
        .map_err(|e| ExecError::Spawn {
            cmd: desc.clone(),
            err: e.to_string(),
        })?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        let stderr = alizy_core::redact_keys(String::from_utf8_lossy(&out.stderr).trim());
        Err(ExecError::Failed {
            cmd: desc,
            stderr: stderr.chars().take(500).collect(),
            code: out.status.code(),
        })
    }
}

pub fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}
