//! Client for alizyd's Unix-socket protocol. One connection per request keeps
//! the client stateless; requests carrying keys are zeroized after sending.

use alizy_core::ipc::{Command, IpcError, Payload, Request, Response, MAX_MESSAGE_BYTES, SOCKET_PATH};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub struct DaemonClient {
    path: String,
}

impl Default for DaemonClient {
    fn default() -> Self {
        Self {
            path: std::env::var("ALIZY_SOCKET").unwrap_or_else(|_| SOCKET_PATH.to_string()),
        }
    }
}

fn explain_connect_error(e: &std::io::Error, path: &str) -> String {
    match e.kind() {
        std::io::ErrorKind::NotFound => format!(
            "The Alizy service (alizyd) is not running: {path} does not exist. Start it with `sudo systemctl enable --now alizyd`."
        ),
        std::io::ErrorKind::PermissionDenied => format!(
            "Permission denied on {path}. Your session is not in the `alizy` group yet: add it with `sudo usermod -aG alizy $USER`, then reboot (logging out is not enough if your systemd user manager lingers)."
        ),
        std::io::ErrorKind::ConnectionRefused => "The Alizy service is not accepting connections (it may be restarting).".into(),
        _ => format!("Cannot reach the Alizy service: {e}"),
    }
}

/// Why a daemon call failed: an error the daemon returned (with its code and
/// optional host key), or a local transport problem.
#[derive(Debug, Clone)]
pub enum CallError {
    Ipc(IpcError),
    Local(String),
}

impl CallError {
    pub fn into_message(self) -> String {
        match self {
            Self::Ipc(e) => e.message,
            Self::Local(m) => m,
        }
    }
}

impl DaemonClient {
    pub async fn call(&self, command: Command, timeout: Duration) -> Result<Payload, String> {
        self.call_ipc(command, timeout).await.map_err(CallError::into_message)
    }

    /// Like [`call`](Self::call) but keeps the daemon's structured error.
    pub async fn call_ipc(&self, command: Command, timeout: Duration) -> Result<Payload, CallError> {
        use CallError::Local;
        let fut = async {
            let mut s = UnixStream::connect(&self.path)
                .await
                .map_err(|e| Local(explain_connect_error(&e, &self.path)))?;
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let mut line =
                Zeroizing::new(serde_json::to_vec(&Request { id, command }).map_err(|e| Local(e.to_string()))?);
            line.push(b'\n');
            s.write_all(&line).await.map_err(|e| Local(e.to_string()))?;
            drop(line);
            let mut reader = BufReader::new(s);
            let mut buf = Vec::new();
            (&mut reader)
                .take(MAX_MESSAGE_BYTES as u64 * 8)
                .read_until(b'\n', &mut buf)
                .await
                .map_err(|e| Local(e.to_string()))?;
            if buf.is_empty() {
                return Err(Local(
                    "the service closed the connection (permission denied or protocol error)".to_string(),
                ));
            }
            let resp: Response =
                serde_json::from_slice(&buf).map_err(|e| Local(format!("invalid response from service: {e}")))?;
            if resp.id != id && resp.id != 0 {
                return Err(Local("mismatched response from service".into()));
            }
            resp.result.map_err(CallError::Ipc)
        };
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| Local("the Alizy service did not respond in time".to_string()))?
    }

    pub async fn quick(&self, command: Command) -> Result<Payload, String> {
        self.call(command, Duration::from_secs(8)).await
    }
}
