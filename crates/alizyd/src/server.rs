//! Unix-socket IPC server: newline-delimited JSON, bounded message size,
//! per-peer authorisation, explicit command dispatch (no generic execution).

use crate::auth::{is_privileged, Authorizer, Peer};
use crate::engine::Engine;
use alizy_core::ipc::{Command, ErrorCode, IpcError, Payload, Request, Response, MAX_MESSAGE_BYTES, PROTOCOL_VERSION};
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroizing;

pub fn bind(path: &Path, auth: &Authorizer) -> std::io::Result<UnixListener> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    if let Some(gid) = auth.group() {
        nix::unistd::chown(path, Some(nix::unistd::Uid::from_raw(0)), Some(gid)).map_err(std::io::Error::from)?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(auth.socket_mode()))?;
    Ok(listener)
}

/// Connection limits (DoS resistance against local clients).
const MAX_CLIENTS: usize = 64;
const MAX_CLIENTS_PER_UID: usize = 16;
/// A client must send each request within this time.
const READ_TIMEOUT: Duration = Duration::from_secs(60);

static PER_UID: Mutex<Option<HashMap<u32, usize>>> = Mutex::new(None);

struct UidSlot(u32);
impl UidSlot {
    fn acquire(uid: u32) -> Option<Self> {
        let mut g = PER_UID.lock().unwrap();
        let m = g.get_or_insert_with(HashMap::new);
        let n = m.entry(uid).or_insert(0);
        if *n >= MAX_CLIENTS_PER_UID {
            return None;
        }
        *n += 1;
        Some(UidSlot(uid))
    }
}
impl Drop for UidSlot {
    fn drop(&mut self) {
        if let Some(m) = PER_UID.lock().unwrap().as_mut() {
            if let Some(n) = m.get_mut(&self.0) {
                *n = n.saturating_sub(1);
            }
        }
    }
}

pub async fn serve(listener: UnixListener, engine: Arc<Engine>, auth: Arc<Authorizer>) {
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CLIENTS));
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    tracing::warn!("too many IPC clients; dropping connection");
                    continue;
                };
                let engine = engine.clone();
                let auth = auth.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle(stream, engine, auth).await {
                        tracing::debug!("client session ended: {e}");
                    }
                });
            }
            Err(e) => {
                tracing::error!("accept failed: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
    }
}

async fn handle(stream: UnixStream, engine: Arc<Engine>, auth: Arc<Authorizer>) -> std::io::Result<()> {
    let cred = stream.peer_cred()?;
    let peer = Peer::from_cred(cred.uid(), cred.gid(), cred.pid());
    if let Err(e) = auth.admit(&peer) {
        tracing::warn!(uid = peer.uid, "rejected IPC peer: {e}");
        return Ok(());
    }
    let Some(_uid_slot) = UidSlot::acquire(peer.uid) else {
        tracing::warn!(uid = peer.uid, "too many connections from this user; dropping");
        return Ok(());
    };
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);
    loop {
        let mut buf = Zeroizing::new(Vec::with_capacity(1024));
        let mut limited = (&mut reader).take(MAX_MESSAGE_BYTES as u64 + 1);
        let Ok(n) = tokio::time::timeout(READ_TIMEOUT, limited.read_until(b'\n', &mut buf)).await else {
            return Ok(()); // idle client
        };
        let n = n?;
        if n == 0 {
            return Ok(());
        }
        if buf.len() > MAX_MESSAGE_BYTES {
            let resp = Response {
                id: 0,
                result: Err(IpcError::new(ErrorCode::BadRequest, "message too large")),
            };
            write(&mut wr, &resp).await?;
            return Ok(());
        }
        let req: Request = match serde_json::from_slice(&buf) {
            Ok(r) => r,
            Err(_) => {
                let resp = Response {
                    id: 0,
                    result: Err(IpcError::new(ErrorCode::BadRequest, "malformed request")),
                };
                write(&mut wr, &resp).await?;
                continue;
            }
        };
        let id = req.id;
        // Authorise every privileged request (no caching across requests).
        if is_privileged(&req.command) {
            match auth.authorize_mutation(&peer).await {
                Ok(()) => {}
                Err(e) => {
                    write(
                        &mut wr,
                        &Response {
                            id,
                            result: Err(IpcError::new(ErrorCode::Unauthorized, e)),
                        },
                    )
                    .await?;
                    continue;
                }
            }
        }
        let result = dispatch(&engine, req.command).await;
        write(&mut wr, &Response { id, result }).await?;
    }
}

async fn dispatch(engine: &Engine, cmd: Command) -> Result<Payload, IpcError> {
    Ok(match cmd {
        Command::Hello { protocol } => {
            if protocol != PROTOCOL_VERSION {
                return Err(IpcError::new(
                    ErrorCode::Unsupported,
                    format!("protocol {protocol} not supported (daemon speaks {PROTOCOL_VERSION})"),
                ));
            }
            Payload::Hello {
                protocol: PROTOCOL_VERSION,
                version: env!("CARGO_PKG_VERSION").into(),
            }
        }
        Command::GetStatus => Payload::Status(Box::new(engine.status())),
        Command::Connect { spec } => {
            engine.connect(*spec).await?;
            Payload::Ok
        }
        Command::Disconnect => {
            engine.disconnect().await?;
            Payload::Ok
        }
        Command::GetPolicy => Payload::Policy(engine.policy().await),
        Command::SetPolicy { policy } => {
            engine.set_policy(policy).await?;
            Payload::Ok
        }
        Command::VerifyFirewall => {
            let (verified, tag) = engine.verify_firewall().await;
            Payload::Firewall { verified, tag }
        }
        Command::GetEvents { since } => Payload::Events(engine.events.since(since)),
        Command::GetSystemReport => Payload::System(Box::new(engine.system_report().await?)),
        Command::SetSplit { config } => {
            engine.set_split(config).await?;
            Payload::Ok
        }
        Command::GetSplitStatus => Payload::Split(Box::new(engine.split_status().await)),
        Command::TestRoute { query } => {
            if query.len() > 255 {
                return Err(IpcError::new(ErrorCode::BadRequest, "query too long"));
            }
            Payload::RouteTest(Box::new(engine.test_route(&query).await))
        }
    })
}

async fn write(wr: &mut tokio::net::unix::OwnedWriteHalf, resp: &Response) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(resp).map_err(std::io::Error::other)?;
    line.push(b'\n');
    wr.write_all(&line).await
}
