//! SSH tunnel backend: an OpenSSH dynamic forward (`ssh -N -D`) carries TCP,
//! `badvpn-tun2socks` turns the `alizy0` TUN into SOCKS connections, and the
//! in-daemon DNS-over-SOCKS forwarder answers the system resolver.
//!
//! Privilege: `ssh`, `ssh-keyscan` and `badvpn-tun2socks` never run as root.
//! [`unprivileged_command`] spawns them as the `alizy-ssh` system user
//! (uid *and* primary gid; std drops supplementary groups and the child
//! verifies that before exec), with a cleared environment, the fixed
//! `SAFE_PATH`, `HOME` set to the runtime directory, stdin from /dev/null and
//! `PR_SET_PDEATHSIG=SIGKILL` so nothing outlives the daemon.
//!
//! Secrets: the password reaches ssh only through the one-shot askpass socket
//! (see `crate::askpass`). It is never in argv, the environment, a file or a
//! log line; the child environment (which holds the one-shot askpass token)
//! is never logged either.

use crate::askpass::AskpassServer;
use crate::exec::{argv, run};
use crate::socks_dns::{socks5_connect, DnsForwarder};
use alizy_core::ipc::{ErrorCode, TunnelStats};
use alizy_core::routing::{DnsPlan, RoutePlan, SSH_DNS_FORWARDER, SSH_NETIF_V4, SSH_NETIF_V6};
use alizy_core::ssh::{HostKey, SshConfig, SshPublic, DEFAULT_SSH_DNS};
use alizy_core::sysprobe::{find_exe, SAFE_PATH};
use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;

/// Runtime directory for known_hosts files and askpass sockets (0750 root:alizy-ssh).
pub const RUNTIME_DIR: &str = "/run/alizy/ssh";
/// System user that runs ssh, ssh-keyscan and tun2socks.
pub const SSH_USER: &str = "alizy-ssh";
pub const SSH_EXE: &str = "ssh";
pub const KEYSCAN_EXE: &str = "ssh-keyscan";
pub const TUN2SOCKS_EXE: &str = "badvpn-tun2socks";

/// The SSH connection must carry a SOCKS request within this time.
const READY_DEADLINE: Duration = Duration::from_secs(20);
const READY_POLL: Duration = Duration::from_millis(250);
/// One readiness probe (`socks5_connect` has no timeout of its own).
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const KEYSCAN_TIMEOUT: Duration = Duration::from_secs(20);
const STOP_GRACE: Duration = Duration::from_secs(3);
/// Bytes of child stderr kept for error classification.
const STDERR_CAP: usize = 8 * 1024;
const TUN_NETMASK_V4: &str = "255.255.255.252";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SshError {
    #[error("the SSH server's host key has changed (it now presents {}); refusing to connect", .0.fingerprint_sha256())]
    HostKeyChanged(HostKey),
    #[error("authentication failed: the SSH server rejected the username or password")]
    AuthFailed,
    #[error("{0}")]
    MissingDependency(String),
    #[error("{0}")]
    Other(String),
}

impl SshError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::HostKeyChanged(_) => ErrorCode::HostKeyChanged,
            Self::AuthFailed => ErrorCode::AuthFailed,
            Self::MissingDependency(_) => ErrorCode::MissingDependency,
            Self::Other(_) => ErrorCode::Tunnel,
        }
    }

    pub fn host_key(&self) -> Option<HostKey> {
        match self {
            Self::HostKeyChanged(k) => Some(k.clone()),
            _ => None,
        }
    }
}

/// What ssh's stderr says about why it exited. A changed key carries no key
/// material in stderr, so [`start`] fetches the new key with `ssh-keyscan`
/// to build [`SshError::HostKeyChanged`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StderrClass {
    HostKeyChanged,
    AuthFailed,
}

pub fn classify_ssh_stderr(stderr: &str) -> Option<StderrClass> {
    if stderr.contains("REMOTE HOST IDENTIFICATION HAS CHANGED") || stderr.contains("Host key verification failed") {
        Some(StderrClass::HostKeyChanged)
    } else if stderr.contains("Permission denied") {
        Some(StderrClass::AuthFailed)
    } else {
        None
    }
}

/// Last non-empty line (ssh's actual complaint), trimmed.
pub fn last_line(s: &str) -> &str {
    s.lines().map(str::trim).rfind(|l| !l.is_empty()).unwrap_or("")
}

/// Everything needed to bring an SSH tunnel up.
pub struct SshUp<'a> {
    pub iface: &'a str,
    pub cfg: &'a SshConfig,
    /// (uid, primary gid) of `alizy-ssh`.
    pub user: (u32, u32),
    pub runtime: &'a Path,
    /// Loopback port for `ssh -D`, chosen (and allowed in the firewall) by the engine.
    pub socks_port: u16,
    pub upstreams: Vec<IpAddr>,
    pub ipv6: bool,
    pub routes: &'a RoutePlan,
    pub dns: &'a DnsPlan,
}

/// Bounded tail of a child's stderr.
#[derive(Clone)]
pub struct TailBuf {
    cap: usize,
    buf: Arc<Mutex<VecDeque<u8>>>,
}

impl TailBuf {
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            buf: Arc::new(Mutex::new(VecDeque::with_capacity(cap))),
        }
    }

    pub fn push(&self, bytes: &[u8]) {
        let mut b = self.buf.lock().unwrap();
        b.extend(bytes);
        let excess = b.len().saturating_sub(self.cap);
        b.drain(..excess);
    }

    pub fn text(&self) -> String {
        let b = self.buf.lock().unwrap();
        String::from_utf8_lossy(&b.iter().copied().collect::<Vec<u8>>()).into_owned()
    }
}

fn capture(mut r: impl AsyncRead + Unpin + Send + 'static, buf: TailBuf) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut chunk = [0u8; 1024];
        while let Ok(n) = r.read(&mut chunk).await {
            if n == 0 {
                break;
            }
            buf.push(&chunk[..n]);
        }
    })
}

pub fn known_hosts_path(runtime: &Path, p: &SshPublic) -> PathBuf {
    runtime.join(format!("{}.known_hosts", alizy_core::ssh::fingerprint(p)))
}

/// Write the pinned key as `<runtime>/<id>.known_hosts`, mode 0640, group
/// `gid` (alizy-ssh can read it, not change it). The key is validated first so
/// nothing but a well-formed single line is ever written.
pub fn write_known_hosts(runtime: &Path, p: &SshPublic, gid: u32) -> Result<PathBuf, String> {
    let key = p.host_key.as_ref().ok_or("no host key is pinned for this server")?;
    key.validate()?;
    alizy_core::ssh::validate_public(p)?;
    let path = known_hosts_path(runtime, p);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{}: {e}", path.display())),
    }
    let write = || -> io::Result<()> {
        use std::io::Write;
        // create_new: never follows a planted symlink.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .open(&path)?;
        std::os::unix::fs::fchown(&f, None, Some(gid))?;
        f.set_permissions(std::fs::Permissions::from_mode(0o640))?;
        f.write_all(format!("{}\n", key.known_hosts_line(p.host, p.port)).as_bytes())?;
        f.sync_all()
    };
    write().map_err(|e| {
        let _ = std::fs::remove_file(&path);
        format!("{}: {e}", path.display())
    })?;
    Ok(path)
}

/// `ssh` arguments (program excluded). The destination is the literal IP from
/// the profile, the same address the firewall's TCP exception names.
pub fn ssh_argv(cfg: &SshConfig, socks_port: u16, runtime: &Path) -> Vec<String> {
    let p = &cfg.public;
    let kh = known_hosts_path(runtime, p);
    let mut v: Vec<String> = vec![
        "-N".into(),
        "-D".into(),
        format!("127.0.0.1:{socks_port}"),
        "-p".into(),
        p.port.to_string(),
        "-F".into(),
        "/dev/null".into(),
    ];
    for o in [
        "ExitOnForwardFailure=yes".to_string(),
        "ServerAliveInterval=15".into(),
        "ServerAliveCountMax=3".into(),
        "StrictHostKeyChecking=yes".into(),
        format!("UserKnownHostsFile={}", kh.display()),
        "GlobalKnownHostsFile=/dev/null".into(),
        "PubkeyAuthentication=no".into(),
        "PreferredAuthentications=password,keyboard-interactive".into(),
        "NumberOfPasswordPrompts=1".into(),
        "BatchMode=no".into(),
    ] {
        v.push("-o".into());
        v.push(o);
    }
    v.push("--".into());
    v.push(format!("{}@{}", p.username, p.host));
    v
}

pub fn tun2socks_argv(iface: &str, socks_port: u16, ipv6: bool) -> Vec<String> {
    let mut v = vec![
        "--tundev".to_string(),
        iface.into(),
        "--netif-ipaddr".into(),
        SSH_NETIF_V4.to_string(),
        "--netif-netmask".into(),
        TUN_NETMASK_V4.into(),
        "--socks-server-addr".into(),
        format!("127.0.0.1:{socks_port}"),
        "--loglevel".into(),
        "warning".into(),
    ];
    if ipv6 {
        v.push("--netif-ip6addr".into());
        v.push(SSH_NETIF_V6.to_string());
    }
    v
}

pub fn keyscan_argv(host: IpAddr, port: u16) -> Vec<String> {
    argv(&[
        "-T",
        "8",
        "-t",
        "ed25519,ecdsa,rsa",
        "-p",
        &port.to_string(),
        &host.to_string(),
    ])
}

/// First usable key from `ssh-keyscan` output, preferring ed25519 > ecdsa > rsa.
pub fn parse_keyscan(out: &str) -> Option<HostKey> {
    let rank = |t: &str| match t {
        "ssh-ed25519" => Some(0),
        t if t.starts_with("ecdsa-sha2-") => Some(1),
        "ssh-rsa" => Some(2),
        _ => None,
    };
    out.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let (_host, t, k) = (f.next()?, f.next()?, f.next()?);
            let key = HostKey {
                key_type: t.into(),
                key_b64: k.into(),
            };
            let r = rank(t)?;
            key.validate().ok()?;
            Some((r, key))
        })
        .min_by_key(|(r, _)| *r)
        .map(|(_, k)| k)
}

fn check_user(user: (u32, u32)) -> Result<(), String> {
    if user.0 == 0 || user.1 == 0 {
        return Err(format!("{SSH_USER} must not be root"));
    }
    Ok(())
}

/// A command that runs `exe` as `user` = (uid, gid) with a clean environment:
/// `PATH=SAFE_PATH`, `HOME=home`, `LC_ALL=C` plus `extra_env`. stdio is null
/// unless the caller changes it; the child is killed when its `Child` is dropped
/// and when the daemon dies.
///
/// Supplementary groups: when `uid()` is set and `groups()` is not, std calls
/// `setgroups(0, NULL)` before `setuid`. The `pre_exec` hook (which runs after
/// the credential change) re-checks that the group list is empty whenever the
/// daemon itself is root, and fails the spawn otherwise (fail closed).
pub fn unprivileged_command(
    exe: &str,
    args: &[String],
    user: (u32, u32),
    home: &Path,
    extra_env: &[(String, String)],
) -> Command {
    let mut c = Command::new(exe);
    c.args(args)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .env("HOME", home)
        .env("LC_ALL", "C");
    for (k, v) in extra_env {
        c.env(k, v);
    }
    c.uid(user.0)
        .gid(user.1)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let from_root = nix::unistd::geteuid().is_root();
    // SAFETY: the closure runs in the forked child before exec and only makes
    // async-signal-safe system calls (getgroups with a zero-size buffer, prctl);
    // it allocates nothing and touches no locks.
    unsafe {
        c.pre_exec(move || {
            if from_root && libc::getgroups(0, std::ptr::null_mut()) != 0 {
                return Err(io::Error::other("supplementary groups were not dropped"));
            }
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    c
}

/// A loopback TCP port that was free a moment ago.
pub fn pick_loopback_port() -> io::Result<u16> {
    let l = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    Ok(l.local_addr()?.port())
}

/// Create the runtime directory if needed and force it to 0750 root:`gid`.
/// Run as root at startup (packaging normally creates it).
pub fn ensure_runtime_dir(dir: &Path, gid: u32) -> io::Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(md) if md.is_dir() => {}
        Ok(_) => return Err(io::Error::other(format!("{} is not a directory", dir.display()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new().recursive(true).mode(0o750).create(dir)?;
        }
        Err(e) => return Err(e),
    }
    nix::unistd::chown(
        dir,
        Some(nix::unistd::Uid::from_raw(0)),
        Some(nix::unistd::Gid::from_raw(gid)),
    )?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750))
}

/// Fetch the server's host key as `alizy-ssh`.
pub async fn keyscan(user: (u32, u32), host: IpAddr, port: u16) -> Result<HostKey, String> {
    check_user(user)?;
    let exe = find_exe(KEYSCAN_EXE).ok_or("ssh-keyscan is not installed")?;
    let mut c = unprivileged_command(&exe, &keyscan_argv(host, port), user, Path::new("/"), &[]);
    c.stdout(Stdio::piped());
    let out = tokio::time::timeout(KEYSCAN_TIMEOUT, c.output())
        .await
        .map_err(|_| "ssh-keyscan timed out".to_string())?
        .map_err(|e| format!("could not run ssh-keyscan: {e}"))?;
    parse_keyscan(&String::from_utf8_lossy(&out.stdout))
        .ok_or_else(|| format!("{host} port {port} did not present a usable SSH host key"))
}

/// A running SSH tunnel. Dropping it kills both children (kill_on_drop) and
/// stops the forwarder; [`SshTunnel::stop`] does the same and waits.
pub struct SshTunnel {
    ssh: Child,
    tun2socks: Child,
    dns: DnsForwarder,
    /// Released once ssh has authenticated (the server is one-shot anyway).
    askpass: Option<AskpassServer>,
    endpoint: SocketAddr,
    ssh_err: TailBuf,
    t2s_err: TailBuf,
    known_hosts: PathBuf,
    /// Unix seconds of the last liveness check that found both children running.
    alive_at: u64,
}

/// Bring the SSH side up on an existing (empty) firewall plan for it:
/// known_hosts → TUN owned by alizy-ssh → askpass → ssh → SOCKS readiness →
/// tun2socks → DNS forwarder. Routes and system DNS are the adapter's job.
/// On error every child started here is killed (kill_on_drop) and the
/// known_hosts file removed; the TUN is removed by the caller's teardown.
pub async fn start(req: &SshUp<'_>) -> Result<SshTunnel, SshError> {
    check_user(req.user).map_err(SshError::Other)?;
    let ssh_exe = find_exe(SSH_EXE)
        .ok_or_else(|| SshError::MissingDependency("the OpenSSH client (ssh) is not installed".into()))?;
    let t2s_exe = find_exe(TUN2SOCKS_EXE)
        .ok_or_else(|| SshError::MissingDependency("badvpn-tun2socks is not installed".into()))?;
    let known_hosts = write_known_hosts(req.runtime, &req.cfg.public, req.user.1)
        .map_err(|e| SshError::Other(format!("could not write known_hosts: {e}")))?;
    let r = start_children(req, &ssh_exe, &t2s_exe, known_hosts.clone()).await;
    if r.is_err() {
        let _ = std::fs::remove_file(&known_hosts);
    }
    r
}

async fn start_children(
    req: &SshUp<'_>,
    ssh_exe: &str,
    t2s_exe: &str,
    known_hosts: PathBuf,
) -> Result<SshTunnel, SshError> {
    let p = &req.cfg.public;
    let uid = req.user.0.to_string();
    run(
        &argv(&["ip", "tuntap", "add", "dev", req.iface, "mode", "tun", "user", &uid]),
        None,
    )
    .await
    .map_err(|e| SshError::Other(format!("could not create the TUN device: {e}")))?;

    let id = alizy_core::ssh::fingerprint(p);
    let askpass = AskpassServer::start(req.runtime, &id, req.cfg.password.clone(), req.user.0)
        .await
        .map_err(|e| SshError::Other(format!("could not start the password helper: {e}")))?;
    let mut cmd = unprivileged_command(
        ssh_exe,
        &ssh_argv(req.cfg, req.socks_port, req.runtime),
        req.user,
        req.runtime,
        &askpass.env(),
    );
    cmd.stderr(Stdio::piped());
    let mut ssh = cmd
        .spawn()
        .map_err(|e| SshError::Other(format!("could not start ssh: {e}")))?;
    drop(cmd); // holds the askpass token in its environment
    let ssh_err = TailBuf::new(STDERR_CAP);
    let ssh_reader = capture(ssh.stderr.take().expect("stderr piped"), ssh_err.clone());

    wait_ready(req, &mut ssh, &ssh_err, ssh_reader).await?;
    drop(askpass);

    let mut cmd = unprivileged_command(
        t2s_exe,
        &tun2socks_argv(req.iface, req.socks_port, req.ipv6),
        req.user,
        req.runtime,
        &[],
    );
    cmd.stderr(Stdio::piped());
    let mut tun2socks = cmd
        .spawn()
        .map_err(|e| SshError::Other(format!("could not start badvpn-tun2socks: {e}")))?;
    let t2s_err = TailBuf::new(STDERR_CAP);
    capture(tun2socks.stderr.take().expect("stderr piped"), t2s_err.clone());
    tokio::time::sleep(Duration::from_millis(300)).await;
    if let Ok(Some(st)) = tun2socks.try_wait() {
        return Err(SshError::Other(format!(
            "badvpn-tun2socks exited ({st}){}",
            suffix(&t2s_err.text())
        )));
    }

    let socks = SocketAddr::from((Ipv4Addr::LOCALHOST, req.socks_port));
    let dns = DnsForwarder::start(SSH_DNS_FORWARDER, socks, req.upstreams.clone())
        .await
        .map_err(|e| SshError::Other(format!("could not start the DNS forwarder on {SSH_DNS_FORWARDER}: {e}")))?;
    tracing::debug!(listen = %dns.local_addr(), "SSH tunnel DNS forwarder started");
    Ok(SshTunnel {
        ssh,
        tun2socks,
        dns,
        askpass: None,
        endpoint: SocketAddr::new(p.host, p.port),
        ssh_err,
        t2s_err,
        known_hosts,
        alive_at: crate::resolver::now(),
    })
}

fn suffix(stderr: &str) -> String {
    match last_line(stderr) {
        "" => String::new(),
        l => format!(": {}", alizy_core::redact_keys(l)),
    }
}

/// Poll until a SOCKS CONNECT through ssh succeeds; abort as soon as ssh exits.
async fn wait_ready(req: &SshUp<'_>, ssh: &mut Child, err: &TailBuf, reader: JoinHandle<()>) -> Result<(), SshError> {
    let socks = SocketAddr::from((Ipv4Addr::LOCALHOST, req.socks_port));
    let dst = SocketAddr::new(req.upstreams.first().copied().unwrap_or(DEFAULT_SSH_DNS[0]), 53);
    let deadline = tokio::time::Instant::now() + READY_DEADLINE;
    loop {
        match ssh.try_wait() {
            Ok(Some(status)) => {
                // Let the reader drain what ssh printed before it exited.
                let _ = tokio::time::timeout(Duration::from_secs(1), reader).await;
                return Err(exit_error(req, &err.text(), &status.to_string()).await);
            }
            Ok(None) => {}
            Err(e) => return Err(SshError::Other(format!("ssh: {e}"))),
        }
        if let Ok(Ok(_conn)) = tokio::time::timeout(PROBE_TIMEOUT, socks5_connect(socks, dst)).await {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(SshError::Other(format!(
                "the SSH connection did not become ready within {} seconds{}",
                READY_DEADLINE.as_secs(),
                suffix(&err.text())
            )));
        }
        tokio::time::sleep(READY_POLL).await;
    }
}

async fn exit_error(req: &SshUp<'_>, stderr: &str, status: &str) -> SshError {
    let p = &req.cfg.public;
    match classify_ssh_stderr(stderr) {
        Some(StderrClass::AuthFailed) => SshError::AuthFailed,
        Some(StderrClass::HostKeyChanged) => match keyscan(req.user, p.host, p.port).await {
            Ok(k) => SshError::HostKeyChanged(k),
            Err(e) => SshError::Other(format!(
                "host key verification failed and the server's current key could not be fetched: {e}"
            )),
        },
        None => SshError::Other(format!("ssh exited ({status}){}", suffix(stderr))),
    }
}

impl SshTunnel {
    /// Kill both children, stop the forwarder and remove the known_hosts file.
    pub async fn stop(self) {
        let Self {
            mut ssh,
            mut tun2socks,
            dns,
            askpass,
            known_hosts,
            ..
        } = self;
        drop(askpass);
        dns.stop();
        for c in [&mut ssh, &mut tun2socks] {
            let _ = c.start_kill();
            let _ = tokio::time::timeout(STOP_GRACE, c.wait()).await;
        }
        let _ = std::fs::remove_file(&known_hosts);
    }

    /// `Some(reason)` once ssh or tun2socks has exited.
    pub fn try_exited(&mut self) -> Option<String> {
        match self.ssh.try_wait() {
            Ok(Some(st)) => {
                let why = match classify_ssh_stderr(&self.ssh_err.text()) {
                    Some(StderrClass::AuthFailed) => ": authentication failed".to_string(),
                    Some(StderrClass::HostKeyChanged) => ": host key verification failed".to_string(),
                    None => suffix(&self.ssh_err.text()),
                };
                return Some(format!("ssh exited ({st}){why}"));
            }
            Err(e) => return Some(format!("ssh: {e}")),
            Ok(None) => {}
        }
        match self.tun2socks.try_wait() {
            Ok(Some(st)) => {
                return Some(format!(
                    "badvpn-tun2socks exited ({st}){}",
                    suffix(&self.t2s_err.text())
                ))
            }
            Err(e) => return Some(format!("badvpn-tun2socks: {e}")),
            Ok(None) => {}
        }
        self.alive_at = crate::resolver::now();
        None
    }

    /// Byte counters of the TUN; `last_handshake` is the last successful liveness check.
    pub fn stats(&self, iface: &str) -> TunnelStats {
        let read = |what: &str| {
            std::fs::read_to_string(format!("/sys/class/net/{iface}/statistics/{what}"))
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(0)
        };
        TunnelStats {
            rx_bytes: read("rx_bytes"),
            tx_bytes: read("tx_bytes"),
            last_handshake: self.alive_at,
            endpoint: Some(self.endpoint),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alizy_core::ipc::ErrorCode;
    use alizy_core::ssh::{HostKey, SshConfig, SshPublic};
    use std::path::Path;
    use zeroize::Zeroizing;

    const KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAICJ9AyQ1/Hf8ky/h28JhISjg1GkKGhTejR6j6uTwPF1l";

    fn cfg(port: u16) -> SshConfig {
        SshConfig {
            public: SshPublic {
                host: "203.0.113.5".parse().unwrap(),
                port,
                username: "alice".into(),
                host_key: Some(HostKey {
                    key_type: "ssh-ed25519".into(),
                    key_b64: KEY.into(),
                }),
                dns: vec![],
            },
            password: Zeroizing::new("hunter2-secret".into()),
        }
    }

    #[test]
    fn ssh_argv_exact() {
        let c = cfg(2222);
        let id = alizy_core::ssh::fingerprint(&c.public);
        let got = ssh_argv(&c, 1080, Path::new("/run/alizy/ssh"));
        let want: Vec<String> = [
            "-N",
            "-D",
            "127.0.0.1:1080",
            "-p",
            "2222",
            "-F",
            "/dev/null",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=3",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            &format!("UserKnownHostsFile=/run/alizy/ssh/{id}.known_hosts"),
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "PreferredAuthentications=password,keyboard-interactive",
            "-o",
            "NumberOfPasswordPrompts=1",
            "-o",
            "BatchMode=no",
            "--",
            "alice@203.0.113.5",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(got, want);
        assert!(!got.iter().any(|a| a.contains("hunter2")));
    }

    #[test]
    fn ssh_argv_ipv6_host_is_literal() {
        let mut c = cfg(22);
        c.public.host = "2001:db8::5".parse().unwrap();
        let got = ssh_argv(&c, 40000, Path::new("/r"));
        assert_eq!(got.last().unwrap(), "alice@2001:db8::5");
        assert_eq!(got[4], "22");
    }

    #[test]
    fn tun2socks_argv_exact() {
        let v4: Vec<String> = [
            "--tundev",
            "alizy0",
            "--netif-ipaddr",
            "198.18.0.2",
            "--netif-netmask",
            "255.255.255.252",
            "--socks-server-addr",
            "127.0.0.1:1080",
            "--loglevel",
            "warning",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(tun2socks_argv("alizy0", 1080, false), v4);
        let mut v6 = v4.clone();
        v6.extend(["--netif-ip6addr".to_string(), "fd4a:5a00::2".to_string()]);
        assert_eq!(tun2socks_argv("alizy0", 1080, true), v6);
    }

    #[test]
    fn keyscan_argv_exact() {
        assert_eq!(
            keyscan_argv("203.0.113.5".parse().unwrap(), 2222),
            ["-T", "8", "-t", "ed25519,ecdsa,rsa", "-p", "2222", "203.0.113.5"]
        );
    }

    #[test]
    fn ssh_exit_auth_failure_maps_to_error() {
        let stderr = "Warning: Permanently added '203.0.113.5' (ED25519) to the list of known hosts.\r\n\
                      alice@203.0.113.5: Permission denied (password,keyboard-interactive).\r\n";
        assert_eq!(classify_ssh_stderr(stderr), Some(StderrClass::AuthFailed));
        let e = SshError::AuthFailed;
        assert_eq!(e.code(), ErrorCode::AuthFailed);
        assert!(e.to_string().contains("authentication failed"));
        assert_eq!(e.host_key(), None);
    }

    #[test]
    fn known_hosts_mismatch_maps_to_host_key_changed() {
        let stderr = "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
                      @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n\
                      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
                      Host key for 203.0.113.5 has changed and you have requested strict checking.\n\
                      Host key verification failed.\n";
        assert_eq!(classify_ssh_stderr(stderr), Some(StderrClass::HostKeyChanged));
        assert_eq!(
            classify_ssh_stderr("Host key verification failed.\n"),
            Some(StderrClass::HostKeyChanged)
        );
        // A key-change failure never classifies as an auth failure, even if both appear.
        assert_eq!(
            classify_ssh_stderr("Host key verification failed.\nPermission denied\n"),
            Some(StderrClass::HostKeyChanged)
        );
        let k = HostKey {
            key_type: "ssh-ed25519".into(),
            key_b64: KEY.into(),
        };
        let e = SshError::HostKeyChanged(k.clone());
        assert_eq!(e.code(), ErrorCode::HostKeyChanged);
        assert_eq!(e.host_key(), Some(k));
    }

    #[test]
    fn other_ssh_failures_are_unclassified() {
        assert_eq!(
            classify_ssh_stderr("ssh: connect to host 203.0.113.5 port 22: Connection refused\r\n"),
            None
        );
        assert_eq!(
            last_line("a\nssh: connect to host x port 22: Connection refused\r\n\n"),
            "ssh: connect to host x port 22: Connection refused"
        );
        assert_eq!(SshError::Other("x".into()).code(), ErrorCode::Tunnel);
        assert_eq!(
            SshError::MissingDependency("x".into()).code(),
            ErrorCode::MissingDependency
        );
    }

    #[test]
    fn keyscan_output_prefers_ed25519() {
        let out = format!(
            "# 203.0.113.5:22 SSH-2.0-OpenSSH_9.6\n\
             203.0.113.5 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ==\n\
             203.0.113.5 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY=\n\
             203.0.113.5 ssh-ed25519 {KEY}\n"
        );
        let k = parse_keyscan(&out).unwrap();
        assert_eq!((k.key_type.as_str(), k.key_b64.as_str()), ("ssh-ed25519", KEY));
        let k = parse_keyscan(
            "[203.0.113.5]:2222 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ==\n\
             [203.0.113.5]:2222 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY=\n",
        )
        .unwrap();
        assert_eq!(k.key_type, "ecdsa-sha2-nistp256");
        // Garbage and unsupported types are skipped; nothing usable → None.
        assert_eq!(parse_keyscan("x ssh-dss AAAA\nx ssh-ed25519 !!notb64\n"), None);
        assert_eq!(parse_keyscan(""), None);
    }

    #[test]
    fn stderr_buffer_keeps_only_the_tail() {
        let b = TailBuf::new(8);
        b.push(b"0123456789");
        b.push(b"ab");
        assert_eq!(b.text(), "456789ab");
    }

    #[test]
    fn known_hosts_written_after_validation() {
        let dir = tempfile::tempdir().unwrap();
        let gid = nix::unistd::getgid().as_raw();
        let c = cfg(2222);
        let path = write_known_hosts(dir.path(), &c.public, gid).unwrap();
        assert_eq!(path, known_hosts_path(dir.path(), &c.public));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("[203.0.113.5]:2222 ssh-ed25519 {KEY}\n")
        );
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o640);
        // An invalid key (e.g. a newline injection) is refused and nothing is written.
        let mut bad = c.public.clone();
        bad.port = 22;
        bad.host_key = Some(HostKey {
            key_type: "ssh-ed25519".into(),
            key_b64: format!("{KEY}\n203.0.113.9 ssh-ed25519 {KEY}"),
        });
        assert!(write_known_hosts(dir.path(), &bad, gid).is_err());
        assert!(!known_hosts_path(dir.path(), &bad).exists());
        bad.host_key = None;
        assert!(write_known_hosts(dir.path(), &bad, gid).is_err());
    }

    #[tokio::test]
    async fn unprivileged_command_has_clean_env_and_no_password() {
        // Rootless: "dropping" to our own uid/gid exercises the same code path.
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        let dir = tempfile::tempdir().unwrap();
        let env_exe = alizy_core::sysprobe::find_exe("env").unwrap();
        let out = unprivileged_command(&env_exe, &[], (uid, gid), dir.path(), &[("X_EXTRA".into(), "1".into())])
            .stdout(std::process::Stdio::piped())
            .output()
            .await
            .unwrap();
        let text = String::from_utf8(out.stdout).unwrap();
        let mut keys: Vec<&str> = text.lines().filter_map(|l| l.split('=').next()).collect();
        keys.sort();
        assert_eq!(keys, ["HOME", "LC_ALL", "PATH", "X_EXTRA"]);
        assert!(text.contains(&format!("PATH={}", alizy_core::sysprobe::SAFE_PATH)));
        assert!(text.contains(&format!("HOME={}", dir.path().display())));
    }

    #[test]
    fn loopback_port_is_free_and_nonzero() {
        let p = pick_loopback_port().unwrap();
        assert_ne!(p, 0);
        std::net::TcpListener::bind(("127.0.0.1", p)).unwrap();
    }
}
