//! One-shot askpass helper for SSH passwords.
//!
//! The daemon spawns OpenSSH as the unprivileged `alizy-ssh` user with
//! `SSH_ASKPASS_REQUIRE=force`; ssh then runs `alizyd --askpass <prompt>` to get
//! the password. ssh closes inherited descriptors above 2, so the password
//! cannot travel over a pipe. Instead [`AskpassServer`] binds a Unix socket
//! `<dir>/<id>.askpass` (mode 0600, owned by the allowed uid) and hands the
//! password to exactly one client that
//!
//! 1. is running as `allowed_uid` (checked with `SO_PEERCRED`), and
//! 2. sends the random 256-bit token from `ALIZY_ASKPASS_TOKEN` as its first line
//!    (compared in constant time).
//!
//! A connection failing either check is closed without any data and does **not**
//! consume the one-shot: only `allowed_uid` (and root) can open a 0600 socket
//! owned by `allowed_uid` at all, so letting a bad attempt burn the password
//! would only let a confused process deny service to ssh. After the one success
//! the listener is closed and the socket unlinked. The server also gives up after
//! [`LIFETIME`] and on `Drop`.
//!
//! The password never appears in argv, the environment, logs or files.
#![cfg_attr(not(test), allow(dead_code))]

use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroizing;

/// How long an unused server keeps waiting for ssh before it unlinks the socket.
pub const LIFETIME: Duration = Duration::from_secs(60);
/// Per-connection / client-side I/O timeout.
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest password the client accepts.
const MAX_PASSWORD: usize = 4096;
const ENV_SOCK: &str = "ALIZY_ASKPASS_SOCK";
const ENV_TOKEN: &str = "ALIZY_ASKPASS_TOKEN";

pub struct AskpassServer {
    path: PathBuf,
    /// (dev, ino) of the socket we bound, so we never unlink someone else's.
    ident: (u64, u64),
    token: Zeroizing<String>,
    exe: PathBuf,
    task: tokio::task::JoinHandle<()>,
}

fn safe_id(id: &str) -> bool {
    !id.is_empty() && !id.contains('/') && !id.contains("..") && !id.chars().any(char::is_control)
}

fn random_token() -> io::Result<Zeroizing<String>> {
    let mut raw = Zeroizing::new([0u8; 32]);
    std::fs::File::open("/dev/urandom")?.read_exact(&mut raw[..])?;
    let mut hex = Zeroizing::new(String::with_capacity(64));
    for b in raw.iter() {
        hex.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
        hex.push(char::from(b"0123456789abcdef"[usize::from(b & 0xf)]));
    }
    Ok(hex)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Unlink `path` only if it is still the socket identified by `ident`.
fn remove_if_ours(path: &Path, ident: (u64, u64)) {
    if let Ok(md) = std::fs::symlink_metadata(path) {
        if (md.dev(), md.ino()) == ident {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl AskpassServer {
    pub async fn start(dir: &Path, id: &str, password: Zeroizing<String>, allowed_uid: u32) -> io::Result<Self> {
        if !safe_id(id) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsafe askpass id"));
        }
        let exe = std::env::current_exe()?;
        let token = random_token()?;
        let path = dir.join(format!("{id}.askpass"));
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        // The socket briefly exists with umask permissions before the chmod;
        // the production directory is 0750 root:alizy-ssh and the peer-uid check
        // applies regardless, so that window grants nothing.
        let listener = UnixListener::bind(&path)?;
        let md = std::fs::symlink_metadata(&path)?;
        let ident = (md.dev(), md.ino());
        let secure = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).and_then(|()| {
            nix::unistd::chown(&path, Some(nix::unistd::Uid::from_raw(allowed_uid)), None).map_err(io::Error::from)
        });
        if let Err(e) = secure {
            remove_if_ours(&path, ident);
            return Err(e);
        }
        let task = tokio::spawn(serve(
            listener,
            path.clone(),
            ident,
            token.clone(),
            password,
            allowed_uid,
        ));
        Ok(Self {
            path,
            ident,
            token,
            exe,
            task,
        })
    }

    /// Environment for the ssh child (it also needs its own PATH/HOME etc.).
    pub fn env(&self) -> Vec<(String, String)> {
        vec![
            ("SSH_ASKPASS".into(), self.exe.to_string_lossy().into_owned()),
            ("SSH_ASKPASS_REQUIRE".into(), "force".into()),
            ("DISPLAY".into(), ":0".into()),
            (ENV_SOCK.into(), self.path.to_string_lossy().into_owned()),
            (ENV_TOKEN.into(), self.token.as_str().to_owned()),
        ]
    }
}

impl Drop for AskpassServer {
    fn drop(&mut self) {
        self.task.abort();
        remove_if_ours(&self.path, self.ident);
    }
}

async fn serve(
    listener: UnixListener,
    path: PathBuf,
    ident: (u64, u64),
    token: Zeroizing<String>,
    password: Zeroizing<String>,
    allowed_uid: u32,
) {
    let one_shot = async {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                // Transient accept errors (EMFILE, ...): back off briefly.
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            };
            if handle(stream, &token, &password, allowed_uid).await {
                return;
            }
        }
    };
    let _ = tokio::time::timeout(LIFETIME, one_shot).await;
    drop(listener);
    remove_if_ours(&path, ident);
}

/// True once the password has been handed to an authenticated peer (the
/// one-shot is then consumed even if the write itself failed).
async fn handle(mut stream: UnixStream, token: &str, password: &str, allowed_uid: u32) -> bool {
    let peer = nix::sys::socket::getsockopt(&stream, nix::sys::socket::sockopt::PeerCredentials);
    if !matches!(peer, Ok(c) if c.uid() == allowed_uid) {
        return false;
    }
    let mut line = Zeroizing::new([0u8; 128]);
    let mut n = 0;
    let read = tokio::time::timeout(IO_TIMEOUT, async {
        while n < line.len() {
            match stream.read(&mut line[n..]).await {
                Ok(0) | Err(_) => return false,
                Ok(k) => {
                    n += k;
                    if line[..n].contains(&b'\n') {
                        return true;
                    }
                }
            }
        }
        false
    })
    .await;
    if read != Ok(true) {
        return false;
    }
    let end = line[..n].iter().position(|&b| b == b'\n').unwrap_or(n);
    if !ct_eq(&line[..end], token.as_bytes()) {
        return false;
    }
    let _ = tokio::time::timeout(IO_TIMEOUT, async {
        stream.write_all(password.as_bytes()).await?;
        stream.shutdown().await
    })
    .await;
    true
}

/// Client side: ask the server at `sock` for the password.
fn fetch(prompt: &str, sock: &str, token: &str) -> Option<Zeroizing<Vec<u8>>> {
    let p = prompt.to_ascii_lowercase();
    // Never answer host-key confirmations or key passphrases.
    if p.contains("passphrase") || p.contains("yes/no") {
        return None;
    }
    let mut s = std::os::unix::net::UnixStream::connect(sock).ok()?;
    s.set_read_timeout(Some(IO_TIMEOUT)).ok()?;
    s.set_write_timeout(Some(IO_TIMEOUT)).ok()?;
    let mut req = Zeroizing::new(Vec::with_capacity(token.len() + 1));
    req.extend_from_slice(token.as_bytes());
    req.push(b'\n');
    s.write_all(&req).ok()?;
    let mut buf = Zeroizing::new(vec![0u8; MAX_PASSWORD + 1]);
    let mut n = 0;
    loop {
        if n == buf.len() {
            return None; // too long
        }
        match s.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    if n == 0 {
        return None;
    }
    buf.truncate(n);
    Some(buf)
}

/// `alizyd --askpass <prompt>`: print the password + newline and return 0, or
/// return 1 with no output at all.
pub fn run_client() -> i32 {
    // This process briefly holds the password.
    let _ = nix::sys::prctl::set_dumpable(false);
    let mut args = std::env::args_os().skip(2);
    let (Some(prompt), None) = (args.next(), args.next()) else {
        return 1;
    };
    let (Ok(sock), Ok(token)) = (std::env::var(ENV_SOCK), std::env::var(ENV_TOKEN)) else {
        return 1;
    };
    let token = Zeroizing::new(token);
    let Some(pw) = fetch(&prompt.to_string_lossy(), &sock, &token) else {
        return 1;
    };
    let mut out = Zeroizing::new(Vec::with_capacity(pw.len() + 1));
    out.extend_from_slice(&pw);
    out.push(b'\n');
    let mut stdout = io::stdout().lock();
    match stdout.write_all(&out).and_then(|()| stdout.flush()) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixStream;

    fn uid() -> u32 {
        nix::unistd::getuid().as_raw()
    }

    fn env_of(s: &AskpassServer, k: &str) -> String {
        s.env().into_iter().find(|(n, _)| n == k).map(|(_, v)| v).unwrap()
    }

    async fn start(dir: &Path) -> AskpassServer {
        AskpassServer::start(dir, "3f0e5c1a-profile", Zeroizing::new("hunter2 pw".into()), uid())
            .await
            .unwrap()
    }

    /// Raw request on a blocking thread (the server runs on the test runtime).
    async fn raw(sock: String, line: Vec<u8>) -> Vec<u8> {
        tokio::task::spawn_blocking(move || {
            let Ok(mut s) = UnixStream::connect(&sock) else {
                return Vec::new();
            };
            s.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
            let _ = s.write_all(&line);
            let mut out = Vec::new();
            let _ = s.read_to_end(&mut out);
            out
        })
        .await
        .unwrap()
    }

    async fn client(prompt: &'static str, sock: String, token: String) -> Option<Vec<u8>> {
        tokio::task::spawn_blocking(move || fetch(prompt, &sock, &token).map(|p| p.to_vec()))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn env_has_exact_keys_and_socket_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let s = start(dir.path()).await;
        let keys: Vec<String> = s.env().into_iter().map(|(k, _)| k).collect();
        assert_eq!(
            keys,
            [
                "SSH_ASKPASS",
                "SSH_ASKPASS_REQUIRE",
                "DISPLAY",
                "ALIZY_ASKPASS_SOCK",
                "ALIZY_ASKPASS_TOKEN"
            ]
        );
        assert_eq!(env_of(&s, "SSH_ASKPASS_REQUIRE"), "force");
        assert_eq!(env_of(&s, "DISPLAY"), ":0");
        assert_eq!(
            env_of(&s, "SSH_ASKPASS"),
            std::env::current_exe().unwrap().to_string_lossy()
        );
        let tok = env_of(&s, "ALIZY_ASKPASS_TOKEN");
        assert_eq!(tok.len(), 64);
        assert!(tok.bytes().all(|b| b.is_ascii_hexdigit()));
        let sock = env_of(&s, "ALIZY_ASKPASS_SOCK");
        assert_eq!(Path::new(&sock), dir.path().join("3f0e5c1a-profile.askpass"));
        let md = std::fs::metadata(&sock).unwrap();
        assert_eq!(md.permissions().mode() & 0o777, 0o600);
        assert_eq!(md.uid(), uid());
    }

    #[tokio::test]
    async fn tokens_differ_between_servers() {
        let dir = tempfile::tempdir().unwrap();
        let a = AskpassServer::start(dir.path(), "a", Zeroizing::new("x".into()), uid())
            .await
            .unwrap();
        let b = AskpassServer::start(dir.path(), "b", Zeroizing::new("x".into()), uid())
            .await
            .unwrap();
        assert_ne!(env_of(&a, "ALIZY_ASKPASS_TOKEN"), env_of(&b, "ALIZY_ASKPASS_TOKEN"));
    }

    #[tokio::test]
    async fn rejects_unsafe_ids() {
        let dir = tempfile::tempdir().unwrap();
        for id in ["", "../x", "a/b", "..", "a\nb", "a\0b"] {
            assert!(
                AskpassServer::start(dir.path(), id, Zeroizing::new("x".into()), uid())
                    .await
                    .is_err(),
                "{id:?}"
            );
        }
    }

    #[tokio::test]
    async fn serves_once_to_matching_uid_and_token() {
        let dir = tempfile::tempdir().unwrap();
        let s = start(dir.path()).await;
        let got = client(
            "alice@192.0.2.1's password: ",
            env_of(&s, "ALIZY_ASKPASS_SOCK"),
            env_of(&s, "ALIZY_ASKPASS_TOKEN"),
        )
        .await;
        assert_eq!(got.as_deref(), Some(&b"hunter2 pw"[..]));
    }

    #[tokio::test]
    async fn wrong_token_gets_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let s = start(dir.path()).await;
        let sock = env_of(&s, "ALIZY_ASKPASS_SOCK");
        let tok = env_of(&s, "ALIZY_ASKPASS_TOKEN");
        let bad: String = tok.chars().rev().collect();
        assert!(raw(sock.clone(), format!("{bad}\n").into_bytes()).await.is_empty());
        assert!(raw(sock.clone(), b"\n".to_vec()).await.is_empty());
        assert!(raw(sock.clone(), format!("{tok}x\n").into_bytes()).await.is_empty());
        // A wrong-token attempt does not consume the one-shot.
        assert_eq!(raw(sock, format!("{tok}\n").into_bytes()).await, b"hunter2 pw");
    }

    #[tokio::test]
    async fn wrong_uid_gets_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let s = AskpassServer::start(dir.path(), "p", Zeroizing::new("pw".into()), uid() + 1).await;
        // Unprivileged tests cannot chown to another uid; as root we can and the
        // peer-uid check must still refuse us.
        let Ok(s) = s else { return };
        let got = raw(
            env_of(&s, "ALIZY_ASKPASS_SOCK"),
            format!("{}\n", env_of(&s, "ALIZY_ASKPASS_TOKEN")).into_bytes(),
        )
        .await;
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn second_request_gets_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let s = start(dir.path()).await;
        let sock = env_of(&s, "ALIZY_ASKPASS_SOCK");
        let tok = env_of(&s, "ALIZY_ASKPASS_TOKEN");
        assert_eq!(raw(sock.clone(), format!("{tok}\n").into_bytes()).await, b"hunter2 pw");
        assert!(raw(sock.clone(), format!("{tok}\n").into_bytes()).await.is_empty());
        assert!(client("x's password: ", sock, tok).await.is_none());
    }

    #[tokio::test]
    async fn socket_removed_after_use_and_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let s = start(dir.path()).await;
        let sock = env_of(&s, "ALIZY_ASKPASS_SOCK");
        let tok = env_of(&s, "ALIZY_ASKPASS_TOKEN");
        assert!(Path::new(&sock).exists());
        assert_eq!(raw(sock.clone(), format!("{tok}\n").into_bytes()).await, b"hunter2 pw");
        // Removal happens right after the write; give the task a moment.
        for _ in 0..50 {
            if !Path::new(&sock).exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(!Path::new(&sock).exists());
        drop(s);

        let s = start(dir.path()).await;
        let sock = env_of(&s, "ALIZY_ASKPASS_SOCK");
        assert!(Path::new(&sock).exists());
        drop(s);
        assert!(!Path::new(&sock).exists());
    }

    #[tokio::test]
    async fn client_refuses_yes_no_prompt() {
        let dir = tempfile::tempdir().unwrap();
        let s = start(dir.path()).await;
        let sock = env_of(&s, "ALIZY_ASKPASS_SOCK");
        let tok = env_of(&s, "ALIZY_ASKPASS_TOKEN");
        for p in [
            "Are you sure you want to continue connecting (yes/no/[fingerprint])? ",
            "ARE YOU SURE (YES/NO)? ",
            "Enter passphrase for key '/home/a/.ssh/id_ed25519': ",
            "Bad PassPhrase, try again: ",
        ] {
            assert!(client(p, sock.clone(), tok.clone()).await.is_none(), "{p}");
        }
        // Refusals never touched the server: the password is still there.
        assert_eq!(raw(sock, format!("{tok}\n").into_bytes()).await, b"hunter2 pw");
    }

    #[tokio::test]
    async fn client_fails_cleanly_without_server() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("none.askpass").to_string_lossy().into_owned();
        assert!(client("x's password: ", sock, "00".repeat(32)).await.is_none());
    }

    /// End-to-end through the real binary: `cargo build -p alizyd && cargo test
    /// -p alizyd askpass -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn e2e_binary_prints_password() {
        let bin = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("alizyd");
        assert!(bin.exists(), "build the binary first: {}", bin.display());
        let dir = tempfile::tempdir().unwrap();
        let s = start(dir.path()).await;
        let env: Vec<(String, String)> = s.env().into_iter().filter(|(k, _)| k != "SSH_ASKPASS").collect();
        let run = |prompt: &'static str| {
            let bin = bin.clone();
            let env = env.clone();
            tokio::task::spawn_blocking(move || {
                std::process::Command::new(bin)
                    .args(["--askpass", prompt])
                    .env_clear()
                    .envs(env)
                    .output()
                    .unwrap()
            })
        };
        let refused = run("Are you sure (yes/no)? ").await.unwrap();
        assert_eq!(refused.status.code(), Some(1));
        assert!(refused.stdout.is_empty() && refused.stderr.is_empty());
        let out = run("x's password: ").await.unwrap();
        assert_eq!(out.status.code(), Some(0));
        assert_eq!(out.stdout, b"hunter2 pw\n");
        assert!(out.stderr.is_empty());
        let again = run("x's password: ").await.unwrap();
        assert_eq!(again.status.code(), Some(1));
        assert!(again.stdout.is_empty() && again.stderr.is_empty());
    }
}
