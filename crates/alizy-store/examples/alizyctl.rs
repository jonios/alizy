//! alizyctl — test/diagnostic client used for real-system validation.
//!
//! Uses exactly the same data paths as the GUI (its SQLite database under
//! `$XDG_DATA_HOME/io.alizy.app`, the real OS keyring via `SecretStore::detect`)
//! and the daemon socket. It never prints private or pre-shared keys.
//!
//!   cargo run -p alizy-store --example alizyctl -- <command>
//!
//! Commands:
//!   import <path>...            import .conf files / folders (like the GUI)
//!   list                        list profiles
//!   rename <id> <name> | delete <id> | edit-mtu <id> <mtu>
//!   secret-check <id>           show which secret backend holds the key (never the key)
//!   connect <id> | disconnect | status | policy | set-policy <json>
//!   split-status | set-split <json-file> | route-test <query> | events [since] | verify | probe

use alizy_core::ipc::{Command, Payload, Request, Response, TunnelSpec, PROTOCOL_VERSION, SOCKET_PATH};
use alizy_store::{Db, ProfileManager, SecretStore};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

fn data_dir() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var("HOME").expect("HOME")).join(".local/share"));
    base.join("io.alizy.app")
}

async fn call(cmd: Command) -> Result<Payload, String> {
    let path = std::env::var("ALIZY_SOCKET").unwrap_or_else(|_| SOCKET_PATH.into());
    let mut s = UnixStream::connect(&path)
        .await
        .map_err(|e| format!("connect {path}: {e}"))?;
    let mut line = Zeroizing::new(serde_json::to_vec(&Request { id: 1, command: cmd }).map_err(|e| e.to_string())?);
    line.push(b'\n');
    s.write_all(&line).await.map_err(|e| e.to_string())?;
    let mut buf = String::new();
    BufReader::new(s).read_line(&mut buf).await.map_err(|e| e.to_string())?;
    if buf.is_empty() {
        return Err("connection closed by daemon (not authorised?)".into());
    }
    let r: Response = serde_json::from_str(&buf).map_err(|e| e.to_string())?;
    r.result.map_err(|e| format!("{:?}: {}", e.code, e.message))
}

/// Like `call`, but returns the daemon's raw JSON response line (errors included).
async fn call_raw(cmd: Command) -> Result<String, String> {
    let path = std::env::var("ALIZY_SOCKET").unwrap_or_else(|_| SOCKET_PATH.into());
    let mut s = UnixStream::connect(&path)
        .await
        .map_err(|e| format!("connect {path}: {e}"))?;
    let mut line = Zeroizing::new(serde_json::to_vec(&Request { id: 1, command: cmd }).map_err(|e| e.to_string())?);
    line.push(b'\n');
    s.write_all(&line).await.map_err(|e| e.to_string())?;
    let mut buf = String::new();
    BufReader::new(s).read_line(&mut buf).await.map_err(|e| e.to_string())?;
    if buf.is_empty() {
        return Err("connection closed by daemon (not authorised?)".into());
    }
    Ok(buf.trim_end().to_string())
}

fn print(p: &Payload) {
    println!("{}", serde_json::to_string_pretty(p).unwrap());
}

async fn manager() -> ProfileManager {
    let dir = data_dir();
    let db = Db::open(&dir.join("alizy.db")).await.expect("open GUI database");
    ProfileManager::new(db, SecretStore::detect(&dir.join("secrets")))
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let a = |i: usize| {
        args.get(i).cloned().unwrap_or_else(|| {
            eprintln!("missing argument; see source header for usage");
            std::process::exit(2)
        })
    };
    let r: Result<(), String> = async {
        match args.first().map(String::as_str).unwrap_or("") {
            "import" => {
                let m = manager().await;
                let r = m.import_paths(&args[1..]).await;
                for p in &r.imported {
                    println!("imported {} \"{}\" fp={}", p.id, p.name, p.fingerprint);
                }
                for d in &r.duplicates {
                    println!("duplicate of {} \"{}\" ({})", d.existing_id, d.name, d.source);
                }
                for e in &r.errors {
                    println!("error {}: {}", e.source, e.message);
                }
                for w in &r.warnings {
                    println!("warnings {}: {:?}", w.source, w.messages);
                }
                println!("secret backend: {}", m.secrets.backend().name());
                Ok(())
            }
            "list" => {
                for p in manager().await.db.list_profiles().await.map_err(|e| e.to_string())? {
                    let ep = p
                        .config
                        .peers
                        .iter()
                        .find_map(|x| x.endpoint.as_ref().map(|e| e.to_string()));
                    println!(
                        "{}  {:<30} fav={} cat={:?} endpoint={:?}",
                        p.id, p.name, p.favorite, p.category, ep
                    );
                }
                Ok(())
            }
            "rename" => manager()
                .await
                .db
                .rename_profile(&a(1), &a(2))
                .await
                .map_err(|e| e.to_string()),
            "delete" => manager().await.delete(&a(1)).await.map_err(|e| e.to_string()),
            "edit-mtu" => {
                let m = manager().await;
                let row = m.db.get_profile(&a(1)).await.map_err(|e| e.to_string())?;
                let text = alizy_store::manager::redacted_text(&row);
                let text = if text.contains("MTU =") {
                    text.lines()
                        .map(|l| {
                            if l.starts_with("MTU =") {
                                format!("MTU = {}", a(2))
                            } else {
                                l.to_string()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                } else {
                    text.replacen("\n\n[Peer]", &format!("\nMTU = {}\n\n[Peer]", a(2)), 1)
                };
                let w = m.update_text(&row.id, &text).await.map_err(|e| e.to_string())?;
                println!("updated (warnings: {w:?})");
                Ok(())
            }
            "secret-check" => {
                let m = manager().await;
                let ok = m.full_config(&a(1)).await.is_ok();
                println!("backend={} stored_key_readable={ok}", m.secrets.backend().name());
                Ok(())
            }
            "connect" => {
                let m = manager().await;
                let row = m.db.get_profile(&a(1)).await.map_err(|e| e.to_string())?;
                let config = m.full_config(&row.id).await.map_err(|e| e.to_string())?;
                let spec = TunnelSpec {
                    profile_id: row.id,
                    profile_name: row.name,
                    tunnel: alizy_core::TunnelConfig::WireGuard(config),
                    cached_endpoints: row.cached_endpoints,
                };
                print(&call(Command::Connect { spec: Box::new(spec) }).await?);
                Ok(())
            }
            // ssh-connect <host> <port> <user> [<key_type> <key_b64>] — password read from stdin.
            // Talks to the daemon directly (no GUI database); prints the raw response so a
            // host_key_unknown error shows the key to pin on the next call.
            "ssh-connect" => {
                let mut pw = Zeroizing::new(String::new());
                std::io::stdin().read_line(&mut pw).map_err(|e| e.to_string())?;
                let password = Zeroizing::new(pw.trim_end_matches(['\r', '\n']).to_string());
                let host_key = match (args.get(4), args.get(5)) {
                    (Some(t), Some(k)) => Some(alizy_core::ssh::HostKey {
                        key_type: t.clone(),
                        key_b64: k.clone(),
                    }),
                    _ => None,
                };
                let public = alizy_core::ssh::SshPublic {
                    host: a(1).parse().map_err(|e| format!("host: {e}"))?,
                    port: a(2).parse().map_err(|e| format!("port: {e}"))?,
                    username: a(3),
                    host_key,
                    dns: Vec::new(),
                };
                let spec = TunnelSpec {
                    profile_id: "ssh-test".into(),
                    profile_name: "SSH test".into(),
                    tunnel: alizy_core::TunnelConfig::Ssh(alizy_core::ssh::SshConfig { public, password }),
                    cached_endpoints: Vec::new(),
                };
                let raw = call_raw(Command::Connect { spec: Box::new(spec) }).await?;
                println!("{raw}");
                Ok(())
            }
            "disconnect" => call(Command::Disconnect).await.map(|p| print(&p)),
            "status" => call(Command::GetStatus).await.map(|p| print(&p)),
            "policy" => call(Command::GetPolicy).await.map(|p| print(&p)),
            "set-policy" => {
                let policy = serde_json::from_str(&a(1)).map_err(|e| e.to_string())?;
                call(Command::SetPolicy { policy }).await.map(|p| print(&p))
            }
            "split-status" => call(Command::GetSplitStatus).await.map(|p| print(&p)),
            "set-split" => {
                let text = std::fs::read_to_string(a(1)).map_err(|e| e.to_string())?;
                let config = serde_json::from_str(&text).map_err(|e| e.to_string())?;
                call(Command::SetSplit { config }).await.map(|p| print(&p))
            }
            "route-test" => call(Command::TestRoute { query: a(1) }).await.map(|p| print(&p)),
            "events" => call(Command::GetEvents {
                since: args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0),
            })
            .await
            .map(|p| print(&p)),
            "verify" => call(Command::VerifyFirewall).await.map(|p| print(&p)),
            "hello" => call(Command::Hello {
                protocol: PROTOCOL_VERSION,
            })
            .await
            .map(|p| print(&p)),
            "probe" => call(Command::GetSystemReport).await.map(|p| print(&p)),
            _ => Err("unknown command; see the header of crates/alizy-store/examples/alizyctl.rs".into()),
        }
    }
    .await;
    if let Err(e) = r {
        eprintln!("alizyctl: {e}");
        std::process::exit(1);
    }
}
