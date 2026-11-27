//! alizyd — Alizy's privileged system service.
//!
//! The GUI never runs as root; it talks to this daemon over a Unix socket.

#[cfg(target_os = "linux")]
mod askpass;
#[cfg(target_os = "linux")]
mod auth;
#[cfg(target_os = "linux")]
mod cancel;
#[cfg(target_os = "linux")]
mod driver;
#[cfg(target_os = "linux")]
mod egress;
#[cfg(target_os = "linux")]
mod engine;
#[cfg(target_os = "linux")]
mod events;
#[cfg(target_os = "linux")]
mod exec;
#[cfg(target_os = "linux")]
mod lan_proxy;
#[cfg(target_os = "linux")]
mod lan_socks;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod persist;
#[cfg(target_os = "linux")]
mod resolver;
#[cfg(target_os = "linux")]
mod server;
#[cfg(target_os = "linux")]
mod socks_dns;

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("alizyd: this platform is not implemented yet. See docs/PLATFORMS.md.");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    // ssh runs `$SSH_ASKPASS "<prompt>"` (i.e. `alizyd "<prompt>"`, no flag) as
    // the unprivileged alizy-ssh user, with ALIZY_ASKPASS_SOCK set; the explicit
    // `--askpass PROMPT` form is accepted too. Handle it before any logging,
    // runtime or root-only setup.
    if askpass::invoked_as_client() {
        std::process::exit(askpass::run_client());
    }
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("alizyd: cannot start async runtime: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = rt.block_on(linux_main::run()) {
        eprintln!("alizyd: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod linux_main {
    use crate::auth::{AuthMode, Authorizer};
    use crate::driver::ssh::{LinuxSsh, SshDriver, SshEnv};
    use crate::driver::wireguard::{LinuxWg, WireGuardDriver};
    use crate::driver::TunnelDriver;
    use crate::engine::Engine;
    use crate::linux::{self, LinuxAdapter};
    use crate::persist::Persist;
    use crate::resolver::Resolver;
    use alizy_core::firewall::{is_safe_iface_name, TUNNEL_IFACE};
    use alizy_core::ipc::SOCKET_PATH;
    use alizy_core::sysprobe::DnsBackend;
    use anyhow::{anyhow, bail, Context};
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::signal::unix::{signal, SignalKind};

    const USAGE: &str = "usage: alizyd [--socket PATH] [--state-dir DIR] [--auth polkit|same-uid] [--group NAME]
              [--iface NAME] [--dns-backend auto|systemd-resolved|resolvconf|file|none]
              [--resolv-conf PATH]
       alizyd --askpass PROMPT    (internal) SSH_ASKPASS helper run by ssh
       alizyd --probe             print the system compatibility report (JSON)
       alizyd --check             print compatibility findings as tab-separated lines (exit 2 on blockers)
       alizyd --remove-firewall   remove Alizy's nftables table, routing rules and interface
       alizyd --version";

    struct Args {
        socket: PathBuf,
        state_dir: PathBuf,
        auth: String,
        group: String,
        iface: String,
        dns: String,
        resolv_conf: Option<PathBuf>,
    }

    enum Mode {
        Run(Args),
        Done,
        Remove,
        Check,
    }

    /// `alizyd --check`: the compatibility findings as `severity<TAB>message<TAB>fix`
    /// lines (for the shell installer). Exit status 2 when a blocker was found.
    fn check() -> anyhow::Result<()> {
        use alizy_core::sysprobe::Severity;
        let clean = |s: &str| s.replace(['\t', '\n'], " ");
        let report = alizy_core::sysprobe::probe();
        let mut blocked = false;
        for f in &report.findings {
            let sev = match f.severity {
                Severity::Blocker => {
                    blocked = true;
                    "blocker"
                }
                Severity::Warning => "warning",
                Severity::Info => "info",
            };
            println!(
                "{sev}\t{}\t{}",
                clean(&f.message),
                clean(f.fix.as_deref().unwrap_or(""))
            );
        }
        if blocked {
            std::process::exit(2);
        }
        Ok(())
    }

    fn parse_args() -> anyhow::Result<Mode> {
        let mut a = Args {
            socket: SOCKET_PATH.into(),
            state_dir: "/var/lib/alizy".into(),
            auth: "polkit".into(),
            group: "alizy".into(),
            iface: TUNNEL_IFACE.into(),
            dns: "auto".into(),
            resolv_conf: None,
        };
        let mut it = std::env::args().skip(1);
        while let Some(arg) = it.next() {
            let mut val = || it.next().ok_or_else(|| anyhow!("{arg} needs a value\n{USAGE}"));
            match arg.as_str() {
                "--socket" => a.socket = val()?.into(),
                "--state-dir" => a.state_dir = val()?.into(),
                "--auth" => a.auth = val()?,
                "--group" => a.group = val()?,
                "--iface" => a.iface = val()?,
                "--dns-backend" => a.dns = val()?,
                "--resolv-conf" => a.resolv_conf = Some(val()?.into()),
                "--version" => {
                    println!("alizyd {}", env!("CARGO_PKG_VERSION"));
                    return Ok(Mode::Done);
                }
                "--probe" => {
                    println!("{}", serde_json::to_string_pretty(&alizy_core::sysprobe::probe())?);
                    return Ok(Mode::Done);
                }
                "--check" => return Ok(Mode::Check),
                "--remove-firewall" => return Ok(Mode::Remove),
                "-h" | "--help" => {
                    println!("{USAGE}");
                    return Ok(Mode::Done);
                }
                other => bail!("unknown argument `{other}`\n{USAGE}"),
            }
        }
        if !is_safe_iface_name(&a.iface) {
            bail!("invalid interface name");
        }
        Ok(Mode::Run(a))
    }

    /// sd_notify(READY=1) without a library: one datagram to $NOTIFY_SOCKET.
    fn notify_ready() {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr, UnixDatagram};
        let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
            return;
        };
        let path = path.to_string_lossy().into_owned();
        let addr = match path.strip_prefix('@') {
            Some(abs) => SocketAddr::from_abstract_name(abs.as_bytes()),
            None => SocketAddr::from_pathname(&path),
        };
        let sent = addr.and_then(|a| UnixDatagram::unbound().and_then(|s| s.send_to_addr(b"READY=1", &a)));
        match sent {
            Ok(_) => tracing::info!("signalled readiness to systemd (protection in place)"),
            Err(e) => tracing::error!("could not notify systemd readiness: {e}"),
        }
    }

    /// `alizy-ssh` (uid, primary gid), or `None` (SSH tunnels disabled) when the
    /// user is missing or is root. Prepares the runtime directory when we are root.
    fn ssh_env() -> SshEnv {
        let runtime = PathBuf::from(linux::ssh::RUNTIME_DIR);
        let user = match nix::unistd::User::from_name(linux::ssh::SSH_USER) {
            Ok(Some(u)) if !u.uid.is_root() && u.gid.as_raw() != 0 => Some((u.uid.as_raw(), u.gid.as_raw())),
            Ok(Some(_)) => {
                tracing::error!("{} must not be root; SSH tunnels disabled", linux::ssh::SSH_USER);
                None
            }
            Ok(None) => {
                tracing::warn!(
                    "system user {} is missing; SSH tunnels are unavailable (WireGuard is unaffected)",
                    linux::ssh::SSH_USER
                );
                None
            }
            Err(e) => {
                tracing::warn!("looking up {}: {e}; SSH tunnels unavailable", linux::ssh::SSH_USER);
                None
            }
        };
        if let Some((_, gid)) = user {
            if nix::unistd::geteuid().is_root() {
                if let Err(e) = linux::ssh::ensure_runtime_dir(&runtime, 0, gid) {
                    tracing::error!("SSH runtime directory {}: {e}", runtime.display());
                }
            }
        }
        SshEnv { user, runtime }
    }

    async fn remove_everything() -> anyhow::Result<()> {
        for c in alizy_core::routing::teardown_commands(TUNNEL_IFACE) {
            let _ = crate::exec::run(&c, None).await;
        }
        linux::firewall::remove().await.map_err(|e| anyhow!(e))?;
        println!("Removed table inet alizy, Alizy routing rules and interface {TUNNEL_IFACE}.");
        Ok(())
    }

    pub async fn run() -> anyhow::Result<()> {
        // Private keys live in this process while a tunnel is up: forbid core
        // dumps and ptrace attachment by non-root processes.
        let _ = nix::sys::prctl::set_dumpable(false);
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_env("ALIZYD_LOG").unwrap_or_else(|_| "info".into()),
            )
            .with_target(false)
            .without_time() // journald timestamps
            .init();
        let args = match parse_args()? {
            Mode::Run(a) => a,
            Mode::Done => return Ok(()),
            Mode::Remove => return remove_everything().await,
            Mode::Check => return check(),
        };

        let mode = match args.auth.as_str() {
            "polkit" => {
                let g = nix::unistd::Group::from_name(&args.group)?.ok_or_else(|| {
                    anyhow!(
                        "group `{}` does not exist; install the sysusers file or run `groupadd --system {}`",
                        args.group,
                        args.group
                    )
                })?;
                AuthMode::Polkit { group: g.gid }
            }
            "same-uid" => AuthMode::SameUid,
            other => bail!("unknown auth mode `{other}`"),
        };
        let dns_override = match args.dns.as_str() {
            "auto" => None,
            "systemd-resolved" => Some(Some(DnsBackend::SystemdResolved)),
            "resolvconf" => Some(Some(DnsBackend::Resolvconf)),
            "file" => Some(Some(DnsBackend::ResolvConfFile)),
            "none" => Some(None),
            other => bail!("unknown DNS backend `{other}`"),
        };

        let persist =
            Persist::new(&args.state_dir).with_context(|| format!("state dir {}", args.state_dir.display()))?;
        let adapter = LinuxAdapter::new(&args.state_dir, dns_override, args.resolv_conf.clone()).await;
        tracing::info!(dns_backend = ?adapter.dns_backend(), "alizyd {} starting", env!("CARGO_PKG_VERSION"));
        // The protocol registry: the only place that lists concrete drivers.
        let drivers: Vec<Box<dyn TunnelDriver>> = vec![
            Box::new(WireGuardDriver::new(LinuxWg)),
            Box::new(SshDriver::new(LinuxSsh, ssh_env())),
        ];
        let engine = Engine::start(
            adapter,
            drivers,
            persist,
            Resolver::new(args.resolv_conf.clone()),
            args.iface.clone(),
        )
        .await;

        let auth = Arc::new(Authorizer::new(mode));
        let listener =
            crate::server::bind(&args.socket, &auth).with_context(|| format!("binding {}", args.socket.display()))?;
        tracing::info!("listening on {}", args.socket.display());
        tokio::spawn(crate::server::serve(listener, engine.clone(), auth));

        // Protection is applied (Engine::start ran recovery) and the socket is
        // up: only now tell systemd we are ready. With Type=notify this holds
        // back network-pre.target — and therefore all networking — until the
        // kill switch is actually in the kernel.
        notify_ready();

        // Report exact missing requirements (after protection is in place).
        let report = tokio::task::spawn_blocking(alizy_core::sysprobe::probe).await?;
        for f in &report.findings {
            match f.severity {
                alizy_core::sysprobe::Severity::Blocker => tracing::error!(
                    "{}{}",
                    f.message,
                    f.fix.as_ref().map(|x| format!(" Fix: {x}")).unwrap_or_default()
                ),
                alizy_core::sysprobe::Severity::Warning => tracing::warn!("{}", f.message),
                alizy_core::sysprobe::Severity::Info => tracing::info!("{}", f.message),
            }
        }

        // Supervisor + network monitor.
        let sup = engine.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(std::time::Duration::from_secs(2));
            iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                iv.tick().await;
                sup.tick().await;
            }
        });
        // Split-tunnel DNS refresh on its own loop with an overall deadline,
        // independent of firewall supervision.
        let dns_engine = engine.clone();
        tokio::spawn(async move {
            loop {
                if tokio::time::timeout(std::time::Duration::from_secs(60), dns_engine.refresh_split_dns())
                    .await
                    .is_err()
                {
                    tracing::warn!("split-tunnel DNS refresh round exceeded 60 s; continuing next round");
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
        let mut netrx = linux::netmon::spawn(args.iface.clone());
        let net_engine = engine.clone();
        tokio::spawn(async move {
            while let Some(msg) = netrx.recv().await {
                net_engine.on_network_change(msg).await;
            }
        });

        let mut term = signal(SignalKind::terminate())?;
        let mut int = signal(SignalKind::interrupt())?;
        tokio::select! {
            _ = term.recv() => {},
            _ = int.recv() => {},
        }
        engine.shutdown().await;
        let _ = std::fs::remove_file(&args.socket);
        Ok(())
    }
}
