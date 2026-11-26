//! Linux system detection and package-manager guidance.
//!
//! One shared Linux implementation: behaviour is decided by *detected
//! capabilities* (kernel module, executables, active services, resolv.conf
//! ownership), never by distribution name. The distribution is only used to
//! phrase installation guidance. Nothing here installs anything.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsRelease {
    pub id: String,
    pub id_like: Vec<String>,
    pub name: String,
    pub version_id: String,
    pub pretty_name: String,
}

/// Parse `/etc/os-release` (shell-style KEY=value, optionally quoted).
pub fn parse_os_release(text: &str) -> OsRelease {
    let mut m = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|x| x.strip_suffix('"'))
                .or_else(|| v.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')))
                .unwrap_or(v);
            m.insert(k.trim().to_string(), v.replace("\\\"", "\""));
        }
    }
    let get = |k: &str| m.get(k).cloned().unwrap_or_default();
    OsRelease {
        id: get("ID").to_ascii_lowercase(),
        id_like: get("ID_LIKE")
            .split_whitespace()
            .map(|s| s.to_ascii_lowercase())
            .collect(),
        name: get("NAME"),
        version_id: get("VERSION_ID"),
        pretty_name: get("PRETTY_NAME"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageManager {
    Pacman,
    Apt,
    Dnf,
    Zypper,
    Unknown,
}

/// Dependencies Alizy can check for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Dependency {
    WireguardTools,
    Nftables,
    Iproute2,
    Polkit,
    Resolvconf,
    Webkit,
    AppIndicator,
    OpenSsh,
    Tun2Socks,
}

impl Dependency {
    pub fn label(self) -> &'static str {
        match self {
            Self::WireguardTools => "WireGuard tools (wg)",
            Self::Nftables => "nftables (nft)",
            Self::Iproute2 => "iproute2 (ip)",
            Self::Polkit => "polkit (pkcheck)",
            Self::Resolvconf => "resolvconf",
            Self::Webkit => "WebKitGTK 4.1 runtime",
            Self::AppIndicator => "Ayatana AppIndicator (system tray)",
            Self::OpenSsh => "OpenSSH client (ssh ≥ 8.4)",
            Self::Tun2Socks => "tun2socks (badvpn-tun2socks)",
        }
    }
}

impl PackageManager {
    /// Pick the adapter from the detected executables, falling back to os-release hints.
    pub fn detect(os: &OsRelease, has_exe: impl Fn(&str) -> bool) -> Self {
        let family = |ids: &[&str]| ids.iter().any(|i| os.id == *i || os.id_like.iter().any(|l| l == i));
        // Executables are authoritative; os-release only breaks ties.
        let candidates = [
            (Self::Pacman, "pacman", family(&["arch"])),
            (Self::Apt, "apt-get", family(&["debian", "ubuntu"])),
            (Self::Dnf, "dnf", family(&["fedora", "rhel", "centos"])),
            (Self::Zypper, "zypper", family(&["suse", "opensuse"])),
        ];
        if let Some((pm, _, _)) = candidates.iter().find(|(_, exe, fam)| *fam && has_exe(exe)) {
            return *pm;
        }
        candidates
            .iter()
            .find(|(_, exe, _)| has_exe(exe))
            .map(|(pm, _, _)| *pm)
            .unwrap_or(Self::Unknown)
    }

    pub fn package_name(self, dep: Dependency) -> Option<&'static str> {
        use Dependency::*;
        use PackageManager::*;
        Some(match (self, dep) {
            (Unknown, _) => return None,
            (_, WireguardTools) => "wireguard-tools",
            (_, Nftables) => "nftables",
            (Dnf, Iproute2) => "iproute",
            (_, Iproute2) => "iproute2",
            (Apt, Polkit) => "polkitd",
            (_, Polkit) => "polkit",
            (Pacman, Resolvconf) => "openresolv",
            (Dnf, Resolvconf) => "openresolv",
            (Zypper, Resolvconf) => "openresolv",
            (Apt, Resolvconf) => "resolvconf",
            (Pacman, Webkit) => "webkit2gtk-4.1",
            (Apt, Webkit) => "libwebkit2gtk-4.1-0",
            (Dnf, Webkit) => "webkit2gtk4.1",
            (Zypper, Webkit) => "libwebkit2gtk-4_1-0",
            (Pacman, AppIndicator) => "libayatana-appindicator",
            (Apt, AppIndicator) => "libayatana-appindicator3-1",
            (Dnf, AppIndicator) => "libayatana-appindicator-gtk3",
            (Zypper, AppIndicator) => "libayatana-appindicator3-1",
            (Pacman, OpenSsh) => "openssh",
            (Apt, OpenSsh) => "openssh-client",
            (Dnf, OpenSsh) | (Zypper, OpenSsh) => "openssh-clients",
            (_, Tun2Socks) => "badvpn",
        })
    }

    /// A command the *user* can run. Alizy only displays it.
    pub fn install_command(self, deps: &[Dependency]) -> Option<String> {
        let pkgs: Vec<&str> = deps.iter().filter_map(|d| self.package_name(*d)).collect();
        if pkgs.is_empty() {
            return None;
        }
        let prefix = match self {
            Self::Pacman => "sudo pacman -S --needed",
            Self::Apt => "sudo apt install",
            Self::Dnf => "sudo dnf install",
            Self::Zypper => "sudo zypper install",
            Self::Unknown => return None,
        };
        Some(format!("{prefix} {}", pkgs.join(" ")))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsBackend {
    /// systemd-resolved owns resolution; per-link DNS via resolvectl.
    SystemdResolved,
    /// resolvconf/openresolv present; per-interface records via `resolvconf -a`.
    Resolvconf,
    /// Plain /etc/resolv.conf (possibly written by NetworkManager); Alizy backs it
    /// up, writes its own and re-asserts it while connected.
    ResolvConfFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IptablesFlavor {
    Nft,
    Legacy,
    Absent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Alizy cannot work.
    Blocker,
    /// Feature degraded.
    Warning,
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub message: String,
    pub fix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemReport {
    pub os: OsRelease,
    pub kernel: String,
    pub package_manager: PackageManager,
    pub kernel_wireguard: KernelWireguard,
    pub executables: BTreeMap<String, Option<String>>,
    pub systemd: bool,
    pub firewalld_active: bool,
    pub ufw_active: bool,
    pub iptables: IptablesFlavor,
    pub network_manager_active: bool,
    pub resolved_active: bool,
    pub resolv_conf_target: Option<String>,
    pub dns_backend: DnsBackend,
    pub desktop: Option<String>,
    pub findings: Vec<Finding>,
    /// True when every optional SSH-tunnel dependency is present and usable.
    #[serde(default)]
    pub ssh_ready: bool,
    /// Missing or too-old optional SSH-tunnel dependencies. Never blocks WireGuard.
    #[serde(default)]
    pub ssh_missing: Vec<Dependency>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelWireguard {
    /// /sys/module/wireguard exists (loaded or built-in).
    Loaded,
    /// A loadable module file exists for the running kernel.
    Available,
    Missing,
}

/// Pick the DNS backend from facts, not from the distribution name.
pub fn choose_dns_backend(resolved_active: bool, resolv_conf_target: Option<&str>, has_resolvconf: bool) -> DnsBackend {
    let points_to_resolved = resolv_conf_target
        .map(|t| t.contains("/run/systemd/resolve/"))
        .unwrap_or(false);
    if resolved_active && points_to_resolved {
        DnsBackend::SystemdResolved
    } else if has_resolvconf {
        DnsBackend::Resolvconf
    } else {
        DnsBackend::ResolvConfFile
    }
}

/// A usable resolvconf: not systemd's compatibility shim (a link to
/// `resolvectl`), which only works while systemd-resolved is running and is
/// covered by the systemd-resolved backend when it is.
pub fn has_real_resolvconf() -> bool {
    find_exe("resolvconf").is_some_and(|p| !is_resolvectl_shim(Path::new(&p)))
}

fn is_resolvectl_shim(path: &Path) -> bool {
    std::fs::canonicalize(path)
        .ok()
        .and_then(|p| p.file_name().map(|n| n == "resolvectl"))
        .unwrap_or(false)
}

/// Executables the daemon needs, mapped to the package that provides them.
pub const REQUIRED_EXES: &[(&str, Dependency)] = &[
    ("wg", Dependency::WireguardTools),
    ("ip", Dependency::Iproute2),
    ("nft", Dependency::Nftables),
    ("pkcheck", Dependency::Polkit),
];
pub const OPTIONAL_EXES: &[&str] = &[
    "wg-quick",
    "resolvectl",
    "resolvconf",
    "nmcli",
    "iptables",
    "systemctl",
    "firewall-cmd",
    "ufw",
    "ssh",
    "ssh-keyscan",
    "badvpn-tun2socks",
];

/// Parse `ssh -V` output (`OpenSSH_X.Yp...`); true when the version is 8.4 or newer.
pub fn openssh_version_ok(ssh_v_output: &str) -> bool {
    let Some(rest) = ssh_v_output.trim_start().strip_prefix("OpenSSH_") else {
        return false;
    };
    let mut parts = rest.splitn(2, '.');
    let major: u32 = match parts.next().and_then(|m| m.parse().ok()) {
        Some(m) => m,
        None => return false,
    };
    let minor: u32 = parts
        .next()
        .map(|m| m.chars().take_while(|c| c.is_ascii_digit()).collect::<String>())
        .and_then(|m| m.parse().ok())
        .unwrap_or(0);
    (major, minor) >= (8, 4)
}

/// Pure SSH dependency check. `ssh_v` is the `ssh -V` output when it could be
/// obtained; `None` (no output, timed out) counts OpenSSH as missing. The
/// daemon calls this with `ssh -V` run as alizy-ssh.
pub fn compute_ssh_missing(has_exe: impl Fn(&str) -> bool, ssh_v: Option<&str>) -> Vec<Dependency> {
    let mut missing = Vec::new();
    let openssh_ok = has_exe("ssh") && has_exe("ssh-keyscan") && ssh_v.map(openssh_version_ok).unwrap_or(false);
    if !openssh_ok {
        missing.push(Dependency::OpenSsh);
    }
    if !has_exe("badvpn-tun2socks") {
        missing.push(Dependency::Tun2Socks);
    }
    missing
}

/// Presence-only SSH dependency check, used by [`probe`]: it never executes
/// ssh (`probe` may run as root). An installed ssh of unknown version is
/// *not* reported missing; the daemon replaces this with the versioned check
/// ([`compute_ssh_missing`] fed by `ssh -V` run as alizy-ssh) via
/// [`SystemReport::set_ssh_missing`].
pub fn compute_ssh_missing_unversioned(has_exe: impl Fn(&str) -> bool) -> Vec<Dependency> {
    let mut missing = Vec::new();
    if !(has_exe("ssh") && has_exe("ssh-keyscan")) {
        missing.push(Dependency::OpenSsh);
    }
    if !has_exe("badvpn-tun2socks") {
        missing.push(Dependency::Tun2Socks);
    }
    missing
}

/// Fixed search path. The daemon never inherits PATH from a caller.
pub const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

pub fn find_exe(name: &str) -> Option<String> {
    SAFE_PATH.split(':').map(|d| Path::new(d).join(name)).find_map(|p| {
        let md = std::fs::metadata(&p).ok()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if md.is_file() && md.permissions().mode() & 0o111 != 0 {
                return Some(p.to_string_lossy().into_owned());
            }
            None
        }
        #[cfg(not(unix))]
        {
            md.is_file().then(|| p.to_string_lossy().into_owned())
        }
    })
}

fn systemctl_active(unit: &str) -> bool {
    let Some(sc) = find_exe("systemctl") else { return false };
    std::process::Command::new(sc)
        .args(["is-active", "--quiet", unit])
        .env_clear()
        .env("PATH", SAFE_PATH)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn kernel_wireguard(kernel: &str) -> KernelWireguard {
    if Path::new("/sys/module/wireguard").exists() {
        return KernelWireguard::Loaded;
    }
    let base = format!("/lib/modules/{kernel}");
    let found = ["kernel/drivers/net/wireguard", "updates/dkms", "extra"]
        .iter()
        .any(|d| {
            std::fs::read_dir(Path::new(&base).join(d))
                .map(|rd| {
                    rd.flatten()
                        .any(|e| e.file_name().to_string_lossy().starts_with("wireguard.ko"))
                })
                .unwrap_or(false)
        });
    if found {
        KernelWireguard::Available
    } else {
        KernelWireguard::Missing
    }
}

fn iptables_flavor() -> IptablesFlavor {
    let Some(ipt) = find_exe("iptables") else {
        return IptablesFlavor::Absent;
    };
    let out = std::process::Command::new(ipt).arg("--version").env_clear().output();
    match out {
        Ok(o) if String::from_utf8_lossy(&o.stdout).contains("nf_tables") => IptablesFlavor::Nft,
        Ok(_) => IptablesFlavor::Legacy,
        Err(_) => IptablesFlavor::Absent,
    }
}

fn ufw_enabled() -> bool {
    std::fs::read_to_string("/etc/ufw/ufw.conf")
        .map(|s| s.lines().any(|l| l.trim().eq_ignore_ascii_case("ENABLED=yes")))
        .unwrap_or(false)
}

/// Run all detection. Safe to call unprivileged (no root-only operations).
pub fn probe() -> SystemReport {
    let os = std::fs::read_to_string("/etc/os-release")
        .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
        .map(|t| parse_os_release(&t))
        .unwrap_or_default();
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let mut executables = BTreeMap::new();
    for (e, _) in REQUIRED_EXES {
        executables.insert(e.to_string(), find_exe(e));
    }
    for e in OPTIONAL_EXES {
        executables.insert(e.to_string(), find_exe(e));
    }
    let has = |e: &str| {
        executables
            .get(e)
            .map(|v| v.is_some())
            .unwrap_or_else(|| find_exe(e).is_some())
    };
    let package_manager = PackageManager::detect(&os, |e| find_exe(e).is_some());
    let systemd = Path::new("/run/systemd/system").is_dir();
    let resolved_active = systemd && systemctl_active("systemd-resolved.service");
    let resolv_conf_target = std::fs::canonicalize("/etc/resolv.conf")
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let dns_backend = choose_dns_backend(resolved_active, resolv_conf_target.as_deref(), has_real_resolvconf());
    let kw = kernel_wireguard(&kernel);
    let ssh_missing = compute_ssh_missing_unversioned(has);
    let mut report = SystemReport {
        firewalld_active: systemd && systemctl_active("firewalld.service"),
        ufw_active: ufw_enabled(),
        iptables: iptables_flavor(),
        network_manager_active: systemd && systemctl_active("NetworkManager.service"),
        desktop: std::env::var("XDG_CURRENT_DESKTOP").ok().filter(|s| !s.is_empty()),
        os,
        kernel,
        package_manager,
        kernel_wireguard: kw,
        executables,
        systemd,
        resolved_active,
        resolv_conf_target,
        dns_backend,
        findings: Vec::new(),
        ssh_ready: ssh_missing.is_empty(),
        ssh_missing,
    };
    report.findings = analyse(&report);
    report
}

impl SystemReport {
    /// Replace the SSH dependency result (e.g. with the daemon's versioned
    /// check) and recompute `ssh_ready` and the findings.
    pub fn set_ssh_missing(&mut self, missing: Vec<Dependency>) {
        self.ssh_ready = missing.is_empty();
        self.ssh_missing = missing;
        self.findings = analyse(self);
    }
}

/// Turn raw facts into actionable findings with exact missing requirements.
pub fn analyse(r: &SystemReport) -> Vec<Finding> {
    let mut f = Vec::new();
    let pm = r.package_manager;
    let missing: Vec<Dependency> = REQUIRED_EXES
        .iter()
        .filter(|(e, _)| r.executables.get(*e).map(|v| v.is_none()).unwrap_or(true))
        .map(|(_, d)| *d)
        .collect();
    for (exe, dep) in REQUIRED_EXES {
        if missing.contains(dep) {
            f.push(Finding {
                severity: Severity::Blocker,
                message: format!("Required executable `{exe}` was not found ({}).", dep.label()),
                fix: pm.install_command(&[*dep]),
            });
        }
    }
    match r.kernel_wireguard {
        KernelWireguard::Missing => f.push(Finding {
            severity: Severity::Blocker,
            message: format!(
                "Kernel {} has no WireGuard module. WireGuard is built into Linux 5.6+; install a kernel with CONFIG_WIREGUARD.",
                r.kernel
            ),
            fix: None,
        }),
        KernelWireguard::Available => f.push(Finding {
            severity: Severity::Info,
            message: "WireGuard kernel module is available and will be loaded on first connect.".into(),
            fix: None,
        }),
        KernelWireguard::Loaded => {}
    }
    if !r.systemd {
        f.push(Finding {
            severity: Severity::Warning,
            message: "systemd was not detected. The alizyd service unit and boot-time kill-switch recovery require systemd; start alizyd from your init system manually.".into(),
            fix: None,
        });
    }
    if r.firewalld_active {
        f.push(Finding {
            severity: Severity::Info,
            message: "firewalld is active. Alizy uses its own nftables table alongside firewalld and re-applies it if a reload removes it.".into(),
            fix: None,
        });
    }
    if r.ufw_active {
        f.push(Finding {
            severity: Severity::Info,
            message: "ufw is active. Its rules are preserved; Alizy's drop rules are enforced in addition to them."
                .into(),
            fix: None,
        });
    }
    if r.iptables == IptablesFlavor::Legacy {
        f.push(Finding {
            severity: Severity::Info,
            message: "iptables-legacy is in use by other software. Both rule sets apply; a drop in either is final, so the kill switch still holds.".into(),
            fix: None,
        });
    }
    if r.dns_backend == DnsBackend::ResolvConfFile {
        f.push(Finding {
            severity: Severity::Warning,
            message: if r.network_manager_active {
                "DNS is managed by NetworkManager without systemd-resolved. Alizy backs up /etc/resolv.conf, writes the VPN DNS and re-asserts it while connected; the firewall blocks DNS outside the tunnel either way.".into()
            } else {
                "No DNS manager detected. Alizy will back up and rewrite /etc/resolv.conf while connected.".into()
            },
            fix: pm.install_command(&[Dependency::Resolvconf]),
        });
    }
    if !r.ssh_missing.is_empty() {
        let names: Vec<&str> = r.ssh_missing.iter().map(|d| d.label()).collect();
        let mut message = format!("SSH profiles unavailable: missing {}.", names.join(", "));
        if r.ssh_missing.contains(&Dependency::OpenSsh) {
            message.push_str(" OpenSSH 8.4 or newer required.");
        }
        message.push_str(" WireGuard profiles are unaffected.");
        // Optional feature: informational, so WireGuard-only users see no warning.
        f.push(Finding {
            severity: Severity::Info,
            message,
            fix: pm.install_command(&r.ssh_missing),
        });
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(id: &str, like: &str) -> OsRelease {
        OsRelease {
            id: id.into(),
            id_like: like.split_whitespace().map(String::from).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn systemd_resolvconf_shim_is_not_resolvconf() {
        let dir = std::env::temp_dir().join(format!("alizy-shim-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("resolvectl");
        std::fs::write(&target, b"").unwrap();
        let link = dir.join("resolvconf");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(is_resolvectl_shim(&link));
        let real = dir.join("real-resolvconf");
        std::fs::write(&real, b"").unwrap();
        assert!(!is_resolvectl_shim(&real));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn parses_os_release() {
        let r =
            parse_os_release("NAME=\"Linux Mint\"\nID=linuxmint\nID_LIKE=\"ubuntu debian\"\nVERSION_ID=\"22\"\n# c\n");
        assert_eq!(r.id, "linuxmint");
        assert_eq!(r.id_like, vec!["ubuntu", "debian"]);
        assert_eq!(r.name, "Linux Mint");
        assert_eq!(r.version_id, "22");
    }

    #[test]
    fn package_manager_from_executables_not_name() {
        // EndeavourOS / Manjaro are Arch-like
        assert_eq!(
            PackageManager::detect(&os("endeavouros", "arch"), |e| e == "pacman"),
            PackageManager::Pacman
        );
        assert_eq!(
            PackageManager::detect(&os("pop", "ubuntu debian"), |e| e == "apt-get"),
            PackageManager::Apt
        );
        assert_eq!(
            PackageManager::detect(&os("opensuse-tumbleweed", "opensuse suse"), |e| e == "zypper"),
            PackageManager::Zypper
        );
        // name says fedora but only apt exists → trust the system
        assert_eq!(
            PackageManager::detect(&os("fedora", ""), |e| e == "apt-get"),
            PackageManager::Apt
        );
        assert_eq!(PackageManager::detect(&os("x", ""), |_| false), PackageManager::Unknown);
    }

    #[test]
    fn install_guidance() {
        use Dependency::*;
        assert_eq!(
            PackageManager::Dnf
                .install_command(&[WireguardTools, Iproute2])
                .unwrap(),
            "sudo dnf install wireguard-tools iproute"
        );
        assert_eq!(
            PackageManager::Apt.install_command(&[Polkit]).unwrap(),
            "sudo apt install polkitd"
        );
        assert_eq!(
            PackageManager::Pacman.install_command(&[Nftables]).unwrap(),
            "sudo pacman -S --needed nftables"
        );
        assert!(PackageManager::Unknown.install_command(&[Nftables]).is_none());
    }

    #[test]
    fn dns_backend_from_facts() {
        assert_eq!(
            choose_dns_backend(true, Some("/run/systemd/resolve/stub-resolv.conf"), false),
            DnsBackend::SystemdResolved
        );
        // resolved running but resolv.conf managed by NetworkManager → not resolved
        assert_eq!(
            choose_dns_backend(true, Some("/etc/resolv.conf"), false),
            DnsBackend::ResolvConfFile
        );
        assert_eq!(
            choose_dns_backend(false, Some("/etc/resolv.conf"), true),
            DnsBackend::Resolvconf
        );
    }

    #[test]
    fn findings_name_exact_missing_requirement() {
        let mut exes = BTreeMap::new();
        exes.insert("wg".to_string(), None);
        exes.insert("ip".to_string(), Some("/usr/bin/ip".into()));
        exes.insert("nft".to_string(), Some("/usr/bin/nft".into()));
        exes.insert("pkcheck".to_string(), Some("/usr/bin/pkcheck".into()));
        let r = SystemReport {
            os: os("debian", ""),
            kernel: "6.1.0".into(),
            package_manager: PackageManager::Apt,
            kernel_wireguard: KernelWireguard::Loaded,
            executables: exes,
            systemd: true,
            firewalld_active: false,
            ufw_active: true,
            iptables: IptablesFlavor::Nft,
            network_manager_active: true,
            resolved_active: false,
            resolv_conf_target: Some("/etc/resolv.conf".into()),
            dns_backend: DnsBackend::ResolvConfFile,
            desktop: None,
            findings: vec![],
            ssh_ready: false,
            ssh_missing: vec![],
        };
        let f = analyse(&r);
        let blocker = f.iter().find(|x| x.severity == Severity::Blocker).unwrap();
        assert!(blocker.message.contains("`wg`"));
        assert_eq!(blocker.fix.as_deref(), Some("sudo apt install wireguard-tools"));
        assert!(f.iter().any(|x| x.message.contains("ufw")));
        assert!(f.iter().any(|x| x.message.contains("NetworkManager")));
    }

    fn report_with_ssh_missing(pm: PackageManager, ssh_missing: Vec<Dependency>) -> SystemReport {
        let mut exes = BTreeMap::new();
        for (e, _) in REQUIRED_EXES {
            exes.insert(e.to_string(), Some(format!("/usr/bin/{e}")));
        }
        SystemReport {
            os: os("arch", ""),
            kernel: "6.1.0".into(),
            package_manager: pm,
            kernel_wireguard: KernelWireguard::Loaded,
            executables: exes,
            systemd: true,
            firewalld_active: false,
            ufw_active: false,
            iptables: IptablesFlavor::Nft,
            network_manager_active: false,
            resolved_active: true,
            resolv_conf_target: Some("/run/systemd/resolve/stub-resolv.conf".into()),
            dns_backend: DnsBackend::SystemdResolved,
            desktop: None,
            findings: vec![],
            ssh_ready: ssh_missing.is_empty(),
            ssh_missing,
        }
    }

    #[test]
    fn ssh_missing_is_info_not_warning_or_blocker() {
        let r = report_with_ssh_missing(PackageManager::Pacman, vec![Dependency::OpenSsh, Dependency::Tun2Socks]);
        let f = analyse(&r);
        assert!(!f.iter().any(|x| x.severity == Severity::Blocker));
        assert!(!f.iter().any(|x| x.severity == Severity::Warning));
        let w = f
            .iter()
            .find(|x| x.message.contains("SSH profiles unavailable"))
            .unwrap();
        assert_eq!(w.severity, Severity::Info);
        assert!(w.message.contains("OpenSSH 8.4 or newer required"));
        assert_eq!(w.fix.as_deref(), Some("sudo pacman -S --needed openssh badvpn"));
        let ok = report_with_ssh_missing(PackageManager::Pacman, vec![]);
        assert!(!analyse(&ok).iter().any(|x| x.message.contains("SSH profiles")));
    }

    #[test]
    fn openssh_version_parse() {
        assert!(openssh_version_ok("OpenSSH_10.6p2, OpenSSL 3.0"));
        assert!(openssh_version_ok("OpenSSH_8.4p1"));
        assert!(openssh_version_ok("OpenSSH_9.0p1 Debian"));
        assert!(!openssh_version_ok("OpenSSH_8.3p1"));
        assert!(!openssh_version_ok("OpenSSH_7.9p1"));
        assert!(!openssh_version_ok("garbage"));
        assert!(!openssh_version_ok(""));
    }

    #[test]
    fn ssh_dependency_packages() {
        use Dependency::*;
        assert_eq!(PackageManager::Pacman.package_name(OpenSsh), Some("openssh"));
        assert_eq!(PackageManager::Apt.package_name(OpenSsh), Some("openssh-client"));
        assert_eq!(PackageManager::Dnf.package_name(OpenSsh), Some("openssh-clients"));
        assert_eq!(PackageManager::Zypper.package_name(OpenSsh), Some("openssh-clients"));
        for pm in [
            PackageManager::Pacman,
            PackageManager::Apt,
            PackageManager::Dnf,
            PackageManager::Zypper,
        ] {
            assert_eq!(pm.package_name(Tun2Socks), Some("badvpn"));
        }
        assert_eq!(OpenSsh.label(), "OpenSSH client (ssh \u{2265} 8.4)");
        assert_eq!(Tun2Socks.label(), "tun2socks (badvpn-tun2socks)");
    }

    #[test]
    fn ssh_missing_computed_from_exes_and_version() {
        let all = |_: &str| true;
        assert!(compute_ssh_missing(all, Some("OpenSSH_9.6p1")).is_empty());
        assert_eq!(
            compute_ssh_missing(all, Some("OpenSSH_8.3p1")),
            vec![Dependency::OpenSsh]
        );
        assert_eq!(
            compute_ssh_missing(|e| e == "ssh", Some("OpenSSH_9.6p1")),
            vec![Dependency::OpenSsh, Dependency::Tun2Socks]
        );
        assert_eq!(
            compute_ssh_missing(|e| e == "badvpn-tun2socks", None),
            vec![Dependency::OpenSsh]
        );
    }

    #[test]
    fn probe_ssh_check_is_presence_only() {
        // The pure function `probe` uses: it gets only an existence check, so
        // it cannot run anything. Version unknown is not "missing".
        let seen = std::cell::RefCell::new(Vec::new());
        let all = |e: &str| {
            seen.borrow_mut().push(e.to_string());
            true
        };
        assert!(compute_ssh_missing_unversioned(all).is_empty());
        assert_eq!(*seen.borrow(), ["ssh", "ssh-keyscan", "badvpn-tun2socks"]);
        assert_eq!(
            compute_ssh_missing_unversioned(|e| e == "ssh"),
            vec![Dependency::OpenSsh, Dependency::Tun2Socks]
        );
        assert_eq!(
            compute_ssh_missing_unversioned(|e| e != "badvpn-tun2socks"),
            vec![Dependency::Tun2Socks]
        );
    }

    #[test]
    fn daemon_overrides_ssh_result() {
        let mut r = report_with_ssh_missing(PackageManager::Apt, vec![]);
        r.findings = analyse(&r);
        assert!(r.ssh_ready);
        // e.g. `ssh -V` as alizy-ssh says 8.2: too old.
        r.set_ssh_missing(vec![Dependency::OpenSsh]);
        assert!(!r.ssh_ready);
        assert_eq!(r.ssh_missing, vec![Dependency::OpenSsh]);
        let f = r.findings.iter().find(|x| x.message.contains("SSH profiles")).unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.fix.as_deref(), Some("sudo apt install openssh-client"));
        r.set_ssh_missing(vec![]);
        assert!(r.ssh_ready && !r.findings.iter().any(|x| x.message.contains("SSH profiles")));
    }
}
