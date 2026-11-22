//! Kernel WireGuard via iproute2 and wireguard-tools. Keys are passed to
//! `wg setconf` over stdin; no key ever touches the filesystem or argv.

use crate::exec::{argv, run};
use alizy_core::config::WgConfig;
use alizy_core::firewall::FWMARK;
use alizy_core::ipc::TunnelStats;
use std::net::SocketAddr;

/// Interface presence in the daemon's *network namespace*. /proc/net is
/// per-netns, whereas /sys/class/net reflects whichever sysfs was mounted.
pub fn exists(iface: &str) -> bool {
    std::fs::read_to_string("/proc/net/dev")
        .map(|s| {
            s.lines()
                .skip(2)
                .any(|l| l.split(':').next().map(str::trim) == Some(iface))
        })
        .unwrap_or(false)
}

pub async fn create(iface: &str, cfg: &WgConfig, endpoints: &[Option<SocketAddr>]) -> Result<(), String> {
    run(&argv(&["ip", "link", "add", "dev", iface, "type", "wireguard"]), None)
        .await
        .map_err(|e| {
            format!("could not create WireGuard interface (is the wireguard kernel module available?): {e}")
        })?;
    let conf = cfg.to_wg_setconf(endpoints, FWMARK);
    run(&argv(&["wg", "setconf", iface, "/dev/stdin"]), Some(conf.as_bytes()))
        .await
        .map_err(|e| format!("wg setconf failed: {e}"))?;
    Ok(())
}

/// Update one peer endpoint in place (used after network changes).
pub async fn set_endpoint(iface: &str, peer: &str, ep: SocketAddr) -> Result<(), String> {
    run(
        &argv(&["wg", "set", iface, "peer", peer, "endpoint", &ep.to_string()]),
        None,
    )
    .await
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// Statistics through `wg show <if> transfer|latest-handshakes|endpoints`, which
/// (unlike `dump`) never print the private key.
pub async fn stats(iface: &str) -> Result<Option<TunnelStats>, String> {
    if !exists(iface) {
        return Ok(None);
    }
    let mut out = Vec::with_capacity(3);
    for what in ["transfer", "latest-handshakes", "endpoints"] {
        out.push(
            run(&argv(&["wg", "show", iface, what]), None)
                .await
                .map_err(|e| e.to_string())?,
        );
    }
    let (transfer, handshakes, endpoints) = (&out[0], &out[1], &out[2]);
    Ok(Some(parse_stats(transfer, handshakes, endpoints)))
}

pub fn parse_stats(transfer: &str, handshakes: &str, endpoints: &str) -> TunnelStats {
    let mut s = TunnelStats::default();
    for line in transfer.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() == 3 {
            s.rx_bytes += f[1].parse::<u64>().unwrap_or(0);
            s.tx_bytes += f[2].parse::<u64>().unwrap_or(0);
        }
    }
    for line in handshakes.lines() {
        if let Some(ts) = line.split_whitespace().nth(1).and_then(|t| t.parse::<u64>().ok()) {
            s.last_handshake = s.last_handshake.max(ts);
        }
    }
    s.endpoint = endpoints
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1))
        .find_map(|e| e.parse::<SocketAddr>().ok());
    s
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_wg_show_output() {
        let s = super::parse_stats(
            "PEER1=\t100\t200\nPEER2=\t1\t2\n",
            "PEER1=\t1700000000\nPEER2=\t0\n",
            "PEER1=\t198.51.100.7:51820\nPEER2=\t(none)\n",
        );
        assert_eq!((s.rx_bytes, s.tx_bytes, s.last_handshake), (101, 202, 1700000000));
        assert_eq!(s.endpoint.unwrap().to_string(), "198.51.100.7:51820");
    }
}
