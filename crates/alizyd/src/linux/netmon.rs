//! Network change detection via `ip -o monitor`. Events on Alizy's own
//! interface are ignored; everything else is debounced into a single signal.

use alizy_core::sysprobe::{find_exe, SAFE_PATH};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

pub fn spawn(own_iface: String) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel(4);
    tokio::spawn(async move {
        loop {
            if let Err(e) = monitor(&own_iface, &tx).await {
                tracing::warn!("network monitor stopped: {e}; restarting in 5s");
            }
            if tx.is_closed() {
                return;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
    rx
}

async fn monitor(own_iface: &str, tx: &mpsc::Sender<String>) -> Result<(), String> {
    let ip = find_exe("ip").ok_or("`ip` not installed")?;
    let mut child = Command::new(ip)
        .args(["-o", "monitor", "link", "address", "route"])
        .env_clear()
        .env("PATH", SAFE_PATH)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut lines = BufReader::new(child.stdout.take().ok_or("no stdout")?).lines();
    let mut pending: Option<String> = None;
    loop {
        let next = if pending.is_some() {
            tokio::time::timeout(Duration::from_millis(1500), lines.next_line()).await
        } else {
            Ok(lines.next_line().await)
        };
        match next {
            Ok(Ok(Some(line))) => {
                if is_relevant(&line, own_iface) {
                    pending.get_or_insert_with(|| summarize(&line));
                }
            }
            Ok(Ok(None)) => return Err("ip monitor exited".into()),
            Ok(Err(e)) => return Err(e.to_string()),
            Err(_) => {
                // Debounce window elapsed.
                if let Some(msg) = pending.take() {
                    if tx.send(msg).await.is_err() {
                        return Ok(());
                    }
                }
            }
        }
    }
}

fn is_relevant(line: &str, own_iface: &str) -> bool {
    let own = format!("dev {own_iface} ");
    let own_link = format!(": {own_iface}:");
    !line.contains(&own) && !line.contains(&own_link) && !line.contains(" table 19034") && !line.contains("dev lo ")
}

fn summarize(line: &str) -> String {
    line.chars().take(160).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn filters_own_interface() {
        assert!(!super::is_relevant(
            "3: alizy0: <POINTOPOINT,NOARP,UP> mtu 1420",
            "alizy0"
        ));
        assert!(!super::is_relevant("10.0.0.0/8 dev alizy0 scope link", "alizy0"));
        assert!(super::is_relevant(
            "2: wlan0: <BROADCAST,MULTICAST,UP> mtu 1500 state DOWN",
            "alizy0"
        ));
        assert!(super::is_relevant(
            "default via 192.168.1.1 dev wlan0 proto dhcp",
            "alizy0"
        ));
    }
}
