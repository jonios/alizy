//! nftables backend. Applies rendered plans atomically and verifies them by
//! reading the table back from the kernel.

use crate::exec::{argv, run, ExecError};
use alizy_core::firewall::{render_removal, FirewallPlan, TABLE_FAMILY, TABLE_NAME};

pub async fn apply(plan: &FirewallPlan) -> Result<(), String> {
    let script = plan.render();
    run(&argv(&["nft", "-f", "-"]), Some(script.as_bytes()))
        .await
        .map(|_| ())
        .map_err(|e| format!("nftables rejected the ruleset: {e}"))
}

/// Read back `inet alizy`. `Ok(None)` = table absent.
pub async fn read_table() -> Result<Option<String>, String> {
    match run(&argv(&["nft", "list", "table", TABLE_FAMILY, TABLE_NAME]), None).await {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.stderr_contains("No such file") => Ok(None),
        Err(ExecError::NotFound(p)) => Err(format!("`{p}` is not installed")),
        Err(e) => Err(e.to_string()),
    }
}

/// Canonical form of `nft list table` output for comparison: rule handles
/// and counter values removed, whitespace normalised.
pub fn normalize(table: &str) -> String {
    let mut out = String::with_capacity(table.len());
    for line in table.lines() {
        let mut words: Vec<&str> = line.split_whitespace().collect();
        if let Some(pos) = words.iter().position(|w| *w == "#") {
            words.truncate(pos); // "# handle N"
        }
        let mut cleaned = Vec::with_capacity(words.len());
        let mut k = 0;
        while k < words.len() {
            if words[k] == "packets" || words[k] == "bytes" {
                k += 2; // counter values change constantly
                continue;
            }
            cleaned.push(words[k]);
            k += 1;
        }
        if !cleaned.is_empty() {
            out.push_str(&cleaned.join(" "));
            out.push('\n');
        }
    }
    out
}

/// Snapshot taken right after Alizy's own atomic apply.
#[derive(Clone)]
pub struct Baseline {
    pub tag: String,
    /// None = the table is expected to be absent.
    pub table: Option<String>,
}

/// Apply, then read back and record the exact kernel state as the baseline.
pub async fn apply_and_snapshot(plan: &FirewallPlan) -> Result<Baseline, String> {
    apply(plan).await?;
    let read = read_table().await?;
    let tag = plan.tag();
    match (plan.needs_table(), read) {
        (true, Some(t)) if t.contains(&tag) && (!plan.kill_switch || t.contains("kill-switch")) => Ok(Baseline {
            tag,
            table: Some(normalize(&t)),
        }),
        (true, _) => Err("the applied ruleset could not be read back from the kernel".into()),
        (false, None) => Ok(Baseline { tag, table: None }),
        (false, Some(_)) => Err("the Alizy table is still present after removal".into()),
    }
}

/// True only if the kernel table is identical (modulo handles/counters) to the baseline.
pub async fn verify_against(baseline: &Baseline) -> Result<bool, String> {
    let now = read_table().await?;
    Ok(match (&baseline.table, now) {
        (Some(expected), Some(t)) => normalize(&t) == *expected,
        (None, None) => true,
        _ => false,
    })
}

pub async fn remove() -> Result<(), String> {
    run(&argv(&["nft", "-f", "-"]), Some(render_removal().as_bytes()))
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::normalize;

    #[test]
    fn normalization_ignores_handles_and_counters_only() {
        let a = "table inet alizy { # handle 7\n  chain output { # handle 1\n    counter packets 10 bytes 900 reject with icmpx admin-prohibited comment \"x\" # handle 4\n  }\n}\n";
        let b = "table inet alizy { # handle 9\n  chain output { # handle 2\n    counter packets 99 bytes 1 reject with icmpx admin-prohibited comment \"x\" # handle 5\n  }\n}\n";
        assert_eq!(normalize(a), normalize(b));
        let tampered = b.replace("reject with icmpx admin-prohibited", "accept");
        assert_ne!(normalize(a), normalize(&tampered));
        let inserted = b.replace(
            "chain output { # handle 2\n",
            "chain output { # handle 2\n    accept # handle 8\n",
        );
        assert_ne!(normalize(a), normalize(&inserted));
    }
}
