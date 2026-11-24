//! Prints a representative firewall plan. Used by tests/leak to syntax-check
//! the renderer against the real kernel: `cargo run --example render_plan`.
use alizy_core::firewall::{FirewallPlan, NetworkPolicy, TunnelRules};
use alizy_core::split::DirectSets;

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let policy = NetworkPolicy {
        kill_switch: true,
        allow_lan: mode != "nolan",
        ipv6_enabled: mode != "nov6",
        ..Default::default()
    };
    let tunnel = Some(TunnelRules {
        iface: "alizy0".into(),
        endpoints: vec![
            "198.51.100.7:51820".parse().unwrap(),
            "[2001:db8::7]:51820".parse().unwrap(),
        ],
        ..Default::default()
    });
    let direct = DirectSets {
        v4: vec![("192.0.2.0".parse().unwrap(), "192.0.2.127".parse().unwrap())],
        v6: vec![("2001:db8:100::".parse().unwrap(), "2001:db8:100::ffff".parse().unwrap())],
    };
    print!("{}", FirewallPlan::with_split(&policy, tunnel, direct).render());
}
