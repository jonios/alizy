//! Connection state machine.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Reconnecting,
    Error,
    /// No tunnel, kill switch is blocking all non-permitted traffic.
    Protected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    ConnectRequested,
    TunnelUp,
    /// Connection attempt or live tunnel failed.
    Failed {
        kill_switch: bool,
    },
    DisconnectRequested,
    /// Teardown finished.
    TornDown {
        kill_switch: bool,
    },
    /// Handshake stale, link lost or network changed while connected.
    Degraded,
    /// Kill switch toggled while there is no tunnel.
    KillSwitchChanged {
        enabled: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("illegal transition from {from:?} on {event:?}")]
pub struct IllegalTransition {
    pub from: ConnectionState,
    pub event: Event,
}

/// The single source of truth for legal state changes.
pub fn transition(from: ConnectionState, event: Event) -> Result<ConnectionState, IllegalTransition> {
    use ConnectionState::*;
    use Event::*;
    let to = match (from, event) {
        // Connecting is allowed from any idle or live state (switching profiles
        // from Connected goes straight to Connecting; the firewall stays up).
        (Disconnected | Protected | Error | Connected | Reconnecting, ConnectRequested) => Connecting,
        (Connecting | Reconnecting, TunnelUp) => Connected,
        (Connecting | Reconnecting | Connected, Failed { kill_switch }) => {
            if kill_switch {
                Protected
            } else {
                Error
            }
        }
        (Connected, Degraded) => Reconnecting,
        (Connecting | Connected | Reconnecting | Error | Protected, DisconnectRequested) => Disconnecting,
        (Disconnecting, TornDown { kill_switch }) => {
            if kill_switch {
                Protected
            } else {
                Disconnected
            }
        }
        (Disconnected | Error, KillSwitchChanged { enabled: true }) => Protected,
        (Protected, KillSwitchChanged { enabled: false }) => Disconnected,
        (s @ (Connected | Connecting | Reconnecting), KillSwitchChanged { .. }) => s,
        (s @ (Disconnected | Error), KillSwitchChanged { enabled: false }) => s,
        (Protected, KillSwitchChanged { enabled: true }) => Protected,
        _ => return Err(IllegalTransition { from, event }),
    };
    Ok(to)
}

impl ConnectionState {
    pub fn has_tunnel(self) -> bool {
        matches!(self, Self::Connected | Self::Reconnecting | Self::Connecting)
    }
}

#[cfg(test)]
mod tests {
    use super::ConnectionState::*;
    use super::Event::*;
    use super::*;

    #[test]
    fn happy_path() {
        let s = transition(Disconnected, ConnectRequested).unwrap();
        let s = transition(s, TunnelUp).unwrap();
        assert_eq!(s, Connected);
        let s = transition(s, DisconnectRequested).unwrap();
        assert_eq!(transition(s, TornDown { kill_switch: false }).unwrap(), Disconnected);
    }

    #[test]
    fn failure_fails_closed_with_kill_switch() {
        assert_eq!(transition(Connecting, Failed { kill_switch: true }).unwrap(), Protected);
        assert_eq!(transition(Connected, Failed { kill_switch: true }).unwrap(), Protected);
        assert_eq!(transition(Connecting, Failed { kill_switch: false }).unwrap(), Error);
    }

    #[test]
    fn switching_profiles_from_connected() {
        assert_eq!(transition(Connected, ConnectRequested).unwrap(), Connecting);
    }

    #[test]
    fn reconnect_cycle() {
        let s = transition(Connected, Degraded).unwrap();
        assert_eq!(s, Reconnecting);
        assert_eq!(transition(s, TunnelUp).unwrap(), Connected);
    }

    #[test]
    fn illegal_transitions_rejected() {
        assert!(transition(Disconnected, TunnelUp).is_err());
        assert!(transition(Disconnected, Degraded).is_err());
        assert!(transition(Connected, TornDown { kill_switch: true }).is_err());
        assert!(transition(Disconnecting, ConnectRequested).is_err());
    }

    #[test]
    fn kill_switch_toggle_when_idle() {
        assert_eq!(
            transition(Disconnected, KillSwitchChanged { enabled: true }).unwrap(),
            Protected
        );
        assert_eq!(
            transition(Protected, KillSwitchChanged { enabled: false }).unwrap(),
            Disconnected
        );
    }
}
