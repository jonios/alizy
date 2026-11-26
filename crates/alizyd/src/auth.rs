//! IPC peer authorisation.
//!
//! * `Polkit` (production): peer must be root or a member of the `alizy` group
//!   (also enforced by socket permissions), and state-changing commands are
//!   authorised per process by polkit (`io.alizy.daemon.control`) using the
//!   peer's pid + process start time (no pid-reuse race).
//! * `SameUid` (tests/containers): only peers with the daemon's own uid.

use crate::exec::{argv, run};
use alizy_core::ipc::Command;
use nix::unistd::{getgrouplist, Gid, Uid, User};
use std::ffi::CString;

pub const POLKIT_ACTION: &str = "io.alizy.daemon.control";

#[derive(Debug, Clone)]
pub enum AuthMode {
    Polkit { group: Gid },
    SameUid,
}

#[derive(Debug, Clone, Copy)]
pub struct Peer {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<i32>,
    /// Start time of `pid` captured when the connection was accepted. Used to
    /// detect pid reuse before asking polkit about the process.
    pub start_time: Option<u64>,
}

impl Peer {
    pub fn from_cred(uid: u32, gid: u32, pid: Option<i32>) -> Self {
        Self {
            uid,
            gid,
            pid,
            start_time: pid.and_then(process_start_time),
        }
    }
}

/// Commands that require per-request polkit authorisation: everything that
/// changes state, plus TestRoute (it makes the root daemon resolve arbitrary
/// names and spawn processes).
pub fn is_privileged(c: &Command) -> bool {
    matches!(
        c,
        Command::Connect { .. }
            | Command::Disconnect
            | Command::SetPolicy { .. }
            | Command::SetSplit { .. }
            | Command::SetLanProxy { .. }
            | Command::TestRoute { .. }
    )
}

pub struct Authorizer {
    mode: AuthMode,
}

impl Authorizer {
    pub fn new(mode: AuthMode) -> Self {
        Self { mode }
    }

    pub fn socket_mode(&self) -> u32 {
        match self.mode {
            AuthMode::Polkit { .. } => 0o660,
            AuthMode::SameUid => 0o600,
        }
    }

    pub fn group(&self) -> Option<Gid> {
        match self.mode {
            AuthMode::Polkit { group } => Some(group),
            AuthMode::SameUid => None,
        }
    }

    /// May this peer talk to the daemon at all?
    pub fn admit(&self, p: &Peer) -> Result<(), String> {
        match &self.mode {
            AuthMode::SameUid => {
                if p.uid == Uid::effective().as_raw() {
                    Ok(())
                } else {
                    Err("peer uid differs from daemon uid".into())
                }
            }
            AuthMode::Polkit { group } => {
                if p.uid == 0 || p.gid == group.as_raw() {
                    return Ok(());
                }
                let user = User::from_uid(Uid::from_raw(p.uid))
                    .map_err(|e| e.to_string())?
                    .ok_or("unknown peer user")?;
                let name = CString::new(user.name).map_err(|e| e.to_string())?;
                let groups = getgrouplist(&name, Gid::from_raw(p.gid)).map_err(|e| e.to_string())?;
                if groups.contains(group) {
                    Ok(())
                } else {
                    Err("peer is not a member of the alizy group".into())
                }
            }
        }
    }

    /// Authorise a state-changing command.
    pub async fn authorize_mutation(&self, p: &Peer) -> Result<(), String> {
        match &self.mode {
            AuthMode::SameUid => Ok(()),
            AuthMode::Polkit { .. } => {
                if p.uid == 0 {
                    return Ok(());
                }
                let pid = p.pid.ok_or("peer pid unavailable")?;
                let accepted = p.start_time.ok_or("peer start time was unavailable at connect")?;
                let start = process_start_time(pid).ok_or("the connecting process has exited")?;
                if start != accepted {
                    // The original client exited and its pid was reused: refuse.
                    return Err("the connecting process has exited (pid reused)".into());
                }
                let subject = format!("{pid},{start},{}", p.uid);
                run(
                    &argv(&["pkcheck", "--action-id", POLKIT_ACTION, "--process", &subject]),
                    None,
                )
                .await
                .map(|_| ())
                .map_err(|e| format!("polkit denied the request: {e}"))
            }
        }
    }
}

/// Field 22 of /proc/<pid>/stat (process start time in clock ticks).
fn process_start_time(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm (field 2) may contain spaces/parens: split after the last ')'.
    let rest = &stat[stat.rfind(')')? + 2..];
    rest.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn reads_own_start_time() {
        assert!(super::process_start_time(std::process::id() as i32).is_some());
    }
}
