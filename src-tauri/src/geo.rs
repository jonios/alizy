//! Offline IP → country lookup for the map and the flags in the config list.
//!
//! The table is DB-IP's "IP to Country Lite" (CC BY 4.0, <https://db-ip.com>),
//! compacted by `scripts/geoip/build.mjs` and compiled into the binary, so a
//! lookup never leaves this machine. Hostnames are resolved with the system
//! resolver, the same way the ping probes resolve them.

use flate2::read::GzDecoder;
use serde::Serialize;
use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::OnceLock;

static RAW: &[u8] = include_bytes!("../geoip/country.bin.gz");

struct Table {
    codes: Vec<[u8; 2]>,
    v4: Vec<u32>,
    v4c: Vec<u8>,
    /// upper 64 bits of each IPv6 range start
    v6: Vec<u64>,
    v6c: Vec<u8>,
}

fn table() -> Option<&'static Table> {
    static T: OnceLock<Option<Table>> = OnceLock::new();
    T.get_or_init(|| match parse() {
        Ok(t) => Some(t),
        Err(err) => {
            tracing::warn!("country table unusable: {err}");
            None
        }
    })
    .as_ref()
}

struct Cursor<'a> {
    b: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], &'static str> {
        let s = self.b.get(self.at..self.at + n).ok_or("truncated")?;
        self.at += n;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16, &'static str> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, &'static str> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn leb(&mut self) -> Result<u64, &'static str> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let b = self.take(1)?[0];
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err("bad varint")
    }
    /// `n` delta-encoded starts followed by `n` code indexes.
    fn ranges(&mut self, codes: usize) -> Result<(Vec<u64>, Vec<u8>), &'static str> {
        let n = self.u32()? as usize;
        let mut starts = Vec::with_capacity(n);
        let mut prev = 0u64;
        for _ in 0..n {
            prev = prev.checked_add(self.leb()?).ok_or("overflow")?;
            starts.push(prev);
        }
        let cs = self.take(n)?.to_vec();
        if cs.iter().any(|&c| c as usize >= codes) {
            return Err("bad code index");
        }
        Ok((starts, cs))
    }
}

fn parse() -> Result<Table, &'static str> {
    let mut b = Vec::new();
    GzDecoder::new(RAW).read_to_end(&mut b).map_err(|_| "not gzip")?;
    let mut c = Cursor { b: &b, at: 0 };
    if c.take(5)? != b"AGEO\x02" {
        return Err("unknown format");
    }
    let n = c.u16()? as usize;
    let codes = (0..n)
        .map(|_| c.take(2).map(|s| [s[0], s[1]]))
        .collect::<Result<Vec<_>, _>>()?;
    let (v4, v4c) = c.ranges(n)?;
    let (v6, v6c) = c.ranges(n)?;
    let v4 = v4
        .into_iter()
        .map(|s| u32::try_from(s).map_err(|_| "IPv4 start out of range"))
        .collect::<Result<_, _>>()?;
    Ok(Table {
        codes,
        v4,
        v4c,
        v6,
        v6c,
    })
}

/// Index of the range containing `key`: the last start ≤ key.
fn find<T: Ord>(starts: &[T], key: &T) -> Option<usize> {
    starts.partition_point(|s| s <= key).checked_sub(1)
}

/// ISO 3166-1 alpha-2 code ("DE"), or None for unknown, private or reserved addresses.
pub fn country(ip: IpAddr) -> Option<String> {
    let t = table()?;
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };
    let code = match ip {
        IpAddr::V4(v4) => t.v4c[find(&t.v4, &u32::from(v4))?],
        IpAddr::V6(v6) => t.v6c[find(&t.v6, &((u128::from(v6) >> 64) as u64))?],
    };
    let cc = t.codes[code as usize];
    (&cc != b"ZZ").then(|| String::from_utf8_lossy(&cc).into_owned())
}

#[derive(Debug, Clone, Serialize)]
pub struct GeoResult {
    pub profile_id: String,
    /// ISO 3166-1 alpha-2, uppercase; None when the host is unknown or did not resolve.
    pub country: Option<String>,
}

/// Look up every `(profile_id, host)`; hosts shared by several profiles are resolved once.
pub async fn locate_all(targets: Vec<(String, String)>) -> Vec<GeoResult> {
    let mut hosts: Vec<String> = targets.iter().map(|(_, h)| h.clone()).collect();
    hosts.sort();
    hosts.dedup();
    let mut set = tokio::task::JoinSet::new();
    for host in hosts {
        set.spawn_blocking(move || {
            let ip = host
                .parse::<IpAddr>()
                .ok()
                .or_else(|| (host.as_str(), 0).to_socket_addrs().ok()?.map(|a| a.ip()).next());
            (host, ip.and_then(country))
        });
    }
    let mut found: HashMap<String, Option<String>> = HashMap::new();
    while let Some(r) = set.join_next().await {
        if let Ok((h, c)) = r {
            found.insert(h, c);
        }
    }
    targets
        .into_iter()
        .map(|(profile_id, host)| GeoResult {
            profile_id,
            country: found.get(&host).cloned().flatten(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_loads_and_answers() {
        assert!(table().is_some());
        assert_eq!(country("1.0.0.1".parse().unwrap()).as_deref(), Some("AU"));
        assert_eq!(country("10.0.0.1".parse().unwrap()), None);
        assert_eq!(country("127.0.0.1".parse().unwrap()), None);
        assert_eq!(country("8.8.8.8".parse().unwrap()).as_deref(), Some("US"));
        // Hetzner: DE, with a FI block right after it inside the same /32
        assert_eq!(country("2a01:4f8:1::1".parse().unwrap()).as_deref(), Some("DE"));
        assert_eq!(country("2a01:4f8:fff2:7::1".parse().unwrap()).as_deref(), Some("FI"));
        assert_eq!(country("::ffff:1.0.0.1".parse().unwrap()).as_deref(), Some("AU"));
    }
}
