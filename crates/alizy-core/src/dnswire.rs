//! Minimal DNS wire-format codec for the split-tunnel Domain Resolution Engine:
//! A / AAAA queries, CNAME-chain following and TTL extraction. Pure; the
//! daemon performs the network I/O against the system resolver so that the
//! answers match what applications on this host receive.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_AAAA: u16 = 28;
/// RFC 1035: a domain name is at most 255 octets on the wire.
const MAX_NAME_OCTETS: usize = 255;
/// Answer records examined per response; anything beyond is ignored.
pub const MAX_ANSWERS: usize = 64;
/// Addresses accepted per answer.
pub const MAX_ADDRS: usize = 32;
const TYPE_OPT: u16 = 41;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("truncated or malformed DNS message")]
    Malformed,
    #[error("response does not match the query")]
    Mismatch,
    #[error("server returned rcode {0}")]
    Rcode(u8),
    #[error("response truncated (TC); retry over TCP")]
    Truncated,
    #[error("invalid query name")]
    BadName,
}

pub fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, WireError> {
    let mut m = Vec::with_capacity(64);
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&[0x01, 0x00]); // RD
    m.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 1]); // QD=1, AN=0, NS=0, AR=1 (EDNS)
    encode_name(&mut m, name)?;
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&[0, 1]); // IN
                                  // EDNS0 OPT: root name, type 41, udp size 1232, no flags, no rdata
    m.push(0);
    m.extend_from_slice(&TYPE_OPT.to_be_bytes());
    m.extend_from_slice(&1232u16.to_be_bytes());
    m.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    Ok(m)
}

fn encode_name(m: &mut Vec<u8>, name: &str) -> Result<(), WireError> {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return Err(WireError::BadName);
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(WireError::BadName);
        }
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    Ok(())
}

fn read_u16(b: &[u8], p: usize) -> Result<u16, WireError> {
    Ok(u16::from_be_bytes([
        *b.get(p).ok_or(WireError::Malformed)?,
        *b.get(p + 1).ok_or(WireError::Malformed)?,
    ]))
}

fn read_u32(b: &[u8], p: usize) -> Result<u32, WireError> {
    Ok(((read_u16(b, p)? as u32) << 16) | read_u16(b, p + 2)? as u32)
}

/// Decode a (possibly compressed) name; returns (name, position after it).
fn decode_name(b: &[u8], mut p: usize) -> Result<(String, usize), WireError> {
    let mut labels = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    let mut octets = 0usize;
    loop {
        let len = *b.get(p).ok_or(WireError::Malformed)? as usize;
        if len & 0xc0 == 0xc0 {
            let ptr = (read_u16(b, p)? & 0x3fff) as usize;
            if end.is_none() {
                end = Some(p + 2);
            }
            jumps += 1;
            if jumps > 32 || ptr >= b.len() {
                return Err(WireError::Malformed);
            }
            p = ptr;
            continue;
        }
        if len == 0 {
            let after = end.unwrap_or(p + 1);
            return Ok((labels.join(".").to_ascii_lowercase(), after));
        }
        if len > 63 {
            return Err(WireError::Malformed);
        }
        octets += len + 1;
        if octets > MAX_NAME_OCTETS {
            return Err(WireError::Malformed);
        }
        let l = b.get(p + 1..p + 1 + len).ok_or(WireError::Malformed)?;
        labels.push(String::from_utf8_lossy(l).into_owned());
        p += 1 + len;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Answer {
    /// Addresses belonging to the final name of the CNAME chain, with TTL.
    pub addrs: Vec<(IpAddr, u32)>,
    /// CNAME chain starting at the queried name (excluding it).
    pub cnames: Vec<String>,
    /// Smallest TTL across the chain (0 if no answer).
    pub min_ttl: u32,
}

pub fn parse_response(b: &[u8], id: u16, qname: &str, qtype: u16) -> Result<Answer, WireError> {
    if b.len() < 12 {
        return Err(WireError::Malformed);
    }
    if read_u16(b, 0)? != id || b[2] & 0x80 == 0 {
        return Err(WireError::Mismatch);
    }
    if b[2] & 0x02 != 0 {
        return Err(WireError::Truncated);
    }
    let rcode = b[3] & 0x0f;
    // NXDOMAIN is a valid "no addresses" answer, not a failure of the resolver.
    if rcode != 0 && rcode != 3 {
        return Err(WireError::Rcode(rcode));
    }
    let qd = read_u16(b, 4)?;
    let an = read_u16(b, 6)?;
    let mut p = 12;
    let want = qname.trim_end_matches('.').to_ascii_lowercase();
    for i in 0..qd {
        let (n, after) = decode_name(b, p)?;
        if i == 0 && (n != want || read_u16(b, after)? != qtype) {
            return Err(WireError::Mismatch);
        }
        p = after + 4;
    }
    let mut records = Vec::new();
    for _ in 0..an.min(MAX_ANSWERS as u16) {
        let (owner, after) = decode_name(b, p)?;
        let rtype = read_u16(b, after)?;
        let ttl = read_u32(b, after + 4)?;
        let rdlen = read_u16(b, after + 8)? as usize;
        let rdata_at = after + 10;
        let rdata = b.get(rdata_at..rdata_at + rdlen).ok_or(WireError::Malformed)?;
        let value = match rtype {
            TYPE_A if rdlen == 4 => Some(Rec::Addr(IpAddr::V4(Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3],
            )))),
            TYPE_AAAA if rdlen == 16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(rdata);
                Some(Rec::Addr(IpAddr::V6(Ipv6Addr::from(a))))
            }
            TYPE_CNAME => Some(Rec::Cname(decode_name(b, rdata_at)?.0)),
            _ => None,
        };
        if let Some(v) = value {
            records.push((owner, ttl, v));
        }
        p = rdata_at + rdlen;
    }
    // Follow the CNAME chain from the queried name.
    let mut ans = Answer::default();
    let mut current = want;
    let mut min_ttl = u32::MAX;
    for _ in 0..16 {
        match records
            .iter()
            .find(|(o, _, r)| *o == current && matches!(r, Rec::Cname(_)))
        {
            Some((_, ttl, Rec::Cname(target))) => {
                min_ttl = min_ttl.min(*ttl);
                ans.cnames.push(target.clone());
                current = target.clone();
            }
            _ => break,
        }
    }
    for (o, ttl, r) in &records {
        if let Rec::Addr(ip) = r {
            let fam_ok = (qtype == TYPE_A) == ip.is_ipv4();
            if *o == current && fam_ok && is_routable_answer(ip) && ans.addrs.len() < MAX_ADDRS {
                let ttl = (*ttl).min(MAX_TTL);
                min_ttl = min_ttl.min(ttl);
                ans.addrs.push((*ip, ttl));
            }
        }
    }
    ans.min_ttl = if min_ttl == u32::MAX { 0 } else { min_ttl };
    Ok(ans)
}

/// TTLs are clamped to one day so a hostile server cannot pin addresses.
pub const MAX_TTL: u32 = 86_400;

/// Addresses that must never become split-tunnel bypass targets, whatever a
/// DNS server answers: unspecified, loopback, multicast, broadcast, link-local.
pub fn is_routable_answer(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            !(a.is_unspecified()
                || a.is_loopback()
                || a.is_multicast()
                || a.is_broadcast()
                || a.is_link_local()
                || a.octets()[0] == 0)
        }
        IpAddr::V6(a) => {
            !(a.is_unspecified() || a.is_loopback() || a.is_multicast() || (a.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

enum Rec {
    Addr(IpAddr),
    Cname(String),
}

/// Nameservers from resolv.conf text (max 3, as glibc).
pub fn nameservers(resolv_conf: &str) -> Vec<IpAddr> {
    resolv_conf
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            (it.next() == Some("nameserver")).then(|| it.next()).flatten()
        })
        .filter_map(|s| s.split('%').next().and_then(|x| x.parse().ok()))
        .take(3)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a response for tests: question + answers (owner, type, ttl, rdata).
    fn response(id: u16, q: &str, qtype: u16, answers: &[(&str, u16, u32, Vec<u8>)], flags: u8, rcode: u8) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
        m.push(0x81 | flags);
        m.push(0x80 | rcode);
        m.extend_from_slice(&[0, 1]);
        m.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0]);
        encode_name(&mut m, q).unwrap();
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&[0, 1]);
        for (owner, t, ttl, rdata) in answers {
            if *owner == q {
                m.extend_from_slice(&[0xc0, 12]); // compression pointer to question name
            } else {
                encode_name(&mut m, owner).unwrap();
            }
            m.extend_from_slice(&t.to_be_bytes());
            m.extend_from_slice(&[0, 1]);
            m.extend_from_slice(&ttl.to_be_bytes());
            m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            m.extend_from_slice(rdata);
        }
        m
    }

    fn name_bytes(n: &str) -> Vec<u8> {
        let mut v = Vec::new();
        encode_name(&mut v, n).unwrap();
        v
    }

    #[test]
    fn query_encoding() {
        let q = build_query(0x1234, "bank.example.com", TYPE_A).unwrap();
        assert_eq!(&q[..2], &[0x12, 0x34]);
        assert_eq!(&q[12..17], &[4, b'b', b'a', b'n', b'k']);
        assert!(build_query(1, "a..b", TYPE_A).is_err());
    }

    #[test]
    fn multiple_a_records_and_min_ttl() {
        let r = response(
            7,
            "bank.example.com",
            TYPE_A,
            &[
                ("bank.example.com", TYPE_A, 300, vec![192, 0, 2, 10]),
                ("bank.example.com", TYPE_A, 60, vec![192, 0, 2, 11]),
            ],
            0,
            0,
        );
        let a = parse_response(&r, 7, "bank.example.com", TYPE_A).unwrap();
        assert_eq!(a.addrs.len(), 2);
        assert_eq!(a.min_ttl, 60);
    }

    #[test]
    fn follows_cname_chain() {
        let r = response(
            9,
            "www.example.com",
            TYPE_AAAA,
            &[
                ("www.example.com", TYPE_CNAME, 120, name_bytes("edge.cdn.example.net")),
                ("edge.cdn.example.net", TYPE_CNAME, 30, name_bytes("a1.cdn.example.net")),
                (
                    "a1.cdn.example.net",
                    TYPE_AAAA,
                    20,
                    "2001:db8::10".parse::<Ipv6Addr>().unwrap().octets().to_vec(),
                ),
                (
                    "unrelated.example.org",
                    TYPE_AAAA,
                    999,
                    "2001:db8::66".parse::<Ipv6Addr>().unwrap().octets().to_vec(),
                ),
            ],
            0,
            0,
        );
        let a = parse_response(&r, 9, "www.example.com", TYPE_AAAA).unwrap();
        assert_eq!(a.cnames, vec!["edge.cdn.example.net", "a1.cdn.example.net"]);
        assert_eq!(a.addrs, vec![("2001:db8::10".parse().unwrap(), 20)]);
        assert_eq!(a.min_ttl, 20);
    }

    #[test]
    fn rejects_mismatch_and_handles_errors() {
        let r = response(1, "a.example.com", TYPE_A, &[], 0, 0);
        assert_eq!(parse_response(&r, 2, "a.example.com", TYPE_A), Err(WireError::Mismatch));
        assert_eq!(parse_response(&r, 1, "b.example.com", TYPE_A), Err(WireError::Mismatch));
        let nx = response(1, "a.example.com", TYPE_A, &[], 0, 3);
        assert_eq!(parse_response(&nx, 1, "a.example.com", TYPE_A).unwrap().addrs.len(), 0);
        let fail = response(1, "a.example.com", TYPE_A, &[], 0, 2);
        assert_eq!(
            parse_response(&fail, 1, "a.example.com", TYPE_A),
            Err(WireError::Rcode(2))
        );
        let tc = response(1, "a.example.com", TYPE_A, &[], 0x02, 0);
        assert_eq!(
            parse_response(&tc, 1, "a.example.com", TYPE_A),
            Err(WireError::Truncated)
        );
        assert_eq!(parse_response(&[0; 5], 1, "a", TYPE_A), Err(WireError::Malformed));
    }

    #[test]
    fn hostile_answers_are_bounded() {
        // A name longer than 255 octets (via compression) is rejected.
        let mut r = response(1, "a.example.com", TYPE_A, &[], 0, 0);
        let long: Vec<u8> = (0..5)
            .flat_map(|_| {
                let mut l = vec![63u8];
                l.extend(std::iter::repeat_n(b'x', 63));
                l
            })
            .chain([0])
            .collect();
        let at = r.len();
        r.extend_from_slice(&long);
        r[7] = 1; // ANCOUNT = 1
        r.extend_from_slice(&[0xc0 | (at >> 8) as u8, at as u8]);
        r.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        assert_eq!(
            parse_response(&r, 1, "a.example.com", TYPE_A),
            Err(WireError::Malformed)
        );
        // TTLs clamped, special addresses dropped, address count capped.
        let mut ans: Vec<(&str, u16, u32, Vec<u8>)> = vec![
            ("a.example.com", TYPE_A, u32::MAX, vec![192, 0, 2, 1]),
            ("a.example.com", TYPE_A, 60, vec![127, 0, 0, 1]),
            ("a.example.com", TYPE_A, 60, vec![0, 0, 0, 0]),
            ("a.example.com", TYPE_A, 60, vec![224, 0, 0, 1]),
        ];
        for i in 0..60u8 {
            ans.push(("a.example.com", TYPE_A, 60, vec![198, 51, 100, i]));
        }
        let a = parse_response(
            &response(2, "a.example.com", TYPE_A, &ans, 0, 0),
            2,
            "a.example.com",
            TYPE_A,
        )
        .unwrap();
        assert_eq!(a.addrs[0], ("192.0.2.1".parse().unwrap(), MAX_TTL));
        assert!(a.addrs.iter().all(|(ip, _)| is_routable_answer(ip)));
        assert_eq!(a.addrs.len(), MAX_ADDRS);
    }

    #[test]
    fn compression_loop_is_rejected() {
        let mut r = response(1, "a.example.com", TYPE_A, &[], 0, 0);
        r.truncate(12);
        r.extend_from_slice(&[0xc0, 12]); // pointer to itself
        assert!(parse_response(&r, 1, "a.example.com", TYPE_A).is_err());
    }

    #[test]
    fn parses_resolv_conf() {
        let ns = nameservers("# x\nnameserver 127.0.0.53\noptions edns0\nnameserver fe80::1%eth0\n");
        assert_eq!(ns.len(), 2);
    }
}
