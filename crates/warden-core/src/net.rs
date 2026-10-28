//! Addresses: CIDR allowlists, and the key a remote peer is counted and
//! blocked by ([`Key`]).

use std::fmt;
use std::net::{IpAddr, Ipv6Addr};

/// The IPv6 prefix one subscriber gets: RFC 6177 gives a site a /64 at
/// least (more often a /56 or a /48), and every address in it is the same
/// attacker. Default of `actions.firewall.ipv6_prefix`.
pub const DEFAULT_IPV6_PREFIX: u8 = 64;
/// The widest IPv6 aggregation allowed: a /48 is a whole site.
pub const MIN_IPV6_PREFIX: u8 = 48;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

fn mask4(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix.min(32))) }
}

fn mask6(prefix: u8) -> u128 {
    if prefix == 0 { 0 } else { u128::MAX << (128 - u32::from(prefix.min(128))) }
}

/// Do `a/pa` and `b/pb` share an address? (One contains the other: CIDR
/// blocks never overlap partially.)
fn nets_overlap(a: IpAddr, pa: u8, b: IpAddr, pb: u8) -> bool {
    let p = pa.min(pb);
    match (canonical(a), canonical(b)) {
        (IpAddr::V4(a), IpAddr::V4(b)) => u32::from(a) & mask4(p) == u32::from(b) & mask4(p),
        (IpAddr::V6(a), IpAddr::V6(b)) => u128::from(a) & mask6(p) == u128::from(b) & mask6(p),
        _ => false,
    }
}

impl Cidr {
    /// Parse `10.0.0.0/8`, `2001:db8::/32` or a bare address.
    pub fn parse(s: &str) -> Option<Self> {
        let (a, p) = match s.trim().split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s.trim(), None),
        };
        let addr: IpAddr = a.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            Some(p) => p.parse::<u8>().ok().filter(|v| *v <= max)?,
            None => max,
        };
        Some(Self { addr, prefix })
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        let ip = canonical(*ip);
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                (u32::from(net) & mask4(self.prefix)) == (u32::from(ip) & mask4(self.prefix))
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                (u128::from(net) & mask6(self.prefix)) == (u128::from(ip) & mask6(self.prefix))
            }
            _ => false,
        }
    }

    /// Does this network share any address with `key`'s?
    pub fn overlaps(&self, key: &Key) -> bool {
        nets_overlap(self.addr, self.prefix, key.net, key.prefix)
    }
}

/// `::ffff:1.2.3.4` → `1.2.3.4`.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// A parsed allowlist.
#[derive(Debug, Clone, Default)]
pub struct IpSet(Vec<Cidr>);

impl IpSet {
    pub fn new<'a>(items: impl IntoIterator<Item = &'a String>) -> Self {
        Self(items.into_iter().filter_map(|s| Cidr::parse(s)).collect())
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.0.iter().any(|c| c.contains(ip))
    }

    /// Is any address of `key`'s network in the set? An allowlisted
    /// address inside an attacker's /64 means the /64 is not one party.
    pub fn overlaps(&self, key: &Key) -> bool {
        self.0.iter().any(|c| c.overlaps(key))
    }
}

/// What a remote peer is counted, scored and blocked by: an IPv4 address
/// (/32), or the IPv6 network of `actions.firewall.ipv6_prefix` bits that
/// holds the address (a /64 by default).
///
/// Until 0.14.2 every table was keyed by the full address. An attacker with
/// one IPv6 /64 — what a VPS or a home line gets — sent each request from a
/// new address and was never counted twice: 4 000 addresses × 4 rejected
/// requests, zero blocks (N25 of the 0.14.2 review). IPv4 is not aggregated:
/// behind a CGNAT a /24 is other people.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key {
    net: IpAddr,
    prefix: u8,
}

impl Key {
    /// The key of `ip` when IPv6 is aggregated to `ipv6_prefix` bits (kept
    /// within [`MIN_IPV6_PREFIX`]..=128; 128 aggregates nothing).
    pub fn of(ip: IpAddr, ipv6_prefix: u8) -> Self {
        match canonical(ip) {
            IpAddr::V4(v4) => Self { net: IpAddr::V4(v4), prefix: 32 },
            IpAddr::V6(v6) => {
                let p = ipv6_prefix.clamp(MIN_IPV6_PREFIX, 128);
                Self { net: IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask6(p))), prefix: p }
            }
        }
    }

    /// The address itself (/32 or /128).
    pub fn exact(ip: IpAddr) -> Self {
        let ip = canonical(ip);
        Self { net: ip, prefix: if ip.is_ipv4() { 32 } else { 128 } }
    }

    /// The network address (the address itself for a single address).
    pub fn addr(&self) -> IpAddr {
        self.net
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// More than one address?
    pub fn is_network(&self) -> bool {
        self.prefix < if self.net.is_ipv4() { 32 } else { 128 }
    }

    pub fn is_ipv4(&self) -> bool {
        self.net.is_ipv4()
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        Cidr { addr: self.net, prefix: self.prefix }.contains(ip)
    }

    /// An address (`2001:db8::5`) or a network written as `addr/len`,
    /// whose length is the full one or — for IPv6 — `ipv6_prefix`: the
    /// keys Warden itself blocks by. The address is masked to the length.
    pub fn parse(s: &str, ipv6_prefix: u8) -> Option<Self> {
        let c = Cidr::parse(s)?;
        let full = if c.addr.is_ipv4() { 32 } else { 128 };
        if c.prefix == full {
            return Some(Self::exact(c.addr));
        }
        let p = ipv6_prefix.clamp(MIN_IPV6_PREFIX, 128);
        (c.addr.is_ipv6() && canonical(c.addr).is_ipv6() && c.prefix == p).then(|| Self::of(c.addr, p))
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_network() { write!(f, "{}/{}", self.net, self.prefix) } else { write!(f, "{}", self.net) }
    }
}

/// The `ffff:ffff:…::` mask of an IPv6 prefix, as nftables writes it.
pub fn ipv6_mask(prefix: u8) -> Ipv6Addr {
    Ipv6Addr::from(mask6(prefix.min(128)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cidr_matching() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(&"10.1.2.3".parse().unwrap()));
        assert!(!c.contains(&"11.1.2.3".parse().unwrap()));
        assert!(c.contains(&"::ffff:10.9.9.9".parse().unwrap()));
        let c6 = Cidr::parse("2001:db8::/32").unwrap();
        assert!(c6.contains(&"2001:db8:1::5".parse().unwrap()));
        assert!(!c6.contains(&"2001:db9::5".parse().unwrap()));
        assert!(Cidr::parse("1.2.3.4").unwrap().contains(&"1.2.3.4".parse().unwrap()));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(&"8.8.8.8".parse().unwrap()));
        assert!(Cidr::parse("1.2.3.4/33").is_none());
        assert!(Cidr::parse("nope").is_none());
    }

    #[test]
    fn keys_aggregate_ipv6_only() {
        let a = Key::of(ip("2001:db8:aa:1::5"), 64);
        let b = Key::of(ip("2001:db8:aa:1:ffff:1:2:3"), 64);
        assert_eq!(a, b, "one /64, one key");
        assert_ne!(a, Key::of(ip("2001:db8:aa:2::5"), 64));
        assert_eq!(a.to_string(), "2001:db8:aa:1::/64");
        assert!(a.is_network() && a.contains(&ip("2001:db8:aa:1::77")) && !a.contains(&ip("2001:db8:aa:2::1")));
        // IPv4 is never aggregated, mapped addresses are IPv4
        let v4 = Key::of(ip("203.0.113.7"), 64);
        assert_eq!(v4.to_string(), "203.0.113.7");
        assert!(!v4.is_network());
        assert_eq!(Key::of(ip("::ffff:203.0.113.7"), 64), v4);
        assert_ne!(v4, Key::of(ip("203.0.113.8"), 64));
        // /128 aggregates nothing; the prefix is kept in bounds
        assert_eq!(Key::of(ip("2001:db8::5"), 128).to_string(), "2001:db8::5");
        assert_eq!(Key::of(ip("2001:db8:1:2::5"), 0).prefix(), MIN_IPV6_PREFIX);
        assert_eq!(Key::of(ip("2001:db8:1:2::5"), 56).to_string(), "2001:db8:1::/56");
    }

    #[test]
    fn allowlists_see_inside_a_network() {
        let allow = IpSet::new(&["2001:db8:aa:1::10/128".to_string(), "10.0.0.0/8".to_string()]);
        let k = Key::of(ip("2001:db8:aa:1::5"), 64);
        assert!(!allow.contains(&ip("2001:db8:aa:1::5")));
        assert!(allow.overlaps(&k), "an allowlisted address lies inside the /64");
        assert!(!allow.overlaps(&Key::of(ip("2001:db8:aa:2::5"), 64)));
        assert!(allow.overlaps(&Key::of(ip("10.1.2.3"), 64)));
        // a wider allowlisted network contains the key and the address
        let wide = IpSet::new(&["2001:db8::/32".to_string()]);
        assert!(wide.overlaps(&k) && wide.contains(&ip("2001:db8:aa:1::5")));
    }

    #[test]
    fn keys_parse_as_operators_write_them() {
        assert_eq!(Key::parse("2001:db8:aa:1::/64", 64), Some(Key::of(ip("2001:db8:aa:1::"), 64)));
        // the host bits are masked off
        assert_eq!(Key::parse("2001:db8:aa:1::9/64", 64).unwrap().to_string(), "2001:db8:aa:1::/64");
        assert_eq!(Key::parse("2001:db8::9", 64), Some(Key::exact(ip("2001:db8::9"))));
        assert_eq!(Key::parse("203.0.113.9/32", 64), Some(Key::exact(ip("203.0.113.9"))));
        // only the configured prefix: the firewall has no set for another one
        assert_eq!(Key::parse("2001:db8::/48", 64), None);
        assert_eq!(Key::parse("203.0.113.0/24", 64), None);
        assert_eq!(Key::parse("bogus", 64), None);
    }

    #[test]
    fn masks() {
        assert_eq!(ipv6_mask(64).to_string(), "ffff:ffff:ffff:ffff::");
        assert_eq!(ipv6_mask(56).to_string(), "ffff:ffff:ffff:ff00::");
        assert_eq!(ipv6_mask(128).to_string(), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    }
}
