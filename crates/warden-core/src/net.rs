//! Minimal CIDR handling for allowlists.

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
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
                let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(self.prefix)) };
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 { 0 } else { u128::MAX << (128 - u32::from(self.prefix)) };
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
