//! Network counters and socket tables from procfs.

use crate::util::read_string;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Parse `/proc/net/snmp` / `/proc/net/netstat` (header line + value line
/// per protocol) into `proto -> field -> value`.
pub fn parse_snmp(content: &str) -> HashMap<String, HashMap<String, i64>> {
    let mut out: HashMap<String, HashMap<String, i64>> = HashMap::new();
    let lines: Vec<&str> = content.lines().collect();
    for pair in lines.chunks(2) {
        let [h, v] = pair else { continue };
        let (Some((p1, keys)), Some((p2, vals))) = (h.split_once(':'), v.split_once(':')) else { continue };
        if p1 != p2 {
            continue;
        }
        let m = out.entry(p1.to_owned()).or_default();
        for (k, v) in keys.split_whitespace().zip(vals.split_whitespace()) {
            if let Ok(n) = v.parse() {
                m.insert(k.to_owned(), n);
            }
        }
    }
    out
}

/// Merged snmp + netstat counters.
pub fn counters() -> io::Result<HashMap<String, HashMap<String, i64>>> {
    let mut m = parse_snmp(&read_string("/proc/net/snmp")?);
    if let Ok(s) = read_string("/proc/net/netstat") {
        for (k, v) in parse_snmp(&s) {
            m.entry(k).or_default().extend(v);
        }
    }
    Ok(m)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct IfStats {
    pub name: String,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_errs: u64,
    pub rx_drop: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errs: u64,
    pub tx_drop: u64,
}

pub fn parse_net_dev(content: &str) -> Vec<IfStats> {
    content
        .lines()
        .skip(2)
        .filter_map(|l| {
            let (name, rest) = l.split_once(':')?;
            let v: Vec<u64> = rest.split_whitespace().filter_map(|x| x.parse().ok()).collect();
            if v.len() < 16 {
                return None;
            }
            Some(IfStats {
                name: name.trim().to_owned(),
                rx_bytes: v[0],
                rx_packets: v[1],
                rx_errs: v[2],
                rx_drop: v[3],
                tx_bytes: v[8],
                tx_packets: v[9],
                tx_errs: v[10],
                tx_drop: v[11],
            })
        })
        .collect()
}

pub fn net_dev() -> io::Result<Vec<IfStats>> {
    Ok(parse_net_dev(&read_string("/proc/net/dev")?))
}

/// `(count, max)` of the netfilter connection tracking table.
pub fn conntrack() -> Option<(u64, u64)> {
    let c = crate::util::read_u64("/proc/sys/net/netfilter/nf_conntrack_count")?;
    let m = crate::util::read_u64("/proc/sys/net/netfilter/nf_conntrack_max")?;
    Some((c, m))
}

pub const TCP_ESTABLISHED: u8 = 0x01;
pub const TCP_LISTEN: u8 = 0x0A;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub struct Socket {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: u8,
    /// For LISTEN sockets: maximum backlog.
    pub tx_queue: u64,
    /// For LISTEN sockets: current accept-queue length.
    pub rx_queue: u64,
    pub uid: u32,
    pub inode: u64,
}

fn parse_hex_addr(s: &str) -> Option<SocketAddr> {
    let (a, p) = s.split_once(':')?;
    let port = u16::from_str_radix(p, 16).ok()?;
    let ip = match a.len() {
        8 => IpAddr::V4(Ipv4Addr::from(u32::from_str_radix(a, 16).ok()?.to_ne_bytes())),
        32 => {
            // The kernel prints the in-memory u32 words in host byte order;
            // to_ne_bytes() recovers the original network-order bytes.
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                // `get`: 32 bytes need not be 32 characters
                let w = u32::from_str_radix(a.get(i * 8..i * 8 + 8)?, 16).ok()?;
                bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_ne_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// Parse `/proc/net/tcp` or `/proc/net/tcp6`.
pub fn parse_tcp(content: &str) -> Vec<Socket> {
    content
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 10 {
                return None;
            }
            let (tx, rx) = f[4].split_once(':')?;
            Some(Socket {
                local: parse_hex_addr(f[1])?,
                remote: parse_hex_addr(f[2])?,
                state: u8::from_str_radix(f[3], 16).ok()?,
                tx_queue: u64::from_str_radix(tx, 16).ok()?,
                rx_queue: u64::from_str_radix(rx, 16).ok()?,
                uid: f[7].parse().ok()?,
                inode: f[9].parse().ok()?,
            })
        })
        .collect()
}

pub fn tcp_sockets() -> Vec<Socket> {
    let mut v = Vec::new();
    for p in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(s) = read_string(p) {
            v.extend(parse_tcp(&s));
        }
    }
    v
}

/// Ports sshd listens on, from `sshd_config` text: `Port` lines and the
/// ports of `ListenAddress` lines (`host:port`, `[v6]:port`). Keywords are
/// case-insensitive and may be followed by `=`.
pub fn parse_sshd_ports(text: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let (key, rest) = match line.split_once(|c: char| c.is_whitespace() || c == '=') {
            Some((k, r)) => (k, r.trim_start_matches(|c: char| c.is_whitespace() || c == '=').trim()),
            None => continue,
        };
        let value = rest.split_whitespace().next().unwrap_or("");
        let port = if key.eq_ignore_ascii_case("port") {
            value.parse().ok()
        } else if key.eq_ignore_ascii_case("listenaddress") {
            // `1.2.3.4:2222`, `[::1]:2222`; a bare address has no port
            match value.rsplit_once(':') {
                Some((host, p)) if value.starts_with('[') && host.ends_with(']') => p.parse().ok(),
                Some((host, p)) if !host.contains(':') => p.parse().ok(),
                _ => None,
            }
        } else {
            None
        };
        if let Some(p) = port
            && p > 0
            && !ports.contains(&p)
        {
            ports.push(p);
        }
    }
    ports
}

/// Ports of the local sshd: `/etc/ssh/sshd_config` and the files of
/// `/etc/ssh/sshd_config.d/`, or 22.
pub fn sshd_ports() -> Vec<u16> {
    let mut text = read_string("/etc/ssh/sshd_config").unwrap_or_default();
    if let Ok(dir) = std::fs::read_dir("/etc/ssh/sshd_config.d") {
        let mut files: Vec<_> =
            dir.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "conf")).collect();
        files.sort();
        for f in files {
            if let Ok(t) = std::fs::read_to_string(f) {
                text.push('\n');
                text.push_str(&t);
            }
        }
    }
    let ports = parse_sshd_ports(&text);
    if ports.is_empty() { vec![22] } else { ports }
}

/// Remote addresses with an established TCP connection to one of `ports`.
pub fn established_peers(sockets: &[Socket], ports: &[u16]) -> HashSet<IpAddr> {
    sockets
        .iter()
        .filter(|s| s.state == TCP_ESTABLISHED && ports.contains(&s.local.port()))
        .map(|s| match s.remote.ip() {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            v4 => v4,
        })
        .collect()
}

/// Map socket inodes to owning PIDs (scans /proc/*/fd; call sparingly).
pub fn socket_owners(inodes: &HashSet<u64>) -> HashMap<u64, i32> {
    let mut out = HashMap::new();
    if inodes.is_empty() {
        return out;
    }
    for pid in crate::process::pids() {
        for (_, t) in crate::process::fds(pid) {
            if let Some(i) = crate::process::socket_inode(&t)
                && inodes.contains(&i)
            {
                out.entry(i).or_insert(pid);
            }
        }
        if out.len() == inodes.len() {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snmp_pairs() {
        let m = parse_snmp(
            "Tcp: RtoMin MaxConn OutSegs RetransSegs\nTcp: 200 -1 1000 10\nTcpExt: ListenOverflows SyncookiesSent\nTcpExt: 5 7\n",
        );
        assert_eq!(m["Tcp"]["MaxConn"], -1);
        assert_eq!(m["Tcp"]["RetransSegs"], 10);
        assert_eq!(m["TcpExt"]["SyncookiesSent"], 7);
    }

    #[test]
    fn net_dev_parsing() {
        let s = "Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n  eth0: 1000 10 1 2 0 0 0 0 2000 20 3 4 0 0 0 0\n";
        let v = parse_net_dev(s);
        assert_eq!(v[0].name, "eth0");
        assert_eq!(v[0].rx_drop, 2);
        assert_eq!(v[0].tx_errs, 3);
    }

    #[test]
    fn tcp_table() {
        let s = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0CEA 00000000:0000 0A 00000080:00000005 00:00000000 00000000   117        0 25427 1 0000000000000000 100 0 0 10 0\n";
        let v = parse_tcp(s);
        assert_eq!(v[0].local, "127.0.0.1:3306".parse().unwrap());
        assert_eq!(v[0].state, TCP_LISTEN);
        assert_eq!(v[0].uid, 117);
        assert_eq!(v[0].inode, 25427);
        assert_eq!((v[0].tx_queue, v[0].rx_queue), (128, 5));
        let s6 = "hdr\n   0: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 999 1\n";
        let v6 = parse_tcp(s6);
        assert_eq!(v6[0].local, "[::1]:80".parse().unwrap());
    }

    #[test]
    fn sshd_ports_from_config() {
        let cfg = "# Port 2200\nPort 22\nport=2222\nListenAddress 0.0.0.0\nListenAddress [::]:2223\nListenAddress 10.0.0.1:2224\nListenAddress ::1\nMatch User x\n";
        assert_eq!(parse_sshd_ports(cfg), vec![22, 2222, 2223, 2224]);
        assert!(parse_sshd_ports("Port\nPort x\nPort 0").is_empty());
    }

    #[test]
    fn established_peers_by_local_port() {
        let tcp6 = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0000000000000000FFFF00000100007F:0016 0000000000000000FFFF00000500A8C0:C350 01 00000000:00000000 00:00000000 00000000     0        0 1 1\n   1: 0000000000000000FFFF00000100007F:0050 0000000000000000FFFF00000600A8C0:C351 01 00000000:00000000 00:00000000 00000000     0        0 2 1\n";
        let peers = established_peers(&parse_tcp(tcp6), &[22]);
        assert_eq!(peers.into_iter().collect::<Vec<_>>(), vec!["192.168.0.5".parse::<IpAddr>().unwrap()]);
    }
}
