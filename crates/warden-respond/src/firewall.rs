//! nftables blocklist management.
//!
//! Warden owns a dedicated table (`inet warden`) with two timeout sets and a
//! high-priority input chain. Blocks expire inside the kernel; nothing has
//! to be cleaned up if the daemon dies, and other firewall tooling (ufw,
//! firewalld, docker) is untouched.

use std::net::IpAddr;
use std::time::Duration;
use warden_core::config::FirewallConfig;
use warden_core::net::{IpSet, canonical};
use warden_sys::cmd::{run_cmd, run_with_input, which};

#[derive(Debug)]
pub struct Firewall {
    cfg: FirewallConfig,
    allow: IpSet,
    ready: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Blocked {
    pub ip: String,
    pub expires_seconds: Option<u64>,
}

impl Firewall {
    pub fn new(cfg: &FirewallConfig, extra_allow: &[String]) -> Self {
        let all: Vec<String> = cfg.allowlist.iter().chain(extra_allow).cloned().collect();
        Self { cfg: cfg.clone(), allow: IpSet::new(&all), ready: false }
    }

    /// The nft script that (re)creates Warden's table, preserving set contents.
    pub fn ruleset(&self) -> String {
        let t = &self.cfg.table;
        format!(
            "table inet {t} {{\n  set {s4} {{ type ipv4_addr; flags timeout; size 262144; }}\n  set {s6} {{ type ipv6_addr; flags timeout; size 262144; }}\n  chain input {{ type filter hook input priority filter - 10; policy accept; }}\n}}\nflush chain inet {t} input\nadd rule inet {t} input ip saddr @{s4} counter drop comment \"warden blocklist\"\nadd rule inet {t} input ip6 saddr @{s6} counter drop comment \"warden blocklist\"\n",
            s4 = self.cfg.set_v4,
            s6 = self.cfg.set_v6,
        )
    }

    pub fn ensure(&mut self) -> Result<(), String> {
        if self.ready {
            return Ok(());
        }
        if !self.cfg.enabled {
            return Err("firewall actions disabled in configuration".into());
        }
        if which("nft").is_none() {
            return Err("nft not found (install nftables)".into());
        }
        let o =
            run_with_input("nft", &["-f", "-"], &self.ruleset(), Duration::from_secs(15)).map_err(|e| e.to_string())?;
        if !o.status.success() {
            return Err(format!("nft: {}", String::from_utf8_lossy(&o.stderr).trim()));
        }
        self.ready = true;
        Ok(())
    }

    fn set_for(&self, ip: &IpAddr) -> &str {
        if ip.is_ipv4() { &self.cfg.set_v4 } else { &self.cfg.set_v6 }
    }

    pub fn is_allowlisted(&self, ip: &IpAddr) -> bool {
        self.allow.contains(ip)
    }

    pub fn block(&mut self, ip: IpAddr, ttl: Option<Duration>) -> Result<String, String> {
        let ip = canonical(ip);
        if self.is_allowlisted(&ip) {
            return Err(format!("{ip} is allowlisted"));
        }
        if ip.is_unspecified() || ip.is_multicast() {
            return Err(format!("{ip} is not a unicast address"));
        }
        self.ensure()?;
        if self.cfg.max_blocked > 0 && self.list().len() >= self.cfg.max_blocked {
            return Err(format!("blocklist full ({} entries)", self.cfg.max_blocked));
        }
        let ttl = ttl.unwrap_or(self.cfg.default_ttl).as_secs().max(60);
        let elem = format!("{{ {ip} timeout {ttl}s }}");
        let set = self.set_for(&ip).to_owned();
        let o = run_cmd("nft", &["add", "element", "inet", &self.cfg.table, &set, &elem], Duration::from_secs(10))
            .map_err(|e| e.to_string())?;
        if !o.status.success() {
            let err = String::from_utf8_lossy(&o.stderr);
            // Table deleted behind our back (firewall reload) → recreate once.
            if err.contains("No such file") {
                self.ready = false;
                self.ensure()?;
                let o2 =
                    run_cmd("nft", &["add", "element", "inet", &self.cfg.table, &set, &elem], Duration::from_secs(10))
                        .map_err(|e| e.to_string())?;
                if o2.status.success() {
                    return Ok(format!("blocked {ip} for {ttl}s"));
                }
            }
            return Err(format!("nft add element: {}", err.trim()));
        }
        Ok(format!("blocked {ip} for {ttl}s"))
    }

    pub fn unblock(&mut self, ip: IpAddr) -> Result<String, String> {
        let ip = canonical(ip);
        self.ensure()?;
        let set = self.set_for(&ip).to_owned();
        let elem = format!("{{ {ip} }}");
        let o = run_cmd("nft", &["delete", "element", "inet", &self.cfg.table, &set, &elem], Duration::from_secs(10))
            .map_err(|e| e.to_string())?;
        if o.status.success() {
            Ok(format!("unblocked {ip}"))
        } else {
            Err(String::from_utf8_lossy(&o.stderr).trim().to_owned())
        }
    }

    /// Current set contents (from the kernel, so blocks survive restarts).
    pub fn list(&self) -> Vec<Blocked> {
        let mut out = Vec::new();
        for set in [&self.cfg.set_v4, &self.cfg.set_v6] {
            let Ok(o) = run_cmd("nft", &["-j", "list", "set", "inet", &self.cfg.table, set], Duration::from_secs(10))
            else {
                continue;
            };
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&o.stdout) {
                out.extend(parse_set_json(&v));
            }
        }
        out
    }
}

pub fn parse_set_json(v: &serde_json::Value) -> Vec<Blocked> {
    let mut out = Vec::new();
    let Some(items) = v.get("nftables").and_then(|x| x.as_array()) else { return out };
    for it in items {
        let Some(elems) = it.get("set").and_then(|s| s.get("elem")).and_then(|e| e.as_array()) else { continue };
        for e in elems {
            match e {
                serde_json::Value::String(s) => out.push(Blocked { ip: s.clone(), expires_seconds: None }),
                serde_json::Value::Object(_) => {
                    let inner = e.get("elem").unwrap_or(e);
                    if let Some(ip) = inner.get("val").and_then(|x| x.as_str()) {
                        out.push(Blocked {
                            ip: ip.to_owned(),
                            expires_seconds: inner.get("expires").and_then(|x| x.as_u64()),
                        });
                    }
                }
                _ => {}
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_and_allowlist() {
        let f = Firewall::new(&FirewallConfig::default(), &["10.0.0.0/8".into()]);
        let r = f.ruleset();
        assert!(r.contains("table inet warden"));
        assert!(r.contains("flush chain inet warden input"));
        assert!(r.contains("ip saddr @blocklist4"));
        assert!(f.is_allowlisted(&"127.0.0.1".parse().unwrap()));
        assert!(f.is_allowlisted(&"10.2.3.4".parse().unwrap()));
        assert!(!f.is_allowlisted(&"203.0.113.1".parse().unwrap()));
    }

    #[test]
    fn refuses_allowlisted_block() {
        let mut f = Firewall::new(&FirewallConfig::default(), &[]);
        assert!(f.block("127.0.0.1".parse().unwrap(), None).unwrap_err().contains("allowlisted"));
    }

    #[test]
    fn parses_nft_json() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"nftables":[{"metainfo":{}},{"set":{"family":"inet","name":"blocklist4","table":"warden","type":"ipv4_addr","flags":["timeout"],"elem":[{"elem":{"val":"203.0.113.9","timeout":3600,"expires":3540}},"198.51.100.1"]}}]}"#,
        )
        .unwrap();
        let b = parse_set_json(&v);
        assert_eq!(b.len(), 2);
        assert_eq!(b[0].expires_seconds, Some(3540));
    }
}
