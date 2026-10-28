//! nftables blocklist management.
//!
//! Warden owns a dedicated table (`inet warden`) with timeout sets and a
//! high-priority input chain. Blocks expire inside the kernel; nothing has
//! to be cleaned up if the daemon dies, and other firewall tooling (ufw,
//! firewalld, docker) is untouched.
//!
//! The sets:
//! * `blocklist4` — IPv4 addresses;
//! * `blocklist6` — single IPv6 addresses: a block narrowed to one address
//!   (see `Responder::execute_blocks`), an operator's `wardenctl block`, the
//!   blocks of 0.14.2 and earlier;
//! * `blocklist6_64` — IPv6 networks of `ipv6_prefix` bits (N25), stored as
//!   their network address and matched by
//!   `ip6 saddr & ffff:ffff:ffff:ffff:: @blocklist6_64`: a hash lookup of the
//!   masked source, not an interval set. With an interval set of 45 000
//!   networks every `nft` call took 0.33 s here — nft reads every element of
//!   every interval set to check overlaps — while an addition to a plain set
//!   takes ~3 ms whatever its size. Plain sets also never conflict: a /128
//!   and the /64 around it can both be blocked.
//!
//! A set of an earlier `ipv6_prefix` stays matched (with its own mask) until
//! its last block has expired; then it is removed.
//!
//! Blocks are added in batches, one `nft -f -` transaction each
//! ([`Firewall::block_keys`]); the network lane of the executor collects
//! them (N23: one `nft` process per address held kills up for seconds).

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use warden_core::config::FirewallConfig;
use warden_core::net::{IpSet, Key, ipv6_mask};
use warden_sys::cmd::{run_cmd, run_with_input, which};

/// How `nft` is reached: the real command, or a stand-in in tests.
pub trait Backend: Send + Sync + fmt::Debug {
    /// Apply a script as one transaction (`nft -f -`).
    fn apply(&self, script: &str) -> Result<(), String>;
    /// `nft -j list set inet <table> <set>`: one set with its elements.
    fn list_set(&self, table: &str, set: &str) -> Result<serde_json::Value, String>;
    /// `nft -j -t list sets table inet <table>`: the sets, without elements.
    fn list_sets(&self, table: &str) -> Result<serde_json::Value, String>;
    /// Is nft there at all?
    fn available(&self) -> Result<(), String>;
}

/// The `nft` command.
#[derive(Debug, Default)]
pub struct Nft;

const NFT_TIMEOUT: Duration = Duration::from_secs(15);

fn nft_json(args: &[&str]) -> Result<serde_json::Value, String> {
    let o = run_cmd("nft", args, NFT_TIMEOUT).map_err(|e| e.to_string())?;
    if !o.status.success() {
        return Err(format!("nft: {}", String::from_utf8_lossy(&o.stderr).trim()));
    }
    serde_json::from_slice(&o.stdout).map_err(|e| format!("nft: unreadable JSON: {e}"))
}

impl Backend for Nft {
    fn apply(&self, script: &str) -> Result<(), String> {
        let o = run_with_input("nft", &["-f", "-"], script, NFT_TIMEOUT).map_err(|e| e.to_string())?;
        if o.status.success() { Ok(()) } else { Err(format!("nft: {}", String::from_utf8_lossy(&o.stderr).trim())) }
    }

    fn list_set(&self, table: &str, set: &str) -> Result<serde_json::Value, String> {
        nft_json(&["-j", "list", "set", "inet", table, set])
    }

    fn list_sets(&self, table: &str) -> Result<serde_json::Value, String> {
        nft_json(&["-j", "-t", "list", "sets", "table", "inet", table])
    }

    fn available(&self) -> Result<(), String> {
        which("nft").map(|_| ()).ok_or_else(|| "nft not found (install nftables)".into())
    }
}

/// The table or set is gone (`nft flush ruleset`, a firewall reload).
fn missing(err: &str) -> bool {
    err.contains("No such file or directory")
}

/// Why a block was not made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockError {
    /// By configuration: the address is allowlisted, or firewall actions
    /// are off. Not a failure.
    Refused(String),
    /// nft failed, the blocklist is full, the address cannot be blocked.
    Failed(String),
}

impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockError::Refused(m) | BlockError::Failed(m) => f.write_str(m),
        }
    }
}

#[derive(Debug)]
pub struct Firewall {
    cfg: FirewallConfig,
    allow: IpSet,
    backend: Arc<dyn Backend>,
    ready: bool,
    /// Network sets of earlier `ipv6_prefix` values still in the table, with
    /// their prefix: matched until their blocks have expired.
    legacy_nets: Vec<(String, u8)>,
    /// Entries in the sets: as listed at the last [`Firewall::reconcile`]
    /// plus the blocks added since. Expired entries are noticed only at the
    /// next reconciliation, so the count errs on the high side. (0.14.2
    /// listed both sets on every block near `max_blocked`: 92 ms a block.)
    count: usize,
    reconciled: Option<Instant>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Blocked {
    /// An address, or a network (`2001:db8:aa:1::/64`).
    pub ip: String,
    pub expires_seconds: Option<u64>,
}

/// A failed transaction is halved to find the element that fails it, at
/// most this many times (so at most 31 nft calls for a batch).
const MAX_BISECT: u32 = 4;

impl Firewall {
    pub fn new(cfg: &FirewallConfig, extra_allow: &[String]) -> Self {
        Self::with_backend(cfg, extra_allow, Arc::new(Nft))
    }

    pub fn with_backend(cfg: &FirewallConfig, extra_allow: &[String], backend: Arc<dyn Backend>) -> Self {
        let all: Vec<String> = cfg.allowlist.iter().chain(extra_allow).cloned().collect();
        Self {
            cfg: cfg.clone(),
            allow: IpSet::new(&all),
            backend,
            ready: false,
            legacy_nets: Vec::new(),
            count: 0,
            reconciled: None,
        }
    }

    /// Apply a new configuration in place, keeping what is known about the
    /// table unless the table, the sets or the prefix changed.
    pub fn reconfigure(&mut self, cfg: &FirewallConfig, extra_allow: &[String]) {
        let layout = |c: &FirewallConfig| (c.table.clone(), c.set_v4.clone(), c.set_v6.clone(), c.ipv6_prefix);
        if layout(cfg) != layout(&self.cfg) || cfg.enabled != self.cfg.enabled {
            self.ready = false;
            self.reconciled = None;
        }
        let all: Vec<String> = cfg.allowlist.iter().chain(extra_allow).cloned().collect();
        self.allow = IpSet::new(&all);
        self.cfg = cfg.clone();
    }

    pub fn ipv6_prefix(&self) -> u8 {
        self.cfg.ipv6_prefix
    }

    /// Does `ipv6_prefix` aggregate at all (is there a network set)?
    fn aggregates(&self) -> bool {
        self.cfg.ipv6_prefix < 128
    }

    /// The set of IPv6 networks for the configured prefix.
    pub fn net_set(&self) -> String {
        format!("{}_{}", self.cfg.set_v6, self.cfg.ipv6_prefix)
    }

    /// The nft script that (re)creates Warden's table, preserving set
    /// contents, and puts the rules back.
    pub fn ruleset(&self) -> String {
        let t = &self.cfg.table;
        let (s4, s6) = (&self.cfg.set_v4, &self.cfg.set_v6);
        let set = |name: &str, ty: &str| format!("  set {name} {{ type {ty}; flags timeout; size 262144; }}\n");
        let mut s = format!("table inet {t} {{\n");
        s += &set(s4, "ipv4_addr");
        s += &set(s6, "ipv6_addr");
        if self.aggregates() {
            s += &set(&self.net_set(), "ipv6_addr");
        }
        s += "  chain input { type filter hook input priority filter - 10; policy accept; }\n}\n";
        s += &format!("flush chain inet {t} input\n");
        s += &format!("add rule inet {t} input ip saddr @{s4} counter drop comment \"warden blocklist\"\n");
        s += &format!("add rule inet {t} input ip6 saddr @{s6} counter drop comment \"warden blocklist\"\n");
        let mut nets: Vec<(String, u8)> = self.legacy_nets.clone();
        if self.aggregates() {
            nets.insert(0, (self.net_set(), self.cfg.ipv6_prefix));
        }
        for (name, p) in nets {
            s += &format!(
                "add rule inet {t} input ip6 saddr and {} @{name} counter drop comment \"warden blocklist /{p}\"\n",
                ipv6_mask(p)
            );
        }
        s
    }

    /// Network sets of other prefixes in a `list sets` answer.
    fn legacy_from(&self, v: &serde_json::Value) -> Vec<(String, u8)> {
        let current = self.aggregates().then(|| self.net_set());
        let stem = format!("{}_", self.cfg.set_v6);
        set_names(v)
            .into_iter()
            .filter(|n| Some(n) != current.as_ref())
            .filter_map(|n| {
                let p: u8 = n.strip_prefix(&stem)?.parse().ok()?;
                (warden_core::net::MIN_IPV6_PREFIX..128).contains(&p).then_some((n, p))
            })
            .collect()
    }

    pub fn ensure(&mut self) -> Result<(), String> {
        if self.ready {
            return Ok(());
        }
        if !self.cfg.enabled {
            return Err("firewall actions disabled in configuration".into());
        }
        self.backend.available()?;
        // the table may hold network sets of an earlier `ipv6_prefix`
        self.legacy_nets = self.backend.list_sets(&self.cfg.table).map(|v| self.legacy_from(&v)).unwrap_or_default();
        self.backend.apply(&self.ruleset())?;
        self.ready = true;
        // blocks from before a restart are in the kernel: count them
        let _ = self.reconcile();
        Ok(())
    }

    fn set_for(&self, key: &Key) -> String {
        if key.is_ipv4() {
            self.cfg.set_v4.clone()
        } else if key.is_network() {
            self.net_set()
        } else {
            self.cfg.set_v6.clone()
        }
    }

    pub fn is_allowlisted(&self, ip: &IpAddr) -> bool {
        self.allow.contains(ip)
    }

    /// Does the allowlist reach into `key`'s network (without covering the
    /// address that is to be blocked)?
    pub fn allowlist_overlaps(&self, key: &Key) -> bool {
        self.allow.overlaps(key)
    }

    /// Entries in the sets (see [`Firewall::reconcile`]).
    pub fn count(&self) -> usize {
        self.count
    }

    /// Block one address (an operator's `wardenctl block`): exactly that
    /// address, or a network written with the configured prefix.
    pub fn block(&mut self, ip: IpAddr, ttl: Option<Duration>) -> Result<String, String> {
        self.block_key(Key::exact(ip), ttl)
    }

    pub fn block_key(&mut self, key: Key, ttl: Option<Duration>) -> Result<String, String> {
        let ttl = ttl.unwrap_or(self.cfg.default_ttl);
        self.block_keys(&[(key, ttl)]).pop().unwrap_or_else(|| Err(BlockError::Failed("nothing to do".into()))).map_err(
            |e| match e {
                BlockError::Refused(m) | BlockError::Failed(m) => m,
            },
        )
    }

    /// Why `key` cannot be blocked at all, before nft is asked. A network
    /// that holds an allowlisted address is never blocked as a whole (the
    /// responder blocks the one address instead).
    fn refuse(&self, key: &Key) -> Option<BlockError> {
        let a = key.addr();
        if !key.is_network() && self.is_allowlisted(&a) {
            return Some(BlockError::Refused(format!("{a} is allowlisted")));
        }
        if key.is_network() && self.allowlist_overlaps(key) {
            return Some(BlockError::Refused(format!("{key} holds allowlisted addresses")));
        }
        if a.is_unspecified() || a.is_multicast() {
            return Some(BlockError::Failed(format!("{key} is not a unicast address")));
        }
        None
    }

    /// Block a batch in one nft transaction. One result per item, in
    /// order. A failed transaction is split in halves to find the element
    /// that fails it; a table that disappeared is recreated once.
    pub fn block_keys(&mut self, items: &[(Key, Duration)]) -> Vec<Result<String, BlockError>> {
        let mut out: Vec<Option<Result<String, BlockError>>> =
            items.iter().map(|(k, _)| self.refuse(k).map(Err)).collect();
        if out.iter().all(Option::is_some) {
            // all refused: nft is not touched
            return out.into_iter().flatten().collect();
        }
        if let Err(e) = self.ensure() {
            let disabled = !self.cfg.enabled;
            return out
                .into_iter()
                .map(|r| {
                    r.unwrap_or_else(|| {
                        Err(if disabled { BlockError::Refused(e.clone()) } else { BlockError::Failed(e.clone()) })
                    })
                })
                .collect();
        }
        let max = self.cfg.max_blocked;
        let mut todo: Vec<usize> = Vec::new();
        for (i, r) in out.iter_mut().enumerate() {
            if r.is_some() {
                continue;
            }
            if max > 0 && self.count + todo.len() >= max {
                *r = Some(Err(BlockError::Failed(format!("blocklist full ({max} entries)"))));
                continue;
            }
            todo.push(i);
        }
        let ttls: Vec<u64> = items.iter().map(|(_, t)| t.as_secs().max(60)).collect();
        let res = self.apply_elements(items, &ttls, &todo, 0);
        for (i, r) in todo.into_iter().zip(res) {
            if r.is_ok() {
                self.count += 1;
            }
            out[i] = Some(r.map(|()| format!("blocked {} for {}s", items[i].0, ttls[i])).map_err(BlockError::Failed));
        }
        out.into_iter().map(|r| r.unwrap_or_else(|| Err(BlockError::Failed("not attempted".into())))).collect()
    }

    fn add_script(&self, items: &[(Key, Duration)], ttls: &[u64], which: &[usize]) -> String {
        let t = &self.cfg.table;
        let mut per_set: Vec<(String, Vec<String>)> = Vec::new();
        for &i in which {
            let set = self.set_for(&items[i].0);
            let elem = format!("{} timeout {}s", items[i].0.addr(), ttls[i]);
            match per_set.iter_mut().find(|(s, _)| *s == set) {
                Some((_, v)) => v.push(elem),
                None => per_set.push((set, vec![elem])),
            }
        }
        per_set.into_iter().map(|(s, v)| format!("add element inet {t} {s} {{ {} }}\n", v.join(", "))).collect()
    }

    fn apply_elements(
        &mut self,
        items: &[(Key, Duration)],
        ttls: &[u64],
        which: &[usize],
        depth: u32,
    ) -> Vec<Result<(), String>> {
        if which.is_empty() {
            return Vec::new();
        }
        let script = self.add_script(items, ttls, which);
        let mut res = self.backend.apply(&script);
        if let Err(e) = &res
            && missing(e)
        {
            // table deleted behind our back (a firewall reload): recreate once
            self.ready = false;
            self.count = 0;
            res = self.ensure().and_then(|()| self.backend.apply(&script));
        }
        match res {
            Ok(()) => which.iter().map(|_| Ok(())).collect(),
            Err(e) if which.len() == 1 || depth >= MAX_BISECT || missing(&e) => {
                which.iter().map(|_| Err(format!("nft add element: {e}"))).collect()
            }
            Err(_) => {
                let (a, b) = which.split_at(which.len() / 2);
                let mut r = self.apply_elements(items, ttls, a, depth + 1);
                r.extend(self.apply_elements(items, ttls, b, depth + 1));
                r
            }
        }
    }

    /// Remove a block. An IPv6 address takes its network's block with it;
    /// a network (`2001:db8:aa:1::/64`) is removed as written.
    pub fn unblock(&mut self, key: Key) -> Result<String, String> {
        self.ensure()?;
        let t = self.cfg.table.clone();
        let mut targets = vec![(self.set_for(&key), key)];
        if key.is_ipv4() || key.is_network() {
            // as given
        } else if self.aggregates() {
            let net = Key::of(key.addr(), self.cfg.ipv6_prefix);
            targets.push((self.net_set(), net));
        }
        let mut done = Vec::new();
        let mut errors = Vec::new();
        for (set, k) in targets {
            match self.backend.apply(&format!("delete element inet {t} {set} {{ {} }}\n", k.addr())) {
                Ok(()) => {
                    self.count = self.count.saturating_sub(1);
                    done.push(k.to_string());
                }
                Err(e) => errors.push(e),
            }
        }
        if done.is_empty() { Err(errors.join("; ")) } else { Ok(format!("unblocked {}", done.join(" and "))) }
    }

    /// Every set of the table, as listed now.
    fn sets(&self) -> Vec<(String, Option<u8>)> {
        let mut v = vec![(self.cfg.set_v4.clone(), None), (self.cfg.set_v6.clone(), None)];
        if self.aggregates() {
            v.push((self.net_set(), Some(self.cfg.ipv6_prefix)));
        }
        v.extend(self.legacy_nets.iter().map(|(n, p)| (n.clone(), Some(*p))));
        v
    }

    /// Current set contents (from the kernel, so blocks survive restarts).
    pub fn list(&self) -> Vec<Blocked> {
        let mut out = Vec::new();
        for (set, prefix) in self.sets() {
            if let Ok(v) = self.backend.list_set(&self.cfg.table, &set) {
                out.extend(parse_set_json(&v).into_iter().map(|mut b| {
                    if let Some(p) = prefix {
                        b.ip = format!("{}/{p}", b.ip);
                    }
                    b
                }));
            }
        }
        out
    }

    /// Count the sets again (the network lane does this once a minute):
    /// expired blocks leave the count, a vanished table is noticed, a
    /// network set of an earlier prefix that has emptied is removed.
    /// Returns the number of entries.
    pub fn reconcile(&mut self) -> Result<usize, String> {
        if !self.ready {
            return Ok(self.count);
        }
        let mut n = 0;
        let mut emptied = Vec::new();
        for (set, _) in self.sets() {
            match self.backend.list_set(&self.cfg.table, &set) {
                Ok(v) => {
                    let k = parse_set_json(&v).len();
                    n += k;
                    if k == 0 && self.legacy_nets.iter().any(|(l, _)| *l == set) {
                        emptied.push(set);
                    }
                }
                Err(e) if missing(&e) => {
                    // gone: the next block puts the table back
                    self.ready = false;
                    self.count = 0;
                    return Err(e);
                }
                Err(e) => return Err(e),
            }
        }
        self.count = n;
        self.reconciled = Some(Instant::now());
        if !emptied.is_empty() {
            self.legacy_nets.retain(|(l, _)| !emptied.contains(l));
            let mut script = self.ruleset();
            for s in &emptied {
                script += &format!("delete set inet {} {s}\n", self.cfg.table);
            }
            if self.backend.apply(&script).is_err() {
                self.ready = false; // rebuilt from what is there at the next block
            }
        }
        Ok(n)
    }

    /// When the sets were last counted.
    pub fn reconciled(&self) -> Option<Instant> {
        self.reconciled
    }
}

/// Names of the sets in a `list sets` / `list table` answer.
fn set_names(v: &serde_json::Value) -> Vec<String> {
    v.get("nftables")
        .and_then(|x| x.as_array())
        .into_iter()
        .flatten()
        .filter_map(|it| it.get("set")?.get("name")?.as_str().map(str::to_owned))
        .collect()
}

/// An element value: an address, `{"prefix": {"addr", "len"}}` or
/// `{"range": [a, b]}`.
fn element_value(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(o) => {
            if let Some(p) = o.get("prefix") {
                let a = p.get("addr")?.as_str()?;
                let l = p.get("len")?.as_u64()?;
                return Some(format!("{a}/{l}"));
            }
            let r = o.get("range")?.as_array()?;
            Some(format!("{}-{}", r.first()?.as_str()?, r.get(1)?.as_str()?))
        }
        _ => None,
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
                    if let Some(ip) = inner.get("val").and_then(element_value) {
                        out.push(Blocked { ip, expires_seconds: inner.get("expires").and_then(|x| x.as_u64()) });
                    }
                }
                _ => {}
            }
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod fake {
    //! A stand-in for nft: keeps the sets in memory, records the scripts,
    //! can be slowed down and made to fail.

    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, Default)]
    pub struct FakeNft {
        pub scripts: Mutex<Vec<String>>,
        /// `list set` calls
        pub lists: AtomicUsize,
        /// set → elements
        pub sets: Mutex<BTreeMap<String, Vec<String>>>,
        pub delay: Duration,
        /// Fail a script that contains this text.
        pub fail_on: Mutex<Option<String>>,
        pub table_exists: Mutex<bool>,
    }

    impl FakeNft {
        pub fn applies(&self) -> usize {
            self.scripts.lock().unwrap().len()
        }

        pub fn elements(&self, set: &str) -> Vec<String> {
            self.sets.lock().unwrap().get(set).cloned().unwrap_or_default()
        }
    }

    impl Backend for FakeNft {
        fn apply(&self, script: &str) -> Result<(), String> {
            std::thread::sleep(self.delay);
            self.scripts.lock().unwrap().push(script.to_owned());
            if let Some(f) = self.fail_on.lock().unwrap().as_deref()
                && script.contains(f)
            {
                return Err(format!("nft: Error: injected failure on {f}"));
            }
            let mut exists = self.table_exists.lock().unwrap();
            let mut sets = self.sets.lock().unwrap();
            for line in script.lines() {
                let w: Vec<&str> = line.split_whitespace().collect();
                if line.starts_with("table inet ") {
                    *exists = true;
                } else if line.starts_with("  set ") {
                    sets.entry(w[1].to_owned()).or_default();
                } else if line.starts_with("add element") || line.starts_with("delete element") {
                    if !*exists {
                        return Err("Error: Could not process rule: No such file or directory".into());
                    }
                    let set = w[4].to_owned();
                    let body = line.split_once('{').unwrap().1.trim_end().trim_end_matches('}');
                    let elems: Vec<String> =
                        body.split(',').map(|e| e.split_whitespace().next().unwrap_or("").to_owned()).collect();
                    let v = sets.entry(set).or_default();
                    if line.starts_with("add") {
                        for e in elems {
                            if !v.contains(&e) {
                                v.push(e);
                            }
                        }
                    } else {
                        for e in elems {
                            let Some(i) = v.iter().position(|x| *x == e) else {
                                return Err("Error: element does not exist".into());
                            };
                            v.remove(i);
                        }
                    }
                } else if line.starts_with("delete set") {
                    sets.remove(w[4]);
                }
            }
            Ok(())
        }

        fn list_set(&self, _table: &str, set: &str) -> Result<serde_json::Value, String> {
            self.lists.fetch_add(1, Ordering::Relaxed);
            if !*self.table_exists.lock().unwrap() {
                return Err("Error: No such file or directory".into());
            }
            let elems = self.elements(set);
            Ok(
                serde_json::json!({"nftables": [{"set": {"name": set, "elem": elems.iter().map(|e| serde_json::json!({"elem": {"val": e, "expires": 100}})).collect::<Vec<_>>()}}]}),
            )
        }

        fn list_sets(&self, _table: &str) -> Result<serde_json::Value, String> {
            if !*self.table_exists.lock().unwrap() {
                return Err("Error: No such file or directory".into());
            }
            let names: Vec<String> = self.sets.lock().unwrap().keys().cloned().collect();
            Ok(
                serde_json::json!({"nftables": names.iter().map(|n| serde_json::json!({"set": {"name": n}})).collect::<Vec<_>>()}),
            )
        }

        fn available(&self) -> Result<(), String> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeNft;
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn fw(nft: &Arc<FakeNft>) -> Firewall {
        Firewall::with_backend(&FirewallConfig::default(), &[], nft.clone())
    }

    #[test]
    fn ruleset_and_allowlist() {
        let f = Firewall::new(&FirewallConfig::default(), &["10.0.0.0/8".into()]);
        let r = f.ruleset();
        assert!(r.contains("table inet warden"));
        assert!(r.contains("flush chain inet warden input"));
        assert!(r.contains("ip saddr @blocklist4"));
        assert!(r.contains("ip6 saddr @blocklist6 "));
        assert!(r.contains("set blocklist6_64 { type ipv6_addr; flags timeout;"), "{r}");
        assert!(r.contains("ip6 saddr and ffff:ffff:ffff:ffff:: @blocklist6_64 counter drop"), "{r}");
        assert!(!r.contains("interval"), "plain sets: nft calls stay O(1)");
        assert!(f.is_allowlisted(&"127.0.0.1".parse().unwrap()));
        assert!(f.is_allowlisted(&"10.2.3.4".parse().unwrap()));
        assert!(!f.is_allowlisted(&"203.0.113.1".parse().unwrap()));
        // per address: no network set
        let f = Firewall::new(&FirewallConfig { ipv6_prefix: 128, ..Default::default() }, &[]);
        assert!(!f.ruleset().contains("blocklist6_"), "{}", f.ruleset());
    }

    #[test]
    fn refuses_allowlisted_block() {
        let nft = Arc::new(FakeNft::default());
        let mut f = fw(&nft);
        assert!(f.block("127.0.0.1".parse().unwrap(), None).unwrap_err().contains("allowlisted"));
        assert_eq!(nft.applies(), 0, "refused before nft");
        // a network is never blocked over an allowlisted address in it
        let cfg = FirewallConfig { allowlist: vec!["2001:db8:aa:1::10/128".into()], ..Default::default() };
        let mut f = Firewall::with_backend(&cfg, &[], nft.clone());
        let e = f.block_key(Key::of(ip("2001:db8:aa:1::5"), 64), None).unwrap_err();
        assert!(e.contains("holds allowlisted"), "{e}");
        assert!(f.block_key(Key::of(ip("2001:db8:aa:2::5"), 64), None).is_ok());
    }

    #[test]
    fn a_batch_is_one_transaction_into_the_right_sets() {
        let nft = Arc::new(FakeNft::default());
        let mut f = fw(&nft);
        let h = Duration::from_secs(3600);
        let items = [
            (Key::of(ip("203.0.113.5"), 64), h),
            (Key::of(ip("2001:db8:aa:1::5"), 64), h),
            (Key::exact(ip("2001:db8:bb::7")), h),
            (Key::of(ip("198.51.100.9"), 64), Duration::from_secs(5)),
        ];
        let before = nft.applies();
        let res = f.block_keys(&items);
        assert!(res.iter().all(|r| r.is_ok()), "{res:?}");
        assert_eq!(res[1].as_ref().unwrap(), "blocked 2001:db8:aa:1::/64 for 3600s");
        assert_eq!(res[3].as_ref().unwrap(), "blocked 198.51.100.9 for 60s", "a minute at least");
        // ensure (ruleset) + one transaction for all four
        let scripts = nft.scripts.lock().unwrap().clone();
        assert_eq!(scripts.len() - before, 2, "{scripts:#?}");
        let add = scripts.last().unwrap();
        assert!(
            add.contains("add element inet warden blocklist4 { 203.0.113.5 timeout 3600s, 198.51.100.9 timeout 60s }")
        );
        assert!(add.contains("add element inet warden blocklist6_64 { 2001:db8:aa:1:: timeout 3600s }"), "{add}");
        assert!(add.contains("add element inet warden blocklist6 { 2001:db8:bb::7 timeout 3600s }"));
        assert_eq!(f.count(), 4);
    }

    #[test]
    fn a_bad_element_fails_alone() {
        let nft = Arc::new(FakeNft::default());
        let mut f = fw(&nft);
        f.ensure().unwrap();
        *nft.fail_on.lock().unwrap() = Some("203.0.113.66".into());
        let items: Vec<(Key, Duration)> =
            (60..70).map(|i| (Key::of(ip(&format!("203.0.113.{i}")), 64), Duration::from_secs(600))).collect();
        let res = f.block_keys(&items);
        let failed: Vec<usize> = res.iter().enumerate().filter(|(_, r)| r.is_err()).map(|(i, _)| i).collect();
        assert_eq!(failed, [6], "{res:?}");
        assert_eq!(nft.elements("blocklist4").len(), 9);
    }

    #[test]
    fn a_vanished_table_is_recreated() {
        let nft = Arc::new(FakeNft::default());
        let mut f = fw(&nft);
        assert!(f.block(ip("203.0.113.1"), None).is_ok());
        // `nft flush ruleset`
        *nft.table_exists.lock().unwrap() = false;
        nft.sets.lock().unwrap().clear();
        assert!(f.block(ip("203.0.113.2"), None).is_ok());
        assert_eq!(nft.elements("blocklist4"), ["203.0.113.2"]);
        // noticed by the reconciliation as well
        *nft.table_exists.lock().unwrap() = false;
        assert!(f.reconcile().is_err());
        assert_eq!(f.count(), 0);
        assert!(f.block(ip("203.0.113.3"), None).is_ok());
    }

    #[test]
    fn the_count_is_reconciled_not_listed_per_block() {
        let nft = Arc::new(FakeNft::default());
        let cfg = FirewallConfig { max_blocked: 3, ..Default::default() };
        let mut f = Firewall::with_backend(&cfg, &[], nft.clone());
        let items: Vec<(Key, Duration)> =
            (1..=5).map(|i| (Key::of(ip(&format!("203.0.113.{i}")), 64), Duration::from_secs(600))).collect();
        let res = f.block_keys(&items);
        let listed = nft.lists.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(res.iter().filter(|r| r.is_ok()).count(), 3);
        assert!(matches!(&res[4], Err(BlockError::Failed(m)) if m.contains("blocklist full")));
        assert!(f.block(ip("203.0.113.8"), None).unwrap_err().contains("blocklist full"));
        assert_eq!(nft.lists.load(std::sync::atomic::Ordering::Relaxed), listed, "a block never lists the sets");
        // two expire in the kernel; the next reconciliation makes room
        nft.sets.lock().unwrap().get_mut("blocklist4").unwrap().truncate(1);
        assert_eq!(f.reconcile().unwrap(), 1);
        assert!(f.block(ip("203.0.113.9"), None).is_ok());
    }

    #[test]
    fn unblocking_an_address_lifts_its_network_too() {
        let nft = Arc::new(FakeNft::default());
        let mut f = fw(&nft);
        let net = Key::of(ip("2001:db8:aa:1::5"), 64);
        assert!(f.block_key(net, None).is_ok());
        assert_eq!(nft.elements("blocklist6_64"), ["2001:db8:aa:1::"]);
        let m = f.unblock(Key::exact(ip("2001:db8:aa:1::5"))).unwrap();
        assert_eq!(m, "unblocked 2001:db8:aa:1::/64");
        assert!(nft.elements("blocklist6_64").is_empty());
        assert!(f.unblock(Key::exact(ip("2001:db8:aa:1::5"))).is_err(), "nothing left to lift");
        // listing shows networks with their length
        f.block_key(net, None).unwrap();
        f.block(ip("203.0.113.4"), None).unwrap();
        let l: Vec<String> = f.list().into_iter().map(|b| b.ip).collect();
        assert_eq!(l, ["203.0.113.4", "2001:db8:aa:1::/64"]);
    }

    #[test]
    fn a_network_set_of_an_earlier_prefix_holds_until_it_empties() {
        let nft = Arc::new(FakeNft::default());
        let mut f = fw(&nft);
        f.block_key(Key::of(ip("2001:db8:aa:1::5"), 64), None).unwrap();
        // the operator moves to /56
        let cfg = FirewallConfig { ipv6_prefix: 56, ..Default::default() };
        let mut f = Firewall::with_backend(&cfg, &[], nft.clone());
        f.ensure().unwrap();
        let r = nft.scripts.lock().unwrap().last().unwrap().clone();
        assert!(r.contains("ip6 saddr and ffff:ffff:ffff:ff00:: @blocklist6_56"), "{r}");
        assert!(r.contains("ip6 saddr and ffff:ffff:ffff:ffff:: @blocklist6_64"), "the /64 blocks still hold: {r}");
        assert_eq!(f.list().len(), 1);
        // the last /64 block expires: the old set goes
        nft.sets.lock().unwrap().get_mut("blocklist6_64").unwrap().clear();
        f.reconcile().unwrap();
        let r = nft.scripts.lock().unwrap().last().unwrap().clone();
        assert!(r.contains("delete set inet warden blocklist6_64"), "{r}");
        assert!(!r.contains("@blocklist6_64"), "{r}");
        assert!(!nft.sets.lock().unwrap().contains_key("blocklist6_64"));
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
        // interval sets (an operator's own) list prefixes
        let v: serde_json::Value = serde_json::from_str(
            r#"{"nftables":[{"set":{"name":"x","elem":[{"elem":{"val":{"prefix":{"addr":"2001:db8:cc:1::","len":64}},"timeout":7200,"expires":7199}}]}}]}"#,
        )
        .unwrap();
        assert_eq!(parse_set_json(&v)[0].ip, "2001:db8:cc:1::/64");
    }
}
