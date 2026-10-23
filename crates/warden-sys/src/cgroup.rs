//! cgroup v2 helpers: freeze/thaw, kill, memory accounting, unit lookup.

use crate::util::{read_string, read_u64};
use std::io;
use std::path::PathBuf;

pub const ROOT: &str = "/sys/fs/cgroup";

pub fn is_v2() -> bool {
    std::path::Path::new(ROOT).join("cgroup.controllers").exists()
}

/// Absolute sysfs directory of a cgroup path (`/system.slice/x.service`).
pub fn dir(path: &str) -> PathBuf {
    let rel = path.trim_start_matches('/');
    if rel.is_empty() { PathBuf::from(ROOT) } else { PathBuf::from(ROOT).join(rel) }
}

/// The systemd unit (`*.service` / `*.scope`) owning a cgroup path.
pub fn unit_of(path: &str) -> Option<String> {
    path.rsplit('/').find(|c| c.ends_with(".service") || c.ends_with(".scope")).map(str::to_owned)
}

fn hex_id(s: &str) -> Option<&str> {
    let s = s.trim_end_matches(".scope");
    (s.len() >= 12 && s.chars().all(|c| c.is_ascii_hexdigit())).then_some(s)
}

fn docker_name(id: &str) -> Option<String> {
    let cfg = std::fs::read_to_string(format!("/var/lib/docker/containers/{id}/config.v2.json")).ok()?;
    // Avoid a JSON dependency here: "Name":"/web-1"
    let start = cfg.find("\"Name\":\"")? + 8;
    let end = cfg[start..].find('"')? + start;
    Some(cfg[start..end].trim_start_matches('/').to_owned()).filter(|n| !n.is_empty())
}

/// Identify the container a cgroup path belongs to: Docker (systemd and
/// cgroupfs drivers), Podman, containerd/Kubernetes, LXC and systemd-nspawn.
pub fn container_of(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    for (i, p) in parts.iter().enumerate() {
        if let Some(id) = p
            .strip_prefix("docker-")
            .and_then(hex_id)
            .or_else(|| (i > 0 && parts[i - 1] == "docker").then(|| hex_id(p)).flatten())
        {
            return Some(match docker_name(id) {
                Some(n) => format!("docker:{n}"),
                None => format!("docker:{}", &id[..12]),
            });
        }
        if let Some(id) = p.strip_prefix("libpod-").and_then(hex_id) {
            return Some(format!("podman:{}", &id[..12]));
        }
        if let Some(id) = p.strip_prefix("cri-containerd-").or_else(|| p.strip_prefix("crio-")).and_then(hex_id) {
            let pod = parts.iter().find_map(|x| {
                let x = x.trim_end_matches(".slice");
                x.rsplit_once("-pod").map(|(_, u)| u).or_else(|| x.strip_prefix("pod")).map(|u| u.replace('_', "-"))
            });
            return Some(match pod {
                Some(u) => format!("k8s:pod-{}/{}", &u[..u.len().min(8)], &id[..12]),
                None => format!("containerd:{}", &id[..12]),
            });
        }
        if let Some(n) = p.strip_prefix("lxc.payload.") {
            return Some(format!("lxc:{n}"));
        }
        if *p == "lxc" && i + 1 < parts.len() {
            return Some(format!("lxc:{}", parts[i + 1]));
        }
        if let Some(n) = p.strip_prefix("systemd-nspawn@").and_then(|x| x.strip_suffix(".service")) {
            return Some(format!("machine:{n}"));
        }
        if let Some(n) = p.strip_prefix("machine-").and_then(|x| x.strip_suffix(".scope")) {
            return Some(format!("machine:{n}"));
        }
    }
    None
}

/// Effective memory view inside a container: when the cgroup namespace root
/// has a `memory.max` limit (true root cgroups have none), returns
/// `(limit, used_without_reclaimable_cache)`.
pub fn namespace_memory_limit() -> Option<(u64, u64)> {
    let root = std::path::Path::new(ROOT);
    let max = read_string(root.join("memory.max")).ok()?;
    let limit: u64 = max.trim().parse().ok()?; // "max" → None
    let current = read_u64(root.join("memory.current"))?;
    let inactive_file = read_string(root.join("memory.stat"))
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| l.strip_prefix("inactive_file ").and_then(|v| v.trim().parse::<u64>().ok()))
        })
        .unwrap_or(0);
    Some((limit, current.saturating_sub(inactive_file)))
}

/// Leaf cgroups ranked by memory PSI `some avg10` (which service is stalling).
pub fn top_memory_pressure(max_depth: usize, limit: usize) -> Vec<(String, f64)> {
    let mut leaves = Vec::new();
    walk(&PathBuf::from(ROOT), "", 0, max_depth, &mut leaves);
    let mut v: Vec<(String, f64)> = leaves
        .into_iter()
        .filter_map(|(p, _)| {
            let psi = crate::psi::read_path(dir(&p).join("memory.pressure")).ok()?;
            Some((p, psi.some.avg10)).filter(|x| x.1 > 0.0)
        })
        .collect();
    v.sort_by(|a, b| b.1.total_cmp(&a.1));
    v.truncate(limit);
    v
}

/// Freeze (or thaw) every task in the cgroup.
pub fn freeze(path: &str, frozen: bool) -> io::Result<()> {
    guard_root(path)?;
    std::fs::write(dir(path).join("cgroup.freeze"), if frozen { "1" } else { "0" })
}

/// SIGKILL every task in the cgroup (Linux 5.14+).
pub fn kill(path: &str) -> io::Result<()> {
    guard_root(path)?;
    std::fs::write(dir(path).join("cgroup.kill"), "1")
}

fn guard_root(path: &str) -> io::Result<()> {
    let p = path.trim_matches('/');
    if p.is_empty() || p == "init.scope" || p == "system.slice" || p == "user.slice" {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "refusing to act on a top-level cgroup"));
    }
    Ok(())
}

pub fn procs(path: &str) -> Vec<i32> {
    read_string(dir(path).join("cgroup.procs"))
        .map(|s| s.lines().filter_map(|l| l.trim().parse().ok()).collect())
        .unwrap_or_default()
}

/// Memory charged to a cgroup, split by how hard it is to get back.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct MemoryUsage {
    /// `memory.current`: everything charged (what `systemctl status` shows).
    pub current: u64,
    pub anon: u64,
    /// Page cache (includes shmem).
    pub file: u64,
    pub shmem: u64,
    /// Kernel memory: slab (dentries, inodes), stacks, page tables, sockets.
    pub kernel: u64,
    pub slab_reclaimable: u64,
}

impl MemoryUsage {
    /// Memory the kernel cannot simply drop under pressure.
    pub fn pinned(&self) -> u64 {
        self.anon + self.shmem + self.kernel.saturating_sub(self.slab_reclaimable)
    }

    /// Clean page cache and reclaimable slab: freed on demand, not a leak.
    pub fn reclaimable(&self) -> u64 {
        self.current.saturating_sub(self.pinned())
    }

    pub fn parse_stat(current: u64, stat: &str) -> Self {
        let mut m = std::collections::HashMap::new();
        for l in stat.lines() {
            if let Some((k, v)) = l.split_once(' ')
                && let Ok(v) = v.trim().parse::<u64>()
            {
                m.insert(k, v);
            }
        }
        let g = |k: &str| m.get(k).copied().unwrap_or(0);
        // `kernel` exists since Linux 5.18; sum its parts on older kernels.
        let kernel = m.get("kernel").copied().unwrap_or_else(|| {
            g("kernel_stack")
                + g("pagetables")
                + g("percpu")
                + g("sock")
                + g("slab_reclaimable")
                + g("slab_unreclaimable")
        });
        Self {
            current,
            anon: g("anon"),
            file: g("file"),
            shmem: g("shmem"),
            kernel,
            slab_reclaimable: g("slab_reclaimable"),
        }
    }
}

/// Memory usage of one cgroup (v2).
pub fn memory_usage(path: &str) -> Option<MemoryUsage> {
    let d = dir(path);
    let current = read_u64(d.join("memory.current"))?;
    let stat = read_string(d.join("memory.stat")).unwrap_or_default();
    Some(MemoryUsage::parse_stat(current, &stat))
}

/// Leaf cgroups ranked by memory they *pin* (anon + shmem + unreclaimable
/// kernel memory). Ranking by `memory.current` would put whoever last read
/// a lot of files on top — page cache is reclaimable and is not what causes
/// memory pressure. Walks the hierarchy up to `max_depth` levels.
pub fn top_memory(max_depth: usize, limit: usize) -> Vec<(String, MemoryUsage)> {
    let mut out = Vec::new();
    walk(&PathBuf::from(ROOT), "", 0, max_depth, &mut out);
    out.sort_by_key(|b| std::cmp::Reverse(b.1.pinned()));
    out.truncate(limit);
    out
}

fn walk(abs: &std::path::Path, rel: &str, depth: usize, max: usize, out: &mut Vec<(String, MemoryUsage)>) {
    let Ok(rd) = std::fs::read_dir(abs) else { return };
    let mut has_child = false;
    for e in rd.filter_map(Result::ok) {
        if e.file_type().map(|t| t.is_dir()).unwrap_or(false) && depth < max {
            has_child = true;
            let name = e.file_name().to_string_lossy().into_owned();
            walk(&e.path(), &format!("{rel}/{name}"), depth + 1, max, out);
        }
    }
    if (!has_child || depth == max)
        && !rel.is_empty()
        && let Some(current) = read_u64(abs.join("memory.current"))
    {
        let stat = read_string(abs.join("memory.stat")).unwrap_or_default();
        out.push((rel.to_owned(), MemoryUsage::parse_stat(current, &stat)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_lookup() {
        assert_eq!(unit_of("/system.slice/nginx.service").as_deref(), Some("nginx.service"));
        assert_eq!(
            unit_of("/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox-12.scope").as_deref(),
            Some("app-firefox-12.scope")
        );
        assert_eq!(unit_of("/system.slice/php8.3-fpm.service/pool-a").as_deref(), Some("php8.3-fpm.service"));
        assert_eq!(unit_of("/"), None);
    }

    #[test]
    fn containers() {
        let id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(container_of(&format!("/system.slice/docker-{id}.scope")).unwrap(), "docker:0123456789ab");
        assert_eq!(container_of(&format!("/docker/{id}")).unwrap(), "docker:0123456789ab");
        assert_eq!(container_of(&format!("/machine.slice/libpod-{id}.scope")).unwrap(), "podman:0123456789ab");
        assert_eq!(
            container_of(&format!(
                "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1a2b3c4d_5e6f.slice/cri-containerd-{id}.scope"
            ))
            .unwrap(),
            "k8s:pod-1a2b3c4d/0123456789ab"
        );
        assert_eq!(container_of("/lxc.payload.web/init.scope").unwrap(), "lxc:web");
        assert_eq!(container_of("/machine.slice/systemd-nspawn@db.service").unwrap(), "machine:db");
        assert_eq!(container_of("/system.slice/nginx.service"), None);
    }

    #[test]
    fn memory_breakdown() {
        let stat = "anon 104857600\nfile 2147483648\nkernel 805306368\nshmem 0\nslab_reclaimable 754974720\n";
        let m = MemoryUsage::parse_stat(3_057_655_808, stat);
        assert_eq!(m.pinned(), 104_857_600 + 805_306_368 - 754_974_720);
        assert!(m.reclaimable() > 2_800_000_000);
        // pre-5.18 kernels: no `kernel` key
        let m = MemoryUsage::parse_stat(10, "anon 1\nslab_reclaimable 4\nslab_unreclaimable 2\nkernel_stack 3\n");
        assert_eq!(m.kernel, 9);
    }

    #[test]
    fn refuses_top_level() {
        assert!(freeze("/", true).is_err());
        assert!(kill("/system.slice").is_err());
        assert!(kill("/init.scope").is_err());
    }

    #[test]
    fn dir_mapping() {
        assert_eq!(dir("/system.slice/a.service"), PathBuf::from("/sys/fs/cgroup/system.slice/a.service"));
        assert_eq!(dir("/"), PathBuf::from("/sys/fs/cgroup"));
    }
}
