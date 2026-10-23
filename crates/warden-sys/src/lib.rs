//! # warden-sys
//!
//! Thin, allocation-conscious wrappers over the Linux interfaces Warden
//! relies on. Everything here is synchronous and side-effect free unless the
//! function name says otherwise (`cgroup::kill`, `pidfd::terminate`, ...).
//!
//! | module | interface |
//! |---|---|
//! | [`psi`] | `/proc/pressure/*`, kernel PSI triggers |
//! | [`mem`] | `/proc/meminfo`, `/proc/vmstat` |
//! | [`system`] | `/proc/stat`, loadavg, file-nr, pid_max |
//! | [`process`] | `/proc/<pid>/*` |
//! | [`dbus`] | minimal D-Bus client (systemd unit state changes) |
//! | [`pidfd`] | `pidfd_open` / `pidfd_send_signal` |
//! | [`cgroup`] | cgroup v2 (`cgroup.freeze`, `cgroup.kill`, memory) |
//! | [`clock`] | a clock that keeps running during suspend (`CLOCK_BOOTTIME`) |
//! | [`mounts`] | mountinfo, `statvfs` |
//! | [`du`] | bounded `du -x` walk: who uses the space on a filesystem |
//! | [`pace`] | adaptive pacing of background scans by I/O pressure |
//! | [`kmsg`] | `/dev/kmsg` |
//! | [`proc_connector`] | netlink proc connector (exec/uid/ptrace events) |
//! | [`fanotify`] | fanotify mount marks (writer PID for changed files) |
//! | [`fanotify_fid`] | fanotify filesystem marks in file-handle mode (`chmod u+s` in real time) |
//! | [`net`] | snmp/netstat counters, `/proc/net/{dev,tcp,tcp6}`, conntrack |
//! | [`kernel`] | taint, modules, LSM state, clock sync |
//! | [`hw`] | EDAC, thermal zones |
//! | [`safefs`] | race-free file operations on directory descriptors (`openat`, `O_NOFOLLOW`) |
//! | [`pagecache`] | `cachestat` + `fadvise`: scans do not pollute the page cache |
//! | [`selfstat`] | the daemon's own per-thread CPU/I/O, memory, allocator |
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod cgroup;
pub mod clock;
pub mod cmd;
pub mod dbus;
pub mod du;
pub mod fanotify;
pub mod fanotify_fid;
pub mod fsflags;
pub mod hw;
pub mod kernel;
pub mod kmsg;
pub mod mem;
pub mod mounts;
pub mod net;
pub mod pace;
pub mod pagecache;
pub mod pidfd;
pub mod proc_connector;
pub mod process;
pub mod psi;
pub mod safefs;
pub mod sched;
pub mod sdnotify;
pub mod selfstat;
pub mod sysctl;
pub mod system;
pub mod users;
pub mod util;
