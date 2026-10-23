//! Real-time process events through the netlink *proc connector*
//! (`CONFIG_PROC_EVENTS`, requires `CAP_NET_ADMIN`).
//!
//! Unlike eBPF this needs no compiler toolchain, no BTF and works on every
//! distribution kernel since 2.6.15, while still delivering fork/exec/
//! uid/gid/ptrace/exit events with near-zero overhead.

use crate::util::{cvt, u32_ne};
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const NETLINK_CONNECTOR: libc::c_int = 11;
const CN_IDX_PROC: u32 = 1;
const CN_VAL_PROC: u32 = 1;
const PROC_CN_MCAST_LISTEN: u32 = 1;
const NLMSG_HDRLEN: usize = 16;
const CN_MSG_LEN: usize = 20;

pub const PROC_EVENT_FORK: u32 = 0x0000_0001;
pub const PROC_EVENT_EXEC: u32 = 0x0000_0002;
pub const PROC_EVENT_UID: u32 = 0x0000_0004;
pub const PROC_EVENT_GID: u32 = 0x0000_0040;
pub const PROC_EVENT_SID: u32 = 0x0000_0080;
pub const PROC_EVENT_PTRACE: u32 = 0x0000_0100;
pub const PROC_EVENT_COMM: u32 = 0x0000_0200;
pub const PROC_EVENT_COREDUMP: u32 = 0x4000_0000;
pub const PROC_EVENT_EXIT: u32 = 0x8000_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcEvent {
    Fork {
        parent_pid: i32,
        parent_tgid: i32,
        child_pid: i32,
        child_tgid: i32,
    },
    Exec {
        pid: i32,
        tgid: i32,
    },
    Uid {
        pid: i32,
        tgid: i32,
        ruid: u32,
        euid: u32,
    },
    Gid {
        pid: i32,
        tgid: i32,
        rgid: u32,
        egid: u32,
    },
    Sid {
        pid: i32,
        tgid: i32,
    },
    Ptrace {
        pid: i32,
        tgid: i32,
        tracer_pid: i32,
        tracer_tgid: i32,
    },
    Comm {
        pid: i32,
        tgid: i32,
        comm: String,
    },
    Coredump {
        pid: i32,
        tgid: i32,
    },
    Exit {
        pid: i32,
        tgid: i32,
        exit_code: u32,
        exit_signal: u32,
    },
    /// Subscription acknowledgement or unknown event type.
    Other(u32),
}

fn i32_at(b: &[u8], off: usize) -> Option<i32> {
    u32_ne(b, off).map(|v| v as i32)
}

/// Parse one `struct proc_event` (the payload of a `cn_msg`).
pub fn parse_proc_event(ev: &[u8]) -> Option<ProcEvent> {
    let what = u32_ne(ev, 0)?;
    // Layout: what(4) cpu(4) timestamp_ns(8) event_data(union) at offset 16.
    let d = 16;
    Some(match what {
        PROC_EVENT_FORK => ProcEvent::Fork {
            parent_pid: i32_at(ev, d)?,
            parent_tgid: i32_at(ev, d + 4)?,
            child_pid: i32_at(ev, d + 8)?,
            child_tgid: i32_at(ev, d + 12)?,
        },
        PROC_EVENT_EXEC => ProcEvent::Exec { pid: i32_at(ev, d)?, tgid: i32_at(ev, d + 4)? },
        PROC_EVENT_UID => ProcEvent::Uid {
            pid: i32_at(ev, d)?,
            tgid: i32_at(ev, d + 4)?,
            ruid: u32_ne(ev, d + 8)?,
            euid: u32_ne(ev, d + 12)?,
        },
        PROC_EVENT_GID => ProcEvent::Gid {
            pid: i32_at(ev, d)?,
            tgid: i32_at(ev, d + 4)?,
            rgid: u32_ne(ev, d + 8)?,
            egid: u32_ne(ev, d + 12)?,
        },
        PROC_EVENT_SID => ProcEvent::Sid { pid: i32_at(ev, d)?, tgid: i32_at(ev, d + 4)? },
        PROC_EVENT_PTRACE => ProcEvent::Ptrace {
            pid: i32_at(ev, d)?,
            tgid: i32_at(ev, d + 4)?,
            tracer_pid: i32_at(ev, d + 8)?,
            tracer_tgid: i32_at(ev, d + 12)?,
        },
        PROC_EVENT_COMM => {
            let raw = ev.get(d + 8..d + 24)?;
            let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
            ProcEvent::Comm {
                pid: i32_at(ev, d)?,
                tgid: i32_at(ev, d + 4)?,
                comm: String::from_utf8_lossy(&raw[..end]).into_owned(),
            }
        }
        PROC_EVENT_COREDUMP => ProcEvent::Coredump { pid: i32_at(ev, d)?, tgid: i32_at(ev, d + 4)? },
        PROC_EVENT_EXIT => ProcEvent::Exit {
            pid: i32_at(ev, d)?,
            tgid: i32_at(ev, d + 4)?,
            exit_code: u32_ne(ev, d + 8)?,
            exit_signal: u32_ne(ev, d + 12)?,
        },
        other => ProcEvent::Other(other),
    })
}

/// Parse a datagram that may contain several netlink messages.
pub fn parse_datagram(buf: &[u8]) -> Vec<ProcEvent> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + NLMSG_HDRLEN <= buf.len() {
        let Some(len) = u32_ne(buf, off).map(|v| v as usize) else { break };
        if len < NLMSG_HDRLEN || off + len > buf.len() {
            break;
        }
        let msg = &buf[off..off + len];
        // cn_msg: id.idx(4) id.val(4) seq(4) ack(4) len(2) flags(2) data[]
        if msg.len() >= NLMSG_HDRLEN + CN_MSG_LEN
            && u32_ne(msg, NLMSG_HDRLEN) == Some(CN_IDX_PROC)
            && let Some(ev) = parse_proc_event(&msg[NLMSG_HDRLEN + CN_MSG_LEN..])
        {
            out.push(ev);
        }
        // NLMSG_ALIGN
        off += (len + 3) & !3;
    }
    out
}

/// Datagrams fetched per `recvmmsg` call and the room for each (a proc
/// event is ~76 bytes; the slack covers future kernels).
const BATCH: usize = 64;
const SLOT: usize = 512;

#[derive(Debug)]
pub struct Connector {
    fd: OwnedFd,
    buf: Vec<u8>,
    /// The kernel drops unwanted event types before they reach us (Linux 6.6+).
    pub filtered: bool,
}

impl Connector {
    /// Subscribe to every event type.
    pub fn open() -> io::Result<Self> {
        Self::open_filtered(0)
    }

    /// Subscribe to the event types in `mask` (`PROC_EVENT_*` bits; 0 = all).
    /// Linux 6.6+ filters in the kernel — a fork storm then costs no
    /// datagrams at all; older kernels deliver everything and the caller
    /// ignores what it does not need.
    pub fn open_filtered(mask: u32) -> io::Result<Self> {
        // SAFETY: plain socket(2) call.
        let raw =
            cvt(unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, NETLINK_CONNECTOR) })?;
        // SAFETY: fresh descriptor owned by us.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // Large receive buffer: exec storms (configure scripts, builds) burst.
        let rcvbuf: libc::c_int = 4 << 20;
        // SAFETY: valid option pointer/len.
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUFFORCE,
                &rcvbuf as *const _ as *const libc::c_void,
                size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        // SAFETY: zeroed sockaddr_nl is valid; we fill the fields we need.
        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        sa.nl_pid = 0; // let the kernel assign
        sa.nl_groups = CN_IDX_PROC;
        // SAFETY: sa is a valid sockaddr_nl.
        cvt(unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        })?;

        // Subscribe: nlmsghdr + cn_msg + u32 op (+ u32 event mask on 6.6+:
        // older kernels ignore an 8-byte request entirely, hence the check).
        let filtered = mask != 0 && crate::system::kernel_at_least(6, 6);
        let payload: usize = if filtered { 8 } else { 4 };
        let total = NLMSG_HDRLEN + CN_MSG_LEN + payload;
        let mut msg = Vec::with_capacity(total);
        msg.extend_from_slice(&(total as u32).to_ne_bytes()); // nlmsg_len
        msg.extend_from_slice(&(libc::NLMSG_DONE as u16).to_ne_bytes()); // nlmsg_type
        msg.extend_from_slice(&0u16.to_ne_bytes()); // nlmsg_flags
        msg.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_seq
        msg.extend_from_slice(&std::process::id().to_ne_bytes()); // nlmsg_pid
        msg.extend_from_slice(&CN_IDX_PROC.to_ne_bytes());
        msg.extend_from_slice(&CN_VAL_PROC.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes()); // seq
        msg.extend_from_slice(&0u32.to_ne_bytes()); // ack
        msg.extend_from_slice(&(payload as u16).to_ne_bytes()); // len
        msg.extend_from_slice(&0u16.to_ne_bytes()); // flags
        msg.extend_from_slice(&PROC_CN_MCAST_LISTEN.to_ne_bytes());
        if filtered {
            msg.extend_from_slice(&mask.to_ne_bytes());
        }
        // SAFETY: msg is a valid buffer of `total` bytes.
        let sent = unsafe { libc::send(fd.as_raw_fd(), msg.as_ptr() as *const libc::c_void, msg.len(), 0) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd, buf: vec![0u8; BATCH * SLOT], filtered })
    }

    /// Like [`recv`](Self::recv) but gives up after `timeout`
    /// (`Ok(Some(vec![]))`), so the caller can check for reloads.
    pub fn recv_timeout(&mut self, timeout: std::time::Duration) -> io::Result<Option<Vec<ProcEvent>>> {
        // Under load a datagram is usually already queued: try first, poll
        // only when the queue is empty (one syscall per event, not two).
        if let Some(r) = self.recv_flags(libc::MSG_DONTWAIT)? {
            return Ok(r);
        }
        if !crate::util::wait_readable(self.fd.as_raw_fd(), timeout)? {
            return Ok(Some(Vec::new()));
        }
        self.recv()
    }

    /// Block until events arrive. `ENOBUFS` (we were too slow and the kernel
    /// dropped events) is reported as `Ok(None)` so callers can count losses.
    pub fn recv(&mut self) -> io::Result<Option<Vec<ProcEvent>>> {
        loop {
            if let Some(r) = self.recv_flags(0)? {
                return Ok(r);
            }
        }
    }

    /// Everything queued, up to [`BATCH`] datagrams per system call
    /// (`recvmmsg`). `Ok(None)`: nothing queued (`EAGAIN`) or interrupted.
    fn recv_flags(&mut self, flags: libc::c_int) -> io::Result<Option<Option<Vec<ProcEvent>>>> {
        // SAFETY: zeroed iovec/mmsghdr arrays are valid; each iovec points
        // into its own SLOT-sized part of `buf`, which outlives the call.
        let mut iov: [libc::iovec; BATCH] = unsafe { std::mem::zeroed() };
        let mut hdrs: [libc::mmsghdr; BATCH] = unsafe { std::mem::zeroed() };
        for (i, (v, h)) in iov.iter_mut().zip(hdrs.iter_mut()).enumerate() {
            v.iov_base = self.buf[i * SLOT..].as_mut_ptr() as *mut libc::c_void;
            v.iov_len = SLOT;
            h.msg_hdr.msg_iov = v;
            h.msg_hdr.msg_iovlen = 1;
        }
        // Block (when asked to) only for the first datagram, then take
        // whatever else is already queued.
        let flags = flags | libc::MSG_WAITFORONE;
        // SAFETY: hdrs/iov/buf are valid for BATCH entries.
        let n = unsafe {
            libc::recvmmsg(self.fd.as_raw_fd(), hdrs.as_mut_ptr(), BATCH as libc::c_uint, flags, std::ptr::null_mut())
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(libc::EINTR) | Some(libc::EAGAIN) => Ok(None),
                Some(libc::ENOBUFS) => Ok(Some(None)),
                _ => Err(e),
            };
        }
        let mut out = Vec::new();
        for (i, h) in hdrs.iter().take(n as usize).enumerate() {
            let len = (h.msg_len as usize).min(SLOT);
            out.extend(parse_datagram(&self.buf[i * SLOT..i * SLOT + len]));
        }
        Ok(Some(Some(out)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn datagram(what: u32, data: &[u32]) -> Vec<u8> {
        let mut ev = Vec::new();
        ev.extend_from_slice(&what.to_ne_bytes());
        ev.extend_from_slice(&0u32.to_ne_bytes()); // cpu
        ev.extend_from_slice(&123u64.to_ne_bytes()); // ts
        for d in data {
            ev.extend_from_slice(&d.to_ne_bytes());
        }
        let total = NLMSG_HDRLEN + CN_MSG_LEN + ev.len();
        let mut m = Vec::new();
        m.extend_from_slice(&(total as u32).to_ne_bytes());
        m.extend_from_slice(&[0u8; 12]);
        m.extend_from_slice(&CN_IDX_PROC.to_ne_bytes());
        m.extend_from_slice(&CN_VAL_PROC.to_ne_bytes());
        m.extend_from_slice(&[0u8; 8]);
        m.extend_from_slice(&(ev.len() as u16).to_ne_bytes());
        m.extend_from_slice(&[0u8; 2]);
        m.extend_from_slice(&ev);
        m
    }

    #[test]
    fn parses_exec_uid_fork() {
        let e = parse_datagram(&datagram(PROC_EVENT_EXEC, &[100, 100]));
        assert_eq!(e, vec![ProcEvent::Exec { pid: 100, tgid: 100 }]);
        let e = parse_datagram(&datagram(PROC_EVENT_UID, &[7, 7, 1000, 0]));
        assert_eq!(e, vec![ProcEvent::Uid { pid: 7, tgid: 7, ruid: 1000, euid: 0 }]);
        let e = parse_datagram(&datagram(PROC_EVENT_FORK, &[1, 1, 2, 2]));
        assert!(matches!(e[0], ProcEvent::Fork { child_tgid: 2, .. }));
        let e = parse_datagram(&datagram(PROC_EVENT_EXIT, &[5, 5, 9, 17, 1, 1]));
        assert!(matches!(e[0], ProcEvent::Exit { exit_code: 9, .. }));
    }

    #[test]
    fn concatenated_and_truncated() {
        let mut d = datagram(PROC_EVENT_EXEC, &[1, 1]);
        d.extend(datagram(PROC_EVENT_EXEC, &[2, 2]));
        assert_eq!(parse_datagram(&d).len(), 2);
        assert!(parse_datagram(&d[..10]).is_empty());
    }

    #[test]
    fn live_filtered_subscription_sees_exec_but_not_fork() {
        let Ok(mut c) = Connector::open_filtered(PROC_EVENT_EXEC | PROC_EVENT_EXIT) else {
            return; // needs CAP_NET_ADMIN
        };
        let child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id() as i32;
        let mut child = child;
        child.wait().unwrap();
        let mut seen = Vec::new();
        let t = std::time::Instant::now();
        while t.elapsed() < std::time::Duration::from_secs(3)
            && !seen.iter().any(|e| matches!(e, ProcEvent::Exit { tgid, .. } if *tgid == pid))
        {
            if let Some(v) = c.recv_timeout(std::time::Duration::from_millis(200)).unwrap() {
                seen.extend(v);
            }
        }
        assert!(seen.iter().any(|e| matches!(e, ProcEvent::Exec { tgid, .. } if *tgid == pid)), "{seen:?}");
        if c.filtered {
            assert!(!seen.iter().any(|e| matches!(e, ProcEvent::Fork { .. })), "forks are filtered in the kernel");
        }
    }
}
