//! Minimal `sd_notify(3)` implementation (no libsystemd dependency).

use std::io;
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

/// Send a state string (`READY=1`, `WATCHDOG=1`, `STATUS=...`).
/// Returns `Ok(false)` when not running under systemd.
pub fn notify(state: &str) -> io::Result<bool> {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else { return Ok(false) };
    let path = path.to_string_lossy().into_owned();
    let sock = UnixDatagram::unbound()?;
    if let Some(name) = path.strip_prefix('@') {
        use std::os::linux::net::SocketAddrExt;
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
        sock.send_to_addr(state.as_bytes(), &addr)?;
    } else {
        sock.send_to(state.as_bytes(), &path)?;
    }
    Ok(true)
}

/// The watchdog interval requested by the unit (`WatchdogSec=`), if any.
pub fn watchdog_interval() -> Option<Duration> {
    let usec: u64 = std::env::var("WATCHDOG_USEC").ok()?.parse().ok()?;
    if let Ok(pid) = std::env::var("WATCHDOG_PID")
        && pid.parse::<u32>().ok() != Some(std::process::id())
    {
        return None;
    }
    Some(Duration::from_micros(usec))
}

/// Running as a systemd service (journald captures stdout)?
pub fn under_systemd() -> bool {
    std::env::var_os("JOURNAL_STREAM").is_some() || std::env::var_os("INVOCATION_ID").is_some()
}
