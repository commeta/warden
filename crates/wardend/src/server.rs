//! Control socket (`wardenctl`) and the Prometheus/health HTTP endpoint.
//!
//! Both servers run on the daemon's single async thread, together with the
//! event engine and the watchdog pinger. Two rules keep that safe:
//!
//! * **Nothing here blocks the thread.** A handler that does file or
//!   subprocess work, or takes a lock another thread can hold for long,
//!   runs on the blocking pool ([`blocking`]). What the control socket needs
//!   from the action executor lives in `warden_respond::Handles` with locks
//!   of its own, so no command waits for a long action in progress.
//! * **Neither server can be taken down from outside.** A failed `accept`
//!   is logged and retried, never fatal; the number of concurrent
//!   connections is capped well below the descriptor limit, so a client
//!   cannot exhaust descriptors and starve the rest of the daemon (the
//!   scheduler, the sensors, the FIM) of them.

use crate::dryrun;
use crate::eventlog::Ring;
use std::future::Future;
use std::io;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use warden_core::ipc::{Request, Response};
use warden_core::sync::{lock, read};
use warden_core::{ActionSpec, Event, Severity};
use warden_detect::fim::FimMsg;
use warden_detect::{Shared, Sink};
use warden_respond::Handles;

/// Simultaneous control-socket clients (root only; `wardenctl` is one at a time).
const MAX_CONTROL_CLIENTS: usize = 16;
/// Simultaneous HTTP clients (a scraper and a health checker, with room).
const MAX_HTTP_CLIENTS: usize = 32;
/// A control request is one JSON line; this is far more than any of them.
const MAX_REQUEST_LINE: usize = 1 << 20;
/// A control client that sends nothing for this long is dropped.
const CONTROL_IDLE: Duration = Duration::from_secs(300);
/// Time allowed for an HTTP client to send its request, and to take the answer.
const HTTP_IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct Ctx {
    pub shared: Arc<Shared>,
    pub ring: Ring,
    pub handles: Handles,
    pub sink: Sink,
    pub reload: tokio::sync::mpsc::Sender<()>,
    pub config_files: Arc<Mutex<Vec<String>>>,
    /// Component threads currently running (for `wardenctl profile`).
    pub running: Option<warden_detect::runtime::Registry>,
    /// The dry-run switch (configuration, `--dry-run`, runtime override).
    pub dry_run: Arc<Mutex<crate::dryrun::DryRun>>,
}

/// Run blocking work off the async thread.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, Response> {
    tokio::task::spawn_blocking(f).await.map_err(|e| Response::err(format!("internal error: {e}")))
}

async fn fim_call(
    shared: &Arc<Shared>,
    make: impl FnOnce(std::sync::mpsc::Sender<serde_json::Value>) -> FimMsg,
) -> Response {
    let tx = lock(&shared.fim_tx).clone();
    let Some(tx) = tx else {
        return Response::err("FIM is not running (fim.enabled = false or no [[fim.site]] configured)");
    };
    let (rtx, rrx) = std::sync::mpsc::channel();
    if tx.send(make(rtx)).is_err() {
        return Response::err("FIM worker stopped");
    }
    // Scans can take a while on big sites.
    match tokio::task::spawn_blocking(move || rrx.recv_timeout(Duration::from_secs(3600))).await {
        Ok(Ok(v)) if v.get("error").is_some() => Response::err(v["error"].as_str().unwrap_or("error").to_owned()),
        Ok(Ok(v)) => Response::ok(v),
        _ => Response::err("FIM worker did not answer"),
    }
}

pub async fn handle(ctx: &Ctx, req: Request) -> Response {
    let shared = &ctx.shared;
    // (the scope guard is not held across awaits)
    match req {
        Request::Profile => {
            let _g = warden_detect::prof::enter(warden_detect::prof::scope_id("control"));
            let mut v = warden_detect::prof::report();
            if let Some(o) = v.as_object_mut() {
                o.insert("version".into(), warden_core::VERSION.into());
                o.insert("uptime_seconds".into(), shared.started.elapsed().as_secs().into());
                o.insert("running".into(), serde_json::json!(ctx.running.as_ref().map(|r| r.running())));
                o.insert("sensors".into(), serde_json::json!(*lock(&shared.sensors)));
            }
            Response::ok(v)
        }
        Request::Ping => Response::ok("pong"),
        Request::Status => {
            let cfg = shared.config();
            let lineage = lock(&shared.lineage);
            Response::ok(serde_json::json!({
                "version": warden_core::VERSION,
                "host": shared.hostname,
                "pid": std::process::id(),
                "uptime_seconds": shared.started.elapsed().as_secs(),
                "dry_run": shared.is_dry_run(),
                "dry_run_source": lock(&ctx.dry_run).source().as_str(),
                "dry_run_override_since_ms": lock(&ctx.dry_run).override_since_ms(),
                "kernel": warden_sys::system::kernel_release(),
                "seccomp": warden_sys::sched::seccomp_mode(),
                "config_files": *lock(&ctx.config_files),
                "levels": *lock(&shared.levels),
                "sensors": *lock(&shared.sensors),
                "events_in_memory": lock(&ctx.ring).len(),
                "events_dropped": shared.dropped_events.load(Ordering::Relaxed),
                "fim_sites": cfg.fim.sites.iter().map(|s| s.name.clone()).collect::<Vec<_>>(),
                "waf_sources": *lock(&shared.waf_sources),
                "policies": cfg.policies.len(),
                "lineage": {"pairs": lineage.pairs(), "learning": lineage.learning(), "learning_remaining_seconds": lineage.learning_remaining().as_secs()},
                "heuristics_max_score": lock(&shared.heuristics).max_score(warden_sys::clock::now()),
                "pacing": {
                    "enabled": cfg.daemon.pacing.enabled,
                    "io_pressure_target_percent": cfg.daemon.pacing.io_pressure,
                    "io_pressure_percent": warden_sys::pace::io_pressure().map(|p| (p * 1000.0).round() / 10.0),
                    "scans": warden_sys::pace::stats(),
                },
            }))
        }
        Request::Events { limit, since_id, min_severity } => {
            let r = lock(&ctx.ring);
            let mut v: Vec<&crate::eventlog::RingEntry> = r
                .iter()
                .filter(|e| since_id.is_none_or(|s| e.id > s))
                .filter(|e| min_severity.is_none_or(|m| e.severity >= m))
                .collect();
            let skip = v.len().saturating_sub(limit);
            v.drain(..skip);
            let out: Vec<serde_json::Value> = v.iter().filter_map(|e| serde_json::from_str(&e.json).ok()).collect();
            Response::ok(out)
        }
        Request::Reload => match ctx.reload.send(()).await {
            Ok(()) => Response::ok("reload requested"),
            Err(_) => Response::err("reload channel closed"),
        },
        Request::SetDryRun { enabled } => {
            let (res, effective, source) = {
                let mut d = lock(&ctx.dry_run);
                let res = match enabled {
                    Some(on) => d.set(on, warden_core::event::now_ms()),
                    None => Ok(d.reset()),
                };
                shared.dry_run.store(d.effective(), Ordering::SeqCst);
                (res, d.effective(), d.source())
            };
            let warning = match res {
                Ok(change) => {
                    if let Some(c) = change {
                        tracing::warn!(
                            enabled = c.enabled,
                            source = c.source.as_str(),
                            "dry-run mode changed via control socket"
                        );
                        ctx.sink.emit(dryrun::event(&c));
                    }
                    None
                }
                // --dry-run: nothing changed
                Err(e) if enabled == Some(false) && source == dryrun::Source::Cli => return Response::err(e),
                // changed, but not persisted
                Err(e) => {
                    tracing::error!(error = %e, "dry-run override");
                    ctx.sink.emit(dryrun::event(&dryrun::Change { enabled: effective, source, reason: e.clone() }));
                    Some(e)
                }
            };
            Response::ok(serde_json::json!({"dry_run": effective, "source": source.as_str(), "warning": warning}))
        }
        Request::Top { limit } => {
            let cfg = shared.config();
            let r = blocking(move || {
                let prot = warden_core::protect::Protection::new(&cfg.protection);
                let total = warden_sys::mem::meminfo().map(|m| m.total).unwrap_or(0);
                let mut c = cfg.memory.culprit.clone();
                c.min_rss = warden_core::ByteSize(0);
                // paging activity over half a second (0.13.3 always showed 0)
                let mut act = warden_detect::memory::Activity::default();
                act.sample();
                std::thread::sleep(Duration::from_millis(500));
                warden_detect::memory::rank_culprits(&c, &prot, &mut act, total, limit)
            })
            .await;
            match r {
                Ok(v) => Response::ok(v),
                Err(e) => e,
            }
        }
        Request::Scores => Response::ok(lock(&shared.heuristics).view(warden_sys::clock::now())),
        Request::FimStatus => fim_call(shared, |reply| FimMsg::Status { reply }).await,
        Request::FimScan { site } => fim_call(shared, |reply| FimMsg::Scan { site, reply: Some(reply) }).await,
        Request::FimAccept { site, path } => fim_call(shared, |reply| FimMsg::Accept { site, path, reply }).await,
        Request::FimPause { site, seconds } => fim_call(shared, |reply| FimMsg::Pause { site, seconds, reply }).await,
        Request::Blocklist => {
            let fw = ctx.handles.firewall.clone();
            match blocking(move || lock(&fw).list()).await {
                Ok(v) => Response::ok(v),
                Err(e) => e,
            }
        }
        Request::Block { ip, ttl_secs } => {
            let Ok(addr) = ip.parse() else { return Response::err(format!("invalid IP {ip}")) };
            let fw = ctx.handles.firewall.clone();
            match blocking(move || lock(&fw).block(addr, ttl_secs.map(Duration::from_secs))).await {
                Ok(Ok(m)) => Response::ok(m),
                Ok(Err(e)) => Response::err(e),
                Err(e) => e,
            }
        }
        Request::Unblock { ip } => {
            let Ok(addr) = ip.parse() else { return Response::err(format!("invalid IP {ip}")) };
            let fw = ctx.handles.firewall.clone();
            match blocking(move || lock(&fw).unblock(addr)).await {
                Ok(Ok(m)) => Response::ok(m),
                Ok(Err(e)) => Response::err(e),
                Err(e) => e,
            }
        }
        Request::QuarantineList => {
            let q = ctx.handles.quarantine.clone();
            match blocking(move || read(&q).list()).await {
                Ok(v) => Response::ok(v),
                Err(e) => e,
            }
        }
        Request::QuarantineRestore { id } => {
            let q = ctx.handles.quarantine.clone();
            let id2 = id.clone();
            match blocking(move || read(&q).restore(&id2)).await {
                Ok(Ok(e)) => {
                    ctx.sink.emit(
                        Event::new(
                            "warden.quarantine_restored",
                            Severity::Notice,
                            format!("{} restored from quarantine", e.original),
                        )
                        .source("control")
                        .fingerprint(format!("warden.quarantine_restored:{id}")),
                    );
                    Response::ok(e)
                }
                Ok(Err(e)) => Response::err(e.to_string()),
                Err(e) => e,
            }
        }
        Request::Tuning => {
            let tuner = ctx.handles.tuner.clone();
            let applied = match blocking(move || lock(&tuner).changes()).await {
                Ok(v) => v,
                Err(e) => return e,
            };
            let cfg = shared.config();
            Response::ok(serde_json::json!({
                "advice": *lock(&shared.advice),
                "applied": applied,
                "auto_grow": cfg.tuning.auto_grow,
                "persist": cfg.tuning.persist,
            }))
        }
        Request::TuningRevert => {
            let tuner = ctx.handles.tuner.clone();
            let r = match blocking(move || lock(&tuner).revert()).await {
                Ok(v) => v,
                Err(e) => return e,
            };
            ctx.sink.emit(
                Event::new(
                    "warden.tuning_reverted",
                    Severity::Notice,
                    format!("{} sysctl change(s) reverted", r.len()),
                )
                .source("control")
                .fingerprint(format!("warden.tuning_reverted:{}", warden_core::event::now_ms()))
                .detail("changes", r.clone()),
            );
            Response::ok(r)
        }
        Request::Snapshot { reason } => {
            ctx.sink.emit(
                Event::new(
                    "warden.manual_snapshot",
                    Severity::Notice,
                    reason.unwrap_or_else(|| "manual snapshot".into()),
                )
                .source("control")
                .fingerprint(format!("warden.manual_snapshot:{}", warden_core::event::now_ms()))
                .actions(vec![ActionSpec::Snapshot]),
            );
            Response::ok("snapshot requested; see `wardenctl events` for the result")
        }
    }
}

// ---------------------------------------------------------------------------
// Accepting connections
// ---------------------------------------------------------------------------

/// Errors after which nothing can be accepted until something is released:
/// out of descriptors, buffers or memory. Retrying at once would spin.
fn is_resource_exhaustion(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM))
}

/// Accept connections for ever.
///
/// * A slot is taken from `limit` *before* accepting, so excess clients wait
///   in the kernel's backlog instead of holding descriptors.
/// * A failing `accept` is never fatal: it is logged (at most every 30 s —
///   a persistent failure must not flood the log) and retried after a pause
///   — a long one when the system is out of resources.
async fn accept_loop<S, F, Fut>(
    what: &'static str,
    limit: Arc<Semaphore>,
    mut accept: F,
    mut serve: impl FnMut(S, OwnedSemaphorePermit),
) where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<S>>,
{
    let mut next_log = Instant::now();
    loop {
        let Ok(permit) = limit.clone().acquire_owned().await else { return };
        match accept().await {
            Ok(stream) => serve(stream, permit),
            Err(e) => {
                drop(permit);
                if Instant::now() >= next_log {
                    tracing::warn!(server = what, error = %e, "accept failed; retrying");
                    next_log = Instant::now() + Duration::from_secs(30);
                }
                let pause = if is_resource_exhaustion(&e) { 500 } else { 50 };
                tokio::time::sleep(Duration::from_millis(pause)).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Control socket
// ---------------------------------------------------------------------------

/// Create the control socket: bound under a temporary name with its final
/// permissions and moved into place, so it is never reachable with
/// anything but `0600`, and a client never sees a half-made socket.
pub fn bind_control(path: &std::path::Path) -> io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension(format!("sock.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let listener = UnixListener::bind(&tmp)?;
    let publish = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
        .and_then(|()| std::fs::rename(&tmp, path));
    if let Err(e) = publish {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(listener)
}

/// Device and inode of a path (not following a symlink).
pub fn file_id(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).ok().map(|m| (m.dev(), m.ino()))
}

pub async fn control_server(ctx: Ctx, listener: UnixListener) {
    tracing::info!(socket = %ctx.shared.config().daemon.control_socket.display(), "control socket listening");
    let l = &listener;
    accept_loop(
        "control",
        Arc::new(Semaphore::new(MAX_CONTROL_CLIENTS)),
        || async { l.accept().await.map(|(s, _)| s) },
        |stream, permit| {
            let ctx = ctx.clone();
            tokio::spawn(async move {
                serve_control_client(&ctx, stream).await;
                drop(permit);
            });
        },
    )
    .await;
}

/// Read one request line of at most [`MAX_REQUEST_LINE`] bytes. `None` at
/// end of stream, on a client that stays silent for [`CONTROL_IDLE`], and on
/// a line that is too long.
async fn read_request_line<R: AsyncBufReadExt + Unpin>(rd: &mut R, buf: &mut Vec<u8>) -> Option<String> {
    buf.clear();
    let mut limited = (&mut *rd).take(MAX_REQUEST_LINE as u64 + 1);
    let n = tokio::time::timeout(CONTROL_IDLE, limited.read_until(b'\n', buf)).await.ok()?.ok()?;
    if n == 0 || buf.len() > MAX_REQUEST_LINE {
        return None;
    }
    Some(String::from_utf8_lossy(buf).trim().to_owned())
}

async fn serve_control_client(ctx: &Ctx, stream: tokio::net::UnixStream) {
    let uid = stream.peer_cred().map(|c| c.uid()).unwrap_or(u32::MAX);
    let (rd, mut wr) = stream.into_split();
    if uid != 0 {
        let msg = serde_json::to_string(&Response::err("permission denied: root only")).unwrap_or_default();
        let _ = wr.write_all(format!("{msg}\n").as_bytes()).await;
        return;
    }
    let mut rd = BufReader::new(rd);
    let mut buf = Vec::new();
    while let Some(line) = read_request_line(&mut rd, &mut buf).await {
        if line.is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Request>(&line) {
            Ok(req) => handle(ctx, req).await,
            Err(e) => Response::err(format!("bad request: {e}")),
        };
        let mut out = serde_json::to_string(&resp).unwrap_or_default();
        out.push('\n');
        if wr.write_all(out.as_bytes()).await.is_err() {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Prometheus / health
// ---------------------------------------------------------------------------

pub async fn metrics_server(shared: Arc<Shared>, listener: TcpListener) {
    if let Ok(a) = listener.local_addr() {
        tracing::info!(listen = %a, "metrics endpoint listening");
    }
    let l = &listener;
    accept_loop(
        "metrics",
        Arc::new(Semaphore::new(MAX_HTTP_CLIENTS)),
        || async { l.accept().await.map(|(s, _)| s) },
        |stream, permit| {
            let shared = shared.clone();
            tokio::spawn(async move {
                serve_http_client(&shared, stream).await;
                drop(permit);
            });
        },
    )
    .await;
}

fn http_response(shared: &Shared, path: &str) -> (&'static str, &'static str, String) {
    match path {
        "/metrics" => {
            shared.metrics.set("warden_uptime_seconds", &[], shared.started.elapsed().as_secs_f64());
            warden_detect::prof::export(&shared.metrics);
            ("200 OK", "text/plain; version=0.0.4", shared.metrics.render())
        }
        "/health" | "/healthz" => {
            let age = shared.heartbeat_age().as_millis() as u64;
            let ok = age < 30_000;
            (
                if ok { "200 OK" } else { "503 Service Unavailable" },
                "application/json",
                serde_json::json!({"status": if ok {"ok"} else {"stalled"}, "heartbeat_age_ms": age, "version": warden_core::VERSION}).to_string(),
            )
        }
        _ => ("404 Not Found", "text/plain", "not found\n".into()),
    }
}

async fn serve_http_client(shared: &Shared, mut s: tokio::net::TcpStream) {
    let mut buf = [0u8; 2048];
    let n = match tokio::time::timeout(HTTP_IO_TIMEOUT, s.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return,
    };
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req.split_whitespace().nth(1).unwrap_or("/");
    let (status, ctype, body) = http_response(shared, path);
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = tokio::time::timeout(HTTP_IO_TIMEOUT, s.write_all(resp.as_bytes())).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    type Script = VecDeque<Result<u32, i32>>;

    /// An `accept` that plays back `script` and then waits for ever.
    fn scripted(script: Script) -> impl FnMut() -> std::pin::Pin<Box<dyn Future<Output = io::Result<u32>> + Send>> {
        let script = Arc::new(Mutex::new(script));
        move || {
            let next = lock(&script).pop_front();
            Box::pin(async move {
                match next {
                    Some(Ok(n)) => Ok(n),
                    Some(Err(code)) => Err(io::Error::from_raw_os_error(code)),
                    None => std::future::pending().await,
                }
            })
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_failing_accept_does_not_end_the_server() {
        // Out of descriptors, an aborted connection — then clients again.
        // (This used to end the task for good: control socket and /health
        // dead until the daemon was restarted.)
        let served = Arc::new(Mutex::new(Vec::new()));
        let s2 = served.clone();
        let accept = scripted(VecDeque::from([Err(libc::EMFILE), Err(libc::ECONNABORTED), Ok(1), Ok(2)]));
        let task =
            tokio::spawn(accept_loop("test", Arc::new(Semaphore::new(8)), accept, move |c, _p| lock(&s2).push(c)));
        for _ in 0..40 {
            if lock(&served).len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(*lock(&served), vec![1, 2]);
        assert!(!task.is_finished());
        task.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_clients_are_capped_before_accepting() {
        let accepted = Arc::new(Mutex::new(Vec::new()));
        let permits = Arc::new(Mutex::new(Vec::new()));
        let (a2, p2) = (accepted.clone(), permits.clone());
        let accept = scripted(VecDeque::from([Ok(1), Ok(2), Ok(3)]));
        let task = tokio::spawn(accept_loop("test", Arc::new(Semaphore::new(2)), accept, move |c, p| {
            lock(&a2).push(c);
            lock(&p2).push(p); // the client "stays connected"
        }));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(lock(&accepted).len(), 2, "the third client waits for a slot");
        lock(&permits).pop(); // one client leaves
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(*lock(&accepted), vec![1, 2, 3]);
        task.abort();
    }

    #[test]
    fn exhaustion_is_recognised() {
        assert!(is_resource_exhaustion(&io::Error::from_raw_os_error(libc::EMFILE)));
        assert!(is_resource_exhaustion(&io::Error::from_raw_os_error(libc::ENFILE)));
        assert!(!is_resource_exhaustion(&io::Error::from_raw_os_error(libc::ECONNABORTED)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn request_lines_are_bounded() {
        let mut buf = Vec::new();
        let mut ok = BufReader::new(&b"{\"cmd\":\"ping\"}\n{\"cmd\":\"status\"}\n"[..]);
        assert_eq!(read_request_line(&mut ok, &mut buf).await.as_deref(), Some("{\"cmd\":\"ping\"}"));
        assert_eq!(read_request_line(&mut ok, &mut buf).await.as_deref(), Some("{\"cmd\":\"status\"}"));
        assert_eq!(read_request_line(&mut ok, &mut buf).await, None);
        let huge = vec![b'x'; MAX_REQUEST_LINE + 10];
        let mut rd = BufReader::new(&huge[..]);
        assert_eq!(read_request_line(&mut rd, &mut buf).await, None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn control_socket_is_private_from_the_start() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("run/control.sock");
        let _l = bind_control(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        // only the final name remains
        assert_eq!(std::fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
        // a stale socket from a crashed run is replaced
        let _l2 = bind_control(&path).unwrap();
    }
}
