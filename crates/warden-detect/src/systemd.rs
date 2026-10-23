//! Failed systemd units with optional automatic restart.
//!
//! Two sources feed the same state ([`UnitState`] in [`Shared`]):
//!
//! * **D-Bus sensor** (`systemd_dbus`, default): subscribes to systemd's
//!   `PropertiesChanged` signals and reacts the moment a unit's
//!   `ActiveState` becomes `failed`; a full `ListUnitsFiltered` runs at
//!   start, after `daemon-reload`/re-exec and every `dbus_reconcile`.
//! * **Polling detector**: `systemctl list-units --state=failed,…` every
//!   `interval`, only while the sensor is not running (no system bus, D-Bus
//!   disabled, or a failure).
//!
//! A unit that left the failed list is *recovered* only when it settled: one
//! that is starting or stopping again (an auto-restart, a timer firing a
//! failed oneshot) stays failed until systemd says how that ended.

use crate::runtime::{Cx, Detector, SensorState, Shared, Sink, lock};
use crate::util::run_cmd;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use warden_core::config::SystemdConfig;
use warden_core::ratelimit::SlidingWindow;
use warden_core::{ActionSpec, Event, GlobList, Severity, Subject};
use warden_sys::dbus::{self, Connection, Message, Value};

pub fn parse_failed(out: &str) -> BTreeSet<String> {
    parse_units(out).failed
}

/// What systemd reports about units at one moment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnitSnapshot {
    pub failed: BTreeSet<String>,
    /// Units starting or stopping right now (`activating`, `deactivating`).
    pub transitional: BTreeSet<String>,
}

impl UnitSnapshot {
    pub fn failed(failed: BTreeSet<String>) -> Self {
        Self { failed, transitional: BTreeSet::new() }
    }

    fn add(&mut self, unit: String, active_state: &str) {
        match active_state {
            "failed" => {
                self.failed.insert(unit);
            }
            "activating" | "deactivating" => {
                self.transitional.insert(unit);
            }
            _ => {}
        }
    }
}

/// The `ActiveState`s a reconciliation asks systemd for.
pub const RECONCILE_STATES: &[&str] = &["failed", "activating", "deactivating"];

/// `systemctl list-units --plain --no-legend` output (`UNIT LOAD ACTIVE SUB
/// DESCRIPTION`); a line without the ACTIVE column counts as failed (the
/// output of `--state=failed` on old systemd).
pub fn parse_units(out: &str) -> UnitSnapshot {
    let mut s = UnitSnapshot::default();
    for l in out.lines() {
        let mut cols = l.trim_start_matches(['●', '*', ' ']).split_whitespace();
        let Some(unit) = cols.next().filter(|u| u.contains('.')) else { continue };
        let active = cols.nth(1).unwrap_or("failed");
        s.add(unit.to_owned(), active);
    }
    s
}

/// Failed units seen so far and, per unit, the failures of the last hour.
#[derive(Debug, Default)]
pub struct UnitState {
    failed: Option<BTreeSet<String>>,
    restarts: HashMap<String, SlidingWindow>,
}

/// Compiled `[systemd]` rules.
pub struct UnitRules {
    cfg: SystemdConfig,
    ignore: GlobList,
    auto: GlobList,
}

impl UnitRules {
    pub fn new(cfg: &SystemdConfig) -> Self {
        Self { ignore: GlobList::new(&cfg.ignore), auto: GlobList::new(&cfg.auto_restart), cfg: cfg.clone() }
    }

    /// Apply a complete snapshot of the units (startup, polling,
    /// reconciliation).
    pub fn reconcile(&self, st: &mut UnitState, cx: &Cx<'_>, snap: UnitSnapshot, via: &'static str) {
        let now_failed: BTreeSet<String> = snap.failed.into_iter().filter(|u| !self.ignore.is_match(u)).collect();
        let first = st.failed.is_none();
        let prev = st.failed.take().unwrap_or_default();
        for unit in now_failed.difference(&prev) {
            self.report_failed(st, cx, unit, first, via);
        }
        let mut still = now_failed.clone();
        for unit in prev.difference(&now_failed) {
            if snap.transitional.contains(unit) {
                // started again (a timer, an auto-restart): how that ends
                // decides — a signal or the next reconciliation
                still.insert(unit.clone());
            } else {
                Self::report_recovered(cx, unit);
            }
        }
        cx.metric("warden_systemd_failed_units", &[], still.len() as f64);
        cx.shared.set_level("systemd", if still.is_empty() { "ok" } else { "warning" });
        st.failed = Some(still);
    }

    /// One unit changed `ActiveState` (D-Bus signal).
    pub fn on_state(&self, st: &mut UnitState, cx: &Cx<'_>, unit: &str, active: &str) {
        if self.ignore.is_match(unit) {
            return;
        }
        let failed = st.failed.get_or_insert_with(BTreeSet::new);
        match active {
            "failed" if !failed.contains(unit) => {
                failed.insert(unit.to_owned());
                self.report_failed(st, cx, unit, false, "dbus");
            }
            // "activating"/"deactivating" are transitions (an auto-restart in
            // progress): only a settled state counts as recovery.
            "active" | "reloading" | "inactive" if failed.remove(unit) => Self::report_recovered(cx, unit),
            _ => return,
        }
        let n = st.failed.as_ref().map(BTreeSet::len).unwrap_or(0);
        cx.metric("warden_systemd_failed_units", &[], n as f64);
        cx.shared.set_level("systemd", if n == 0 { "ok" } else { "warning" });
    }

    fn report_failed(&self, st: &mut UnitState, cx: &Cx<'_>, unit: &str, first: bool, via: &'static str) {
        let mut actions = Vec::new();
        let mut note = String::new();
        let mut keeps_failing = false;
        if self.auto.is_match(unit) {
            // The restart budget is the responder's, charged for restarts that
            // really ran (`systemd.max_restarts_per_hour`); here only the
            // failures are counted. (0.13.3 charged its own budget here: in
            // dry-run three failures "exhausted" it although nothing was
            // restarted, and the first real restart after `dry-run off`
            // was refused.) Real time: an hour is an hour, sleep included.
            let max = self.cfg.max_restarts_per_hour;
            let w = st
                .restarts
                .entry(unit.to_owned())
                .or_insert_with(|| SlidingWindow::new(Duration::from_secs(3600), usize::MAX));
            w.record(cx.real);
            let failures = w.count(cx.real);
            actions.push(ActionSpec::RestartUnit { unit: Some(unit.to_owned()) });
            keeps_failing = failures > max;
            note = if keeps_failing {
                format!(
                    "failed {failures} times within an hour: restarts beyond {max} per hour (systemd.max_restarts_per_hour) are refused"
                )
            } else {
                "auto-restart requested".into()
            };
        }
        if !self.cfg.watch_failed && actions.is_empty() {
            return;
        }
        let sev = if keeps_failing { Severity::Critical } else { Severity::Warning };
        let mut ev = Event::new("systemd.unit_failed", sev, format!("unit {unit} failed"))
            .subject(Subject::Unit { name: unit.to_owned() })
            .fingerprint(format!("systemd.unit_failed:{unit}"))
            .detail("already_failed_at_start", first)
            .detail("detected_by", via)
            .actions(actions);
        if !note.is_empty() {
            ev = ev.detail("auto_restart", note);
        }
        if let Ok(o) = run_cmd(
            "journalctl",
            &["-u", unit, "-n", "15", "--no-pager", "-o", "short-iso", "-q"],
            Duration::from_secs(10),
        ) {
            let tail = String::from_utf8_lossy(&o.stdout).into_owned();
            if !tail.trim().is_empty() {
                ev = ev.detail("journal_tail", tail);
            }
        }
        cx.emit(ev);
    }

    fn report_recovered(cx: &Cx<'_>, unit: &str) {
        cx.emit(
            Event::new("systemd.unit_failed", Severity::Info, format!("unit {unit} recovered"))
                .subject(Subject::Unit { name: unit.to_owned() })
                .fingerprint(format!("systemd.unit_failed:{unit}:resolved"))
                .resolved(),
        );
    }
}

// ---------------------------------------------------------------------------
// D-Bus sensor
// ---------------------------------------------------------------------------

const SYSTEMD: &str = "org.freedesktop.systemd1";
const SYSTEMD_PATH: &str = "/org/freedesktop/systemd1";
const MANAGER: &str = "org.freedesktop.systemd1.Manager";
const UNIT_PREFIX: &str = "/org/freedesktop/systemd1/unit/";
const CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// Names of the units in the `failed` state.
pub fn list_failed(c: &mut Connection) -> std::io::Result<BTreeSet<String>> {
    Ok(list_units(c, &["failed"])?.failed)
}

/// Units in the given `ActiveState`s (`ListUnitsFiltered`; each record is
/// `(name, description, load, active, sub, …)`).
pub fn list_units(c: &mut Connection, states: &[&str]) -> std::io::Result<UnitSnapshot> {
    let m = Message::method_call(SYSTEMD, SYSTEMD_PATH, MANAGER, "ListUnitsFiltered")
        .with_body("as", &[Value::strings(states)])?;
    let r = c.call(m, CALL_TIMEOUT)?;
    let mut s = UnitSnapshot::default();
    for u in r.args()?.first().map(|a| a.items().to_vec()).unwrap_or_default() {
        let f = u.items();
        if let (Some(name), Some(active)) = (f.first().and_then(Value::as_str), f.get(3).and_then(Value::as_str)) {
            s.add(name.to_owned(), active);
        }
    }
    Ok(s)
}

/// Unique bus name that currently owns `name`, if anyone does.
fn name_owner(c: &mut Connection, name: &str) -> std::io::Result<Option<String>> {
    let m =
        Message::method_call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetNameOwner")
            .with_body("s", &[Value::str(name)])?;
    match c.call(m, CALL_TIMEOUT) {
        Ok(r) => Ok(r.args()?.first().and_then(Value::as_str).map(str::to_owned)),
        Err(e) if e.to_string().contains("NameHasNoOwner") => Ok(None),
        Err(e) => Err(e),
    }
}

/// Was `m` sent by `owner`? The bus stamps the sender itself, so this cannot
/// be forged — unlike the signal's path and arguments, which any local
/// process may send straight to us, past the match rules.
fn sent_by(m: &Message, owner: Option<&str>) -> bool {
    owner.is_some() && m.sender.as_deref() == owner
}

/// `(unit, ActiveState)` from a unit `PropertiesChanged` signal. Whether the
/// signal really came from systemd is for the caller to check (`sent_by`).
pub fn unit_state_change(m: &Message) -> Option<(String, String)> {
    if !m.is_signal("org.freedesktop.DBus.Properties", "PropertiesChanged") {
        return None;
    }
    let unit = dbus::unescape_path_component(m.path.as_deref()?.strip_prefix(UNIT_PREFIX)?);
    let args = m.args().ok()?;
    if args.first()?.as_str()? != "org.freedesktop.systemd1.Unit" {
        return None;
    }
    let state = args.get(1)?.dict_get("ActiveState")?.as_str()?.to_owned();
    Some((unit, state))
}

pub fn run_systemd_sensor(shared: &Arc<Shared>, sink: &Sink) -> Result<(), String> {
    let cfg = shared.config();
    if !cfg.systemd.enabled || !cfg.systemd.dbus || !std::path::Path::new("/run/systemd/system").exists() {
        return Ok(());
    }
    let addr = std::env::var("DBUS_SYSTEM_BUS_ADDRESS").unwrap_or_else(|_| dbus::SYSTEM_BUS_DEFAULT.into());
    watch_units(shared, sink, &addr)
}

/// Follow systemd at `address` until the connection breaks, the
/// configuration is reloaded or the daemon shuts down.
pub fn watch_units(shared: &Arc<Shared>, sink: &Sink, address: &str) -> Result<(), String> {
    let cfg = shared.config();
    let generation = shared.generation();
    let rules = UnitRules::new(&cfg.systemd);
    let err = |e: std::io::Error| format!("D-Bus {address}: {e}");
    let mut c = Connection::connect(address).map_err(err)?;
    c.hello().map_err(err)?;
    for rule in [
        format!(
            "type='signal',sender='{SYSTEMD}',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged',\
             path_namespace='{}',arg0='org.freedesktop.systemd1.Unit'",
            UNIT_PREFIX.trim_end_matches('/')
        ),
        format!("type='signal',sender='{SYSTEMD}',interface='{MANAGER}',member='Reloading'"),
        format!("type='signal',sender='org.freedesktop.DBus',member='NameOwnerChanged',arg0='{SYSTEMD}'"),
    ] {
        c.add_match(&rule).map_err(err)?;
    }
    // systemd emits unit signals on the bus only while someone is subscribed.
    let subscribe =
        |c: &mut Connection| c.call(Message::method_call(SYSTEMD, SYSTEMD_PATH, MANAGER, "Subscribe"), CALL_TIMEOUT);
    subscribe(&mut c).map_err(err)?;
    // The match rules name the sender, but a process can also address a
    // signal to us directly, and those skip the rules: only messages from the
    // connection that owns the systemd name are believed.
    let mut owner = name_owner(&mut c, SYSTEMD).map_err(err)?;
    let reconcile = |c: &mut Connection| -> Result<(), String> {
        let snap = list_units(c, RECONCILE_STATES).map_err(err)?;
        let cx = Cx::new(shared, &cfg, sink, "systemd");
        rules.reconcile(&mut lock(&shared.systemd), &cx, snap, "dbus");
        Ok(())
    };
    reconcile(&mut c)?;
    shared.set_sensor("systemd_dbus", SensorState::Running);
    let mut next = Instant::now() + cfg.systemd.dbus_reconcile;
    loop {
        if shared.generation() != generation || shared.is_shutting_down() {
            return Err("configuration reloaded".into());
        }
        let mut resync = Instant::now() >= next;
        match c.recv(Duration::from_secs(2)).map_err(err)? {
            None => {}
            Some(m) if m.is_signal("org.freedesktop.DBus", "NameOwnerChanged") => {
                // systemd re-executed or reconnected: the subscription is gone.
                let args = m.args().unwrap_or_default();
                let ours = m.sender.as_deref() == Some("org.freedesktop.DBus")
                    && args.first().and_then(Value::as_str) == Some(SYSTEMD);
                let new_owner = args.get(2).and_then(Value::as_str).filter(|s| !s.is_empty());
                if ours {
                    owner = new_owner.map(str::to_owned);
                    if owner.is_some() {
                        subscribe(&mut c).map_err(err)?;
                        resync = true;
                    }
                }
            }
            Some(m) if !sent_by(&m, owner.as_deref()) => {
                shared.metrics.inc("warden_systemd_signals_rejected_total", &[], 1.0);
            }
            Some(m) => {
                if let Some((unit, state)) = unit_state_change(&m) {
                    shared.metrics.inc("warden_systemd_signals_total", &[], 1.0);
                    let cx = Cx::new(shared, &cfg, sink, "systemd");
                    rules.on_state(&mut lock(&shared.systemd), &cx, &unit, &state);
                } else if m.is_signal(MANAGER, "Reloading") {
                    // `true` when the reload starts, `false` when it is done.
                    resync = matches!(m.args().ok().as_deref(), Some([Value::Bool(false), ..]));
                }
            }
        }
        if resync {
            reconcile(&mut c)?;
            next = Instant::now() + cfg.systemd.dbus_reconcile;
        }
    }
}

// ---------------------------------------------------------------------------
// polling fallback
// ---------------------------------------------------------------------------

pub struct SystemdDetector {
    rules: UnitRules,
    cfg: SystemdConfig,
    available: Option<bool>,
}

impl SystemdDetector {
    pub fn new(cfg: &SystemdConfig) -> Self {
        Self { rules: UnitRules::new(cfg), cfg: cfg.clone(), available: None }
    }
}

impl Detector for SystemdDetector {
    fn name(&self) -> &'static str {
        "systemd"
    }

    fn interval(&self) -> Duration {
        self.cfg.interval
    }

    fn sections(&self) -> &'static [&'static str] {
        &["/systemd"]
    }

    fn reconfigure(&mut self, cfg: &warden_core::Config) -> bool {
        // the failed units and restart windows live in `Shared` and survive
        // any reload; only the rules change
        self.rules = UnitRules::new(&cfg.systemd);
        self.cfg = cfg.systemd.clone();
        true
    }

    fn tick(&mut self, cx: &mut Cx<'_>) {
        if self.available == Some(false) || cx.shared.sensor_running("systemd_dbus") {
            return;
        }
        if self.available.is_none() {
            self.available = Some(std::path::Path::new("/run/systemd/system").exists());
            if self.available == Some(false) {
                tracing::info!("systemd not running; systemd detector disabled");
                return;
            }
        }
        let out = match run_cmd(
            "systemctl",
            &[
                "list-units",
                "--state=failed,activating,deactivating",
                "--no-legend",
                "--plain",
                "--no-pager",
                "--full",
                "--all",
            ],
            Duration::from_secs(15),
        ) {
            Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
            Err(e) => {
                tracing::debug!(error = %e, "systemctl failed");
                return;
            }
        };
        self.rules.reconcile(&mut lock(&cx.shared.systemd), cx, parse_units(&out), "systemctl");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_list_units() {
        let s = "nginx.service loaded failed failed A high performance web server\n● php8.3-fpm.service loaded failed failed PHP\n\n";
        let v = parse_failed(s);
        assert!(v.contains("nginx.service"));
        assert!(v.contains("php8.3-fpm.service"));
        assert_eq!(v.len(), 2);
        let s = parse_units(
            "nginx.service loaded failed failed nginx\n● fwupd-refresh.service loaded activating start Refresh fwupd metadata\nx.service loaded deactivating stop-sigterm X\n",
        );
        assert_eq!(s.failed, BTreeSet::from(["nginx.service".to_owned()]));
        assert_eq!(s.transitional.len(), 2);
    }

    #[test]
    fn a_failed_oneshot_started_by_its_timer_does_not_flap() {
        let cfg = warden_core::Config::default();
        let shared = Shared::new(cfg.clone());
        let (sink, events) = Sink::collector();
        let cx = Cx::new(&shared, &cfg, &sink, "systemd");
        let rules = UnitRules::new(&cfg.systemd);
        let mut st = UnitState::default();
        let unit = || "fwupd-refresh.service".to_owned();
        rules.reconcile(&mut st, &cx, UnitSnapshot::failed([unit()].into()), "dbus");
        // the timer runs it again: activating during the reconciliation
        let running = UnitSnapshot { failed: BTreeSet::new(), transitional: [unit()].into() };
        rules.reconcile(&mut st, &cx, running.clone(), "dbus");
        assert_eq!(lock(&shared.levels)["systemd"], "warning", "still failed until it settles");
        // ...and fails again: no second "failed", no "recovered" in between
        rules.on_state(&mut st, &cx, &unit(), "failed");
        rules.reconcile(&mut st, &cx, UnitSnapshot::failed([unit()].into()), "dbus");
        // next time it succeeds
        rules.reconcile(&mut st, &cx, running, "dbus");
        rules.on_state(&mut st, &cx, &unit(), "inactive");
        let titles: Vec<String> = lock(&events).iter().map(|e| e.title.clone()).collect();
        assert_eq!(titles, ["unit fwupd-refresh.service failed", "unit fwupd-refresh.service recovered"]);
    }

    #[test]
    fn state_changes_drive_failure_and_recovery() {
        let mut cfg = warden_core::Config::default();
        cfg.systemd.auto_restart = vec!["php*-fpm.service".into()];
        cfg.systemd.max_restarts_per_hour = 1;
        cfg.systemd.ignore = vec!["noisy-*.service".into()];
        let shared = Shared::new(cfg.clone());
        let (sink, events) = Sink::collector();
        let cx = Cx::new(&shared, &cfg, &sink, "systemd");
        let rules = UnitRules::new(&cfg.systemd);
        let mut st = UnitState::default();
        rules.reconcile(&mut st, &cx, UnitSnapshot::failed(["cron.service".to_owned()].into()), "dbus");
        rules.on_state(&mut st, &cx, "php8.3-fpm.service", "failed");
        rules.on_state(&mut st, &cx, "php8.3-fpm.service", "failed"); // repeated signal
        rules.on_state(&mut st, &cx, "noisy-x.service", "failed");
        rules.on_state(&mut st, &cx, "php8.3-fpm.service", "activating"); // restart in progress
        rules.on_state(&mut st, &cx, "php8.3-fpm.service", "active");
        rules.on_state(&mut st, &cx, "php8.3-fpm.service", "failed"); // second failure within the hour
        let ev = lock(&events);
        let t: Vec<(&str, Severity)> = ev.iter().map(|e| (e.title.as_str(), e.severity)).collect();
        assert_eq!(
            t,
            [
                ("unit cron.service failed", Severity::Warning),
                ("unit php8.3-fpm.service failed", Severity::Warning),
                ("unit php8.3-fpm.service recovered", Severity::Info),
                ("unit php8.3-fpm.service failed", Severity::Critical),
            ]
        );
        assert_eq!(ev[0].details["already_failed_at_start"], true);
        assert_eq!(ev[1].actions, vec![ActionSpec::RestartUnit { unit: Some("php8.3-fpm.service".into()) }]);
        // it keeps failing: critical; the restart is still asked for and the
        // responder's budget (charged only for restarts that ran) decides
        assert!(ev[3].details["auto_restart"].as_str().unwrap().contains("failed 2 times within an hour"));
        assert_eq!(ev[3].actions, ev[1].actions);
        drop(ev);
        // Reconciliation reports what signals missed.
        lock(&events).clear();
        rules.reconcile(&mut st, &cx, UnitSnapshot::default(), "dbus");
        let titles: Vec<String> = lock(&events).iter().map(|e| e.title.clone()).collect();
        assert_eq!(titles, ["unit cron.service recovered", "unit php8.3-fpm.service recovered"]);
    }
}
