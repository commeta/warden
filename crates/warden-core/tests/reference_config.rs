//! The shipped configuration files must always parse and validate — and the
//! reference file must document the real defaults.
#![allow(clippy::unwrap_used)]

use std::path::PathBuf;
use warden_core::Config;

fn repo(p: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").join(p)
}

#[test]
fn reference_config_is_valid_and_matches_defaults() {
    let text = std::fs::read_to_string(repo("config/warden.toml")).unwrap();
    let c: Config = toml::from_str(&text).unwrap();
    assert!(c.validate().is_empty(), "{:?}", c.validate());
    let d = Config::default();
    // Spot-check that the documented values are the real defaults.
    assert_eq!(c.daemon.dry_run, d.daemon.dry_run);
    assert!(d.daemon.dry_run, "a fresh install observes before it acts");
    assert_eq!(c.memory.sustain, d.memory.sustain);
    assert_eq!(c.memory.swap_storm.sustain, d.memory.swap_storm.sustain);
    assert_eq!(c.memory.on_critical, d.memory.on_critical);
    assert_eq!(c.memory.max_kills_per_episode, d.memory.max_kills_per_episode);
    assert_eq!(c.disk.cleanup, d.disk.cleanup);
    assert_eq!(c.process.setuid_allowlist, d.process.setuid_allowlist);
    assert_eq!(c.process.suspicious_children, d.process.suspicious_children);
    assert_eq!(c.integrity.files, d.integrity.files);
    assert_eq!(c.heuristics.weights, d.heuristics.weights);
    assert_eq!(c.protection.comm, d.protection.comm);
    assert_eq!(c.fim.trusted_writers, d.fim.trusted_writers);
    assert_eq!(c.process.allowed_children.len(), d.process.allowed_children.len());
    assert_eq!(c.process.web_comms, d.process.web_comms);
    assert_eq!(c.process.db_comms, d.process.db_comms);
    assert_eq!(c.process.act_on_existing, d.process.act_on_existing);
    assert_eq!(c.memory.auto_scale, d.memory.auto_scale);
    assert_eq!(c.waf.block_after, d.waf.block_after);
    assert_eq!(c.waf.window, d.waf.window);
    assert_eq!(c.waf.min_rule_severity, d.waf.min_rule_severity);
    assert_eq!(c.tuning.auto_grow, d.tuning.auto_grow);
    assert_eq!(c.tuning.interval, d.tuning.interval);
    assert_eq!(c.health.enabled, d.health.enabled);
    assert_eq!(c.integrity.suid_exclude, d.integrity.suid_exclude);
    assert_eq!(c.integrity.suid_paths, d.integrity.suid_paths);
    assert_eq!(c.daemon.malloc_arenas, d.daemon.malloc_arenas);
    assert_eq!(c.daemon.pacing, d.daemon.pacing);
    assert_eq!(c.integrity.suid_realtime, d.integrity.suid_realtime);
    assert_eq!(c.integrity.suid_rescan, d.integrity.suid_rescan);
    assert_eq!(c.integrity.suid_delay, d.integrity.suid_delay);
    assert_eq!(c.process.exec_fast_path, d.process.exec_fast_path);
    assert_eq!(c.process.exec_recheck_every, d.process.exec_recheck_every);
    assert_eq!(c.systemd.dbus, d.systemd.dbus);
    assert_eq!(c.systemd.dbus_reconcile, d.systemd.dbus_reconcile);
    assert_eq!(c.disk.usage_report, d.disk.usage_report);
    assert_eq!(c.disk.usage_report_every, d.disk.usage_report_every);
    assert_eq!(c.disk.usage_report_max_entries, d.disk.usage_report_max_entries);
    assert_eq!(c.disk.usage_report_max_time, d.disk.usage_report_max_time);
    assert_eq!(c.hardware.clock_max_error, d.hardware.clock_max_error);
    // 0.14.2
    assert_eq!(c.actions.containment_reserve, d.actions.containment_reserve);
    assert_eq!(c.actions.firewall.max_blocks_per_hour, d.actions.firewall.max_blocks_per_hour);
    assert_eq!(c.actions.firewall.protect_ssh_sessions, d.actions.firewall.protect_ssh_sessions);
    assert_eq!(c.actions.firewall.ssh_ports, d.actions.firewall.ssh_ports);
    assert_eq!(c.memory.act_on_psi_alone, d.memory.act_on_psi_alone);
    assert_eq!(c.auth.trust_file, d.auth.trust_file);
    assert_eq!(c.fim.trust_writable_logs, d.fim.trust_writable_logs);
    assert_eq!(c.waf.trust_writable_logs, d.waf.trust_writable_logs);
    assert_eq!(c.waf.discover, d.waf.discover);
    // 0.14.3
    assert_eq!(c.actions.firewall.ipv6_prefix, d.actions.firewall.ipv6_prefix);
    assert_eq!(d.actions.firewall.ipv6_prefix, 64);
    assert_eq!(c.events.max_info_per_minute, d.events.max_info_per_minute);
}

#[test]
fn profiles_merge_with_reference() {
    for profile in ["50-webserver.toml", "50-workstation.toml", "50-database.toml"] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::copy(repo("config/warden.toml"), dir.path().join("warden.toml")).unwrap();
        std::fs::create_dir(dir.path().join("conf.d")).unwrap();
        std::fs::copy(repo(&format!("config/conf.d/{profile}")), dir.path().join("conf.d").join(profile)).unwrap();
        let l = warden_core::load::load(&dir.path().join("warden.toml")).unwrap_or_else(|e| panic!("{profile}: {e}"));
        assert_eq!(l.files.len(), 2);
        if profile.contains("webserver") {
            assert_eq!(l.config.fim.sites.len(), 1);
            assert_eq!(l.config.policies.len(), 1);
            assert_eq!(l.config.process.limits.len(), 3);
            // drop-in arrays of tables append to the reference list
            assert!(l.config.process.allowed_children.len() >= 21);
            // ...but an action list is replaced
            assert_eq!(l.config.process.response.web_spawn.len(), 1);
        } else if profile.contains("database") {
            assert_eq!(l.config.process.limits.len(), 1);
            assert!(l.config.memory.culprit.avoid.iter().any(|a| a == "mysqld"));
        } else {
            assert!(!l.config.fim.enabled);
            // the profile's cleanup playbook replaces the reference one
            assert_eq!(l.config.disk.cleanup.len(), 4, "{:?}", l.config.disk.cleanup);
            assert_eq!(l.config.notify.min_severity, warden_core::Severity::Critical);
        }
    }
}

#[test]
fn defaults_roundtrip_through_toml() {
    let s = toml::to_string_pretty(&Config::default()).unwrap();
    let c: Config = toml::from_str(&s).unwrap();
    assert!(c.validate().is_empty());
    assert_eq!(c.memory.on_critical, Config::default().memory.on_critical);
}
