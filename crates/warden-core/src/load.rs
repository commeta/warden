//! Loading `/etc/warden/warden.toml` plus drop-ins from `conf.d/*.toml`.
//!
//! Merge semantics (drop-ins are applied in lexical order):
//! * tables merge recursively;
//! * the collections listed in [`APPENDED`] (`[[fim.site]]`, `[[policy]]`,
//!   `[[notify.webhook]]`, …) are **appended**, so a drop-in can add a site
//!   without repeating the others;
//!   (Appended to what the main file and earlier drop-ins have: built-in
//!   defaults are not part of the merge, which is why the reference
//!   `warden.toml` spells out lists such as `process.allowed_children`.)
//! * everything else — scalars, plain arrays and **action lists and
//!   playbooks** such as `disk.cleanup` or `memory.on_critical` — is
//!   replaced: a drop-in that sets a playbook sets the whole playbook.
//!
//! (0.13.3 appended any array whose new value consisted of tables, so
//! `web_spawn = [{ do = "kill", tree = true }]` in a drop-in was added to the
//! default `["snapshot"]` instead of replacing it, and a cleanup playbook
//! written as tables grew the default's steps.)

use crate::config::Config;
use std::path::{Path, PathBuf};
use toml::{Table, Value};

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("cannot read {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("{path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("invalid configuration after merging drop-ins: {0}")]
    Merged(String),
    #[error("configuration is semantically invalid:\n  - {}", .0.join("\n  - "))]
    Invalid(Vec<String>),
}

/// Loaded configuration plus the list of files it came from.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub config: Config,
    pub files: Vec<PathBuf>,
}

/// Drop-in directory for a main config path: `<dir>/conf.d`.
pub fn dropin_dir(main: &Path) -> PathBuf {
    main.parent().unwrap_or_else(|| Path::new("/")).join("conf.d")
}

pub fn load(main: &Path) -> Result<Loaded, LoadError> {
    let mut files = Vec::new();
    let mut merged = Table::new();

    if main.exists() {
        merged = parse_file(main)?;
        files.push(main.to_path_buf());
    }

    let dir = dropin_dir(main);
    if let Ok(rd) = std::fs::read_dir(&dir) {
        let mut paths: Vec<PathBuf> = rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "toml") && p.is_file())
            .collect();
        paths.sort();
        for p in paths {
            let t = parse_file(&p)?;
            merge_tables(&mut merged, t);
            files.push(p);
        }
    }

    let config: Config =
        Value::Table(merged).try_into().map_err(|e: toml::de::Error| LoadError::Merged(e.message().to_owned()))?;
    let problems = config.validate();
    if !problems.is_empty() {
        return Err(LoadError::Invalid(problems));
    }
    Ok(Loaded { config, files })
}

/// Parse one file: syntax first, then a full typed parse of the file on its
/// own (every section is optional) so errors carry exact line/column info.
fn parse_file(path: &Path) -> Result<Table, LoadError> {
    let text = std::fs::read_to_string(path).map_err(|source| LoadError::Io { path: path.into(), source })?;
    let table: Table =
        toml::from_str(&text).map_err(|e| LoadError::Parse { path: path.into(), message: e.to_string() })?;
    toml::from_str::<Config>(&text).map_err(|e| LoadError::Parse { path: path.into(), message: e.to_string() })?;
    Ok(table)
}

/// Collections a drop-in adds to instead of replacing (dotted TOML keys).
/// They are lists of independent records — sites, rules, checks — where
/// "one more" is what a drop-in means.
pub const APPENDED: &[&str] = &[
    "policy",
    "notify.webhook",
    "notify.command",
    "process.limit",
    "process.allowed_children",
    "fim.site",
    "waf.log",
    "health.check",
    "kernel.patterns",
];

pub fn merge_tables(base: &mut Table, overlay: Table) {
    merge_at(base, overlay, "");
}

fn merge_at(base: &mut Table, overlay: Table, prefix: &str) {
    for (k, v) in overlay {
        let path = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
        match (base.get_mut(&k), v) {
            (Some(Value::Table(b)), Value::Table(o)) => merge_at(b, o, &path),
            (Some(Value::Array(b)), Value::Array(o)) if APPENDED.contains(&path.as_str()) => b.extend(o),
            (_, v) => {
                base.insert(k, v);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_dropins() {
        let dir = std::env::temp_dir().join(format!("warden-load-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("conf.d")).unwrap();
        std::fs::write(
            dir.join("warden.toml"),
            "[memory]\nsustain = \"10s\"\n[[fim.site]]\nname = 'a'\nroot = '/srv/a'\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("conf.d/10-b.toml"),
            "[memory]\nrepeat = \"5s\"\n[[fim.site]]\nname = 'b'\nroot = '/srv/b'\n",
        )
        .unwrap();
        std::fs::write(dir.join("conf.d/20-c.toml"), "[disk]\nfstypes = ['xfs']\n").unwrap();
        let l = load(&dir.join("warden.toml")).unwrap();
        assert_eq!(l.files.len(), 3);
        assert_eq!(l.config.memory.sustain.as_secs(), 10);
        assert_eq!(l.config.memory.repeat.as_secs(), 5);
        assert_eq!(l.config.fim.sites.len(), 2);
        assert_eq!(l.config.disk.fstypes, vec!["xfs".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn load_with(main: &str, dropin: &str) -> Config {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("conf.d")).unwrap();
        std::fs::write(dir.path().join("warden.toml"), main).unwrap();
        std::fs::write(dir.path().join("conf.d/50-x.toml"), dropin).unwrap();
        load(&dir.path().join("warden.toml")).unwrap().config
    }

    /// A playbook in a drop-in replaces the one in the main file, whatever
    /// form its steps take (0.13.3 appended steps written as tables).
    #[test]
    fn a_dropin_replaces_playbooks() {
        let c = load_with(
            "[disk]\ncleanup = [{ do = \"journal_vacuum\", max_size = \"512MiB\" }, { do = \"truncate_deleted\" }]\n\
             [memory]\non_critical = [\"snapshot\", \"kill\"]\n\
             [process.response]\nweb_spawn = [\"snapshot\"]\n",
            "[disk]\ncleanup = [{ do = \"journal_vacuum\", max_size = \"128MiB\" }]\n\
             [memory]\non_critical = [{ do = \"kill\", tree = true }]\n\
             [process.response]\nweb_spawn = [{ do = \"kill\", tree = true, grace = \"500ms\" }]\n",
        );
        assert_eq!(c.disk.cleanup.len(), 1, "{:?}", c.disk.cleanup);
        assert_eq!(c.memory.on_critical, vec![crate::ActionSpec::Kill { tree: true, grace: None }]);
        assert_eq!(c.process.response.web_spawn.len(), 1, "{:?}", c.process.response.web_spawn);
    }

    #[test]
    fn a_dropin_appends_records() {
        let c = load_with(
            "[[fim.site]]\nname = 'a'\nroot = '/srv/a'\n[[policy]]\nname = 'p1'\nkind = 'disk.*'\neffect = 'alert_only'\n\
             [[health.check]]\nname = 'h1'\ntype = 'tcp'\naddress = '127.0.0.1:1'\n\
             [[process.allowed_children]]\nparent = 'cron'\nchild = '/usr/bin/php'\n",
            "[[fim.site]]\nname = 'b'\nroot = '/srv/b'\n[[policy]]\nname = 'p2'\nkind = 'cpu.*'\neffect = 'alert_only'\n\
             [[health.check]]\nname = 'h2'\ntype = 'tcp'\naddress = '127.0.0.1:2'\n\
             [[process.allowed_children]]\nparent = 'php-fpm*'\nchild = '/usr/bin/convert'\n",
        );
        assert_eq!(c.fim.sites.len(), 2);
        assert_eq!(c.policies.len(), 2);
        assert_eq!(c.health.checks.len(), 2);
        assert_eq!(c.process.allowed_children.len(), 2);
    }

    /// Every appended key names a list of tables in the configuration.
    #[test]
    fn appended_keys_exist() {
        let t: Table = toml::Table::try_from(Config::default()).unwrap();
        for key in APPENDED {
            let mut v = Some(&Value::Table(t.clone()));
            for part in key.split('.') {
                v = v.and_then(|v| v.as_table()).and_then(|t| t.get(part));
            }
            assert!(matches!(v, Some(Value::Array(_))), "{key} is not a list in the configuration: {v:?}");
        }
    }

    #[test]
    fn reports_file_and_line() {
        let dir = std::env::temp_dir().join(format!("warden-load-err-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("warden.toml"), "[memory]\n\nsustain = 12\n").unwrap();
        let err = load(&dir.join("warden.toml")).unwrap_err().to_string();
        assert!(err.contains("warden.toml"), "{err}");
        assert!(err.contains("line 3"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_main_file_yields_defaults() {
        let l = load(Path::new("/nonexistent/warden/warden.toml")).unwrap();
        assert!(l.files.is_empty());
        assert!(l.config.memory.enabled);
    }
}
