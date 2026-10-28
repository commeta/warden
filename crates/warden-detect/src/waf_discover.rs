//! Where the web servers are configured to write ModSecurity's logs.
//!
//! Reads the Apache (`/etc/apache2`, `/etc/httpd`), nginx (`/etc/nginx`)
//! and Angie (`/etc/angie`) configuration the way the servers do — includes
//! with globs, `Define` and the Debian `envvars`, virtual hosts and what
//! they inherit — and lists the ModSecurity log sources per virtual host:
//!
//! * `SecAuditLog` with `SecAuditLogType Serial` (JSON or native);
//! * `SecAuditLogType Concurrent` with its `SecAuditLogStorageDir`;
//! * the error log, where the audit log is piped away (`mlogc`), switched
//!   off while rules run, or written without the messages (no part `H`).
//!
//! Only files owned by root and not writable by others are read: a site
//! user's `.conf` dropped into an include directory must not decide which
//! files a root daemon reads.

use crate::util::{expand_glob, is_glob};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use warden_core::config::{WafFormat, WafLog};

/// One log source found in a web server's configuration.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Found {
    pub server: &'static str,
    /// `ServerName` / `server_name` of the virtual host, or `"default"`.
    pub site: String,
    pub path: PathBuf,
    pub format: WafFormat,
    pub storage_dir: Option<PathBuf>,
    /// `file:line` of the directive.
    pub origin: String,
    /// What the operator should know (a piped log, missing part H...).
    pub notes: Vec<String>,
}

impl Found {
    pub fn to_log(&self) -> WafLog {
        WafLog {
            path: self.path.clone(),
            format: self.format,
            // the server-wide log covers many sites; the Host of each entry says which
            site: (self.site != "default").then(|| self.site.clone()),
            storage_dir: self.storage_dir.clone(),
        }
    }
}

/// Everything found, plus what could not be used.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Discovery {
    pub found: Vec<Found>,
    /// Problems: unreadable or untrusted configuration files, sources
    /// Warden cannot follow.
    pub notes: Vec<String>,
}

impl Discovery {
    /// The sources as `[[waf.log]]` entries, one per path.
    pub fn logs(&self) -> Vec<WafLog> {
        let mut seen = HashSet::new();
        self.found.iter().filter(|f| seen.insert(f.path.clone())).map(Found::to_log).collect()
    }

    /// A `[[waf.log]]` TOML snippet for the configuration.
    pub fn toml(&self) -> String {
        let mut out = String::new();
        let mut seen = HashSet::new();
        for f in self.found.iter().filter(|f| seen.insert(f.path.clone())) {
            out.push_str(&format!("# {} {} ({})\n[[waf.log]]\npath = {:?}\n", f.server, f.site, f.origin, f.path));
            out.push_str(&format!(
                "format = {:?}\n",
                match f.format {
                    WafFormat::Auto => "auto",
                    WafFormat::Json => "json",
                    WafFormat::Native => "native",
                    WafFormat::ErrorLog => "error_log",
                    WafFormat::Concurrent => "concurrent",
                }
            ));
            if let Some(d) = &f.storage_dir {
                out.push_str(&format!("storage_dir = {d:?}\n"));
            }
            if f.site != "default" {
                out.push_str(&format!("site = {:?}\n", f.site));
            }
            out.push('\n');
        }
        out
    }
}

/// Is a web server's configuration there at all? (A cheap check for
/// whether discovery can find anything.)
pub fn web_server_present() -> bool {
    ["/etc/apache2", "/etc/httpd", "/etc/nginx", "/etc/angie"].iter().any(|p| Path::new(p).is_dir())
}

/// Look at every web server configured on this host.
pub fn discover() -> Discovery {
    let mut d = Discovery::default();
    let fs = RealFs;
    for (conf, root, envvars) in [
        ("/etc/apache2/apache2.conf", "/etc/apache2", Some("/etc/apache2/envvars")),
        ("/etc/httpd/conf/httpd.conf", "/etc/httpd", None),
    ] {
        if Path::new(conf).exists() {
            apache(&fs, Path::new(conf), Path::new(root), envvars.map(Path::new), &mut d);
        }
    }
    for (conf, root, name) in
        [("/etc/nginx/nginx.conf", "/etc/nginx", "nginx"), ("/etc/angie/angie.conf", "/etc/angie", "angie")]
    {
        if Path::new(conf).exists() {
            nginx(&fs, Path::new(conf), Path::new(root), name, &mut d);
        }
    }
    d
}

/// Reading configuration files (a fake one in tests).
pub trait ConfFs {
    /// The content of a configuration file, or why it is not used.
    fn read(&self, path: &Path) -> Result<String, String>;
    /// The files a glob include matches, sorted.
    fn glob(&self, pattern: &Path) -> Vec<PathBuf>;
}

/// The real file system, reading only files root controls.
pub struct RealFs;

impl ConfFs for RealFs {
    fn read(&self, path: &Path) -> Result<String, String> {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
        if md.uid() != 0 || md.mode() & 0o022 != 0 {
            return Err(format!(
                "{} is not owned by root or is writable by others: not read (a site user must not choose the logs Warden reads)",
                path.display()
            ));
        }
        if md.len() > 4 * 1024 * 1024 {
            return Err(format!("{}: larger than 4 MiB, skipped", path.display()));
        }
        std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
    }

    fn glob(&self, pattern: &Path) -> Vec<PathBuf> {
        if is_glob(pattern) {
            expand_glob(pattern, 1000).into_iter().map(|(p, _)| p).filter(|p| p.is_file()).collect()
        } else if pattern.is_dir() {
            // Apache: `Include dir` includes every file in it
            let mut v: Vec<PathBuf> = std::fs::read_dir(pattern)
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_file())
                .collect();
            v.sort();
            v
        } else if pattern.exists() {
            vec![pattern.to_path_buf()]
        } else {
            vec![]
        }
    }
}

// ---------------------------------------------------------------------------
// ModSecurity directives (shared by Apache and the nginx connector)
// ---------------------------------------------------------------------------

/// A directive's value and where it was set (`file:line`).
type Located = (String, String);

/// A server or virtual host: its name, its ModSecurity settings, its error log.
#[derive(Debug, Clone, Default)]
struct Context {
    site: String,
    modsec: ModSec,
    error_log: Option<Located>,
}

/// The audit settings in effect for a server or virtual host.
#[derive(Debug, Clone, Default)]
struct ModSec {
    engine: Option<String>,
    rule_engine: Option<String>,
    log: Option<Located>,
    log2: Option<Located>,
    kind: Option<String>,
    storage: Option<String>,
    format: Option<String>,
    parts: Option<String>,
}

impl ModSec {
    /// Apply one directive; true if it was one of ours.
    fn apply(&mut self, key: &str, args: &[String], origin: &str) -> bool {
        let v = || args.first().cloned().unwrap_or_default();
        match key.to_ascii_lowercase().as_str() {
            "secauditengine" => self.engine = Some(v()),
            "secruleengine" => self.rule_engine = Some(v()),
            "secauditlog" => self.log = Some((v(), origin.to_owned())),
            "secauditlog2" => self.log2 = Some((v(), origin.to_owned())),
            "secauditlogtype" => self.kind = Some(v()),
            "secauditlogstoragedir" => self.storage = Some(v()),
            "secauditlogformat" => self.format = Some(v()),
            "secauditlogparts" => self.parts = Some(v()),
            _ => return false,
        }
        true
    }

    /// Values set here override `base` (a virtual host over its server).
    fn over(&self, base: &ModSec) -> ModSec {
        ModSec {
            engine: self.engine.clone().or_else(|| base.engine.clone()),
            rule_engine: self.rule_engine.clone().or_else(|| base.rule_engine.clone()),
            log: self.log.clone().or_else(|| base.log.clone()),
            log2: self.log2.clone().or_else(|| base.log2.clone()),
            kind: self.kind.clone().or_else(|| base.kind.clone()),
            storage: self.storage.clone().or_else(|| base.storage.clone()),
            format: self.format.clone().or_else(|| base.format.clone()),
            parts: self.parts.clone().or_else(|| base.parts.clone()),
        }
    }

    fn rules_on(&self) -> bool {
        self.rule_engine.as_deref().is_some_and(|e| !e.eq_ignore_ascii_case("off"))
    }

    /// Sources for this context. `error_log` is the context's error log, the
    /// fallback when the audit log cannot be followed. `rel` resolves
    /// relative paths.
    fn sources(
        &self,
        server: &'static str,
        site: &str,
        error_log: Option<&Located>,
        rel: &dyn Fn(&str) -> PathBuf,
    ) -> (Vec<Found>, Vec<String>) {
        let mut found = Vec::new();
        let mut notes = Vec::new();
        if !self.rules_on() && self.engine.as_deref().is_none_or(|e| e.eq_ignore_ascii_case("off")) {
            return (found, notes);
        }
        let audit_off = self.engine.as_deref().is_none_or(|e| e.eq_ignore_ascii_case("off"));
        let mut usable = false;
        let mut site_notes = Vec::new();
        // without part H an audit record names no rule: nothing to count
        let has_h = self.parts.as_deref().is_none_or(|p| p.to_ascii_uppercase().contains('H'));
        if !audit_off && !has_h {
            site_notes.push(format!(
                "{site}: SecAuditLogParts {} has no part H, the audit log carries no rule messages: Warden follows the error log",
                self.parts.as_deref().unwrap_or("")
            ));
        }
        if !audit_off
            && has_h
            && let Some((log, origin)) = self.log.as_ref().or(self.log2.as_ref())
        {
            let concurrent = self.kind.as_deref().is_some_and(|k| k.eq_ignore_ascii_case("concurrent"));
            if let Some(cmd) = log.strip_prefix('|') {
                if concurrent && let Some(dir) = &self.storage {
                    // mlogc: no index to read, but the entries are on disk
                    // until shipped
                    found.push(Found {
                        server,
                        site: site.to_owned(),
                        path: rel(dir),
                        format: WafFormat::Concurrent,
                        storage_dir: None,
                        origin: origin.clone(),
                        notes: vec![format!(
                            "the index is piped to `{}`: entries are found by scanning {dir}; one shipped and deleted within a second can be missed — the error log is followed too",
                            cmd.trim()
                        )],
                    });
                } else {
                    site_notes.push(format!(
                        "{site}: the audit log is piped to `{}` ({origin}): Warden follows the error log instead",
                        cmd.trim()
                    ));
                }
            } else if concurrent {
                match &self.storage {
                    Some(dir) => {
                        found.push(Found {
                            server,
                            site: site.to_owned(),
                            path: rel(log),
                            format: WafFormat::Concurrent,
                            storage_dir: Some(rel(dir)),
                            origin: origin.clone(),
                            notes: vec![],
                        });
                        usable = true;
                    }
                    None => site_notes.push(format!(
                        "{site}: SecAuditLogType Concurrent without SecAuditLogStorageDir ({origin}): ModSecurity writes nothing"
                    )),
                }
            } else {
                let format = match self.format.as_deref() {
                    Some(f) if f.eq_ignore_ascii_case("json") => WafFormat::Json,
                    Some(f) if f.eq_ignore_ascii_case("native") => WafFormat::Native,
                    _ => WafFormat::Auto,
                };
                found.push(Found {
                    server,
                    site: site.to_owned(),
                    path: rel(log),
                    format,
                    storage_dir: None,
                    origin: origin.clone(),
                    notes: vec![],
                });
                usable = true;
            }
        }
        // the error log carries the rule messages whenever rules run
        if !usable && self.rules_on() {
            match error_log {
                Some((e, origin)) if !e.starts_with('|') && !e.starts_with("syslog") => found.push(Found {
                    server,
                    site: site.to_owned(),
                    path: rel(e),
                    format: WafFormat::ErrorLog,
                    storage_dir: None,
                    origin: origin.clone(),
                    notes: site_notes.clone(),
                }),
                _ => notes.push(format!("{site}: no audit log and no error log file Warden can follow")),
            }
        }
        notes.extend(site_notes);
        (found, notes)
    }
}

// ---------------------------------------------------------------------------
// Apache
// ---------------------------------------------------------------------------

/// Split an Apache configuration line into words (quotes group).
fn words(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (Some(_), '\\') => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            (None, c) if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            (_, c) => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// `${VAR}` from `Define` and the environment file.
fn expand_vars(s: &str, vars: &HashMap<String, String>) -> String {
    let mut out = s.to_owned();
    for _ in 0..4 {
        let Some(start) = out.find("${") else { break };
        let Some(len) = out[start..].find('}') else { break };
        let name = out[start + 2..start + len].to_owned();
        out.replace_range(start..start + len + 1, vars.get(&name).map(String::as_str).unwrap_or(""));
    }
    out
}

/// `export NAME=value` / `NAME=value` lines of Debian's `envvars`.
fn parse_envvars(text: &str) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    for line in text.lines() {
        let l = line.trim().trim_start_matches("export ").trim();
        let Some((k, v)) = l.split_once('=') else { continue };
        if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let v = v.trim().trim_matches(['"', '\'']);
        // `$SUFFIX` of a second instance: the default instance has none
        let v = v.replace("$SUFFIX", "").replace("${SUFFIX}", "");
        vars.insert(k.to_owned(), v);
    }
    vars
}

struct ApacheWalk<'a> {
    fs: &'a dyn ConfFs,
    root: PathBuf,
    vars: HashMap<String, String>,
    server: ModSec,
    error_log: Option<Located>,
    /// The virtual hosts, in order.
    vhosts: Vec<Context>,
    /// The virtual host being read.
    vhost: Option<Context>,
    visited: HashSet<PathBuf>,
    notes: Vec<String>,
}

impl ApacheWalk<'_> {
    fn rel(&self, p: &str) -> PathBuf {
        let p = Path::new(p);
        if p.is_absolute() { p.to_path_buf() } else { self.root.join(p) }
    }

    fn file(&mut self, path: &Path, depth: usize) {
        if depth > 16 || !self.visited.insert(path.to_path_buf()) {
            return;
        }
        let text = match self.fs.read(path) {
            Ok(t) => t,
            Err(e) => {
                self.notes.push(e);
                return;
            }
        };
        let mut joined = String::new();
        for (n, raw) in text.lines().enumerate() {
            // line continuation
            if let Some(stripped) = raw.strip_suffix('\\') {
                joined.push_str(stripped);
                joined.push(' ');
                continue;
            }
            joined.push_str(raw);
            let line = std::mem::take(&mut joined);
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let origin = format!("{}:{}", path.display(), n + 1);
            self.line(line, &origin, depth);
        }
    }

    fn line(&mut self, line: &str, origin: &str, depth: usize) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("<virtualhost") {
            self.vhost = Some(Context::default());
            return;
        }
        if lower.starts_with("</virtualhost") {
            if let Some(v) = self.vhost.take() {
                self.vhosts.push(v);
            }
            return;
        }
        if line.starts_with('<') {
            return; // other sections (IfModule, Directory…) do not change where logs go
        }
        let w: Vec<String> = words(line).into_iter().map(|w| expand_vars(&w, &self.vars)).collect();
        let Some((key, args)) = w.split_first() else { return };
        let k = key.to_ascii_lowercase();
        match k.as_str() {
            "include" | "includeoptional" => {
                if let Some(a) = args.first() {
                    let pat = self.rel(a);
                    let files = self.fs.glob(&pat);
                    if files.is_empty() && k == "include" && !is_glob(&pat) {
                        self.notes.push(format!("{origin}: Include {} not found", pat.display()));
                    }
                    for f in files {
                        self.file(&f, depth + 1);
                    }
                }
            }
            "define" => {
                if let [name, value, ..] = args {
                    self.vars.insert(name.clone(), value.clone());
                }
            }
            "serverroot" => {
                if let Some(a) = args.first() {
                    self.root = PathBuf::from(a);
                }
            }
            "servername" => {
                if let (Some(v), Some(a)) = (self.vhost.as_mut(), args.first()) {
                    v.site = a.split(':').next().unwrap_or(a).to_owned();
                }
            }
            "errorlog" => {
                let e = args.first().map(|a| (a.clone(), origin.to_owned()));
                match self.vhost.as_mut() {
                    Some(v) => v.error_log = e,
                    None => self.error_log = e,
                }
            }
            _ => {
                match self.vhost.as_mut() {
                    Some(v) => v.modsec.apply(key, args, origin),
                    None => self.server.apply(key, args, origin),
                };
            }
        }
    }
}

/// Apache with mod_security2 (or the libmodsecurity connector).
pub fn apache(fs: &dyn ConfFs, conf: &Path, root: &Path, envvars: Option<&Path>, out: &mut Discovery) {
    let mut vars = HashMap::new();
    if let Some(e) = envvars
        && let Ok(t) = fs.read(e)
    {
        vars = parse_envvars(&t);
    }
    vars.entry("APACHE_LOG_DIR".into()).or_insert_with(|| "/var/log/apache2".into());
    let mut w = ApacheWalk {
        fs,
        root: root.to_path_buf(),
        vars,
        server: ModSec::default(),
        error_log: None,
        vhosts: Vec::new(),
        vhost: None,
        visited: HashSet::new(),
        notes: Vec::new(),
    };
    w.file(conf, 0);
    let rel = |p: &str| w.rel(p);
    let mut contexts =
        vec![Context { site: "default".into(), modsec: w.server.clone(), error_log: w.error_log.clone() }];
    for v in &w.vhosts {
        contexts.push(Context {
            site: if v.site.is_empty() { "default".to_owned() } else { v.site.clone() },
            modsec: v.modsec.over(&w.server),
            error_log: v.error_log.clone().or_else(|| w.error_log.clone()),
        });
    }
    merge(out, contexts, "apache", &rel);
    out.notes.extend(w.notes);
}

/// Add the sources of each context, one entry per path (a log shared by
/// virtual hosts is listed once, under the first of them).
fn merge(out: &mut Discovery, contexts: Vec<Context>, server: &'static str, rel: &dyn Fn(&str) -> PathBuf) {
    let mut by_path: BTreeMap<PathBuf, usize> =
        out.found.iter().enumerate().map(|(i, f)| (f.path.clone(), i)).collect();
    for c in contexts {
        let (found, notes) = c.modsec.sources(server, &c.site, c.error_log.as_ref(), rel);
        for f in found {
            if !by_path.contains_key(&f.path) {
                by_path.insert(f.path.clone(), out.found.len());
                out.found.push(f);
            }
        }
        for n in notes {
            if !out.notes.contains(&n) {
                out.notes.push(n);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// nginx / Angie with the ModSecurity-nginx connector (libmodsecurity 3)
// ---------------------------------------------------------------------------

/// nginx configuration as statements: (words, depth change). `{` opens a
/// block (the words before it name it), `}` closes one, `;` ends a
/// statement; quotes and `#` comments are honoured.
fn nginx_statements(text: &str) -> Vec<(Vec<String>, i8)> {
    let mut out = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            match c {
                '\\' => {
                    if let Some(n) = chars.next() {
                        cur.push(n);
                    }
                }
                c if c == q => quote = None,
                c => cur.push(c),
            }
            continue;
        }
        match c {
            '#' => {
                for n in chars.by_ref() {
                    if n == '\n' {
                        break;
                    }
                }
            }
            '"' | '\'' => quote = Some(c),
            c if c.is_whitespace() => {
                if !cur.is_empty() {
                    words.push(std::mem::take(&mut cur));
                }
            }
            ';' | '{' | '}' => {
                if !cur.is_empty() {
                    words.push(std::mem::take(&mut cur));
                }
                let delta = match c {
                    '{' => 1,
                    '}' => -1,
                    _ => 0,
                };
                out.push((std::mem::take(&mut words), delta));
            }
            c => cur.push(c),
        }
    }
    out
}

struct NginxWalk<'a> {
    fs: &'a dyn ConfFs,
    root: PathBuf,
    visited: HashSet<PathBuf>,
    notes: Vec<String>,
    /// Block names, outermost first (`http`, `server`, `location`…).
    stack: Vec<String>,
    /// Settings per block level.
    levels: Vec<Level>,
    server_name: Option<String>,
    contexts: Vec<Context>,
}

/// What one nginx block sets: `modsecurity on|off`, ModSecurity
/// directives, `error_log`.
#[derive(Debug, Clone, Default)]
struct Level {
    on: Option<bool>,
    modsec: ModSec,
    error_log: Option<Located>,
}

impl NginxWalk<'_> {
    fn rel(&self, p: &str) -> PathBuf {
        let p = Path::new(p);
        if p.is_absolute() { p.to_path_buf() } else { self.root.join(p) }
    }

    fn file(&mut self, path: &Path, depth: usize) {
        if depth > 16 || !self.visited.insert(path.to_path_buf()) {
            return;
        }
        let text = match self.fs.read(path) {
            Ok(t) => t,
            Err(e) => {
                self.notes.push(e);
                return;
            }
        };
        for (words, delta) in nginx_statements(&text) {
            let origin = path.display().to_string();
            match delta {
                1 => {
                    self.stack.push(words.first().cloned().unwrap_or_default());
                    self.levels.push(Level::default());
                    if self.stack.last().is_some_and(|b| b == "server") {
                        self.server_name = None;
                    }
                }
                -1 => {
                    if self.stack.last().is_some_and(|b| b == "server") {
                        let site = self.server_name.take().unwrap_or_else(|| "default".into());
                        let (on, modsec, error_log) = self.effective();
                        if on {
                            self.contexts.push(Context { site, modsec, error_log });
                        }
                    }
                    self.stack.pop();
                    self.levels.pop();
                }
                _ => self.statement(&words, &origin, depth),
            }
        }
    }

    /// What applies at the current level: inherited from the outer ones.
    fn effective(&self) -> (bool, ModSec, Option<Located>) {
        let mut on = false;
        let mut ms = ModSec::default();
        let mut err = None;
        for l in &self.levels {
            if let Some(o) = l.on {
                on = o;
            }
            ms = l.modsec.over(&ms);
            if l.error_log.is_some() {
                err = l.error_log.clone();
            }
        }
        (on, ms, err)
    }

    fn statement(&mut self, w: &[String], origin: &str, depth: usize) {
        let Some((key, args)) = w.split_first() else { return };
        match key.as_str() {
            "include" => {
                if let Some(a) = args.first() {
                    for f in self.fs.glob(&self.rel(a)) {
                        self.file(&f, depth + 1);
                    }
                }
            }
            "server_name" => self.server_name = args.first().cloned(),
            "error_log" => {
                if let (Some(l), Some(a)) = (self.levels.last_mut(), args.first()) {
                    l.error_log = Some((a.clone(), origin.to_owned()));
                }
            }
            "modsecurity" => {
                if let (Some(l), Some(a)) = (self.levels.last_mut(), args.first()) {
                    l.on = Some(a == "on");
                }
            }
            "modsecurity_rules_file" => {
                if let Some(a) = args.first() {
                    let mut ms = ModSec::default();
                    self.modsec_file(&self.rel(a), &mut ms, depth + 1);
                    if let Some(l) = self.levels.last_mut() {
                        l.modsec = ms.over(&l.modsec);
                    }
                }
            }
            "modsecurity_rules" => {
                if let Some(a) = args.first() {
                    let mut ms = ModSec::default();
                    self.modsec_text(a, origin, &mut ms, depth + 1);
                    if let Some(l) = self.levels.last_mut() {
                        l.modsec = ms.over(&l.modsec);
                    }
                }
            }
            _ => {}
        }
    }

    /// A ModSecurity configuration file (`Include` with globs).
    fn modsec_file(&mut self, path: &Path, ms: &mut ModSec, depth: usize) {
        if depth > 16 {
            return;
        }
        match self.fs.read(path) {
            Ok(t) => self.modsec_text(&t, &path.display().to_string(), ms, depth),
            Err(e) => self.notes.push(e),
        }
    }

    fn modsec_text(&mut self, text: &str, origin: &str, ms: &mut ModSec, depth: usize) {
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let w = words(line);
            let Some((key, args)) = w.split_first() else { continue };
            if key.eq_ignore_ascii_case("include") {
                if let Some(a) = args.first() {
                    let base = Path::new(origin).parent().unwrap_or(&self.root).to_path_buf();
                    let p = if Path::new(a).is_absolute() { PathBuf::from(a) } else { base.join(a) };
                    for f in self.fs.glob(&p) {
                        self.modsec_file(&f, ms, depth + 1);
                    }
                }
                continue;
            }
            ms.apply(key, args, &format!("{origin}:{}", n + 1));
        }
    }
}

/// nginx or Angie with ModSecurity-nginx.
pub fn nginx(fs: &dyn ConfFs, conf: &Path, root: &Path, server: &'static str, out: &mut Discovery) {
    let mut w = NginxWalk {
        fs,
        root: root.to_path_buf(),
        visited: HashSet::new(),
        notes: Vec::new(),
        stack: Vec::new(),
        levels: vec![Level::default()],
        server_name: None,
        contexts: Vec::new(),
    };
    w.file(conf, 0);
    // nginx has no SecRuleEngine of its own: `modsecurity on` runs the rules
    let contexts: Vec<Context> = std::mem::take(&mut w.contexts)
        .into_iter()
        .map(|mut c| {
            if c.modsec.rule_engine.is_none() {
                c.modsec.rule_engine = Some("On".into());
            }
            c
        })
        .collect();
    let rel = |p: &str| w.rel(p);
    merge(out, contexts, server, &rel);
    out.notes.extend(w.notes);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An in-memory configuration tree.
    struct Fake(HashMap<PathBuf, String>);

    impl Fake {
        fn new(files: &[(&str, &str)]) -> Self {
            Self(files.iter().map(|(p, c)| (PathBuf::from(p), (*c).to_owned())).collect())
        }
    }

    impl ConfFs for Fake {
        fn read(&self, path: &Path) -> Result<String, String> {
            self.0.get(path).cloned().ok_or_else(|| format!("{} missing", path.display()))
        }
        fn glob(&self, pattern: &Path) -> Vec<PathBuf> {
            let pat = pattern.to_string_lossy();
            let re = regex::Regex::new(&format!("^{}$", regex::escape(&pat).replace("\\*", "[^/]*"))).unwrap();
            let mut v: Vec<PathBuf> = self.0.keys().filter(|p| re.is_match(&p.to_string_lossy())).cloned().collect();
            if v.is_empty() {
                let dir = format!("{}/", pat.trim_end_matches('/'));
                v = self.0.keys().filter(|p| p.to_string_lossy().starts_with(&dir)).cloned().collect();
            }
            v.sort();
            v
        }
    }

    /// Debian: a global serial log, one site with its own JSON log, one in
    /// concurrent mode, one piping to mlogc, one with the engine off.
    #[test]
    fn apache_per_vhost_logs_and_modes() {
        let fs = Fake::new(&[
            ("/etc/apache2/envvars", "export APACHE_LOG_DIR=/var/log/apache2$SUFFIX\n"),
            (
                "/etc/apache2/apache2.conf",
                "ServerRoot \"/etc/apache2\"\nErrorLog ${APACHE_LOG_DIR}/error.log\nIncludeOptional mods-enabled/*.conf\nIncludeOptional sites-enabled/*.conf\n",
            ),
            (
                "/etc/apache2/mods-enabled/security2.conf",
                "<IfModule security2_module>\n  IncludeOptional /etc/modsecurity/*.conf\n</IfModule>\n",
            ),
            (
                "/etc/modsecurity/modsecurity.conf",
                "SecRuleEngine On\nSecAuditEngine RelevantOnly\nSecAuditLogParts ABIJDEFHZ\nSecAuditLogType Serial\nSecAuditLog /var/log/apache2/modsec_audit.log\n",
            ),
            (
                "/etc/apache2/sites-enabled/a.conf",
                "<VirtualHost *:80>\n  ServerName a.example\n  SecAuditLogFormat JSON\n  SecAuditLog ${APACHE_LOG_DIR}/a.example/modsec.json\n</VirtualHost>\n",
            ),
            (
                "/etc/apache2/sites-enabled/b.conf",
                "<VirtualHost *:80>\n  ServerName b.example:80\n  SecAuditLogType Concurrent\n  SecAuditLogStorageDir /var/log/modsec/b/\n  SecAuditLog /var/log/modsec/b.index\n</VirtualHost>\n",
            ),
            (
                "/etc/apache2/sites-enabled/c.conf",
                "<VirtualHost *:80>\n  ServerName c.example\n  ErrorLog ${APACHE_LOG_DIR}/c-error.log\n  SecAuditLog \"|/usr/bin/mlogc /etc/mlogc.conf\"\n</VirtualHost>\n",
            ),
            (
                "/etc/apache2/sites-enabled/d.conf",
                "<VirtualHost *:80>\n  ServerName d.example\n  SecRuleEngine Off\n  SecAuditEngine Off\n</VirtualHost>\n",
            ),
        ]);
        let mut d = Discovery::default();
        apache(
            &fs,
            Path::new("/etc/apache2/apache2.conf"),
            Path::new("/etc/apache2"),
            Some(Path::new("/etc/apache2/envvars")),
            &mut d,
        );
        let got: Vec<(String, String, WafFormat, Option<String>)> = d
            .found
            .iter()
            .map(|f| {
                (
                    f.site.clone(),
                    f.path.display().to_string(),
                    f.format,
                    f.storage_dir.as_ref().map(|p| p.display().to_string()),
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                ("default".into(), "/var/log/apache2/modsec_audit.log".into(), WafFormat::Auto, None),
                ("a.example".into(), "/var/log/apache2/a.example/modsec.json".into(), WafFormat::Json, None),
                (
                    "b.example".into(),
                    "/var/log/modsec/b.index".into(),
                    WafFormat::Concurrent,
                    Some("/var/log/modsec/b/".into())
                ),
                ("c.example".into(), "/var/log/apache2/c-error.log".into(), WafFormat::ErrorLog, None),
            ],
            "{:#?}",
            d
        );
        assert!(d.notes.iter().any(|n| n.contains("piped to `/usr/bin/mlogc")), "{:?}", d.notes);
        assert!(d.found[1].origin.ends_with("a.conf:4"), "{}", d.found[1].origin);
        let toml = d.toml();
        assert!(toml.contains("format = \"concurrent\"\nstorage_dir = \"/var/log/modsec/b/\""), "{toml}");
        // the snippet is valid configuration
        let cfg: warden_core::Config = toml::from_str(&toml).unwrap();
        assert_eq!(cfg.waf.logs.len(), 4);
        assert!(cfg.validate().iter().all(|e| !e.contains("waf.log")), "{:?}", cfg.validate());
    }

    #[test]
    fn audit_log_without_part_h_falls_back_to_the_error_log() {
        let fs = Fake::new(&[(
            "/etc/httpd/conf/httpd.conf",
            "ErrorLog logs/error_log\nSecRuleEngine On\nSecAuditEngine On\nSecAuditLogParts ABZ\nSecAuditLog logs/modsec_audit.log\n",
        )]);
        let mut d = Discovery::default();
        apache(&fs, Path::new("/etc/httpd/conf/httpd.conf"), Path::new("/etc/httpd"), None, &mut d);
        let paths: Vec<String> = d.found.iter().map(|f| f.path.display().to_string()).collect();
        assert_eq!(paths, ["/etc/httpd/logs/error_log"]);
        assert!(d.notes.iter().any(|n| n.contains("no part H")));
    }

    #[test]
    fn nginx_connector_per_server() {
        let fs = Fake::new(&[
            (
                "/etc/nginx/nginx.conf",
                "user www-data;\nerror_log /var/log/nginx/error.log;\nhttp {\n  modsecurity on;\n  modsecurity_rules_file /etc/nginx/modsec/main.conf;\n  include /etc/nginx/sites-enabled/*;\n}\n",
            ),
            ("/etc/nginx/modsec/main.conf", "Include /etc/modsecurity/modsecurity.conf\nInclude crs/*.conf\n"),
            (
                "/etc/modsecurity/modsecurity.conf",
                "SecRuleEngine On\nSecAuditEngine RelevantOnly\nSecAuditLogFormat JSON\nSecAuditLog /var/log/modsec_audit.log\n",
            ),
            (
                "/etc/nginx/sites-enabled/api",
                "server {\n  server_name api.example;\n  error_log /var/log/nginx/api-error.log;\n  modsecurity_rules 'SecAuditLog /var/log/nginx/api-audit.json';\n  location / { proxy_pass http://127.0.0.1:3000; }\n}\n",
            ),
            ("/etc/nginx/sites-enabled/static", "server {\n  server_name static.example;\n  modsecurity off;\n}\n"),
            ("/etc/nginx/sites-enabled/shop", "server { server_name shop.example; }\n"),
        ]);
        let mut d = Discovery::default();
        nginx(&fs, Path::new("/etc/nginx/nginx.conf"), Path::new("/etc/nginx"), "nginx", &mut d);
        let got: Vec<(String, String, WafFormat)> =
            d.found.iter().map(|f| (f.site.clone(), f.path.display().to_string(), f.format)).collect();
        assert_eq!(
            got,
            vec![
                ("api.example".into(), "/var/log/nginx/api-audit.json".into(), WafFormat::Json),
                ("shop.example".into(), "/var/log/modsec_audit.log".into(), WafFormat::Json),
            ],
            "{d:#?}"
        );
    }

    #[test]
    fn config_files_root_does_not_control_are_not_read() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x.conf");
        std::fs::write(&p, "SecAuditLog /etc/shadow\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(RealFs.read(&p).unwrap_err().contains("not read"));
    }

    #[test]
    fn statements_and_words() {
        let s = nginx_statements("a b;\nserver { x \"y z\"; # c\n}\n");
        assert_eq!(
            s,
            vec![
                (vec!["a".into(), "b".into()], 0),
                (vec!["server".into()], 1),
                (vec!["x".into(), "y z".into()], 0),
                (vec![], -1)
            ]
        );
        assert_eq!(
            words(r#"SecAuditLog "|/usr/bin/mlogc /etc/m.conf""#),
            vec!["SecAuditLog", "|/usr/bin/mlogc /etc/m.conf"]
        );
        let vars = HashMap::from([("A".to_owned(), "/x".to_owned())]);
        assert_eq!(expand_vars("${A}/y/${B}", &vars), "/x/y/");
        assert_eq!(
            parse_envvars("export APACHE_LOG_DIR=/var/log/apache2$SUFFIX\nexport LANG=C\n")["APACHE_LOG_DIR"],
            "/var/log/apache2"
        );
    }
}
