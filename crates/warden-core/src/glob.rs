//! Compiled glob lists. Path globs use `literal_separator`, so `*` never
//! crosses `/` while `**` does — the semantics operators expect from shells.

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

#[derive(Debug, Clone)]
pub struct GlobList {
    set: GlobSet,
    len: usize,
}

impl Default for GlobList {
    fn default() -> Self {
        Self { set: GlobSet::empty(), len: 0 }
    }
}

impl GlobList {
    /// Invalid patterns are skipped (configuration validation reports them).
    pub fn new<S: AsRef<str>>(patterns: &[S]) -> Self {
        let mut b = GlobSetBuilder::new();
        let mut len = 0;
        for p in patterns {
            if let Ok(g) = GlobBuilder::new(p.as_ref()).literal_separator(true).backslash_escape(true).build() {
                b.add(g);
                len += 1;
            }
        }
        Self { set: b.build().unwrap_or_else(|_| GlobSet::empty()), len }
    }

    pub fn is_match(&self, s: impl AsRef<std::path::Path>) -> bool {
        self.len > 0 && self.set.is_match(s)
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

/// Lowest-common-prefix directories of absolute path globs: the directories a
/// walker must visit to evaluate the globs (`/etc/cron.d/*` → `/etc/cron.d`).
pub fn glob_roots<S: AsRef<str>>(patterns: &[S]) -> Vec<std::path::PathBuf> {
    let mut roots: Vec<std::path::PathBuf> = patterns
        .iter()
        .map(|p| {
            let p = p.as_ref();
            let cut = p.find(['*', '?', '[', '{']).unwrap_or(p.len());
            let prefix = &p[..cut];
            if cut == p.len() {
                std::path::PathBuf::from(prefix)
            } else {
                match prefix.rfind('/') {
                    Some(0) | None => "/".into(),
                    Some(i) => prefix[..i].into(),
                }
            }
        })
        .collect();
    roots.sort();
    roots.dedup();
    roots
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn star_does_not_cross_slash() {
        let g = GlobList::new(&["/tmp/*", "/var/www/**"]);
        assert!(g.is_match("/tmp/x"));
        assert!(!g.is_match("/tmp/a/b"));
        assert!(g.is_match("/var/www/site/a/b.php"));
    }

    #[test]
    fn names() {
        let g = GlobList::new(&["php-fpm*", "python*"]);
        assert!(g.is_match("php-fpm8.3"));
        assert!(g.is_match("python3"));
        assert!(!g.is_match("bash"));
        assert!(!GlobList::new::<&str>(&[]).is_match("x"));
    }

    #[test]
    fn roots() {
        let r = glob_roots(&["/etc/cron.d/*", "/etc/passwd", "/home/*/.ssh/authorized_keys"]);
        assert_eq!(
            r,
            vec![
                std::path::PathBuf::from("/etc/cron.d"),
                std::path::PathBuf::from("/etc/passwd"),
                std::path::PathBuf::from("/home")
            ]
        );
    }
}
