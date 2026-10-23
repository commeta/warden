//! `/etc/passwd` lookups with mtime-based cache invalidation.

use std::collections::HashMap;
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PasswdEntry {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

pub fn parse_passwd(content: &str) -> Vec<PasswdEntry> {
    content
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 7 {
                return None;
            }
            Some(PasswdEntry {
                name: f[0].to_owned(),
                uid: f[2].parse().ok()?,
                gid: f[3].parse().ok()?,
                home: f[5].to_owned(),
                shell: f[6].to_owned(),
            })
        })
        .collect()
}

#[derive(Debug, Default)]
pub struct Users {
    by_uid: HashMap<u32, String>,
    by_name: HashMap<String, u32>,
    mtime: Option<SystemTime>,
    path: String,
}

impl Users {
    pub fn load() -> Self {
        Self::from_path("/etc/passwd")
    }

    pub fn from_path(path: &str) -> Self {
        let mut u = Self { path: path.to_owned(), ..Default::default() };
        u.refresh();
        u
    }

    /// Reload if the file changed.
    pub fn refresh(&mut self) {
        let mtime = std::fs::metadata(&self.path).and_then(|m| m.modified()).ok();
        if mtime.is_some() && mtime == self.mtime {
            return;
        }
        let entries = std::fs::read_to_string(&self.path).map(|s| parse_passwd(&s)).unwrap_or_default();
        self.by_uid = entries.iter().map(|e| (e.uid, e.name.clone())).collect();
        self.by_name = entries.into_iter().map(|e| (e.name, e.uid)).collect();
        self.mtime = mtime;
    }

    pub fn name(&self, uid: u32) -> Option<&str> {
        self.by_uid.get(&uid).map(String::as_str)
    }

    pub fn uid(&self, name: &str) -> Option<u32> {
        self.by_name.get(name).copied()
    }

    pub fn display(&self, uid: u32) -> String {
        self.name(uid).map(str::to_owned).unwrap_or_else(|| uid.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwd_parsing() {
        let e = parse_passwd(
            "root:x:0:0:root:/root:/bin/bash\n# c\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbad:line\n",
        );
        assert_eq!(e.len(), 2);
        assert_eq!(e[1].uid, 33);
        assert_eq!(e[1].home, "/var/www");
    }

    #[test]
    fn lookups() {
        let u = Users::load();
        assert_eq!(u.name(0), Some("root"));
        assert_eq!(u.uid("root"), Some(0));
        assert_eq!(u.display(4_000_000), "4000000");
    }
}
