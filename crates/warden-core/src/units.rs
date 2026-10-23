//! Human friendly units used across the configuration: byte sizes and
//! durations (`"512MiB"`, `"1.5G"`, `"30s"`, `"6h"`).

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// A size in bytes that can be written as `"100MiB"`, `"1G"`, `"4096"`, `"2.5GiB"`.
///
/// Both SI-looking (`K`, `M`, `G`) and IEC (`KiB`, `MiB`, `GiB`) suffixes are
/// treated as powers of 1024 — on servers nobody means 10^9 when writing `1G`
/// in a config file, and ambiguity here is how disks fill up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ByteSize(pub u64);

impl ByteSize {
    pub const fn b(v: u64) -> Self {
        Self(v)
    }
    pub const fn kib(v: u64) -> Self {
        Self(v * 1024)
    }
    pub const fn mib(v: u64) -> Self {
        Self(v * 1024 * 1024)
    }
    pub const fn gib(v: u64) -> Self {
        Self(v * 1024 * 1024 * 1024)
    }
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid byte size {0:?}: expected e.g. \"512MiB\", \"1G\", \"4096\"")]
pub struct ByteSizeError(String);

impl FromStr for ByteSize {
    type Err = ByteSizeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = s.trim();
        if t.is_empty() {
            return Err(ByteSizeError(s.to_owned()));
        }
        let split = t.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(t.len());
        let (num, unit) = t.split_at(split);
        let value: f64 = num.parse().map_err(|_| ByteSizeError(s.to_owned()))?;
        if !value.is_finite() || value < 0.0 {
            return Err(ByteSizeError(s.to_owned()));
        }
        let mult: u64 = match unit.trim().to_ascii_lowercase().as_str() {
            "" | "b" => 1,
            "k" | "kb" | "kib" => 1 << 10,
            "m" | "mb" | "mib" => 1 << 20,
            "g" | "gb" | "gib" => 1 << 30,
            "t" | "tb" | "tib" => 1 << 40,
            _ => return Err(ByteSizeError(s.to_owned())),
        };
        Ok(ByteSize((value * mult as f64).round() as u64))
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
        let mut v = self.0 as f64;
        let mut i = 0;
        while v >= 1024.0 && i < UNITS.len() - 1 {
            v /= 1024.0;
            i += 1;
        }
        if i == 0 { write!(f, "{}B", self.0) } else { write!(f, "{v:.1}{}", UNITS[i]) }
    }
}

impl Serialize for ByteSize {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Int(u64),
            Str(String),
        }
        match Repr::deserialize(d)? {
            Repr::Int(v) => Ok(ByteSize(v)),
            Repr::Str(s) => s.parse().map_err(serde::de::Error::custom),
        }
    }
}

/// `s` cut to at most `max_chars` characters, with `…` marking the cut.
pub fn truncate(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        None => s.to_owned(),
        Some((end, _)) => format!("{}…", &s[..end]),
    }
}

/// Format a byte count for humans (`1.5GiB`).
pub fn human_bytes(v: u64) -> String {
    ByteSize(v).to_string()
}

/// Format a duration compactly (`1h 2m 3s`).
pub fn human_duration(d: std::time::Duration) -> String {
    humantime::format_duration(std::time::Duration::from_secs(d.as_secs())).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_cuts_on_characters() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("exactly10!", 10), "exactly10!");
        assert_eq!(truncate("abcdefghijk", 10), "abcdefghij…");
        assert_eq!(truncate("привет мир", 6), "привет…", "multi-byte characters are not split");
        assert_eq!(truncate("", 0), "");
        assert_eq!(truncate("x", 0), "…");
    }

    #[test]
    fn parses_sizes() {
        assert_eq!("4096".parse::<ByteSize>().unwrap(), ByteSize(4096));
        assert_eq!("1K".parse::<ByteSize>().unwrap(), ByteSize(1024));
        assert_eq!("512MiB".parse::<ByteSize>().unwrap(), ByteSize::mib(512));
        assert_eq!("1G".parse::<ByteSize>().unwrap(), ByteSize::gib(1));
        assert_eq!("1.5 GiB".parse::<ByteSize>().unwrap(), ByteSize(1610612736));
        assert!("".parse::<ByteSize>().is_err());
        assert!("12XB".parse::<ByteSize>().is_err());
        assert!("-1M".parse::<ByteSize>().is_err());
    }

    #[test]
    fn displays_sizes() {
        assert_eq!(ByteSize(512).to_string(), "512B");
        assert_eq!(ByteSize::mib(3).to_string(), "3.0MiB");
        assert_eq!(ByteSize(1610612736).to_string(), "1.5GiB");
    }

    #[test]
    fn deserializes_from_int_or_string() {
        #[derive(Deserialize)]
        struct T {
            a: ByteSize,
            b: ByteSize,
        }
        let t: T = toml::from_str("a = 100\nb = \"2MiB\"").unwrap();
        assert_eq!(t.a, ByteSize(100));
        assert_eq!(t.b, ByteSize::mib(2));
    }
}
