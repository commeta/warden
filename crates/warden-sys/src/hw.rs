//! Hardware health: EDAC memory error counters and thermal zones.

use crate::util::{read_trimmed, read_u64};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct EdacController {
    pub name: String,
    /// Corrected errors (ECC fixed them — a DIMM is degrading).
    pub ce: u64,
    /// Uncorrected errors (data corruption / imminent crash).
    pub ue: u64,
}

pub fn edac() -> Vec<EdacController> {
    edac_in(Path::new("/sys/devices/system/edac/mc"))
}

/// [`edac`] under another directory (tests).
pub fn edac_in(dir: &Path) -> Vec<EdacController> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut v: Vec<EdacController> = rd
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("mc"))
        .filter_map(|e| {
            Some(EdacController {
                name: e.file_name().to_string_lossy().into_owned(),
                ce: read_u64(e.path().join("ce_count"))?,
                ue: read_u64(e.path().join("ue_count"))?,
            })
        })
        .collect();
    v.sort_by(|a, b| a.name.cmp(&b.name));
    v
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ThermalZone {
    pub zone: String,
    pub kind: String,
    pub celsius: f64,
}

pub fn thermal() -> Vec<ThermalZone> {
    thermal_in(Path::new("/sys/class/thermal"))
}

/// [`thermal`] under another directory (tests).
pub fn thermal_in(dir: &Path) -> Vec<ThermalZone> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut v: Vec<ThermalZone> = rd
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("thermal_zone"))
        .filter_map(|e| {
            let milli: i64 = read_trimmed(e.path().join("temp"))?.parse().ok()?;
            Some(ThermalZone {
                zone: e.file_name().to_string_lossy().into_owned(),
                kind: read_trimmed(e.path().join("type")).unwrap_or_default(),
                celsius: milli as f64 / 1000.0,
            })
        })
        // Some virtual zones report nonsense; ignore outside physical range.
        .filter(|z| z.celsius > -50.0 && z.celsius < 200.0)
        .collect();
    v.sort_by(|a, b| a.zone.cmp(&b.zone));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(p: &Path, s: &str) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, s).unwrap();
    }

    #[test]
    fn edac_controllers_are_read_in_order_and_incomplete_ones_skipped() {
        let d = tempfile::tempdir().unwrap();
        put(&d.path().join("mc1/ce_count"), "7\n");
        put(&d.path().join("mc1/ue_count"), "0\n");
        put(&d.path().join("mc0/ce_count"), "12\n");
        put(&d.path().join("mc0/ue_count"), "1\n");
        put(&d.path().join("mc2/ce_count"), "3\n"); // no ue_count
        put(&d.path().join("power/control"), "auto\n"); // not a controller
        let v = edac_in(d.path());
        assert_eq!(
            v,
            [EdacController { name: "mc0".into(), ce: 12, ue: 1 }, EdacController { name: "mc1".into(), ce: 7, ue: 0 },]
        );
        assert!(edac_in(&d.path().join("absent")).is_empty());
    }

    #[test]
    fn thermal_zones_in_millidegrees_and_nonsense_dropped() {
        let d = tempfile::tempdir().unwrap();
        put(&d.path().join("thermal_zone0/temp"), "47000\n");
        put(&d.path().join("thermal_zone0/type"), "x86_pkg_temp\n");
        put(&d.path().join("thermal_zone1/temp"), "-273150\n"); // a broken virtual sensor
        put(&d.path().join("thermal_zone2/temp"), "61500\n"); // no type
        put(&d.path().join("cooling_device0/cur_state"), "0\n");
        let v = thermal_in(d.path());
        assert_eq!(v.len(), 2);
        assert_eq!((v[0].zone.as_str(), v[0].kind.as_str(), v[0].celsius), ("thermal_zone0", "x86_pkg_temp", 47.0));
        assert_eq!((v[1].zone.as_str(), v[1].kind.as_str(), v[1].celsius), ("thermal_zone2", "", 61.5));
    }
}
