//! Minimal local state: highest policy version applied per policy name
//! (anti-rollback). Losing it only weakens rollback protection until the next
//! signed policy; it is not needed for correctness.

use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    pub versions: BTreeMap<String, u64>,
    /// Last failure recorded per resource and for the policy, so that a failure repeating every
    /// cycle becomes one audit event (see `events.rs`). Losing it costs one repeated event.
    #[serde(default)]
    pub events: BTreeMap<String, String>,
    /// Paths the last clean cycle applied (see `orphans.rs`). Losing it only means an orphan is
    /// not removed.
    #[serde(default)]
    pub managed: BTreeMap<String, crate::orphans::Managed>,
    /// Version of the policy kept in `policy.lkg.jws` (the last known good).
    #[serde(default)]
    pub lkg_version: Option<u64>,
    /// A failed version that was rolled back or stopped: not applied again until a greater
    /// version arrives or the Core releases it (docs/REMEDIATION.md).
    #[serde(default)]
    pub quarantine: Option<crate::remediation::Quarantine>,
    /// Id of the last release (`force`) obeyed: each decision is honoured once.
    #[serde(default)]
    pub last_force: Option<String>,
}

impl State {
    /// A missing file is an empty state.
    pub fn load(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        Ok(delbert_fs::write_private(path, &serde_json::to_vec_pretty(self)?)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        assert!(State::load(&path).unwrap().versions.is_empty());
        let mut s = State::default();
        s.versions.insert("p".into(), 7);
        s.save(&path).unwrap();
        assert_eq!(State::load(&path).unwrap().versions["p"], 7);
    }
}
