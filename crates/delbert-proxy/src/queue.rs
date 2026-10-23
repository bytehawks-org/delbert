//! Store-and-forward of compliance reports. A report is a snapshot of an agent's state, so the
//! queue keeps only the LATEST one per agent: nothing is lost that matters, and a long outage
//! cannot grow it without bound (one small file per agent).

use std::{fs, path::PathBuf};

use anyhow::Result;
use serde_json::{Value, json};

#[derive(Clone)]
pub struct ReportQueue {
    dir: PathBuf,
}

/// A queued report as read from disk; `raw` is what was read, so that [`ReportQueue::ack`] only
/// removes a file nobody has replaced with a newer report in the meantime.
pub struct Pending {
    path: PathBuf,
    raw: String,
    pub item: Value,
}

impl ReportQueue {
    pub fn new(dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&dir)?;
        Ok(ReportQueue { dir })
    }

    /// Keep this envelope as the agent's latest report.
    pub fn push(&self, tenant: &str, agent: &str, received_at: i64, envelope: &Value) -> Result<()> {
        let item = json!({ "tenant": tenant, "agent": agent, "received_at": received_at, "envelope": envelope });
        let path = self.dir.join(format!("{tenant}.{agent}.json"));
        delbert_fs::write_private(&path, &serde_json::to_vec(&item)?)?;
        Ok(())
    }

    /// Up to `limit` queued reports, oldest first.
    pub fn pending(&self, limit: usize) -> Vec<Pending> {
        let mut items: Vec<Pending> = fs::read_dir(&self.dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .filter_map(|e| {
                let raw = fs::read_to_string(e.path()).ok()?;
                Some(Pending { path: e.path(), item: serde_json::from_str(&raw).ok()?, raw })
            })
            .collect();
        items.sort_by_key(|p| p.item["received_at"].as_i64().unwrap_or(0));
        items.truncate(limit);
        items
    }

    /// The Core stored these: forget them (unless a newer report replaced them meanwhile).
    pub fn ack(&self, sent: &[Pending]) {
        for p in sent {
            if fs::read_to_string(&p.path).is_ok_and(|now| now == p.raw) {
                let _ = fs::remove_file(&p.path);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.pending(usize::MAX).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_only_the_latest_report_per_agent_and_acks_what_was_sent() {
        let dir = tempfile::tempdir().unwrap();
        let q = ReportQueue::new(dir.path().join("q")).unwrap();
        assert!(q.is_empty());
        q.push("acme", "a1", 100, &json!({ "report": { "v": 1 } })).unwrap();
        q.push("acme", "a2", 90, &json!({ "report": { "v": 1 } })).unwrap();
        q.push("acme", "a1", 110, &json!({ "report": { "v": 2 } })).unwrap(); // replaces the first
        let pending = q.pending(10);
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].item["agent"], "a2", "oldest first");
        assert_eq!(pending[1].item["envelope"]["report"]["v"], 2);

        // A newer report arriving while the batch is in flight survives the ack.
        q.push("acme", "a1", 120, &json!({ "report": { "v": 3 } })).unwrap();
        q.ack(&pending);
        let left = q.pending(10);
        assert_eq!((left.len(), left[0].item["envelope"]["report"]["v"].clone()), (1, json!(3)));
        q.ack(&left);
        assert!(q.is_empty());
        assert_eq!(q.pending(1).len(), 0);
    }
}
