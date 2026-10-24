//! Store-and-forward of compliance reports. A report is a snapshot of an agent's state, so the
//! queue keeps only the LATEST one per agent: nothing is lost that matters, and a long outage
//! cannot grow it without bound (one small file per agent). Audit events are different: every one
//! matters, so [`EventQueue`] keeps every batch until the Core has acknowledged it (bounded in
//! number; when full it refuses, and the agent keeps the events in its own spool).

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

/// Event batches of the agents of the site, kept until the Core acknowledges them.
#[derive(Clone)]
pub struct EventQueue {
    dir: PathBuf,
}

/// Batches the proxy holds at most; beyond that agents keep their events and retry.
pub const MAX_QUEUED_BATCHES: usize = 5000;

impl EventQueue {
    pub fn new(dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&dir)?;
        Ok(EventQueue { dir })
    }

    /// Keep this agent batch (`{proof, events}`, as the agent sent it). Fails when the queue is full or the write fails:
    /// then the agent must not be told its events are safe.
    pub fn push(&self, tenant: &str, agent: &str, received_at: i64, envelope: &Value) -> Result<()> {
        anyhow::ensure!(self.len() < MAX_QUEUED_BATCHES, "the event queue is full");
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let item = json!({ "tenant": tenant, "agent": agent, "received_at": received_at, "envelope": envelope });
        // Names sort in arrival order.
        let path = self.dir.join(format!("{received_at:012}-{n:010}-{tenant}.{agent}.json"));
        delbert_fs::write_private(&path, &serde_json::to_vec(&item)?)?;
        Ok(())
    }

    /// Up to `limit` batches, oldest first, with their files.
    pub fn pending(&self, limit: usize) -> Vec<(PathBuf, Value)> {
        let mut paths: Vec<PathBuf> = fs::read_dir(&self.dir).into_iter().flatten().flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "json")).collect();
        paths.sort();
        let mut out = Vec::new();
        for path in paths {
            match fs::read(&path).ok().and_then(|raw| serde_json::from_slice::<Value>(&raw).ok()) {
                Some(item) => {
                    out.push((path, item));
                    if out.len() == limit {
                        break;
                    }
                }
                None => {
                    let _ = fs::remove_file(&path); // unreadable: can never be sent
                }
            }
        }
        out
    }

    pub fn ack(&self, sent: &[(PathBuf, Value)]) {
        for (path, _) in sent {
            let _ = fs::remove_file(path);
        }
    }

    pub fn len(&self) -> usize {
        fs::read_dir(&self.dir).map_or(0, |d| d.flatten().filter(|e| e.path().extension().is_some_and(|x| x == "json")).count())
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

    #[test]
    fn event_batches_are_all_kept_in_arrival_order_until_acknowledged() {
        let dir = tempfile::tempdir().unwrap();
        let q = EventQueue::new(dir.path().join("e")).unwrap();
        q.push("acme", "a1", 100, &json!({ "events": [1] })).unwrap();
        q.push("acme", "a1", 100, &json!({ "events": [2] })).unwrap(); // same second: both kept, in order
        q.push("acme", "a2", 99, &json!({ "events": [3] })).unwrap();
        let sent = q.pending(10);
        assert_eq!(sent.iter().map(|(_, i)| i["envelope"]["events"][0].as_i64().unwrap()).collect::<Vec<_>>(), [3, 1, 2]);
        q.push("acme", "a1", 101, &json!({ "events": [4] })).unwrap(); // arrives while the batch is in flight
        q.ack(&sent);
        let left = q.pending(10);
        assert_eq!((left.len(), left[0].1["envelope"]["events"][0].clone()), (1, json!(4)));
        q.ack(&left);
        assert!(q.is_empty());
    }
}
