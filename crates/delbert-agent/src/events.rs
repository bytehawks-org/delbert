//! Per-action audit events (docs/ABSTRACT.md §6).
//!
//! The compliance report says what the host looks like *now*; an event says what the agent *did*.
//! After a cycle the agent derives events from the result:
//!
//! | Event | When |
//! |-------|------|
//! | `resource.changed` | a resource was changed (every time: the change happened) |
//! | `resource.failed` | a resource failed; repeated only when the failure changes |
//! | `policy.applied` | a policy version was applied for the first time |
//! | `policy.rejected` | a policy was refused (bad signature, expired, rollback…); repeated only when the reason changes |
//! | `events.dropped` | the spool overflowed and the oldest events were discarded |
//!
//! An unreachable Core is not an event (it is an availability problem, visible in the report).
//!
//! Events carry names and attribute names only (`detail` is for example `content, mode`), never
//! file contents or secrets. Delivery is at least once: events wait in a spool directory (one
//! crash-safe file each) until the Core, or the site proxy, acknowledges them; an id chosen here
//! lets the receiver drop a second delivery. The spool is bounded: a long outage loses the oldest
//! events, and says so with `events.dropped`. Losing the directory loses only what was not yet
//! delivered, never the agent's ability to work.

use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::Result;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::engine::{Report, Status};

/// Events in one message to the Core.
pub const BATCH: usize = 100;
/// Events kept while the Core cannot be reached.
const SPOOL_LIMIT: usize = 2000;
/// Longest `detail`; the Core cuts at the same length.
const MAX_DETAIL: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub kind: String,
    /// Unix seconds on this host.
    pub at: i64,
    pub resource: Option<String>,
    pub version: Option<u64>,
    pub detail: String,
}

fn new_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn cut(text: &str) -> String {
    text.chars().take(MAX_DETAIL).collect()
}

impl Event {
    fn new(kind: &str, at: i64, resource: Option<&str>, version: Option<u64>, detail: &str) -> Event {
        Event { id: new_id(), kind: kind.into(), at, resource: resource.map(str::to_owned), version, detail: cut(detail) }
    }
}

/// What a cycle produced, as far as events are concerned.
pub enum Outcome<'a> {
    /// A verified policy was applied: its name and version, the version applied before (if any) and the result.
    Applied { policy: &'a str, version: u64, previous: Option<u64>, report: &'a Report },
    /// A verified policy whose application crashed.
    ApplyCrashed { policy: &'a str, version: u64, error: &'a str },
    /// A policy was fetched but refused.
    Rejected { reason: &'a str },
    /// No policy to judge (the Core was unreachable and nothing was cached): nothing to record.
    NoPolicy,
}

/// Records a failure unless it is the one recorded last time under `key`.
fn once(memo: &mut BTreeMap<String, String>, events: &mut Vec<Event>, key: String, event: Event) {
    let signature = format!("{}|{}", event.kind, event.detail);
    if memo.get(&key) != Some(&signature) {
        memo.insert(key, signature);
        events.push(event);
    }
}

/// The events of one cycle. `memo` remembers the last failure per resource (and for the policy)
/// so that a failure repeating every cycle is recorded once; it is kept in the agent's state file.
pub fn derive(outcome: &Outcome, at: i64, memo: &mut BTreeMap<String, String>) -> Vec<Event> {
    let mut events = Vec::new();
    match outcome {
        Outcome::Applied { policy, version, previous, report } => {
            memo.remove("policy");
            memo.remove("apply");
            if *previous != Some(*version) {
                let changed = report.resources.iter().filter(|r| matches!(r.status, Status::Changed(_))).count();
                let failed = report.resources.iter().filter(|r| matches!(r.status, Status::Failed(_))).count();
                events.push(Event::new("policy.applied", at, Some(policy), Some(*version), &format!("{} resources, {changed} changed, {failed} failed", report.resources.len())));
            }
            let mut failing = Vec::new();
            for r in &report.resources {
                match &r.status {
                    Status::Changed(what) => events.push(Event::new("resource.changed", at, Some(&r.id), Some(*version), &what.join(", "))),
                    Status::Failed(why) => {
                        failing.push(r.id.clone());
                        once(memo, &mut events, format!("res:{}", r.id), Event::new("resource.failed", at, Some(&r.id), Some(*version), why));
                    }
                    _ => {}
                }
            }
            // A resource that stopped failing may fail again later and must be recorded then.
            memo.retain(|k, _| k.strip_prefix("res:").is_none_or(|id| failing.iter().any(|f| f == id)));
        }
        Outcome::ApplyCrashed { policy, version, error } => once(memo, &mut events, "apply".into(), Event::new("resource.failed", at, Some(policy), Some(*version), error)),
        Outcome::Rejected { reason } => once(memo, &mut events, "policy".into(), Event::new("policy.rejected", at, None, None, reason)),
        Outcome::NoPolicy => {}
    }
    events
}

/// Events waiting for an acknowledgement, one file each.
pub struct Spool {
    dir: PathBuf,
}

impl Spool {
    pub fn new(dir: PathBuf) -> Result<Spool> {
        fs::create_dir_all(&dir)?;
        Ok(Spool { dir })
    }

    /// Keep these events until they are acknowledged. When the spool is full the oldest events
    /// are discarded and one `events.dropped` event records how many.
    pub fn push(&self, events: &[Event]) -> Result<()> {
        for e in events {
            self.write(e)?;
        }
        let all = self.files();
        if all.len() > SPOOL_LIMIT {
            let excess = all.len() - SPOOL_LIMIT + 1;
            for path in all.iter().take(excess) {
                let _ = fs::remove_file(path);
            }
            self.write(&Event::new("events.dropped", events.first().map_or(0, |e| e.at), None, None, &format!("{excess} events discarded: the spool was full")))?;
        }
        Ok(())
    }

    fn write(&self, e: &Event) -> Result<()> {
        // File names sort in arrival order: milliseconds, a counter for the same millisecond, then the id.
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis());
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        delbert_fs::write_private(&self.dir.join(format!("{ms:020}-{n:010}-{}.json", e.id)), &serde_json::to_vec(e)?)?;
        Ok(())
    }

    fn files(&self) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = fs::read_dir(&self.dir).into_iter().flatten().flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "json")).collect();
        files.sort();
        files
    }

    /// Up to `limit` events, oldest first, with the files to remove once they are acknowledged.
    /// Unreadable files are removed: they can never be sent.
    pub fn pending(&self, limit: usize) -> (Vec<Value>, Vec<PathBuf>) {
        let (mut events, mut paths) = (Vec::new(), Vec::new());
        for path in self.files() {
            match fs::read(&path).ok().and_then(|raw| serde_json::from_slice::<Value>(&raw).ok()) {
                Some(v) => {
                    events.push(v);
                    paths.push(path);
                    if events.len() == limit {
                        break;
                    }
                }
                None => {
                    let _ = fs::remove_file(&path);
                }
            }
        }
        (events, paths)
    }

    pub fn ack(&self, paths: &[PathBuf]) {
        for p in paths {
            let _ = fs::remove_file(p);
        }
    }

    pub fn len(&self) -> usize {
        self.files().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::ResourceReport;

    fn res(id: &str, status: Status) -> ResourceReport {
        ResourceReport { id: id.into(), status }
    }
    fn report(resources: Vec<ResourceReport>) -> Report {
        Report { resources }
    }
    fn kinds(events: &[Event]) -> Vec<String> {
        events.iter().map(|e| format!("{}:{}", e.kind, e.resource.as_deref().unwrap_or("-"))).collect()
    }

    #[test]
    fn changes_are_recorded_every_time_failures_only_when_they_change() {
        let mut memo = BTreeMap::new();
        let r1 = report(vec![res("motd", Status::Changed(vec!["content".into(), "mode".into()])), res("svc", Status::Failed("unit not found".into())), res("ok", Status::Compliant)]);
        let first = derive(&Outcome::Applied { policy: "web", version: 3, previous: None, report: &r1 }, 100, &mut memo);
        assert_eq!(kinds(&first), ["policy.applied:web", "resource.changed:motd", "resource.failed:svc"]);
        assert_eq!(first[0].detail, "3 resources, 1 changed, 1 failed");
        assert_eq!(first[1].detail, "content, mode");

        // Same version, same failure next cycle: nothing new, except a change that happens again.
        let second = derive(&Outcome::Applied { policy: "web", version: 3, previous: Some(3), report: &r1 }, 120, &mut memo);
        assert_eq!(kinds(&second), ["resource.changed:motd"]);

        // The failure changes: recorded again. It stops and returns: recorded again.
        let r2 = report(vec![res("svc", Status::Failed("permission denied".into()))]);
        assert_eq!(kinds(&derive(&Outcome::Applied { policy: "web", version: 3, previous: Some(3), report: &r2 }, 140, &mut memo)), ["resource.failed:svc"]);
        let fixed = report(vec![res("svc", Status::Compliant)]);
        assert!(derive(&Outcome::Applied { policy: "web", version: 3, previous: Some(3), report: &fixed }, 160, &mut memo).is_empty());
        assert_eq!(kinds(&derive(&Outcome::Applied { policy: "web", version: 4, previous: Some(3), report: &r2 }, 180, &mut memo)), ["policy.applied:web", "resource.failed:svc"]);
    }

    #[test]
    fn a_refused_policy_is_recorded_once_and_a_missing_one_never() {
        let mut memo = BTreeMap::new();
        let refuse = |memo: &mut BTreeMap<String, String>, why: &str| derive(&Outcome::Rejected { reason: why }, 1, memo);
        assert_eq!(kinds(&refuse(&mut memo, "bad signature")), ["policy.rejected:-"]);
        assert!(refuse(&mut memo, "bad signature").is_empty());
        assert_eq!(kinds(&refuse(&mut memo, "policy expired")), ["policy.rejected:-"]);
        assert!(derive(&Outcome::NoPolicy, 2, &mut memo).is_empty());
        // After a good policy the same refusal is news again.
        derive(&Outcome::Applied { policy: "p", version: 1, previous: Some(1), report: &report(vec![]) }, 3, &mut memo);
        assert_eq!(kinds(&refuse(&mut memo, "policy expired")), ["policy.rejected:-"]);
    }

    #[test]
    fn details_are_cut_and_ids_are_unique() {
        let long = "x".repeat(2000);
        let e = Event::new("resource.failed", 1, Some("r"), None, &long);
        assert_eq!(e.detail.len(), MAX_DETAIL);
        assert_ne!(new_id(), new_id());
        assert_eq!(new_id().len(), 32);
    }

    #[test]
    fn the_spool_keeps_order_forgets_acknowledged_events_and_discards_the_oldest_when_full() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::new(dir.path().join("events")).unwrap();
        let mk = |n: usize| Event::new("resource.changed", n as i64, Some(&format!("r{n}")), None, "");
        spool.push(&[mk(1), mk(2), mk(3)]).unwrap();
        let (events, paths) = spool.pending(2);
        assert_eq!(events.iter().map(|e| e["resource"].as_str().unwrap()).collect::<Vec<_>>(), ["r1", "r2"]);
        spool.ack(&paths);
        assert_eq!(spool.len(), 1);

        // A corrupt file is dropped instead of blocking the queue.
        fs::write(dir.path().join("events").join("00000000000000000001-bad.json"), "{not json").unwrap();
        assert_eq!(spool.pending(10).0.len(), 1);
        assert_eq!(spool.len(), 1);

        let flood: Vec<Event> = (0..SPOOL_LIMIT + 5).map(mk).collect();
        spool.push(&flood).unwrap();
        assert!(spool.len() <= SPOOL_LIMIT + 1, "bounded: {}", spool.len());
        let all: Vec<Value> = spool.pending(usize::MAX).0;
        assert_eq!(all.last().unwrap()["kind"], "events.dropped");
    }
}
