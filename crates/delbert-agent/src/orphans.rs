//! Files that a new policy version no longer mentions (docs/REMEDIATION.md "Orphans").
//!
//! The agent remembers which paths the last successfully applied policy managed (`State::managed`).
//! When a later version stops declaring one of them (deleted, or renamed: the old path is simply no
//! longer declared), the file is removed, unless the resource that used to declare it said
//! `keep_if_absent_in_policy: true`. The directive is read from the OLD declaration, which is why it
//! is stored with the path.
//!
//! Deliberately conservative:
//! - only paths Delbert itself applied are ever removed (a resource that never applied on this host,
//!   e.g. its `when` was false, is not recorded);
//! - nothing is removed in a cycle with a failed resource: the old record is kept and the next clean
//!   cycle removes;
//! - a directory is removed only if empty; lines, blocks and mounts are never removed (declare
//!   `state: absent`);
//! - a path still declared by any resource (even under another id, or with a `when` that is false on
//!   this host) is not an orphan.

use std::{collections::BTreeMap, fs};

use delbert_policy::{FileState, Resource};
use serde::{Deserialize, Serialize};

use crate::engine::{Ctx, Report, ResourceReport, Status};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    File,
    Directory,
    Link,
}

/// A path the last applied policy managed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Managed {
    pub kind: Kind,
    /// `keep_if_absent_in_policy` of the declaring resource.
    pub keep: bool,
}

/// Path and kind a resource manages, if it manages one that can be removed. Besides the file
/// verbs: a download, a cron job (its file in `/etc/cron.d`) and the boot file of a kernel
/// parameter (the running value is left as it is).
fn managed_path(r: &Resource) -> Option<(String, Kind)> {
    use delbert_policy::Presence;
    if let Some(f) = &r.file {
        return match f.state {
            FileState::File => Some((f.path.clone(), Kind::File)),
            FileState::Directory => Some((f.path.clone(), Kind::Directory)),
            FileState::Link => Some((f.path.clone(), Kind::Link)),
            FileState::Absent => None,
        };
    }
    let file = if let Some(c) = &r.copy {
        c.dest.clone()
    } else if let Some(t) = &r.template {
        t.dest.clone()
    } else if let Some(g) = &r.get_url {
        g.dest.clone()
    } else if let Some(c) = r.cron.as_ref().filter(|c| c.state == Presence::Present) {
        crate::cron::path_of(c)
    } else if let Some(s) = r.sysctl.as_ref().filter(|s| s.persist) {
        crate::system::sysctl_persist_path(s)
    } else {
        return None;
    };
    Some((file, Kind::File))
}

/// Every path the policy declares, applicable on this host or not.
fn declared(resources: &[Resource]) -> BTreeMap<String, (Kind, bool)> {
    resources.iter().filter_map(|r| managed_path(r).map(|(p, k)| (p, (k, r.keep_if_absent_in_policy)))).collect()
}

/// The record after a clean cycle: what applied now, plus what was recorded before and is still
/// declared (its resource did not apply on this host this time).
fn next(old: &BTreeMap<String, Managed>, resources: &[Resource], report: &Report) -> BTreeMap<String, Managed> {
    let applied = |id: &str| report.resources.iter().any(|x| x.id == id && matches!(x.status, Status::Compliant | Status::Changed(_)));
    let mut out = BTreeMap::new();
    for r in resources {
        let Some((path, kind)) = managed_path(r) else { continue };
        if applied(&r.id) {
            out.insert(path, Managed { kind, keep: r.keep_if_absent_in_policy });
        } else if let Some(previous) = old.get(&path) {
            out.entry(path).or_insert_with(|| previous.clone());
        }
    }
    out
}

fn remove(ctx: &Ctx, path: &str, kind: Kind) -> Status {
    let real = ctx.path(path);
    let Ok(meta) = fs::symlink_metadata(&real) else {
        return Status::Compliant; // already gone
    };
    let result = match (kind, meta.is_dir()) {
        (Kind::Directory, true) => fs::remove_dir(&real),
        (Kind::Directory, false) | (Kind::File | Kind::Link, true) => return Status::Compliant, // not what we created: leave it
        (Kind::File | Kind::Link, false) => fs::remove_file(&real),
    };
    match result {
        Ok(()) => Status::Changed(vec!["removed: no longer in the policy".into()]),
        // A directory that still holds something is left alone, and said so.
        Err(e) if kind == Kind::Directory => Status::Skipped(format!("kept (not empty or busy): {e}")),
        Err(e) => Status::Failed(format!("cannot remove: {e}")),
    }
}

/// Run at the end of an apply cycle. Appends one entry per removed (or kept-but-reported) orphan to
/// `report` and returns the record to store: `None` when the cycle was not clean (keep the old one).
pub fn commit(ctx: &Ctx, resources: &[Resource], old: &BTreeMap<String, Managed>, report: &mut Report) -> Option<BTreeMap<String, Managed>> {
    if report.has_failures() {
        return None;
    }
    let still = declared(resources);
    for (path, m) in old {
        if still.contains_key(path) || m.keep {
            continue;
        }
        let started = std::time::Instant::now();
        let status = remove(ctx, path, m.kind);
        if matches!(status, Status::Compliant) {
            continue; // nothing there: no entry
        }
        let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let verb = match m.kind {
            Kind::File => "file",
            Kind::Directory => "directory",
            Kind::Link => "link",
        };
        report.resources.push(ResourceReport { id: format!("removed:{path}"), status, subject: format!("remove {verb} {path}"), ms });
    }
    // A removal that failed must be retried: keep it recorded.
    let mut record = next(old, resources, report);
    for r in &report.resources {
        if let (Some(path), Status::Failed(_)) = (r.id.strip_prefix("removed:"), &r.status) {
            if let Some(m) = old.get(path) {
                record.insert(path.to_string(), m.clone());
            }
        }
    }
    Some(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Mode, run};

    fn policy(yaml_resources: &str) -> Vec<Resource> {
        let yaml = format!("apiVersion: delbert/v1\nkind: Policy\nmetadata: {{ name: t, tenant: x }}\nspec:\n  resources:\n{yaml_resources}");
        delbert_policy::from_yaml(&yaml).unwrap().spec.resources
    }

    /// Apply `resources` and finish the cycle the way the daemon does.
    fn cycle(ctx: &Ctx, resources: &[Resource], old: &BTreeMap<String, Managed>) -> (Report, BTreeMap<String, Managed>) {
        let mut report = run(resources, ctx, Mode::Apply);
        let record = commit(ctx, resources, old, &mut report).unwrap_or_else(|| old.clone());
        (report, record)
    }

    const V1: &str = "    - id: conf\n      copy: { content: \"a\\n\", dest: /etc/app.conf }\n    - id: keepme\n      keep_if_absent_in_policy: true\n      copy: { content: \"k\\n\", dest: /etc/keep.conf }\n    - id: dir\n      file: { path: /etc/app.d, state: directory }\n    - id: lnk\n      file: { path: /etc/current, state: link, target: /etc/app.conf }\n    - id: mine\n      when: \"facts.os_family == 'rhel'\"\n      copy: { content: \"m\\n\", dest: /etc/never-applied }\n";

    #[test]
    fn what_a_new_version_drops_is_removed_unless_it_asked_to_stay() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::write(tmp.path().join("etc/os-release"), "ID=ubuntu\nID_LIKE=debian\n").unwrap();
        let ctx = Ctx::new(tmp.path().to_path_buf(), tmp.path().join("a"));
        let exists = |p: &str| fs::symlink_metadata(tmp.path().join(p)).is_ok();
        // A file somebody else put there: never recorded, never removed.
        fs::write(tmp.path().join("etc/never-applied"), "theirs").unwrap();
        fs::write(tmp.path().join("etc/unrelated"), "x").unwrap();

        let (_, record) = cycle(&ctx, &policy(V1), &BTreeMap::new());
        assert!(exists("etc/app.conf") && exists("etc/keep.conf") && exists("etc/app.d") && exists("etc/current"));
        assert_eq!(record.keys().map(String::as_str).collect::<Vec<_>>(), vec!["/etc/app.conf", "/etc/app.d", "/etc/current", "/etc/keep.conf"]);

        // Version 2 declares nothing of it, and renames nothing: everything recorded goes except the keeper.
        let v2 = policy("    - id: other\n      copy: { content: \"o\\n\", dest: /etc/other.conf }\n");
        fs::write(tmp.path().join("etc/app.d/inside"), "data").unwrap(); // the directory is not empty
        let (report, record) = cycle(&ctx, &v2, &record);
        assert!(!exists("etc/app.conf") && !exists("etc/current"), "file and link removed");
        assert!(exists("etc/keep.conf"), "keep_if_absent_in_policy");
        assert!(exists("etc/app.d/inside"), "a directory with content stays");
        assert!(exists("etc/never-applied") && exists("etc/unrelated"), "only what Delbert applied");
        let removed: Vec<&str> = report.resources.iter().filter(|r| r.id.starts_with("removed:")).map(|r| r.id.as_str()).collect();
        assert_eq!(removed, vec!["removed:/etc/app.conf", "removed:/etc/app.d", "removed:/etc/current"]);
        assert!(matches!(report.resources.iter().find(|r| r.id == "removed:/etc/app.d").unwrap().status, Status::Skipped(_)));
        assert!(!record.contains_key("/etc/keep.conf") && record.contains_key("/etc/other.conf"));
    }

    #[test]
    fn a_rename_keeps_the_new_path_and_drops_the_old_one() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        let ctx = Ctx::new(tmp.path().to_path_buf(), tmp.path().join("a"));
        let (_, record) = cycle(&ctx, &policy("    - id: c\n      copy: { content: \"a\\n\", dest: /etc/old.conf }\n"), &BTreeMap::new());
        let (_, record) = cycle(&ctx, &policy("    - id: c\n      copy: { content: \"a\\n\", dest: /etc/new.conf }\n"), &record);
        assert!(!tmp.path().join("etc/old.conf").exists() && tmp.path().join("etc/new.conf").exists());
        assert_eq!(record.keys().collect::<Vec<_>>(), vec!["/etc/new.conf"]);
    }

    #[test]
    fn a_failing_cycle_removes_nothing_and_remembers_everything() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        let ctx = Ctx::new(tmp.path().to_path_buf(), tmp.path().join("a"));
        let (_, record) = cycle(&ctx, &policy("    - id: c\n      copy: { content: \"a\\n\", dest: /etc/old.conf }\n"), &BTreeMap::new());
        // The new version fails (an artifact that is not there).
        let broken = policy("    - id: b\n      copy: { src: \"artifact://nope\", dest: /etc/b.conf }\n");
        let (report, after) = cycle(&ctx, &broken, &record);
        assert!(report.has_failures());
        assert!(tmp.path().join("etc/old.conf").exists(), "nothing removed while the cycle is not clean");
        assert_eq!(after, record, "the record is kept for the next clean cycle");
    }
    #[test]
    fn a_cron_job_a_download_and_a_boot_parameter_go_when_the_policy_drops_them() {
        let tmp = tempfile::tempdir().unwrap();
        for d in ["etc/cron.d", "etc/sysctl.d", "proc/sys/vm", "opt"] {
            fs::create_dir_all(tmp.path().join(d)).unwrap();
        }
        fs::write(tmp.path().join("proc/sys/vm/swappiness"), "60\n").unwrap();
        fs::write(tmp.path().join("etc/cron.d/foreign"), "0 0 * * * root /bin/true\n").unwrap();
        let mut ctx = Ctx::new(tmp.path().to_path_buf(), "artifacts".into());
        ctx.cron_allow = vec!["/usr/local/bin/backup.sh".into()];
        let v1 = policy(concat!(
            "    - id: job\n      cron: { name: backup, schedule: \"@daily\", command: [/usr/local/bin/backup.sh] }\n",
            "    - id: kept\n      keep_if_absent_in_policy: true\n      cron: { name: keepme, schedule: \"@daily\", command: [/usr/local/bin/backup.sh] }\n",
            "    - id: swap\n      sysctl: { key: vm.swappiness, value: \"10\" }\n",
        ));
        let (report, record) = cycle(&ctx, &v1, &BTreeMap::new());
        assert!(!report.has_failures(), "{:?}", report.resources.iter().map(|r| &r.status).collect::<Vec<_>>());
        assert_eq!(record.keys().map(String::as_str).collect::<Vec<_>>(), vec!["/etc/cron.d/backup", "/etc/cron.d/keepme", "/etc/sysctl.d/90-delbert-vm.swappiness.conf"]);

        let v2 = policy("    - id: other\n      file: { path: /opt/marker }\n");
        let (report, record) = cycle(&ctx, &v2, &record);
        let removed: Vec<&str> = report.resources.iter().filter(|r| r.id.starts_with("removed:")).map(|r| r.id.as_str()).collect();
        assert_eq!(removed, vec!["removed:/etc/cron.d/backup", "removed:/etc/sysctl.d/90-delbert-vm.swappiness.conf"]);
        assert!(!tmp.path().join("etc/cron.d/backup").exists());
        // Kept on request, never ours, and the running value is not put back.
        assert!(tmp.path().join("etc/cron.d/keepme").exists() && tmp.path().join("etc/cron.d/foreign").exists());
        assert_eq!(fs::read_to_string(tmp.path().join("proc/sys/vm/swappiness")).unwrap(), "10\n");
        assert_eq!(record.keys().map(String::as_str).collect::<Vec<_>>(), vec!["/opt/marker"]);
    }
}
