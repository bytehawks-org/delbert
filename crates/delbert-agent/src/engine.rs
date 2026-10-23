//! Policy runner: ordering, dependencies, handlers and reporting.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use delbert_policy::Resource;

use crate::runner::{Runner, SandboxRunner, SystemRunner};
use crate::verbs::{Check, Verb};

/// Execution context. `root` lets tests (and dry experiments) work in a
/// sandbox directory; on a real host it is `/`.
pub struct Ctx {
    pub root: PathBuf,
    /// Directory holding the artifacts referenced as `artifact://<name>`.
    pub artifacts: PathBuf,
    /// Policy variables available to templates.
    pub vars: BTreeMap<String, serde_json::Value>,
    /// Decrypted secrets, available to templates as `secrets.*`. Never logged or reported.
    pub secrets: BTreeMap<String, String>,
    /// Expected SHA-256 (hex) of artifacts, by name; present when the policy pins them.
    pub artifact_hashes: BTreeMap<String, String>,
    /// How verbs run system tools. Commands are refused when `root` is not `/`.
    pub runner: Arc<dyn Runner>,
}

impl Ctx {
    pub fn new(root: PathBuf, artifacts: PathBuf) -> Self {
        let runner: Arc<dyn Runner> = if root == Path::new("/") { Arc::new(SystemRunner) } else { Arc::new(SandboxRunner) };
        Ctx { root, artifacts, vars: BTreeMap::new(), secrets: BTreeMap::new(), artifact_hashes: BTreeMap::new(), runner }
    }

    /// Map an absolute policy path into the root.
    pub fn path(&self, absolute: &str) -> PathBuf {
        self.root.join(absolute.trim_start_matches('/'))
    }

    /// Facts exposed to templates as `facts.*` (read from the root, best effort).
    pub fn facts(&self) -> serde_json::Value {
        let read = |p: &str| fs::read_to_string(self.path(p)).unwrap_or_default();
        let os_release = read("/etc/os-release");
        let field = |key: &str| {
            os_release
                .lines()
                .find_map(|l| l.strip_prefix(key).and_then(|v| v.strip_prefix('=')))
                .map(|v| v.trim_matches('"').to_string())
                .unwrap_or_default()
        };
        serde_json::json!({
            "hostname": read("/etc/hostname").trim(),
            "os_id": field("ID"),
            "os_version_id": field("VERSION_ID"),
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Report drift, change nothing.
    Check,
    /// Converge, then verify.
    Apply,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Compliant,
    /// Check mode: what would change.
    Drifted(Vec<String>),
    /// Apply mode: what was changed (verified by a second check).
    Changed(Vec<String>),
    /// Handler that nobody notified.
    Idle,
    /// Verb not implemented on this agent/platform yet.
    Unsupported(String),
    /// A dependency failed, was skipped or is unsupported.
    Skipped(String),
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct ResourceReport {
    pub id: String,
    pub status: Status,
}

#[derive(Debug, Default)]
pub struct Report {
    pub resources: Vec<ResourceReport>,
}

impl Report {
    pub fn has_drift(&self) -> bool {
        self.resources.iter().any(|r| matches!(r.status, Status::Drifted(_)))
    }
    /// Everything converged (or has nothing to do).
    pub fn is_compliant(&self) -> bool {
        self.resources.iter().all(|r| matches!(r.status, Status::Compliant | Status::Changed(_) | Status::Idle))
    }
    pub fn has_failures(&self) -> bool {
        self.resources.iter().any(|r| matches!(r.status, Status::Failed(_)))
    }
}

/// Verb behind a resource, if this agent implements it.
fn verb_of(r: &Resource) -> Option<&dyn Verb> {
    if let Some(v) = &r.file {
        Some(v)
    } else if let Some(v) = &r.copy {
        Some(v)
    } else if let Some(v) = &r.line_in_file {
        Some(v)
    } else if let Some(v) = &r.template {
        Some(v)
    } else if let Some(v) = &r.package {
        Some(v)
    } else if let Some(v) = &r.service {
        Some(v)
    } else {
        None
    }
}

/// Declared order, adjusted so every resource comes after its dependencies.
/// Handlers are excluded: they run after the main pass, only when notified.
fn order(resources: &[Resource]) -> Vec<&Resource> {
    let regular: Vec<&Resource> = resources.iter().filter(|r| !r.handler).collect();
    let ids: HashSet<&str> = regular.iter().map(|r| r.id.as_str()).collect();
    let mut done: HashSet<&str> = HashSet::new();
    let mut out = Vec::new();
    while out.len() < regular.len() {
        let next = regular.iter().find(|r| {
            !done.contains(r.id.as_str())
                && r.depends_on.iter().all(|d| done.contains(d.as_str()) || !ids.contains(d.as_str()))
        });
        // Policies are validated (no cycles) before they get here.
        let Some(next) = next else { break };
        done.insert(next.id.as_str());
        out.push(*next);
    }
    out
}

fn drifted_dep<'a>(r: &'a Resource, status: &HashMap<&str, Status>) -> Option<&'a str> {
    r.depends_on
        .iter()
        .find(|d| matches!(status.get(d.as_str()), Some(Status::Drifted(_))))
        .map(String::as_str)
}

fn run_one(r: &Resource, ctx: &Ctx, mode: Mode) -> Status {
    let Some(verb) = verb_of(r) else {
        return Status::Unsupported(format!("verb(s) {:?} not implemented", r.verbs()));
    };
    let drift = match verb.check(ctx) {
        Ok(Check::Compliant) => return Status::Compliant,
        Ok(Check::Drift(d)) => d,
        Err(e) => return Status::Failed(format!("{e:#}")),
    };
    if mode == Mode::Check {
        return Status::Drifted(drift);
    }
    if let Err(e) = verb.apply(ctx) {
        return Status::Failed(format!("{e:#}"));
    }
    if verb.is_action() {
        return Status::Changed(drift); // nothing observable to verify
    }
    match verb.check(ctx) {
        Ok(Check::Compliant) => Status::Changed(drift),
        Ok(Check::Drift(d)) => Status::Failed(format!("not converged after apply: {}", d.join(", "))),
        Err(e) => Status::Failed(format!("{e:#}")),
    }
}

/// Run a (validated) policy against the host described by `ctx`.
pub fn run(resources: &[Resource], ctx: &Ctx, mode: Mode) -> Report {
    let mut status: HashMap<&str, Status> = HashMap::new();
    let mut report = Report::default();
    let mut notified: HashSet<&str> = HashSet::new();

    let record = |r: &Resource, s: Status, report: &mut Report| {
        report.resources.push(ResourceReport { id: r.id.clone(), status: s });
    };

    for r in order(resources) {
        let blocked = r.depends_on.iter().find(|d| {
            matches!(
                status.get(d.as_str()),
                Some(Status::Failed(_) | Status::Skipped(_) | Status::Unsupported(_))
            )
        });
        let s = match blocked {
            Some(dep) => Status::Skipped(format!("dependency '{dep}' not satisfied")),
            None => match run_one(r, ctx, mode) {
                // Check mode: the dependency has not been applied, so this resource
                // may be unevaluable (e.g. its file does not exist yet). That is drift, not failure.
                Status::Failed(_) if mode == Mode::Check && drifted_dep(r, &status).is_some() => {
                    let dep = drifted_dep(r, &status).unwrap_or_default();
                    Status::Drifted(vec![format!("cannot evaluate until '{dep}' converges")])
                }
                other => other,
            },
        };
        if matches!(s, Status::Changed(_) | Status::Drifted(_)) {
            notified.extend(r.notify.iter().map(String::as_str));
        }
        status.insert(r.id.as_str(), s.clone());
        record(r, s, &mut report);
    }

    for r in resources.iter().filter(|r| r.handler) {
        let s = match (notified.contains(r.id.as_str()), mode) {
            (false, _) => Status::Idle,
            (true, Mode::Check) => Status::Drifted(vec!["notified".into()]),
            (true, Mode::Apply) => run_one(r, ctx, mode),
        };
        record(r, s, &mut report);
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const POLICY: &str = r#"
apiVersion: delbert/v1
kind: Policy
metadata: { name: t, tenant: example }
spec:
  resources:
    - id: dir
      file: { path: /etc/app, state: directory, mode: "0755" }
    - id: conf
      copy: { content: "port=8080\n", dest: /etc/app/app.conf, mode: "0640" }
      depends_on: [dir]
      notify: [reload]
    - id: extra
      file: { path: /etc/app/extra.conf }
      depends_on: [dir]
    - id: tweak
      line_in_file: { path: /etc/app/extra.conf, line: "debug=false" }
      depends_on: [extra]
    - id: link
      file: { path: /etc/app/current, state: link, target: /etc/app/app.conf }
      depends_on: [dir]
    - id: pkg
      package: { name: app }
    - id: after-pkg
      file: { path: /etc/app/marker }
      depends_on: [pkg]
    - id: reload
      handler: true
      file: { path: /etc/app/reloaded }
"#;

    fn setup() -> (tempfile::TempDir, Ctx) {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        let ctx = Ctx::new(tmp.path().to_path_buf(), tmp.path().join("artifacts"));
        (tmp, ctx)
    }

    fn status<'a>(r: &'a Report, id: &str) -> &'a Status {
        &r.resources.iter().find(|x| x.id == id).unwrap().status
    }

    #[test]
    fn check_changes_nothing_then_apply_converges_and_is_idempotent() {
        let (tmp, ctx) = setup();
        let policy = delbert_policy::from_yaml(POLICY).unwrap();

        let report = run(&policy.spec.resources, &ctx, Mode::Check);
        assert!(report.has_drift());
        assert!(!tmp.path().join("etc/app").exists(), "check must not change anything");

        let report = run(&policy.spec.resources, &ctx, Mode::Apply);
        assert!(matches!(status(&report, "conf"), Status::Changed(_)));
        assert_eq!(
            fs::read_to_string(tmp.path().join("etc/app/app.conf")).unwrap(),
            "port=8080\n"
        );
        assert_eq!(fs::read_to_string(tmp.path().join("etc/app/extra.conf")).unwrap(), "debug=false\n");
        assert!(tmp.path().join("etc/app/reloaded").exists(), "handler ran after notify");
        assert_eq!(fs::read_link(tmp.path().join("etc/app/current")).unwrap().to_str(), Some("/etc/app/app.conf"));

        // Commands are refused in a sandbox root: the package fails, its dependents are skipped.
        assert!(matches!(status(&report, "pkg"), Status::Failed(m) if m.contains("sandbox")));
        assert!(matches!(status(&report, "after-pkg"), Status::Skipped(_)));
        assert!(!tmp.path().join("etc/app/marker").exists());

        // Second apply: everything the agent can handle is already compliant.
        let report = run(&policy.spec.resources, &ctx, Mode::Apply);
        for r in &report.resources {
            assert!(
                matches!(r.status, Status::Compliant | Status::Idle | Status::Skipped(_)) || r.id == "pkg",
                "{} not idempotent: {:?}",
                r.id,
                r.status
            );
        }
    }

    #[test]
    fn missing_artifact_fails_the_resource_only() {
        let (_tmp, ctx) = setup();
        let yaml = r#"
apiVersion: delbert/v1
kind: Policy
metadata: { name: t, tenant: example }
spec:
  resources:
    - id: bad
      copy: { src: "artifact://nope", dest: /etc/x }
    - id: good
      file: { path: /etc/ok, state: directory }
"#;
        let report = run(&delbert_policy::from_yaml(yaml).unwrap().spec.resources, &ctx, Mode::Apply);
        assert!(matches!(status(&report, "bad"), Status::Failed(_)));
        assert!(matches!(status(&report, "good"), Status::Changed(_)));
    }
}
