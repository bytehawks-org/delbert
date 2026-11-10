//! Policy runner: ordering, dependencies, handlers and reporting.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
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
    /// Key of the keyed hash that labels containers (see `containers.rs`); derived from the agent's identity.
    pub hash_key: Vec<u8>,
    /// Where container secret files are written (tmpfs on Linux); see `containers.rs`.
    pub secrets_dir: String,
    /// Directory of custom facts (`facts.d`); empty path = none.
    pub facts_dir: PathBuf,
    /// Executables (absolute paths) a `cron` resource may schedule. A local setting of this agent,
    /// never taken from a policy; empty (the default) refuses every cron resource. See `cron.rs`.
    pub cron_allow: Vec<String>,
    /// How verbs run system tools. Commands are refused when `root` is not `/`.
    pub runner: Arc<dyn Runner>,
}

impl Ctx {
    pub fn new(root: PathBuf, artifacts: PathBuf) -> Self {
        let runner: Arc<dyn Runner> = if root == Path::new("/") { Arc::new(SystemRunner) } else { Arc::new(SandboxRunner) };
        Ctx { root, artifacts, vars: BTreeMap::new(), secrets: BTreeMap::new(), artifact_hashes: BTreeMap::new(), facts_dir: PathBuf::new(), cron_allow: Vec::new(), hash_key: Vec::new(), secrets_dir: "/run/delbert/secrets".into(), runner }
    }

    /// Map an absolute policy path into the root. A Windows drive path (`C:/app` or `C:\app`)
    /// is used as it is when the root is the real one, and lands in `<root>/C/app` in a sandbox
    /// root, so it can never escape it.
    pub fn path(&self, absolute: &str) -> PathBuf {
        match delbert_policy::split_drive(absolute) {
            Some(_) if self.root == Path::new("/") => PathBuf::from(absolute),
            Some((drive, rest)) => self.root.join(drive.to_string()).join(rest.trim_start_matches(['/', '\\'])),
            None => self.root.join(absolute.trim_start_matches('/')),
        }
    }

    /// Facts exposed to templates and `when` as `facts.*` (see `facts.rs`; best effort).
    pub fn facts(&self) -> serde_json::Value {
        crate::facts::all(&self.root, &self.facts_dir)
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
    /// Its `when` is false on this host, or it depends on a resource that does not apply here.
    /// Not a problem: counts as compliant.
    NotApplicable(String),
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct ResourceReport {
    pub id: String,
    pub status: Status,
    /// What the resource acts on, for the audit trail: `copy /etc/app/db.conf`, `service nginx`.
    pub subject: String,
    /// Time spent checking and, in apply mode, converging the resource.
    pub ms: u64,
}

/// Verb and target of a resource, e.g. `file /etc/app`. Names only, never contents.
fn subject(r: &Resource) -> String {
    let target = if let Some(x) = &r.file {
        &x.path
    } else if let Some(x) = &r.copy {
        &x.dest
    } else if let Some(x) = &r.template {
        &x.dest
    } else if let Some(x) = &r.line_in_file {
        &x.path
    } else if let Some(x) = &r.package {
        &x.name
    } else if let Some(x) = &r.service {
        &x.name
    } else if let Some(x) = &r.container {
        &x.name
    } else if let Some(x) = &r.block_in_file {
        &x.path
    } else if let Some(x) = &r.user {
        &x.name
    } else if let Some(x) = &r.group {
        &x.name
    } else if let Some(x) = &r.cron {
        &x.name
    } else if let Some(x) = &r.sysctl {
        &x.key
    } else {
        return r.id.clone();
    };
    format!("{} {target}", r.verbs().first().copied().unwrap_or("resource"))
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
        self.resources.iter().all(|r| matches!(r.status, Status::Compliant | Status::Changed(_) | Status::Idle | Status::NotApplicable(_)))
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
    } else if let Some(v) = &r.container {
        Some(v)
    } else if let Some(v) = &r.block_in_file {
        Some(v)
    } else if let Some(v) = &r.user {
        Some(v)
    } else if let Some(v) = &r.group {
        Some(v)
    } else if let Some(v) = &r.cron {
        Some(v)
    } else if let Some(v) = &r.sysctl {
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
/// Does the resource's `when` hold on this host? No `when`: yes. An expression that cannot be
/// evaluated is an error, not "false": a resource is never applied (or silently dropped) by guess.
fn applies(r: &Resource, facts: &serde_json::Value, ctx: &Ctx) -> Result<bool, String> {
    let Some(when) = &r.when else { return Ok(true) };
    let mut env = minijinja::Environment::new();
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Strict);
    let expression = env.compile_expression(when).map_err(|e| format!("when: {e:#}"))?;
    let value = expression.eval(minijinja::context! { facts => facts, vars => &ctx.vars }).map_err(|e| format!("when: {e:#}"))?;
    Ok(value.is_true())
}

pub fn run(resources: &[Resource], ctx: &Ctx, mode: Mode) -> Report {
    let mut status: HashMap<&str, Status> = HashMap::new();
    let mut report = Report::default();
    let mut notified: HashSet<&str> = HashSet::new();

    let record = |r: &Resource, s: Status, started: std::time::Instant, report: &mut Report| {
        let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        report.resources.push(ResourceReport { id: r.id.clone(), status: s, subject: subject(r), ms });
    };

    // Conditions first: which resources apply to this host. Two that name the same thing and both
    // apply are refused (the Core cannot know, it did not see the host): both fail, nothing is applied by guess.
    let facts = ctx.facts();
    let conditions: HashMap<&str, Result<bool, String>> = resources.iter().filter(|r| r.when.is_some()).map(|r| (r.id.as_str(), applies(r, &facts, ctx))).collect();
    let active = |r: &Resource| conditions.get(r.id.as_str()).is_none_or(|c| matches!(c, Ok(true)));
    let mut clashing: HashMap<&str, String> = HashMap::new();
    for (i, a) in resources.iter().enumerate() {
        for b in &resources[i + 1..] {
            if a.handler || b.handler || (a.when.is_none() && b.when.is_none()) || !active(a) || !active(b) {
                continue;
            }
            if let Some(what) = delbert_policy::clash(a, b) {
                clashing.insert(a.id.as_str(), format!("{what} is also managed by '{}', which applies on this host too", b.id));
                clashing.insert(b.id.as_str(), format!("{what} is also managed by '{}', which applies on this host too", a.id));
            }
        }
    }

    for r in order(resources) {
        let started = std::time::Instant::now();
        let precondition = match conditions.get(r.id.as_str()) {
            Some(Err(e)) => Some(Status::Failed(e.clone())),
            Some(Ok(false)) => Some(Status::NotApplicable("'when' is false on this host".into())),
            _ => clashing.get(r.id.as_str()).map(|m| Status::Failed(m.clone())),
        }
        // A Windows drive path means nothing on another system: refuse it instead of guessing a place
        // for it (a sandbox root maps it to `<root>/C/...`, see `Ctx::path`).
        .or_else(|| {
            let foreign = !cfg!(windows) && ctx.root == Path::new("/");
            delbert_policy::managed_paths(r).into_iter().find(|p| foreign && delbert_policy::split_drive(p).is_some()).map(|p| Status::Failed(format!("'{p}' is a Windows path; scope the resource with 'when: facts.os_family == \"windows\"'")))
        })
        .or_else(|| {
            r.depends_on
                .iter()
                .find(|d| matches!(status.get(d.as_str()), Some(Status::NotApplicable(_))))
                .map(|d| Status::NotApplicable(format!("dependency '{d}' does not apply on this host")))
        });
        if let Some(s) = precondition {
            status.insert(r.id.as_str(), s.clone());
            record(r, s, started, &mut report);
            continue;
        }
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
        record(r, s, started, &mut report);
    }

    for r in resources.iter().filter(|r| r.handler) {
        let started = std::time::Instant::now();
        let s = match (notified.contains(r.id.as_str()), mode) {
            _ if matches!(conditions.get(r.id.as_str()), Some(Ok(false))) => Status::NotApplicable("'when' is false on this host".into()),
            _ if matches!(conditions.get(r.id.as_str()), Some(Err(_))) => Status::Failed(conditions[r.id.as_str()].clone().unwrap_err()),
            (false, _) => Status::Idle,
            (true, Mode::Check) => Status::Drifted(vec!["notified".into()]),
            (true, Mode::Apply) => run_one(r, ctx, mode),
        };
        record(r, s, started, &mut report);
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

    const CONDITIONAL: &str = r#"
apiVersion: delbert/v1
kind: Policy
metadata: { name: t, tenant: example }
spec:
  resources:
    - id: deb-motd
      when: "facts.os_family == 'debian'"
      copy: { content: "deb\n", dest: /etc/motd }
    - id: rhel-motd
      when: "facts.os_family == 'rhel'"
      copy: { content: "rhel\n", dest: /etc/motd }
    - id: deb-follow
      depends_on: [rhel-motd]
      file: { path: /etc/follow }
    - id: broken
      when: "facts.custom.nope.x == 1"
      file: { path: /etc/broken }
    - id: by-var
      when: "vars.mode == 'on' and facts.hostname == 'web01'"
      file: { path: /etc/by-var }
"#;

    fn conditional_setup(os_release: &str) -> (tempfile::TempDir, Ctx) {
        let (tmp, mut ctx) = setup();
        fs::write(tmp.path().join("etc/os-release"), os_release).unwrap();
        fs::write(tmp.path().join("etc/hostname"), "web01\n").unwrap();
        ctx.vars.insert("mode".into(), serde_json::json!("on"));
        (tmp, ctx)
    }

    #[test]
    fn when_selects_resources_by_facts_and_vars_and_fails_closed() {
        let (tmp, ctx) = conditional_setup("ID=ubuntu\nID_LIKE=debian\n");
        let policy = delbert_policy::from_yaml(CONDITIONAL).unwrap();
        let report = run(&policy.spec.resources, &ctx, Mode::Apply);
        assert!(matches!(status(&report, "deb-motd"), Status::Changed(_)));
        assert!(matches!(status(&report, "rhel-motd"), Status::NotApplicable(_)));
        // A dependency that does not apply here takes its dependents with it.
        assert!(matches!(status(&report, "deb-follow"), Status::NotApplicable(m) if m.contains("rhel-motd")));
        // An expression that cannot be evaluated is a failure, never "false".
        assert!(matches!(status(&report, "broken"), Status::Failed(m) if m.starts_with("when:")));
        assert!(matches!(status(&report, "by-var"), Status::Changed(_)));
        assert_eq!(fs::read_to_string(tmp.path().join("etc/motd")).unwrap(), "deb\n");
        assert!(!tmp.path().join("etc/follow").exists() && !tmp.path().join("etc/broken").exists());
        // Not-applicable is not a defect.
        assert!(report.resources.iter().filter(|r| r.id != "broken").all(|r| !matches!(r.status, Status::Failed(_))));

        let (_keep, other) = conditional_setup("ID=rocky\nID_LIKE=\"rhel centos fedora\"\n");
        let report = run(&policy.spec.resources, &other, Mode::Check);
        assert!(matches!(status(&report, "deb-motd"), Status::NotApplicable(_)));
        assert!(matches!(status(&report, "rhel-motd"), Status::Drifted(_)), "{:?}", status(&report, "rhel-motd"));
    }

    #[test]
    fn two_resources_that_both_apply_to_the_same_thing_are_refused() {
        let (tmp, ctx) = conditional_setup("ID=ubuntu\nID_LIKE=debian\n");
        let yaml = r#"
apiVersion: delbert/v1
kind: Policy
metadata: { name: t, tenant: example }
spec:
  resources:
    - id: a
      when: "facts.os_family == 'debian'"
      copy: { content: "a\n", dest: /etc/motd }
    - id: b
      when: "facts.hostname == 'web01'"
      copy: { content: "b\n", dest: /etc/motd }
"#;
        let policy = delbert_policy::from_yaml(yaml).unwrap();
        assert!(delbert_policy::validate(&policy).is_ok(), "different conditions are allowed to name the same file");
        let report = run(&policy.spec.resources, &ctx, Mode::Apply);
        assert!(matches!(status(&report, "a"), Status::Failed(m) if m.contains("'b'")));
        assert!(matches!(status(&report, "b"), Status::Failed(_)));
        assert!(!tmp.path().join("etc/motd").exists(), "nothing applied by guess");
    }
    #[test]
    fn windows_drive_paths_stay_inside_a_sandbox_root_and_are_refused_on_a_unix_host() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = Ctx::new(tmp.path().to_path_buf(), "artifacts".into());
        assert_eq!(ctx.path("C:/app/x.conf"), tmp.path().join("C").join("app/x.conf"));
        assert_eq!(ctx.path(r"d:\app\x.conf"), tmp.path().join("D").join(r"app\x.conf"));
        assert_eq!(ctx.path("/etc/x"), tmp.path().join("etc/x"));

        let policy = delbert_policy::from_yaml("apiVersion: delbert/v1\nkind: Policy\nmetadata: { name: p, tenant: t1 }\nspec:\n  resources:\n    - id: w\n      file: { path: \"C:/delbert-test/marker\", state: directory }\n").unwrap();
        // Sandbox root: applied under <root>/C.
        let report = run(&policy.spec.resources, &ctx, Mode::Apply);
        assert!(!report.has_failures(), "{:?}", report.resources[0].status);
        assert!(tmp.path().join("C/delbert-test/marker").is_dir());
        // Real root on a non-Windows host: refused, nothing is created.
        if !cfg!(windows) {
            let real = Ctx::new("/".into(), "artifacts".into());
            let report = run(&policy.spec.resources, &real, Mode::Check);
            assert!(matches!(&report.resources[0].status, Status::Failed(m) if m.contains("Windows path")), "{:?}", report.resources[0].status);
        }
    }
}
