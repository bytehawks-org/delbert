//! Remediation of a failed policy update (docs/REMEDIATION.md).
//!
//! Only what the policy declares (`remediation:` on a service resource) is ever done. After an
//! update cycle the agent verifies the services that changed; on a failure it does what
//! `on_failure` says:
//!
//! - `none`: report only;
//! - `stop`: stop the service cleanly (a forced kill only if `stop.kill: after_timeout`) and leave
//!   the host as it is;
//! - `rollback`: stop cleanly, re-apply the **last known good** policy as a whole, start cleanly,
//!   verify again.
//!
//! The version that failed is then quarantined (`Quarantine`, kept in the state file): the agent
//! does not apply it again until a greater version arrives or the Core releases it with a signed
//! `force`. All waiting is counted in whole seconds through a `wait` callback, so tests do not sleep.

use std::{net::TcpStream, time::Duration};

use delbert_policy::{KillMode, OnFailure, Remediation, Resource, StopSpec, Verify};
use serde::{Deserialize, Serialize};

use crate::engine::{Ctx, Mode, Report, Status, run};

/// Sleeps one second (or nothing, in tests).
pub type Wait<'a> = &'a dyn Fn(Duration);

/// Seconds to wait for a killed service to disappear.
const AFTER_KILL_SECONDS: u32 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// The last known good policy runs again; the failed version is quarantined.
    RolledBack,
    /// The rollback itself failed: the host needs a person.
    RollbackFailed,
    /// `on_failure: stop`: services were stopped, nothing else changed.
    Stopped,
    /// Remediation was asked for but impossible (no last known good policy): nothing was done and
    /// nothing is quarantined; the failure stays in the report.
    Skipped,
}

/// The agent is inconsistent with the Core until a person (or a newer version) resolves this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quarantine {
    pub state: State,
    /// The version that failed and is not applied again.
    pub failed_version: u64,
    /// The version running now (the last known good), if any.
    pub running_version: Option<u64>,
    /// Resource that failed first, and why.
    pub resource: String,
    pub reason: String,
    /// Unix seconds.
    pub at: i64,
    /// What the agent did, in order (stop, kill, re-apply, start, verify).
    pub steps: Vec<String>,
    /// A service had to be killed.
    pub forced_kill: bool,
}

/// Is the version about to be applied held back by a quarantine? A greater version, or a release
/// (`force`) for exactly the quarantined version that was not obeyed yet, lifts it; the state is
/// updated accordingly (the caller saves it). `Some`: do not apply, the host stays as it is.
pub fn gate(state: &mut crate::state::State, version: u64, force: Option<&delbert_wire::Force>) -> Option<Quarantine> {
    let q = state.quarantine.clone()?;
    if version > q.failed_version {
        state.quarantine = None;
        return None;
    }
    if let Some(f) = force.filter(|f| f.version == q.failed_version && state.last_force.as_deref() != Some(f.id.as_str())) {
        tracing::warn!("the Core released v{}: applying it again", q.failed_version);
        state.last_force = Some(f.id.clone());
        state.quarantine = None;
        return None;
    }
    Some(q)
}

/// A service resource that failed or did not come up.
#[derive(Debug, Clone)]
pub struct Failure {
    pub id: String,
    pub service: String,
    pub reason: String,
    pub remediation: Remediation,
}

fn active_state(ctx: &Ctx, service: &str) -> String {
    ctx.runner
        .run(&["systemctl", "show", "--property=ActiveState", "--value", service])
        .map(|o| o.stdout.trim().to_string())
        .unwrap_or_default()
}

fn port_open(port: u16) -> bool {
    TcpStream::connect_timeout(&std::net::SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_secs(2)).is_ok()
}

/// Did it come up (within `timeout_seconds`) and does it stay up for `settle_seconds`?
pub fn verify(ctx: &Ctx, service: &str, v: &Verify, wait: Wait) -> Result<(), String> {
    let mut up = false;
    for _ in 0..=v.timeout_seconds {
        match active_state(ctx, service).as_str() {
            "active" => {
                up = true;
                break;
            }
            "failed" => return Err(format!("{service} is in the failed state")),
            _ => wait(Duration::from_secs(1)),
        }
    }
    if !up {
        return Err(format!("{service} did not become active within {} s", v.timeout_seconds));
    }
    for second in 1..=v.settle_seconds {
        wait(Duration::from_secs(1));
        if active_state(ctx, service) != "active" {
            return Err(format!("{service} stopped being active {second} s after it came up"));
        }
    }
    if let Some(port) = v.port {
        if !port_open(port) {
            return Err(format!("{service} does not accept connections on 127.0.0.1:{port}"));
        }
    }
    Ok(())
}

pub struct Stopped {
    pub stopped: bool,
    pub forced: bool,
    pub steps: Vec<String>,
}

/// Stop cleanly; kill only if the policy allows it and the deadline passed.
pub fn stop(ctx: &Ctx, service: &str, spec: &StopSpec, wait: Wait) -> Stopped {
    let mut steps = Vec::new();
    let done = |s: &str| matches!(s, "inactive" | "failed" | "");
    if done(&active_state(ctx, service)) {
        steps.push(format!("{service}: already stopped"));
        return Stopped { stopped: true, forced: false, steps };
    }
    if let Err(e) = ctx.runner.run(&["systemctl", "stop", "--no-block", service]).and_then(|o| o.check(&["systemctl", "stop", service])) {
        steps.push(format!("{service}: cannot ask for a stop ({e})"));
        return Stopped { stopped: false, forced: false, steps };
    }
    for second in 0..=spec.graceful_seconds {
        if done(&active_state(ctx, service)) {
            steps.push(format!("{service}: stopped cleanly after {second} s"));
            return Stopped { stopped: true, forced: false, steps };
        }
        wait(Duration::from_secs(1));
    }
    if spec.kill != KillMode::AfterTimeout {
        steps.push(format!("{service}: still stopping after {} s, killing is not allowed by the policy", spec.graceful_seconds));
        return Stopped { stopped: false, forced: false, steps };
    }
    let killed = ctx.runner.run(&["systemctl", "kill", "--signal=SIGKILL", service]).and_then(|o| o.check(&["systemctl", "kill", service]));
    if let Err(e) = killed {
        steps.push(format!("{service}: not stopped after {} s and the kill failed ({e})", spec.graceful_seconds));
        return Stopped { stopped: false, forced: true, steps };
    }
    for _ in 0..=AFTER_KILL_SECONDS {
        if done(&active_state(ctx, service)) {
            steps.push(format!("{service}: killed (SIGKILL) after {} s without a clean stop", spec.graceful_seconds));
            return Stopped { stopped: true, forced: true, steps };
        }
        wait(Duration::from_secs(1));
    }
    steps.push(format!("{service}: killed but still not stopped after {AFTER_KILL_SECONDS} s"));
    Stopped { stopped: false, forced: true, steps }
}

/// Start and wait until it is active.
fn start(ctx: &Ctx, service: &str, timeout_seconds: u32, wait: Wait) -> Result<(), String> {
    if active_state(ctx, service) == "active" {
        return Ok(());
    }
    ctx.runner
        .run(&["systemctl", "start", "--no-block", service])
        .and_then(|o| o.check(&["systemctl", "start", service]))
        .map_err(|e| format!("{service}: cannot start ({e})"))?;
    for _ in 0..=timeout_seconds {
        match active_state(ctx, service).as_str() {
            "active" => return Ok(()),
            "failed" => return Err(format!("{service}: failed to start")),
            _ => wait(Duration::from_secs(1)),
        }
    }
    Err(format!("{service}: not active {timeout_seconds} s after the start"))
}

/// Judge the service resources that declare a remediation, after an apply.
pub fn evaluate(resources: &[Resource], report: &Report, ctx: &Ctx, wait: Wait) -> Vec<Failure> {
    let mut failures = Vec::new();
    for r in resources {
        let (Some(rem), Some(service)) = (&r.remediation, &r.service) else { continue };
        let Some(status) = report.resources.iter().find(|x| x.id == r.id).map(|x| &x.status) else { continue };
        let reason = match status {
            Status::Failed(m) => Some(m.clone()),
            Status::Changed(_) => rem.verify.as_ref().and_then(|v| verify(ctx, &service.name, v, wait).err()),
            _ => None,
        };
        if let Some(reason) = reason {
            failures.push(Failure { id: r.id.clone(), service: service.name.clone(), reason, remediation: rem.clone() });
        }
    }
    failures
}

/// The last known good policy, ready to run.
pub struct Lkg<'a> {
    pub version: u64,
    pub resources: &'a [Resource],
    pub ctx: &'a Ctx,
}

pub struct Remedy {
    pub quarantine: Quarantine,
    pub forced_kill: bool,
}

/// Do what the failed resources' policy says. `None`: nothing to do (all `on_failure: none`).
/// `ctx` runs the stop/start commands; `lkg` is `None` when no last known good policy exists.
pub fn remediate(ctx: &Ctx, failures: &[Failure], failed_version: u64, lkg: Option<Lkg>, at: i64, wait: Wait) -> Option<Remedy> {
    let acting: Vec<&Failure> = failures.iter().filter(|f| f.remediation.on_failure != OnFailure::None).collect();
    let first = acting.first()?;
    let wants_rollback = acting.iter().any(|f| f.remediation.on_failure == OnFailure::Rollback);
    let make = |state, running_version, steps, forced_kill| Remedy {
        quarantine: Quarantine { state, failed_version, running_version, resource: first.id.clone(), reason: first.reason.clone(), at, steps, forced_kill },
        forced_kill,
    };

    if wants_rollback && lkg.is_none() {
        // Nothing to go back to: leave the host alone rather than stop things with no way back.
        return Some(make(State::Skipped, None, vec!["rollback requested but there is no last known good policy: nothing was changed".into()], false));
    }

    let mut steps = Vec::new();
    let (mut forced, mut all_stopped) = (false, true);
    for f in &acting {
        // `stop` and `rollback` both begin with a clean stop of the failed service.
        let s = stop(ctx, &f.service, &f.remediation.stop, wait);
        forced |= s.forced;
        all_stopped &= s.stopped;
        steps.extend(s.steps);
    }
    let Some(lkg) = lkg.filter(|_| wants_rollback) else {
        return Some(make(State::Stopped, None, steps, forced));
    };
    if !all_stopped {
        steps.push("a service did not stop: the rollback was not attempted".into());
        return Some(make(State::RollbackFailed, None, steps, forced));
    }

    let report = run(lkg.resources, lkg.ctx, Mode::Apply);
    let changed = report.resources.iter().filter(|r| matches!(r.status, Status::Changed(_))).count();
    steps.push(format!("re-applied the last known good policy v{} ({changed} resources changed)", lkg.version));
    let mut ok = true;
    for r in report.resources.iter().filter(|r| matches!(r.status, Status::Failed(_))) {
        if let Status::Failed(m) = &r.status {
            steps.push(format!("{}: {m}", r.id));
        }
        ok = false;
    }
    for f in acting.iter().filter(|f| f.remediation.on_failure == OnFailure::Rollback) {
        if let Err(e) = start(ctx, &f.service, f.remediation.start.timeout_seconds, wait) {
            steps.push(e);
            ok = false;
            continue;
        }
        // The known-good declaration decides what "healthy" means; else the failed one's.
        let declared = lkg.resources.iter().find_map(|r| r.service.as_ref().filter(|x| x.name == f.service).and(r.remediation.as_ref()?.verify.clone()));
        match declared.or_else(|| f.remediation.verify.clone()) {
            Some(v) => match verify(ctx, &f.service, &v, wait) {
                Ok(()) => steps.push(format!("{}: started and verified", f.service)),
                Err(e) => {
                    steps.push(e);
                    ok = false;
                }
            },
            None => steps.push(format!("{}: started", f.service)),
        }
    }
    Some(make(if ok { State::RolledBack } else { State::RollbackFailed }, Some(lkg.version), steps, forced))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::FakeRunner;
    use std::sync::Arc;

    fn ctx(runner: FakeRunner) -> (Ctx, Arc<FakeRunner>) {
        let runner = Arc::new(runner);
        let mut ctx = Ctx::new("/".into(), "artifacts".into());
        ctx.runner = runner.clone();
        (ctx, runner)
    }

    fn no_wait(_: Duration) {}

    fn policy(yaml_resources: &str) -> Vec<Resource> {
        let yaml = format!("apiVersion: delbert/v1\nkind: Policy\nmetadata: {{ name: t, tenant: x }}\nspec:\n  resources:\n{yaml_resources}");
        delbert_policy::from_yaml(&yaml).unwrap().spec.resources
    }

    const SERVICE: &str = "    - id: web\n      handler: true\n      service: { name: nginx, state: restarted }\n      remediation:\n        verify: { settle_seconds: 2, timeout_seconds: 3 }\n        on_failure: rollback\n        stop: { graceful_seconds: 2, kill: after_timeout }\n";

    #[test]
    fn verification_needs_the_service_to_come_up_and_stay_up() {
        let v = Verify { settle_seconds: 2, timeout_seconds: 3, port: None };
        let (c, _) = ctx(FakeRunner::new(vec![(&["systemctl", "show"], 0, "activating\n"), (&["systemctl", "show"], 0, "active\n")]));
        assert!(verify(&c, "nginx", &v, &no_wait).is_ok());
        let (c, _) = ctx(FakeRunner::new(vec![(&["systemctl", "show"], 0, "failed\n")]));
        assert!(verify(&c, "nginx", &v, &no_wait).unwrap_err().contains("failed state"));
        let (c, _) = ctx(FakeRunner::new(vec![(&["systemctl", "show"], 0, "activating\n")]));
        assert!(verify(&c, "nginx", &v, &no_wait).unwrap_err().contains("did not become active"));
        // Up, then it falls over during the settle time.
        let (c, _) = ctx(FakeRunner::new(vec![(&["systemctl", "show"], 0, "active\n"), (&["systemctl", "show"], 0, "inactive\n")]));
        assert!(verify(&c, "nginx", &v, &no_wait).unwrap_err().contains("stopped being active"));
    }

    #[test]
    fn a_stop_is_clean_and_a_kill_only_happens_when_the_policy_allows_it() {
        let hang = |kill| StopSpec { graceful_seconds: 2, kill };
        let script = || vec![(&["systemctl", "show"] as &[&str], 0, "deactivating\n"), (&["systemctl", "stop"], 0, "")];
        // Never: waits, gives up, does not touch the process.
        let (c, r) = ctx(FakeRunner::new(script()));
        let s = stop(&c, "db", &hang(KillMode::Never), &no_wait);
        assert!(!s.stopped && !s.forced);
        assert!(!r.calls().iter().any(|c| c.contains("kill")));
        // After timeout: SIGKILL, then the service disappears.
        let mut after = script();
        after.extend([(&["systemctl", "show"] as &[&str], 0, "deactivating\n"); 3]);
        after.push((&["systemctl", "kill"], 0, ""));
        after.push((&["systemctl", "show"], 0, "inactive\n"));
        let (c, r) = ctx(FakeRunner::new(after));
        let s = stop(&c, "db", &hang(KillMode::AfterTimeout), &no_wait);
        assert!(s.stopped && s.forced, "{:?}", s.steps);
        assert!(r.calls().iter().any(|c| c == "systemctl kill --signal=SIGKILL db"));
        // A service that stops on its own is never killed.
        let (c, r) = ctx(FakeRunner::new(vec![(&["systemctl", "show"], 0, "active\n"), (&["systemctl", "show"], 0, "inactive\n"), (&["systemctl", "stop"], 0, "")]));
        let s = stop(&c, "db", &hang(KillMode::AfterTimeout), &no_wait);
        assert!(s.stopped && !s.forced && !r.calls().iter().any(|c| c.contains("kill")));
    }

    #[test]
    fn a_quarantined_version_stays_out_until_a_newer_one_or_a_single_release() {
        let q = Quarantine { state: State::RolledBack, failed_version: 5, running_version: Some(4), resource: "web".into(), reason: "x".into(), at: 1, steps: vec![], forced_kill: false };
        let mut state = crate::state::State { quarantine: Some(q.clone()), ..Default::default() };
        let force = |version, id: &str| delbert_wire::Force { version, id: id.into() };
        // The same version, with no release or a release for another version: held.
        assert!(gate(&mut state, 5, None).is_some());
        assert!(gate(&mut state, 5, Some(&force(6, "a"))).is_some());
        // The release for exactly that version lifts it, once.
        assert!(gate(&mut state, 5, Some(&force(5, "a"))).is_none());
        assert!(state.quarantine.is_none() && state.last_force.as_deref() == Some("a"));
        // The version fails again and is quarantined again: the same release id is not obeyed twice.
        state.quarantine = Some(q.clone());
        assert!(gate(&mut state, 5, Some(&force(5, "a"))).is_some());
        assert!(gate(&mut state, 5, Some(&force(5, "b"))).is_none());
        // A greater version supersedes without any release.
        state.quarantine = Some(q);
        assert!(gate(&mut state, 6, None).is_none() && state.quarantine.is_none());
        // Nothing quarantined: nothing to hold.
        assert!(gate(&mut state, 7, None).is_none());
    }

    #[test]
    fn only_services_that_declare_a_remediation_are_judged() {
        let resources = policy(&format!("{SERVICE}    - id: other\n      handler: true\n      service: {{ name: cron, state: restarted }}\n"));
        let mut report = Report::default();
        for id in ["web", "other"] {
            report.resources.push(crate::engine::ResourceReport { id: id.into(), status: Status::Changed(vec![]), subject: String::new(), ms: 0 });
        }
        let (c, _) = ctx(FakeRunner::new(vec![(&["systemctl", "show"], 0, "failed\n")]));
        let failures = evaluate(&resources, &report, &c, &no_wait);
        assert_eq!(failures.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(), vec!["web"]);
    }

    #[test]
    fn on_failure_none_does_nothing_and_a_missing_lkg_changes_nothing() {
        let resources = policy("    - id: web\n      handler: true\n      service: { name: nginx, state: restarted }\n      remediation: { on_failure: none }\n");
        let f = Failure { id: "web".into(), service: "nginx".into(), reason: "boom".into(), remediation: resources[0].remediation.clone().unwrap() };
        let (c, r) = ctx(FakeRunner::new(vec![]));
        assert!(remediate(&c, &[f], 5, None, 100, &no_wait).is_none());
        assert!(r.calls().is_empty());

        let resources = policy(SERVICE);
        let f = Failure { id: "web".into(), service: "nginx".into(), reason: "boom".into(), remediation: resources[0].remediation.clone().unwrap() };
        let (c, r) = ctx(FakeRunner::new(vec![]));
        let remedy = remediate(&c, &[f], 5, None, 100, &no_wait).unwrap();
        assert_eq!(remedy.quarantine.state, State::Skipped);
        assert!(remedy.quarantine.steps[0].contains("no last known good"));
        assert!(r.calls().is_empty(), "no stop without a way back");
    }

    #[test]
    fn rollback_stops_cleanly_reapplies_the_known_good_policy_and_starts_again() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("etc")).unwrap();
        std::fs::write(tmp.path().join("etc/app.conf"), "broken\n").unwrap();
        let good = policy(&format!("    - id: conf\n      copy: {{ content: \"good\\n\", dest: /etc/app.conf }}\n      notify: [web]\n{SERVICE}"));
        let failed = policy(SERVICE);
        let f = Failure { id: "web".into(), service: "nginx".into(), reason: "nginx is in the failed state".into(), remediation: failed[0].remediation.clone().unwrap() };

        // The host: running, then stops cleanly; after the rollback it comes up and stays up.
        let (host, calls) = ctx(FakeRunner::new(vec![
            (&["systemctl", "show"], 0, "active\n"),
            (&["systemctl", "show"], 0, "inactive\n"),
            (&["systemctl", "stop"], 0, ""),
            (&["systemctl", "restart"], 0, ""),
            (&["systemctl", "start"], 0, ""),
            (&["systemctl", "show"], 0, "inactive\n"),
            (&["systemctl", "show"], 0, "active\n"),
        ]));
        // The known-good context works in the sandbox root but shares the scripted runner.
        let mut lkg_ctx = Ctx::new(tmp.path().to_path_buf(), tmp.path().join("a"));
        lkg_ctx.runner = host.runner.clone();
        let lkg = Lkg { version: 4, resources: &good, ctx: &lkg_ctx };
        let remedy = remediate(&host, &[f], 5, Some(lkg), 100, &no_wait).unwrap();
        assert_eq!(remedy.quarantine.failed_version, 5);
        assert_eq!(remedy.quarantine.running_version, Some(4));
        assert_eq!(remedy.quarantine.state, State::RolledBack, "{:?}", remedy.quarantine.steps);
        assert!(!remedy.forced_kill);
        assert_eq!(std::fs::read_to_string(tmp.path().join("etc/app.conf")).unwrap(), "good\n");
        let order: Vec<String> = calls.calls().into_iter().filter(|c| c.starts_with("systemctl stop") || c.starts_with("systemctl restart") || c.starts_with("systemctl start")).collect();
        assert_eq!(order[0], "systemctl stop --no-block nginx", "stop comes first: {order:?}");
        assert!(order.iter().any(|c| c.starts_with("systemctl start")), "{order:?}");
    }
}
