//! The `command` verb: the only one that runs a program chosen by a policy
//! (docs/ABSTRACT.md §3, docs/POLICY.md "Commands"). Its rules, all enforced here:
//!
//! - **off by default, enabled only on the host:** every executable (the command's and its
//!   guards') must be on the agent's local allow-list (`--command-allow` /
//!   `DELBERT_COMMAND_ALLOW`), by exact absolute path and optionally pinned to a SHA-256
//!   (`/usr/local/bin/migrate@<hex>`). No policy, variable or fact can change the list;
//! - **no shell:** the argv is passed to the program as it is;
//! - **a guard is mandatory** (`creates`, `onlyif`, `unless`; validation refuses a command without
//!   one): the command runs only while the guard says it must, and after a successful run the
//!   guard must say it need not, or the resource fails ("not converged");
//! - **declared user, mandatory timeout, closed environment:** the program runs as `user`, is
//!   killed at `timeout_seconds`, and sees only `PATH`, `HOME`, `USER`, `LOGNAME`, `LC_ALL=C` and
//!   the policy's `env`.
//!
//! What reaches the Core: that the command ran (a `resource.changed` event with its subject and
//! the guard's reason) or failed (exit code and the first 300 characters of its error output).
//! The output of a successful run stays in the agent's log. Not available on Windows.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use delbert_policy::CommandSpec;
use sha2::{Digest, Sha256};

use crate::engine::Ctx;
use crate::runner::{CmdOutput, ExecRequest};
use crate::verbs::{Check, Verb};

const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Refuse an executable that the administrator of this host did not list (or whose content is
/// not the pinned one).
fn allowed(ctx: &Ctx, exe: &str) -> Result<()> {
    let entry = ctx.command_allow.iter().map(|e| e.split_once('@').unwrap_or((e.as_str(), ""))).find(|(path, _)| *path == exe);
    let Some((_, pin)) = entry else {
        bail!("'{exe}' is not on this agent's command allow-list (local setting DELBERT_COMMAND_ALLOW; commands are off by default)");
    };
    if !pin.is_empty() {
        let bytes = std::fs::read(ctx.path(exe)).with_context(|| format!("reading {exe}"))?;
        let actual: String = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
        if !actual.eq_ignore_ascii_case(pin) {
            bail!("'{exe}' does not match the SHA-256 pinned in this agent's command allow-list");
        }
    }
    Ok(())
}

/// Run one argv of the resource (the command or a guard) under its rules.
fn exec(spec: &CommandSpec, ctx: &Ctx, argv: &[String]) -> Result<CmdOutput> {
    if cfg!(windows) {
        bail!("command is not supported on Windows");
    }
    allowed(ctx, argv.first().context("empty command")?)?;
    // `root` keeps the agent's own identity; anybody else must be a local account.
    let (user, home) = if spec.user == "root" {
        (None, "/root".to_string())
    } else {
        let account = crate::accounts::passwd(ctx, &spec.user)?.with_context(|| format!("user '{}' does not exist", spec.user))?;
        (Some((account.uid, account.gid)), account.home)
    };
    let mut env: Vec<(String, String)> = [("PATH", PATH), ("HOME", home.as_str()), ("USER", spec.user.as_str()), ("LOGNAME", spec.user.as_str()), ("LC_ALL", "C")].into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    env.extend(spec.env.iter().map(|(k, v)| (k.clone(), v.clone())));
    ctx.runner.exec(&ExecRequest {
        argv: argv.to_vec(),
        user,
        env,
        cwd: spec.cwd.clone().unwrap_or_else(|| "/".into()).into(),
        timeout: Duration::from_secs(spec.timeout_seconds.into()),
    })
}

/// Why the command has to run now; empty when its guards say it need not. Every guard that is
/// declared must agree.
fn reasons(spec: &CommandSpec, ctx: &Ctx) -> Result<Vec<String>> {
    let mut why = Vec::new();
    if let Some(path) = &spec.creates {
        if ctx.path(path).exists() {
            return Ok(vec![]);
        }
        why.push(format!("{path} does not exist"));
    }
    if !spec.onlyif.is_empty() {
        if !exec(spec, ctx, &spec.onlyif)?.ok() {
            return Ok(vec![]);
        }
        why.push("'onlyif' holds".to_string());
    }
    if !spec.unless.is_empty() {
        if exec(spec, ctx, &spec.unless)?.ok() {
            return Ok(vec![]);
        }
        why.push("'unless' does not hold".to_string());
    }
    Ok(why)
}

impl Verb for CommandSpec {
    fn check(&self, ctx: &Ctx) -> Result<Check> {
        // Also in check mode: a command that this host does not allow is a failure to see, not drift.
        allowed(ctx, self.argv.first().context("command requires 'argv'")?)?;
        let why = reasons(self, ctx)?;
        Ok(if why.is_empty() { Check::Compliant } else { Check::Drift(why) })
    }

    fn apply(&self, ctx: &Ctx) -> Result<()> {
        if reasons(self, ctx)?.is_empty() {
            return Ok(());
        }
        let out = exec(self, ctx, &self.argv)?;
        tracing::info!("command {} (user {}): exit {:?}, {} bytes of output, {} of error output", self.argv[0], self.user, out.code, out.stdout.len(), out.stderr.len());
        let argv: Vec<&str> = self.argv.iter().map(String::as_str).collect();
        // Only the program is named in the error: arguments may carry values that are not for the audit trail.
        out.check(&argv[..1]).map(drop)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::runner::FakeRunner;

    fn spec() -> CommandSpec {
        CommandSpec {
            argv: vec!["/usr/local/bin/migrate".into(), "--apply".into()],
            creates: None,
            onlyif: vec![],
            unless: vec![],
            user: "app".into(),
            timeout_seconds: 60,
            cwd: None,
            env: Default::default(),
        }
    }

    fn ctx(allow: &[&str], script: Vec<(&[&str], i32, &str)>) -> (tempfile::TempDir, Ctx, Arc<FakeRunner>) {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("etc")).unwrap();
        std::fs::write(tmp.path().join("etc/passwd"), "app:x:1500:1501:App:/srv/app:/usr/sbin/nologin\n").unwrap();
        let runner = Arc::new(FakeRunner::new(script));
        let mut ctx = Ctx::new(tmp.path().to_path_buf(), "artifacts".into());
        ctx.runner = runner.clone();
        ctx.command_allow = allow.iter().map(|s| s.to_string()).collect();
        (tmp, ctx, runner)
    }

    #[test]
    fn off_by_default_for_the_command_and_for_its_guards() {
        let (_tmp, closed, runner) = ctx(&[], vec![]);
        let with_creates = CommandSpec { creates: Some("/var/lib/app/done".into()), ..spec() };
        assert!(with_creates.check(&closed).unwrap_err().to_string().contains("allow-list"));
        assert!(with_creates.apply(&closed).is_err());
        // The command is allowed, its guard is not: nothing runs.
        let (_tmp, half, runner2) = ctx(&["/usr/local/bin/migrate"], vec![]);
        let guarded = CommandSpec { unless: vec!["/usr/bin/test".into(), "-f".into(), "/x".into()], ..spec() };
        assert!(guarded.check(&half).unwrap_err().to_string().contains("'/usr/bin/test' is not on"));
        assert!(runner.calls().is_empty() && runner2.calls().is_empty());
    }

    #[test]
    fn creates_runs_once_as_the_declared_user() {
        let (tmp, ctx, runner) = ctx(&["/usr/local/bin/migrate"], vec![(&["/usr/local/bin/migrate"], 0, "")]);
        let spec = CommandSpec { creates: Some("/var/lib/app/done".into()), ..spec() };
        assert_eq!(spec.check(&ctx).unwrap(), Check::Drift(vec!["/var/lib/app/done does not exist".into()]));
        spec.apply(&ctx).unwrap();
        assert_eq!(runner.calls(), vec!["[1500:1501] /usr/local/bin/migrate --apply"]);
        // Once the marker exists nothing runs any more.
        std::fs::create_dir_all(tmp.path().join("var/lib/app/done")).unwrap();
        assert_eq!(spec.check(&ctx).unwrap(), Check::Compliant);
        spec.apply(&ctx).unwrap();
        assert_eq!(runner.calls().len(), 1);
    }

    #[test]
    fn onlyif_and_unless_decide_and_a_failing_command_reports_only_the_program() {
        let allow = ["/usr/local/bin/migrate", "/usr/bin/pending", "/usr/bin/done"];
        // onlyif exits 1: nothing to do.
        let (_t, c, r) = ctx(&allow, vec![(&["/usr/bin/pending"], 1, "")]);
        let spec_onlyif = CommandSpec { onlyif: vec!["/usr/bin/pending".into()], ..spec() };
        assert_eq!(spec_onlyif.check(&c).unwrap(), Check::Compliant);
        spec_onlyif.apply(&c).unwrap();
        assert!(r.calls().iter().all(|call| call.contains("/usr/bin/pending")));
        // unless exits 0: nothing to do; exits 1: run. Both guards must agree.
        let (_t, c, _) = ctx(&allow, vec![(&["/usr/bin/done"], 0, "")]);
        assert_eq!(CommandSpec { unless: vec!["/usr/bin/done".into()], ..spec() }.check(&c).unwrap(), Check::Compliant);
        let (_t, c, r) = ctx(&allow, vec![(&["/usr/bin/pending"], 0, ""), (&["/usr/bin/done"], 1, ""), (&["/usr/local/bin/migrate"], 7, "secret detail")]);
        let both = CommandSpec { onlyif: vec!["/usr/bin/pending".into()], unless: vec!["/usr/bin/done".into()], argv: vec!["/usr/local/bin/migrate".into(), "--token=abc".into()], ..spec() };
        assert_eq!(both.check(&c).unwrap(), Check::Drift(vec!["'onlyif' holds".into(), "'unless' does not hold".into()]));
        let err = both.apply(&c).unwrap_err().to_string();
        assert!(err.contains("`/usr/local/bin/migrate` failed (exit Some(7))") && !err.contains("--token"), "{err}");
        assert!(r.calls().iter().any(|call| call == "[1500:1501] /usr/local/bin/migrate --token=abc"));
    }

    #[test]
    fn a_pinned_executable_must_match_and_an_unknown_user_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("usr/local/bin")).unwrap();
        std::fs::write(tmp.path().join("usr/local/bin/migrate"), "#!/bin/sh\n").unwrap();
        let good: String = Sha256::digest(b"#!/bin/sh\n").iter().map(|b| format!("{b:02x}")).collect();
        let mut ctx = Ctx::new(tmp.path().to_path_buf(), "artifacts".into());
        let spec = CommandSpec { creates: Some("/done".into()), ..spec() };
        ctx.command_allow = vec![format!("/usr/local/bin/migrate@{good}")];
        assert!(matches!(spec.check(&ctx).unwrap(), Check::Drift(_)));
        // No passwd entry for "app" in this root.
        assert!(spec.apply(&ctx).unwrap_err().to_string().contains("user 'app' does not exist"));
        ctx.command_allow = vec![format!("/usr/local/bin/migrate@{}", "0".repeat(64))];
        assert!(spec.check(&ctx).unwrap_err().to_string().contains("does not match the SHA-256"));
    }

    #[test]
    fn a_sandbox_root_never_runs_anything() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = Ctx::new(tmp.path().to_path_buf(), "artifacts".into());
        ctx.command_allow = vec!["/usr/local/bin/migrate".into()];
        let spec = CommandSpec { creates: Some("/done".into()), user: "root".into(), ..spec() };
        assert!(spec.apply(&ctx).unwrap_err().downcast_ref::<crate::runner::Refused>().is_some());
    }
}
