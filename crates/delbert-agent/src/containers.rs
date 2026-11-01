//! The `container` verb: a Podman or Docker container, driven through the engine's command line.
//!
//! Always an argv vector (no shell) and nothing privileged can be declared. A running container
//! cannot be edited, so the agent labels what it creates with a keyed hash of everything that
//! defines it (image, ports, volumes, environment, secrets, restart policy) and recreates the
//! container when the hash differs. The hash is an HMAC under a key derived from the agent's
//! identity: the label shows in `inspect`, and it must not let anyone test guesses of a secret.
//!
//! Configuration comes from Delbert and not from the deployment:
//! - `env_from`: policy variables (the layered `vars`) as environment variables;
//! - `secret_from`: secrets as read-only files under `/run/delbert/secrets/<container>/`
//!   (tmpfs: rewritten after a reboot), bind-mounted into the container. Never environment
//!   variables, which are readable with `inspect` and in `/proc`.
//!
//! A container that exists but was not created by Delbert is never touched.
//!
//! The real engines are exercised by `tests/containers.rs` (ignored by default).

use std::{collections::BTreeMap, fs};

use anyhow::{Context, Result, bail};
use delbert_policy::{ContainerEngine, ContainerSpec, ContainerState};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;

use crate::engine::Ctx;
use crate::fsutil::{Attrs, write_atomic};
use crate::runner::Refused;
use crate::verbs::{Check, Verb};

const LABEL_MANAGED: &str = "io.bytehawks.delbert.managed";
const LABEL_HASH: &str = "io.bytehawks.delbert.hash";
fn engine(ctx: &Ctx, wanted: Option<ContainerEngine>) -> Result<&'static str> {
    let candidates: &[(&str, ContainerEngine)] = &[("podman", ContainerEngine::Podman), ("docker", ContainerEngine::Docker)];
    for (tool, kind) in candidates {
        if wanted.is_some_and(|w| w != *kind) {
            continue;
        }
        match ctx.runner.run(&[tool, "--version"]) {
            Ok(out) if out.ok() => return Ok(tool),
            Err(e) if e.downcast_ref::<Refused>().is_some() => return Err(e),
            _ => {}
        }
    }
    bail!("no container engine found (podman, docker)")
}

/// What the spec means on this host, with variables and secrets resolved.
struct Desired {
    hash: String,
    /// `K=V`, sorted.
    env: Vec<String>,
    /// (host path, container path, mode, value)
    secrets: Vec<(String, String, String, String)>,
}

fn desired(spec: &ContainerSpec, ctx: &Ctx) -> Result<Desired> {
    let mut env: BTreeMap<String, String> = spec.env.clone();
    for name in &spec.env_from {
        let value = ctx.vars.get(name).with_context(|| format!("variable '{name}' (env_from) is not defined"))?;
        env.insert(name.clone(), match value {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        });
    }
    let mut secrets = Vec::new();
    for m in &spec.secret_from {
        let value = ctx.secrets.get(&m.secret).with_context(|| format!("secret '{}' is not available", m.secret))?;
        let host = format!("{}/{}/{}", ctx.secrets_dir, spec.name, m.secret);
        secrets.push((host, m.path.clone(), m.mode.clone().unwrap_or_else(|| "0400".into()), value.clone()));
    }
    let definition = json!({
        "image": spec.image, "ports": spec.ports, "volumes": spec.volumes, "env": env,
        "secrets": secrets.iter().map(|(_, path, mode, value)| json!([path, mode, value])).collect::<Vec<_>>(),
        "restart": spec.restart.map(|r| r.as_arg()),
        "command": spec.command,
    });
    let mut mac = Hmac::<Sha256>::new_from_slice(&ctx.hash_key).expect("any key length");
    mac.update(&serde_json::to_vec(&definition)?);
    let hash: String = mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect();
    Ok(Desired { hash, env: env.into_iter().map(|(k, v)| format!("{k}={v}")).collect(), secrets })
}

/// What the engine says about the container, if it exists.
struct Existing {
    status: String,
    managed: bool,
    hash: String,
}

fn inspect(ctx: &Ctx, tool: &str, name: &str) -> Result<Option<Existing>> {
    let format = format!("{{{{.State.Status}}}}|{{{{index .Config.Labels \"{LABEL_MANAGED}\"}}}}|{{{{index .Config.Labels \"{LABEL_HASH}\"}}}}");
    let out = ctx.runner.run(&[tool, "inspect", "--format", &format, name])?;
    if !out.ok() {
        // Podman: "no such container"; Docker: "No such object".
        if out.stderr.to_lowercase().contains("no such") {
            return Ok(None);
        }
        bail!("`{tool} inspect {name}` failed: {}", out.stderr.trim().chars().take(300).collect::<String>());
    }
    let mut parts = out.stdout.trim().splitn(3, '|');
    let status = parts.next().unwrap_or_default().to_string();
    let managed = parts.next() == Some("true");
    let hash = parts.next().unwrap_or_default().to_string();
    Ok(Some(Existing { status, managed, hash }))
}

fn secret_files_drift(spec: &ContainerSpec, ctx: &Ctx, want: &Desired) -> Vec<String> {
    let mut drift = Vec::new();
    for ((host, _, _, value), m) in want.secrets.iter().zip(&spec.secret_from) {
        match fs::read(ctx.path(host)) {
            Ok(have) if have == value.as_bytes() => {}
            Ok(_) => drift.push(format!("secret file of '{}' differs", m.secret)),
            Err(_) => drift.push(format!("secret file of '{}' is missing", m.secret)),
        }
    }
    drift
}

fn write_secrets(spec: &ContainerSpec, ctx: &Ctx, want: &Desired) -> Result<()> {
    if want.secrets.is_empty() {
        return Ok(());
    }
    let dir = ctx.path(&format!("{}/{}", ctx.secrets_dir, spec.name));
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    for (host, _, mode, value) in &want.secrets {
        write_atomic(ctx, &ctx.path(host), value.as_bytes(), Attrs { owner: None, group: None, mode: Some(mode) })?;
    }
    Ok(())
}

fn create_argv(spec: &ContainerSpec, tool: &str, want: &Desired, run: bool) -> Vec<String> {
    let mut argv: Vec<String> = vec![tool.into(), if run { "run" } else { "create" }.into()];
    if run {
        argv.push("-d".into());
    }
    argv.extend(["--name".into(), spec.name.clone(), "--label".into(), format!("{LABEL_MANAGED}=true"), "--label".into(), format!("{LABEL_HASH}={}", want.hash)]);
    if let Some(r) = spec.restart {
        argv.extend(["--restart".into(), r.as_arg().into()]);
    }
    for p in &spec.ports {
        argv.extend(["-p".into(), p.clone()]);
    }
    for v in &spec.volumes {
        argv.extend(["-v".into(), v.clone()]);
    }
    for (host, path, _, _) in &want.secrets {
        // `Z`: private SELinux label, needed by Podman on Fedora/RHEL; harmless elsewhere.
        argv.extend(["-v".into(), format!("{host}:{path}:ro,Z")]);
    }
    for e in &want.env {
        argv.extend(["-e".into(), e.clone()]);
    }
    argv.push(spec.image.clone().unwrap_or_default());
    argv.extend(spec.command.iter().cloned());
    argv
}

impl Verb for ContainerSpec {
    fn check(&self, ctx: &Ctx) -> Result<Check> {
        let tool = engine(ctx, self.engine)?;
        let existing = inspect(ctx, tool, &self.name)?;
        if self.state == ContainerState::Absent {
            return Ok(if existing.is_some() { Check::Drift(vec!["present".into()]) } else { Check::Compliant });
        }
        let want = desired(self, ctx)?;
        let Some(have) = existing else { return Ok(Check::Drift(vec!["absent".into()])) };
        if !have.managed {
            bail!("container '{}' exists and was not created by Delbert", self.name);
        }
        let mut drift = Vec::new();
        if have.hash != want.hash {
            drift.push("configuration differs".to_string());
        }
        drift.extend(secret_files_drift(self, ctx, &want));
        let running = have.status == "running";
        match (self.state, running) {
            (ContainerState::Running, false) => drift.push(format!("not running ({})", have.status)),
            (ContainerState::Stopped, true) => drift.push("running".into()),
            _ => {}
        }
        Ok(if drift.is_empty() { Check::Compliant } else { Check::Drift(drift) })
    }

    fn apply(&self, ctx: &Ctx) -> Result<()> {
        let tool = engine(ctx, self.engine)?;
        let run = |args: &[&str]| -> Result<()> {
            let mut argv = vec![tool];
            argv.extend_from_slice(args);
            ctx.runner.run(&argv)?.check(&argv).map(drop)
        };
        let existing = inspect(ctx, tool, &self.name)?;
        if let Some(e) = &existing {
            if !e.managed {
                bail!("container '{}' exists and was not created by Delbert", self.name);
            }
        }
        if self.state == ContainerState::Absent {
            if existing.is_some() {
                run(&["rm", "-f", &self.name])?;
            }
            let _ = fs::remove_dir_all(ctx.path(&format!("{}/{}", ctx.secrets_dir, self.name)));
            return Ok(());
        }
        let want = desired(self, ctx)?;
        // A file replaced under a running container is a new inode that the bind mount does not
        // follow: a secret file that was missing or different means the container is recreated too.
        let files_drifted = !secret_files_drift(self, ctx, &want).is_empty();
        // Files first: a container that restarts by itself after a reboot needs them (/run is tmpfs).
        write_secrets(self, ctx, &want)?;
        let recreate = existing.as_ref().is_none_or(|e| e.hash != want.hash || files_drifted);
        if recreate {
            if existing.is_some() {
                run(&["rm", "-f", &self.name])?;
            }
            let argv = create_argv(self, tool, &want, self.state == ContainerState::Running);
            let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
            ctx.runner.run(&argv)?.check(&argv)?;
            return Ok(());
        }
        let running = existing.as_ref().is_some_and(|e| e.status == "running");
        match (self.state, running) {
            (ContainerState::Running, false) => run(&["start", &self.name])?,
            (ContainerState::Stopped, true) => run(&["stop", &self.name])?,
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::FakeRunner;
    use std::sync::Arc;

    const SPEC: &str = "    - id: app\n      container:\n        name: app\n        image: registry.example.com/app@sha256:abc\n        ports: [\"8080:80\"]\n        volumes: [\"/srv/app:/data:ro\"]\n        env: { MODE: prod }\n        env_from: [LOG_LEVEL]\n        secret_from: [{ secret: db, path: /run/secrets/db }]\n        restart: unless-stopped\n";

    fn spec(extra: &str) -> ContainerSpec {
        let yaml = format!("apiVersion: delbert/v1\nkind: Policy\nmetadata: {{ name: t, tenant: x }}\nspec:\n  secrets: [db]\n  resources:\n{SPEC}{extra}");
        delbert_policy::from_yaml(&yaml).unwrap().spec.resources.remove(0).container.unwrap()
    }

    fn setup(script: Vec<(&[&str], i32, &str)>) -> (tempfile::TempDir, Ctx, Arc<FakeRunner>) {
        let tmp = tempfile::tempdir().unwrap();
        let runner = Arc::new(FakeRunner::new(script));
        let mut ctx = Ctx::new(tmp.path().to_path_buf(), tmp.path().join("a"));
        ctx.runner = runner.clone();
        ctx.hash_key = b"agent-key".to_vec();
        ctx.vars.insert("LOG_LEVEL".into(), json!("warn"));
        ctx.secrets.insert("db".into(), "hunter2".into());
        (tmp, ctx, runner)
    }

    fn inspect_out(status: &str, hash: &str) -> String {
        format!("{status}|true|{hash}\n")
    }

    #[test]
    fn a_missing_container_is_created_with_configuration_from_delbert() {
        let (tmp, ctx, runner) = setup(vec![
            (&["podman", "--version"], 0, "podman version 5"),
            (&["podman", "inspect"], 125, "Error: no such container app"),
            (&["podman", "run"], 0, "id"),
        ]);
        let s = spec("");
        assert_eq!(s.check(&ctx).unwrap(), Check::Drift(vec!["absent".into()]));
        s.apply(&ctx).unwrap();
        let calls = runner.calls();
        let run = calls.iter().find(|c| c.starts_with("podman run")).unwrap();
        for part in ["-d", "--name app", "--restart unless-stopped", "-p 8080:80", "-v /srv/app:/data:ro", "-e LOG_LEVEL=warn", "-e MODE=prod", "registry.example.com/app@sha256:abc"] {
            assert!(run.contains(part), "{part} missing in: {run}");
        }
        assert!(run.contains(&format!("{}/run/delbert/secrets/app/db:/run/secrets/db:ro,Z", tmp.path().display())) || run.contains("/run/delbert/secrets/app/db:/run/secrets/db:ro,Z"), "{run}");
        // The secret is a file with the right mode and appears nowhere in a command line.
        let file = tmp.path().join("run/delbert/secrets/app/db");
        assert_eq!(fs::read_to_string(&file).unwrap(), "hunter2");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o400);
        }
        assert!(calls.iter().all(|c| !c.contains("hunter2")), "{calls:?}");
        assert!(run.contains("io.bytehawks.delbert.managed=true") && run.contains("io.bytehawks.delbert.hash="));
    }

    #[test]
    fn the_hash_follows_the_configuration_and_the_secret_but_never_shows_them() {
        let (_t, ctx, _) = setup(vec![]);
        let base = desired(&spec(""), &ctx).unwrap().hash;
        assert_eq!(base, desired(&spec(""), &ctx).unwrap().hash);
        let mut other = spec("");
        other.ports.push("9090:90".into());
        assert_ne!(base, desired(&other, &ctx).unwrap().hash);
        let (_t2, mut ctx2, _) = setup(vec![]);
        ctx2.secrets.insert("db".into(), "hunter3".into());
        assert_ne!(base, desired(&spec(""), &ctx2).unwrap().hash);
        let (_t3, mut ctx3, _) = setup(vec![]);
        ctx3.hash_key = b"another".to_vec();
        assert_ne!(base, desired(&spec(""), &ctx3).unwrap().hash, "keyed");
        assert!(!base.contains("hunter2"));
        // A variable that is not defined is an error, not an empty string.
        let (_t4, mut ctx4, _) = setup(vec![]);
        ctx4.vars.clear();
        assert!(desired(&spec(""), &ctx4).err().unwrap().to_string().contains("LOG_LEVEL"));
    }

    #[test]
    fn a_container_that_matches_is_left_alone_and_a_changed_one_is_recreated() {
        let (tmp, ctx, runner) = setup(vec![(&["podman", "--version"], 0, "")]);
        let s = spec("");
        let hash = desired(&s, &ctx).unwrap().hash;
        // Compliant: same hash, running, secret file in place.
        write_secrets(&s, &ctx, &desired(&s, &ctx).unwrap()).unwrap();
        let (_, ctx_ok, runner_ok) = {
            let r = Arc::new(FakeRunner::new(vec![(&["podman", "--version"], 0, ""), (&["podman", "inspect"], 0, &inspect_out("running", &hash))]));
            let mut c = Ctx::new(tmp.path().to_path_buf(), tmp.path().join("a"));
            c.runner = r.clone();
            c.hash_key = ctx.hash_key.clone();
            c.vars = ctx.vars.clone();
            c.secrets = ctx.secrets.clone();
            ((), c, r)
        };
        assert_eq!(s.check(&ctx_ok).unwrap(), Check::Compliant);
        s.apply(&ctx_ok).unwrap();
        assert!(!runner_ok.calls().iter().any(|c| c.contains(" rm ") || c.contains(" run ") || c.contains(" start ")));
        let _ = runner;

        // Another hash (the secret rotated): rm -f then run.
        let (_t, ctx2, runner2) = setup(vec![
            (&["podman", "--version"], 0, ""),
            (&["podman", "inspect"], 0, &inspect_out("running", "old-hash")),
            (&["podman", "rm"], 0, ""),
            (&["podman", "run"], 0, ""),
        ]);
        assert!(matches!(s.check(&ctx2).unwrap(), Check::Drift(d) if d.contains(&"configuration differs".to_string())));
        s.apply(&ctx2).unwrap();
        let calls = runner2.calls();
        let rm = calls.iter().position(|c| c == "podman rm -f app").expect("removed");
        let run = calls.iter().position(|c| c.starts_with("podman run")).expect("created");
        assert!(rm < run);
    }

    #[test]
    fn a_stopped_container_is_started_and_state_stopped_stops_it() {
        let s = spec("");
        let (_t, ctx, _) = setup(vec![]);
        let hash = desired(&s, &ctx).unwrap().hash;
        let (_t, ctx, runner) = setup(vec![(&["podman", "--version"], 0, ""), (&["podman", "inspect"], 0, &inspect_out("exited", &hash)), (&["podman", "start"], 0, "")]);
        write_secrets(&s, &ctx, &desired(&s, &ctx).unwrap()).unwrap();
        s.apply(&ctx).unwrap();
        assert!(runner.calls().contains(&"podman start app".to_string()));

        let mut stopped = spec("");
        stopped.state = ContainerState::Stopped;
        let (_t, ctx, runner) = setup(vec![(&["podman", "--version"], 0, ""), (&["podman", "inspect"], 0, &inspect_out("running", &hash)), (&["podman", "stop"], 0, "")]);
        write_secrets(&stopped, &ctx, &desired(&stopped, &ctx).unwrap()).unwrap();
        stopped.apply(&ctx).unwrap();
        assert!(runner.calls().contains(&"podman stop app".to_string()));
        // Created but not started when it does not exist yet.
        let (_t, ctx, runner) = setup(vec![(&["podman", "--version"], 0, ""), (&["podman", "inspect"], 125, "Error: no such container app")]);
        let r = stopped.apply(&ctx);
        let _ = r;
        assert!(runner.calls().iter().any(|c| c.starts_with("podman create")), "{:?}", runner.calls());
    }

    #[test]
    fn absent_removes_the_container_and_its_secret_files_and_foreign_containers_are_refused() {
        let mut gone = spec("");
        gone.state = ContainerState::Absent;
        let (tmp, ctx, runner) = setup(vec![(&["podman", "--version"], 0, ""), (&["podman", "inspect"], 0, &inspect_out("running", "h")), (&["podman", "rm"], 0, "")]);
        fs::create_dir_all(tmp.path().join("run/delbert/secrets/app")).unwrap();
        fs::write(tmp.path().join("run/delbert/secrets/app/db"), "x").unwrap();
        assert_eq!(gone.check(&ctx).unwrap(), Check::Drift(vec!["present".into()]));
        gone.apply(&ctx).unwrap();
        assert!(runner.calls().contains(&"podman rm -f app".to_string()));
        assert!(!tmp.path().join("run/delbert/secrets/app").exists());

        // Not ours: "false" in the managed label.
        let s = spec("");
        let (_t, ctx, runner) = setup(vec![(&["podman", "--version"], 0, ""), (&["podman", "inspect"], 0, "running||\n")]);
        assert!(s.check(&ctx).unwrap_err().to_string().contains("not created by Delbert"));
        assert!(s.apply(&ctx).is_err());
        assert!(!runner.calls().iter().any(|c| c.contains(" rm ") || c.contains(" run ")));
    }

    #[test]
    fn the_engine_is_podman_first_then_docker_and_can_be_chosen() {
        let (_t, ctx, _) = setup(vec![(&["podman", "--version"], 1, ""), (&["docker", "--version"], 0, "")]);
        assert_eq!(engine(&ctx, None).unwrap(), "docker");
        let (_t, ctx, _) = setup(vec![(&["podman", "--version"], 0, ""), (&["docker", "--version"], 0, "")]);
        assert_eq!(engine(&ctx, None).unwrap(), "podman");
        assert_eq!(engine(&ctx, Some(ContainerEngine::Docker)).unwrap(), "docker");
        let (_t, ctx, _) = setup(vec![(&["podman", "--version"], 1, ""), (&["docker", "--version"], 1, "")]);
        assert!(engine(&ctx, None).is_err());
    }
}
