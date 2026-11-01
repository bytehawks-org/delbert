//! The `container` verb against a real engine. Ignored by default: set DELBERT_TEST_PODMAN=1
//! (needs `podman` and a local `docker.io/library/debian:13-slim`; runs rootless, touches only
//! containers named `delbert-test-*` and a temporary secrets directory).

use delbert_agent::{engine::Ctx, verbs::{Check, Verb}};
use delbert_policy::ContainerSpec;

fn podman(args: &[&str]) -> String {
    let out = std::process::Command::new("podman").args(args).output().expect("podman");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn spec(name: &str, state: &str) -> ContainerSpec {
    let yaml = format!(
        "apiVersion: delbert/v1\nkind: Policy\nmetadata: {{ name: t, tenant: x }}\nspec:\n  secrets: [db]\n  resources:\n    - id: c\n      container:\n        name: {name}\n        image: docker.io/library/debian:13-slim\n        state: {state}\n        env_from: [LOG_LEVEL]\n        env: {{ MODE: prod }}\n        secret_from: [{{ secret: db, path: /run/secrets/db }}]\n        command: [sleep, \"300\"]\n"
    );
    delbert_policy::from_yaml(&yaml).unwrap().spec.resources.remove(0).container.unwrap()
}

#[test]
#[ignore = "needs podman: set DELBERT_TEST_PODMAN=1 and run with --ignored"]
fn a_real_container_follows_delbert_configuration() {
    if std::env::var("DELBERT_TEST_PODMAN").is_err() {
        eprintln!("DELBERT_TEST_PODMAN not set: skipping");
        return;
    }
    let name = format!("delbert-test-{}", std::process::id());
    let secrets = tempfile::tempdir().unwrap();
    let mut ctx = Ctx::new("/".into(), "/nonexistent".into());
    ctx.secrets_dir = secrets.path().display().to_string();
    ctx.hash_key = b"test-key".to_vec();
    ctx.vars.insert("LOG_LEVEL".into(), serde_json::json!("warn"));
    ctx.secrets.insert("db".into(), "hunter2".into());
    let running = spec(&name, "running");
    let cleanup = scopeguard(name.clone());

    // Created from Delbert's configuration.
    assert!(matches!(running.check(&ctx).unwrap(), Check::Drift(_)));
    running.apply(&ctx).unwrap();
    assert_eq!(running.check(&ctx).unwrap(), Check::Compliant);
    assert_eq!(podman(&["inspect", "--format", "{{.State.Status}}", &name]), "running");
    assert_eq!(podman(&["exec", &name, "printenv", "LOG_LEVEL"]), "warn");
    assert_eq!(podman(&["exec", &name, "cat", "/run/secrets/db"]), "hunter2");
    assert!(!podman(&["inspect", &name]).contains("hunter2"), "a secret must not show in inspect");
    let id = podman(&["inspect", "--format", "{{.Id}}", &name]);

    // A variable changes: recreated.
    ctx.vars.insert("LOG_LEVEL".into(), serde_json::json!("debug"));
    assert!(matches!(running.check(&ctx).unwrap(), Check::Drift(d) if d.iter().any(|x| x.contains("configuration"))));
    running.apply(&ctx).unwrap();
    assert_ne!(podman(&["inspect", "--format", "{{.Id}}", &name]), id);
    assert_eq!(podman(&["exec", &name, "printenv", "LOG_LEVEL"]), "debug");

    // The secret rotates: recreated, and the container reads the new value.
    ctx.secrets.insert("db".into(), "hunter3".into());
    running.apply(&ctx).unwrap();
    assert_eq!(podman(&["exec", &name, "cat", "/run/secrets/db"]), "hunter3");

    // The secret file vanishes (a reboot clears /run): noticed, and the container follows.
    std::fs::remove_dir_all(secrets.path().join(&name)).unwrap();
    assert!(matches!(running.check(&ctx).unwrap(), Check::Drift(d) if d.iter().any(|x| x.contains("missing"))));
    running.apply(&ctx).unwrap();
    assert_eq!(running.check(&ctx).unwrap(), Check::Compliant);
    assert_eq!(podman(&["exec", &name, "cat", "/run/secrets/db"]), "hunter3");

    // Stopped, then removed with its secret files.
    spec(&name, "stopped").apply(&ctx).unwrap();
    assert_eq!(podman(&["inspect", "--format", "{{.State.Status}}", &name]), "exited");
    spec(&name, "absent").apply(&ctx).unwrap();
    assert!(podman(&["ps", "-a", "--filter", &format!("name={name}"), "--format", "{{.Names}}"]).is_empty());
    assert!(!secrets.path().join(&name).exists());
    drop(cleanup);
}

/// Removes the container even if an assertion fails.
struct Cleanup(String);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::process::Command::new("podman").args(["rm", "-f", &self.0]).output();
    }
}
fn scopeguard(name: String) -> Cleanup {
    Cleanup(name)
}
