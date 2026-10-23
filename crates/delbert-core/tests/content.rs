//! Content sources: directory and git (file:// remote), validation, diffs, ownership, scoping.

mod common;

use std::{fs, path::Path, process::Command};

use axum::http::StatusCode as S;
use common::{Client, admin_client, state};
use delbert_core::{api::ContentConfig, compile::Strategy};
use serde_json::{Value, json};
use sqlx::PgPool;

const PW: &str = "a-long-enough-password";

fn policy(name: &str, tenant: &str, path: &str) -> String {
    format!("apiVersion: delbert/v1\nkind: Policy\nmetadata: {{ name: {name}, tenant: {tenant} }}\nspec:\n  resources:\n    - id: f\n      file: {{ path: {path} }}\n")
}

fn write(root: &Path, rel: &str, content: &str) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, content).unwrap();
}

fn git(dir: &Path, args: &[&str]) {
    let ok = Command::new("git").current_dir(dir).args(["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"]).args(args).status().unwrap().success();
    assert!(ok, "git {args:?}");
}

async fn setup(pool: PgPool, tenant_git: bool) -> (Client, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut st = state(pool, vec![Strategy::Error], None);
    st.content = ContentConfig { dir: dir.path().join("content"), allow_tenant_git: tenant_git, allow_file: true, poll: false };
    let admin = admin_client(st).await;
    for t in ["acme", "beta"] {
        assert_eq!(admin.call("POST", "/v1/tenants", Some(json!({ "name": t }))).await.0, S::CREATED);
    }
    (admin, dir)
}

async fn sync(c: &Client, source: &str) -> Value {
    let (s, b) = c.call("POST", &format!("/v1/content/sources/{source}/sync"), None).await;
    assert_eq!(s, S::OK, "{b}");
    b
}

#[sqlx::test]
async fn directory_source_validates_diffs_applies_and_owns(pool: PgPool) {
    let (admin, dir) = setup(pool, false).await;
    let root = dir.path().join("content/main");
    write(&root, "README.md", "ignored");
    write(&root, "tenants/acme/policies/web.yaml", &policy("web", "acme", "/etc/one"));
    write(&root, "tenants/acme/artifacts/motd.txt", "hello\n");
    let (s, src) = admin.call("POST", "/v1/content/sources", Some(json!({ "name": "main", "kind": "directory", "location": "main" }))).await;
    assert_eq!(s, S::CREATED, "{src}");

    // First sync: the artifact then the policy, with diffs; the policy is live.
    let r = sync(&admin, "main").await;
    assert_eq!(r["status"], "applied");
    let changes = r["changes"].as_array().unwrap();
    assert_eq!(changes.len(), 2);
    assert!(changes.iter().any(|c| c["kind"] == "artifact" && c["name"] == "motd.txt" && c["change"] == "added" && c["diff"].as_str().unwrap().contains("+hello")));
    assert!(changes.iter().any(|c| c["kind"] == "policy" && c["name"] == "web" && c["version"] == 1));
    assert_eq!(admin.call("GET", "/v1/tenants/acme/policies", None).await.1[0]["active_version"], 1);
    assert_eq!(sync(&admin, "main").await["status"], "unchanged");

    // The API will not fight the repository.
    let upload = json!({ "yaml": policy("web", "acme", "/etc/hand") });
    let (s, b) = admin.call("POST", "/v1/tenants/acme/policies", Some(upload)).await;
    assert_eq!(s, S::CONFLICT, "{b}");
    assert!(b["error"].as_str().unwrap().contains("managed by content source 'main'"));
    assert_eq!(admin.call("DELETE", "/v1/tenants/acme/policies/web", None).await.0, S::CONFLICT);
    assert_eq!(admin.raw("PUT", "/v1/tenants/acme/artifacts/motd.txt", vec![("content-type", "application/octet-stream".into())], b"x".to_vec()).await.0, S::CONFLICT);

    // A change becomes a new version with a unified diff.
    write(&root, "tenants/acme/policies/web.yaml", &policy("web", "acme", "/etc/two"));
    let r = sync(&admin, "main").await;
    assert_eq!(r["changes"][0]["change"], "changed");
    assert_eq!(r["changes"][0]["version"], 2);
    let diff = r["changes"][0]["diff"].as_str().unwrap();
    assert!(diff.contains("-      file: { path: /etc/one }") && diff.contains("+      file: { path: /etc/two }"), "{diff}");

    // One bad item rejects the whole snapshot: even the good change next to it is not applied.
    write(&root, "tenants/acme/policies/web.yaml", &policy("web", "acme", "/etc/three"));
    write(&root, "tenants/acme/policies/broken.yaml", "this: is: not a policy");
    write(&root, "tenants/acme/policies/wrongname.yaml", &policy("other", "acme", "/etc/x"));
    write(&root, "tenants/ghost/policies/p.yaml", &policy("p", "ghost", "/etc/x"));
    write(&root, "tenants/acme/surprise.txt", "no");
    let r = sync(&admin, "main").await;
    assert_eq!(r["status"], "rejected");
    let errors = r["errors"].as_array().unwrap().iter().map(|e| e.as_str().unwrap().to_owned()).collect::<Vec<_>>().join("\n");
    for needle in ["broken.yaml", "wrongname.yaml", "tenants/ghost", "surprise.txt"] {
        assert!(errors.contains(needle), "{needle} in {errors}");
    }
    assert_eq!(admin.call("GET", "/v1/tenants/acme/policies", None).await.1[0]["active_version"], 2);
    assert_eq!(sync(&admin, "main").await["snapshot"], Value::Null); // the same rejection is not recorded twice
    let (_, src) = admin.call("GET", "/v1/content/sources/main", None).await;
    assert!(src["last_error"].as_str().unwrap().contains("rejected"));

    // Fix it; removals are reported but kept until `prune` is on.
    for f in ["policies/broken.yaml", "policies/wrongname.yaml", "surprise.txt"] {
        fs::remove_file(root.join("tenants/acme").join(f)).unwrap();
    }
    fs::remove_dir_all(root.join("tenants/ghost")).unwrap();
    fs::remove_file(root.join("tenants/acme/artifacts/motd.txt")).unwrap();
    let r = sync(&admin, "main").await;
    assert_eq!(r["status"], "applied", "{r}");
    let removed = r["changes"].as_array().unwrap().iter().find(|c| c["change"] == "removed").unwrap();
    assert_eq!((removed["name"].clone(), removed["applied"].clone()), (json!("motd.txt"), json!(false)));
    assert_eq!(admin.call("GET", "/v1/tenants/acme/policies", None).await.1[0]["active_version"], 3);

    // History: snapshots with their changes and diffs.
    let (_, snaps) = admin.call("GET", "/v1/content/sources/main/snapshots", None).await;
    assert_eq!(snaps.as_array().unwrap().len(), 4); // applied, applied, rejected, applied
    let id = snaps[0]["id"].as_i64().unwrap();
    let (_, detail) = admin.call("GET", &format!("/v1/content/sources/main/snapshots/{id}"), None).await;
    assert!(detail["changes"].as_array().unwrap().len() >= 2);

    // Pruning deactivates a policy whose file is gone.
    fs::remove_file(root.join("tenants/acme/policies/web.yaml")).unwrap();
    assert_eq!(admin.call("PUT", "/v1/content/sources/main", Some(json!({ "location": "main", "prune": true }))).await.0, S::NO_CONTENT);
    let r = sync(&admin, "main").await;
    assert!(r["changes"].as_array().unwrap().iter().any(|c| c["name"] == "web" && c["change"] == "removed" && c["applied"] == true));
    assert_eq!(admin.call("GET", "/v1/tenants/acme/policies", None).await.1[0]["active"], false);
    assert_eq!(admin.call("GET", "/v1/audit/verify", None).await.1["first_bad"], Value::Null);
}

#[sqlx::test]
async fn git_source_follows_a_branch_and_refuses_unsafe_content(pool: PgPool) {
    let (admin, dir) = setup(pool, false).await;
    let repo = dir.path().join("remote");
    fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    write(&repo, "config/tenants/acme/policies/web.yaml", &policy("web", "acme", "/etc/one"));
    write(&repo, "other/ignored.txt", "x");
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "one"]);

    let url = format!("file://{}", repo.display());
    let bad = |loc: &str, branch: &str, subdir: &str| json!({ "name": "g", "kind": "git", "location": loc, "branch": branch, "subdir": subdir });
    assert_eq!(admin.call("POST", "/v1/content/sources", Some(bad("ssh://git@example.com/x.git", "main", ""))).await.0, S::UNPROCESSABLE_ENTITY);
    assert_eq!(admin.call("POST", "/v1/content/sources", Some(bad("-u/tmp/x", "main", ""))).await.0, S::UNPROCESSABLE_ENTITY);
    assert_eq!(admin.call("POST", "/v1/content/sources", Some(bad(&url, "--upload-pack=x", ""))).await.0, S::UNPROCESSABLE_ENTITY);
    assert_eq!(admin.call("POST", "/v1/content/sources", Some(bad(&url, "main", "../etc"))).await.0, S::UNPROCESSABLE_ENTITY);
    assert_eq!(admin.call("POST", "/v1/content/sources", Some(bad(&url, "main", "config"))).await.0, S::CREATED);

    let r = sync(&admin, "g").await;
    assert_eq!(r["status"], "applied", "{r}");
    assert_eq!(r["revision"].as_str().unwrap().len(), 40);
    assert_eq!(sync(&admin, "g").await["status"], "unchanged");

    // A new commit is picked up; the diff is the commit's.
    write(&repo, "config/tenants/acme/policies/web.yaml", &policy("web", "acme", "/etc/two"));
    git(&repo, &["commit", "-q", "-am", "two"]);
    let r = sync(&admin, "g").await;
    assert_eq!(r["changes"][0]["version"], 2);
    assert!(r["changes"][0]["diff"].as_str().unwrap().contains("+      file: { path: /etc/two }"));

    // A symbolic link in the repository is refused outright (it could point anywhere on the Core's disk).
    std::os::unix::fs::symlink("/etc/passwd", repo.join("config/tenants/acme/policies/leak.yaml")).unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "link"]);
    let (s, b) = admin.call("POST", "/v1/content/sources/g/sync", None).await;
    assert_eq!(s, S::BAD_GATEWAY, "{b}");
    assert!(b["error"].as_str().unwrap().contains("link"));
    // An unreachable remote is an error, not a crash, and is remembered.
    fs::remove_dir_all(&repo).unwrap();
    assert_eq!(admin.call("POST", "/v1/content/sources/g/sync", None).await.0, S::BAD_GATEWAY);
    assert!(admin.call("GET", "/v1/content/sources/g", None).await.1["last_error"].as_str().unwrap().contains("git fetch failed"));
}

#[sqlx::test]
async fn scoping_tenant_owned_sources_and_competing_owners(pool: PgPool) {
    let (admin, dir) = setup(pool, true).await;
    let make = |name: &str, role: &str, tenant: Option<&str>| {
        let admin = admin.clone();
        let (name, role, tenant) = (name.to_owned(), role.to_owned(), tenant.map(str::to_owned));
        async move {
            admin.call("POST", "/v1/users", Some(json!({ "username": name, "password": PW, "assignments": [{ "role": role, "tenant": tenant }] }))).await;
            admin.as_user(&name, PW).await
        }
    };
    let tina = make("tina", "tenant-admin", Some("acme")).await;
    let olivia = make("olivia", "operator", Some("acme")).await;
    let outsider = make("outsider", "tenant-admin", Some("beta")).await;

    let repo = dir.path().join("remote");
    fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    write(&repo, "tenants/acme/policies/web.yaml", &policy("web", "acme", "/etc/one"));
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "one"]);
    let url = format!("file://{}", repo.display());

    // A tenant may not read the Core's disk; its own git source works only where enabled and only for itself.
    let dirsrc = json!({ "name": "d", "kind": "directory", "location": "d", "tenant": "acme" });
    assert_eq!(tina.call("POST", "/v1/content/sources", Some(dirsrc)).await.0, S::UNPROCESSABLE_ENTITY);
    assert_eq!(olivia.call("POST", "/v1/content/sources", Some(json!({ "name": "o", "kind": "git", "location": url, "tenant": "acme" }))).await.0, S::FORBIDDEN);
    assert_eq!(tina.call("POST", "/v1/content/sources", Some(json!({ "name": "g", "kind": "git", "location": url, "tenant": "beta" }))).await.0, S::NOT_FOUND);
    assert_eq!(tina.call("POST", "/v1/content/sources", Some(json!({ "name": "g", "kind": "git", "location": url }))).await.0, S::FORBIDDEN); // platform source
    assert_eq!(tina.call("POST", "/v1/content/sources", Some(json!({ "name": "g", "kind": "git", "location": url, "tenant": "acme" }))).await.0, S::CREATED);

    // Visibility: the owner's team sees it, another tenant does not.
    assert_eq!(olivia.call("GET", "/v1/content/sources", None).await.1.as_array().unwrap().len(), 1);
    assert_eq!(outsider.call("GET", "/v1/content/sources", None).await.1.as_array().unwrap().len(), 0);
    assert_eq!(outsider.call("GET", "/v1/content/sources/g", None).await.0, S::NOT_FOUND);
    assert_eq!(olivia.call("PUT", "/v1/content/sources/g", Some(json!({ "location": url, "prune": true }))).await.0, S::FORBIDDEN);
    assert_eq!(olivia.call("POST", "/v1/content/sources/g/sync", None).await.1["status"], "applied"); // operators may sync

    // A tenant-owned source cannot reach other tenants' directories.
    write(&repo, "tenants/beta/policies/p.yaml", &policy("p", "beta", "/etc/x"));
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "other tenant"]);
    let r = sync(&tina, "g").await;
    assert_eq!(r["status"], "rejected");
    assert!(r["errors"][0].as_str().unwrap().contains("may only contain tenant 'acme'"));

    // Two sources cannot own the same item.
    write(&dir.path().join("content/d"), "tenants/acme/policies/web.yaml", &policy("web", "acme", "/etc/dup"));
    assert_eq!(admin.call("POST", "/v1/content/sources", Some(json!({ "name": "d", "kind": "directory", "location": "d" }))).await.0, S::CREATED);
    let r = sync(&admin, "d").await;
    assert_eq!(r["status"], "rejected");
    assert!(r["errors"][0].as_str().unwrap().contains("already managed by source 'g'"));

    // Deleting a source releases its items.
    assert_eq!(tina.call("DELETE", "/v1/content/sources/g", None).await.0, S::NO_CONTENT);
    assert_eq!(sync(&admin, "d").await["status"], "applied");
}

/// Against a real git server (Forgejo) with an access token, when `GIT_TEST_URL`, `GIT_TEST_USER`
/// and `GIT_TEST_TOKEN` point at a private repository whose `main` holds `tenants/acme/policies/web.yaml`.
#[sqlx::test]
async fn private_https_remote_with_a_token(pool: PgPool) {
    let (Ok(url), Ok(user), Ok(token)) = (std::env::var("GIT_TEST_URL"), std::env::var("GIT_TEST_USER"), std::env::var("GIT_TEST_TOKEN")) else {
        eprintln!("GIT_TEST_* not set: skipping");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let mut st = state(pool, vec![Strategy::Error], None);
    st.auth.cookie_secure = false; // the test server speaks plain HTTP
    st.content = ContentConfig { dir: dir.path().join("content"), allow_tenant_git: false, allow_file: false, poll: false };
    let admin = admin_client(st).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;

    // Without the token the private repository is out of reach and nothing leaks.
    assert_eq!(admin.call("POST", "/v1/content/sources", Some(json!({ "name": "g", "kind": "git", "location": url }))).await.0, S::CREATED);
    let (s, b) = admin.call("POST", "/v1/content/sources/g/sync", None).await;
    assert_eq!(s, S::BAD_GATEWAY, "{b}");
    // With it the sync works, and the token is stored sealed and never shown.
    assert_eq!(admin.call("PUT", "/v1/content/sources/g", Some(json!({ "location": url, "auth_user": user, "auth_token": token }))).await.0, S::NO_CONTENT);
    let (_, src) = admin.call("GET", "/v1/content/sources/g", None).await;
    assert_eq!(src["has_token"], true);
    assert!(!src.to_string().contains(&token));
    let r = sync(&admin, "g").await;
    assert_eq!(r["status"], "applied", "{r}");
    assert_eq!(r["changes"][0]["name"], "web");
    let (_, trail) = admin.call("GET", "/v1/audit?limit=1000", None).await;
    assert!(!trail.to_string().contains(&token));
}
