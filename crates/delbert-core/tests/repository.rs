//! The repository layout of docs/REPOSITORY.md: policies, files, templates and variables per scope.

mod common;

use std::{fs, path::Path};

use axum::http::StatusCode as S;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use common::{Client, admin_client, signing_key, state};
use delbert_core::{api::ContentConfig, compile::Strategy};
use delbert_wire::{Expect, Verifier};
use serde_json::{Value, json};
use sqlx::PgPool;

fn policy(name: &str, extra_spec: &str, path: &str) -> String {
    format!("apiVersion: delbert/v1\nkind: Policy\nmetadata: {{ name: {name}, tenant: acme }}\nspec:\n{extra_spec}  resources:\n    - id: f\n      file: {{ path: {path} }}\n")
}

fn write(root: &Path, rel: &str, content: &str) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, content).unwrap();
}

fn resource_ids(token: &str, agent: &str) -> Vec<String> {
    let mut v = Verifier::default();
    v.add_key("k1", &B64.encode(signing_key().verifying_key().to_bytes())).unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let p = v.verify(token, &Expect { tenant: "acme", agent, now }, |_| None).unwrap();
    p.resources.iter().map(|r| r.id.clone()).collect()
}

async fn effective(c: &Client, agent: &str) -> Vec<String> {
    let (s, b) = c.call("GET", &format!("/v1/tenants/acme/agents/{agent}/effective"), None).await;
    assert_eq!(s, S::OK, "{b}");
    resource_ids(b["token"].as_str().unwrap(), agent)
}

async fn variables(c: &Client, agent: &str) -> Value {
    c.call("GET", &format!("/v1/tenants/acme/agents/{agent}/variables"), None).await.1["variables"].clone()
}

async fn sync(c: &Client) -> Value {
    let (s, b) = c.call("POST", "/v1/content/sources/repo/sync", None).await;
    assert_eq!(s, S::OK, "{b}");
    b
}

fn find<'a>(vars: &'a Value, name: &str) -> &'a Value {
    vars.as_array().unwrap().iter().find(|v| v["name"] == name).unwrap_or_else(|| panic!("no {name} in {vars}"))
}

#[sqlx::test]
async fn a_tenant_repository_follows_the_layout(pool: PgPool) {
    let dir = tempfile::tempdir().unwrap();
    let mut st = state(pool, vec![Strategy::Error], None);
    st.content = ContentConfig { dir: dir.path().join("content"), allow_tenant_git: false, allow_file: true, poll: false };
    let admin = admin_client(st).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    for (agent, group) in [("web01", "web"), ("db01", "db")] {
        assert_eq!(admin.call("POST", "/v1/tenants/acme/agents", Some(json!({ "name": agent, "groups": [group] }))).await.0, S::CREATED);
    }
    let top = dir.path().join("content/repo");
    let root = top.join("tenants/acme");
    write(&top, "README.md", "ignored");
    write(&root, "tenant.yaml", "approval_required: false\n");
    write(&root, "policies/tenant/base.yaml", &policy("base", "", "/etc/base"));
    write(&root, "policies/groups/web/nginx.yaml", &policy("nginx", "", "/etc/nginx"));
    write(&root, "policies/hosts/web01/special.yaml", &policy("special", "", "/etc/special"));
    write(&root, "files/tenant/motd.txt", "hello\n");
    write(&root, "templates/tenant/app.conf.j2", "level={{ vars.LOG_LEVEL }}\n");
    write(&root, "variables/tenant.yaml", "vars:\n  LOG_LEVEL: info\n  REGION: eu\nlocked: [REGION]\n");
    write(&root, "variables/groups/web.yaml", "vars:\n  LOG_LEVEL: warn\n");
    write(&root, "variables/hosts/web01.yaml", "vars:\n  PORT: 8080\n");
    let (s, b) = admin.call("POST", "/v1/content/sources", Some(json!({ "name": "repo", "kind": "directory", "location": "repo", "prune": true }))).await;
    assert_eq!(s, S::CREATED, "{b}");

    let r = sync(&admin).await;
    assert_eq!(r["status"], "applied", "{r}");
    let kinds: Vec<String> = r["changes"].as_array().unwrap().iter().map(|c| format!("{}:{}", c["kind"], c["name"])).collect();
    for expected in ["\"variable\":\"tenant/LOG_LEVEL\"", "\"variable\":\"group/web/LOG_LEVEL\"", "\"variable\":\"agent/web01/PORT\"", "\"policy\":\"nginx\"", "\"artifact\":\"app.conf.j2\"", "\"artifact\":\"motd.txt\""] {
        assert!(kinds.contains(&expected.to_string()), "{expected} not in {kinds:?}");
    }

    // The folder decides who gets a policy.
    assert_eq!(effective(&admin, "web01").await, vec!["base/f", "nginx/f", "special/f"]);
    assert_eq!(effective(&admin, "db01").await, vec!["base/f"]);

    // Variables: each scope in its place, the constant wins, and each says where it comes from.
    let web = variables(&admin, "web01").await;
    assert_eq!((find(&web, "LOG_LEVEL")["value"].clone(), find(&web, "LOG_LEVEL")["source"].clone()), (json!("warn"), json!("group:web")));
    assert_eq!(find(&web, "PORT")["source"], "agent:web01");
    assert_eq!(find(&web, "REGION")["locked"], true);
    assert_eq!(find(&variables(&admin, "db01").await, "LOG_LEVEL")["value"], "info");

    // What the repository owns cannot be edited from the API.
    let (s, b) = admin.call("PUT", "/v1/tenants/acme/variables/LOG_LEVEL?scope=group&target=web", Some(json!({ "value": "debug" }))).await;
    assert_eq!(s, S::CONFLICT, "{b}");
    assert!(b.to_string().contains("content source 'repo'"));

    // A second sync of the same revision changes nothing; a changed value is one change.
    assert_eq!(sync(&admin).await["status"], "unchanged");
    write(&root, "variables/groups/web.yaml", "vars:\n  LOG_LEVEL: error\n");
    let r = sync(&admin).await;
    assert_eq!(r["changes"].as_array().unwrap().len(), 1, "{r}");
    assert!(r["changes"][0]["diff"].as_str().unwrap().contains("-\"warn\""));
    assert_eq!(find(&variables(&admin, "web01").await, "LOG_LEVEL")["value"], "error");

    // Moving a policy to another folder moves who gets it.
    fs::remove_file(root.join("policies/groups/web/nginx.yaml")).unwrap();
    write(&root, "policies/groups/db/nginx.yaml", &policy("nginx", "", "/etc/nginx"));
    sync(&admin).await;
    assert_eq!(effective(&admin, "web01").await, vec!["base/f", "special/f"]);
    assert_eq!(effective(&admin, "db01").await, vec!["base/f", "nginx/f"]);

    // prune: a variable that left the repository is removed.
    fs::remove_file(root.join("variables/groups/web.yaml")).unwrap();
    sync(&admin).await;
    assert_eq!(find(&variables(&admin, "web01").await, "LOG_LEVEL")["source"], "tenant");
}

#[sqlx::test]
async fn a_layout_that_contradicts_itself_is_rejected_whole(pool: PgPool) {
    let dir = tempfile::tempdir().unwrap();
    let mut st = state(pool, vec![Strategy::Error], None);
    st.content = ContentConfig { dir: dir.path().join("content"), allow_tenant_git: false, allow_file: true, poll: false };
    let admin = admin_client(st).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    let root = dir.path().join("content/repo/tenants/acme");
    admin.call("POST", "/v1/content/sources", Some(json!({ "name": "repo", "kind": "directory", "location": "repo" }))).await;
    let problems = |r: &Value| r["errors"].as_array().unwrap().iter().map(|e| e.as_str().unwrap().to_string()).collect::<Vec<_>>().join("\n");

    // The folder says "web", the file says "db": one fact in two places.
    write(&root, "policies/groups/web/x.yaml", &policy("x", "  target: { groups: [db] }\n", "/etc/x"));
    // The same name in two folders.
    write(&root, "policies/tenant/dup.yaml", &policy("dup", "", "/etc/a"));
    write(&root, "policies/hosts/h1/dup.yaml", &policy("dup", "", "/etc/b"));
    // Files per group are not supported yet; a template and a file cannot share a name.
    write(&root, "files/groups/web/a.conf", "x");
    write(&root, "files/tenant/same", "1");
    write(&root, "templates/tenant/same", "2");
    // Bad variables.
    write(&root, "variables/tenant.yaml", "vars: { A: 1 }\nlocked: [missing]\n");
    write(&root, "variables/groups/web.yaml", "vars: { 1bad: x }\n");
    write(&root, "variables/elsewhere/x.yaml", "vars: {}\n");

    let r = sync(&admin).await;
    assert_eq!(r["status"], "rejected", "{r}");
    let text = problems(&r);
    for needle in ["the folder says this policy applies to groups [web]", "declared twice", "not supported yet", "invalid variable name", "not part of the layout"] {
        assert!(text.contains(needle), "{needle} missing in:\n{text}");
    }
    // Nothing was applied.
    assert_eq!(admin.call("GET", "/v1/tenants/acme/policies", None).await.1.as_array().unwrap().len(), 0);
    assert_eq!(admin.call("GET", "/v1/tenants/acme/variables", None).await.1.as_array().map_or(0, Vec::len), 0);
}

fn git(dir: &Path, args: &[&str]) {
    let ok = std::process::Command::new("git").current_dir(dir).args(["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"]).args(args).status().unwrap().success();
    assert!(ok, "git {args:?}");
}

/// A repository that belongs to one tenant keeps the tree at its root, with no `tenants/` level.
#[sqlx::test]
async fn a_repository_of_one_tenant_has_the_tree_at_its_root(pool: PgPool) {
    let dir = tempfile::tempdir().unwrap();
    let mut st = state(pool, vec![Strategy::Error], None);
    st.content = ContentConfig { dir: dir.path().join("content"), allow_tenant_git: true, allow_file: true, poll: false };
    let admin = admin_client(st).await;
    for t in ["acme", "beta"] {
        admin.call("POST", "/v1/tenants", Some(json!({ "name": t }))).await;
    }
    admin.call("POST", "/v1/tenants/acme/agents", Some(json!({ "name": "web01", "groups": ["web"] }))).await;
    let repo = dir.path().join("remote");
    fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    write(&repo, "README.md", "# template");
    write(&repo, "policies/groups/web/nginx.yaml", &policy("nginx", "", "/etc/nginx"));
    write(&repo, "variables/tenant.yaml", "vars:\n  LOG_LEVEL: info\n");
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "one"]);
    let url = format!("file://{}", repo.display());
    let (s, b) = admin.call("POST", "/v1/content/sources", Some(json!({ "name": "repo", "kind": "git", "location": url, "tenant": "acme" }))).await;
    assert_eq!(s, S::CREATED, "{b}");
    let r = sync(&admin).await;
    assert_eq!(r["status"], "applied", "{r}");
    assert_eq!(effective(&admin, "web01").await, vec!["nginx/f"]);
    assert_eq!(find(&variables(&admin, "web01").await, "LOG_LEVEL")["value"], "info");

    // It can only ever be acme's: a policy that names another tenant is refused.
    write(&repo, "policies/tenant/other.yaml", &policy("other", "", "/etc/o").replace("tenant: acme", "tenant: beta"));
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "two"]);
    let r = sync(&admin).await;
    assert_eq!(r["status"], "rejected", "{r}");
}

fn branches(repo: &Path) -> Vec<String> {
    let out = std::process::Command::new("git").current_dir(repo).args(["branch", "--list", "--format=%(refname:short)"]).output().unwrap();
    String::from_utf8_lossy(&out.stdout).lines().map(str::to_owned).collect()
}

#[sqlx::test]
async fn the_editor_commits_to_a_new_branch_and_never_to_the_tracked_one(pool: PgPool) {
    let dir = tempfile::tempdir().unwrap();
    let mut st = state(pool, vec![Strategy::Error], None);
    st.content = ContentConfig { dir: dir.path().join("content"), allow_tenant_git: true, allow_file: true, poll: false };
    let admin = admin_client(st).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    admin.call("POST", "/v1/tenants/acme/agents", Some(json!({ "name": "web01", "groups": ["web"] }))).await;
    let repo = dir.path().join("remote");
    fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    write(&repo, "policies/groups/web/nginx.yaml", &policy("nginx", "", "/etc/nginx"));
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "one"]);
    let url = format!("file://{}", repo.display());
    let create = |writable: bool| json!({ "name": "repo", "kind": "git", "location": url, "tenant": "acme", "writable": writable });
    assert_eq!(admin.call("POST", "/v1/content/sources", Some(create(false))).await.0, S::CREATED);
    sync(&admin).await;
    let base = "/v1/content/sources/repo";
    let change = |path: &str, content: &str| json!({ "changes": [{ "path": path, "content": content }] });

    // Reading needs no fetch: the tree and a file come from the mirror.
    let tree = admin.call("GET", &format!("{base}/files"), None).await.1;
    assert_eq!(tree["files"][0]["path"], "policies/groups/web/nginx.yaml");
    assert_eq!(tree["writable"], false);
    let file = admin.call("GET", &format!("{base}/file?path=policies/groups/web/nginx.yaml"), None).await.1;
    assert!(file["content"].as_str().unwrap().contains("/etc/nginx"));

    // A read-only source is not edited.
    let new_policy = policy("nginx", "", "/etc/nginx.d");
    let body = json!({ "message": "move it", "changes": [{ "path": "policies/groups/web/nginx.yaml", "content": new_policy }] });
    assert_eq!(admin.call("POST", &format!("{base}/commits"), Some(body.clone())).await.0, S::CONFLICT);
    assert_eq!(admin.call("PUT", &format!("{base}"), Some(json!({ "location": url, "writable": true }))).await.0, S::NO_CONTENT);

    // Validation tells what would break, and writes nothing.
    let bad = admin.call("POST", &format!("{base}/validate"), Some(change("policies/groups/web/nginx.yaml", &policy("nginx", "  target: { groups: [db] }\n", "/etc/x")))).await.1;
    assert_eq!(bad["ok"], false);
    assert!(bad["errors"][0].as_str().unwrap().contains("the folder says"));
    let ok = admin.call("POST", &format!("{base}/validate"), Some(change("policies/groups/web/nginx.yaml", &new_policy))).await.1;
    assert_eq!(ok["ok"], true, "{ok}");
    assert_eq!(branches(&repo), vec!["main"]);

    // Someone who may read but not edit.
    admin.call("POST", "/v1/users", Some(json!({ "username": "vera", "password": "a-long-enough-password", "assignments": [{ "role": "viewer", "tenant": "acme" }] }))).await;
    let vera = admin.as_user("vera", "a-long-enough-password").await;
    assert_eq!(vera.call("GET", &format!("{base}/files"), None).await.0, S::OK);
    assert_eq!(vera.call("POST", &format!("{base}/validate"), Some(change("a.txt", "x"))).await.0, S::FORBIDDEN);
    assert_eq!(vera.call("POST", &format!("{base}/commits"), Some(body.clone())).await.0, S::FORBIDDEN);

    // A change that breaks the repository is refused; a good one becomes a branch.
    let broken = json!({ "message": "oops", "changes": [{ "path": "policies/groups/web/nginx.yaml", "content": policy("nginx", "  target: { groups: [db] }\n", "/etc/x") }] });
    assert_eq!(admin.call("POST", &format!("{base}/commits"), Some(broken)).await.0, S::UNPROCESSABLE_ENTITY);
    let (s, out) = admin.call("POST", &format!("{base}/commits"), Some(body.clone())).await;
    assert_eq!(s, S::CREATED, "{out}");
    let branch = out["branch"].as_str().unwrap().to_owned();
    assert!(branch.starts_with("delbert/admin-"), "{branch}");
    assert_eq!(branches(&repo).len(), 2, "main untouched, one new branch: {:?}", branches(&repo));
    let main_has: String = String::from_utf8_lossy(&std::process::Command::new("git").current_dir(&repo).args(["show", "main:policies/groups/web/nginx.yaml"]).output().unwrap().stdout).into();
    assert!(main_has.contains("/etc/nginx\n") || main_has.contains("path: /etc/nginx }"), "the tracked branch must not change");
    assert!(!main_has.contains("nginx.d"));
    let log = String::from_utf8_lossy(&std::process::Command::new("git").current_dir(&repo).args(["log", "-1", "--format=%an|%s", &branch]).output().unwrap().stdout).trim().to_owned();
    assert_eq!(log, "admin|move it");
    let (_, audit) = admin.call("GET", "/v1/audit?action=content.commit", None).await;
    assert_eq!(audit["events"][0]["details"]["branch"], branch.as_str());

    // The same content again is nothing to commit.
    let same = json!({ "message": "again", "changes": [{ "path": "policies/groups/web/nginx.yaml", "content": file["content"] }] });
    assert_eq!(admin.call("POST", &format!("{base}/commits"), Some(same)).await.0, S::CONFLICT);

    // Review happens in the forge; once merged, the sync applies it.
    assert_eq!(effective(&admin, "web01").await, vec!["nginx/f"]);
    git(&repo, &["merge", "-q", "--ff-only", &branch]);
    let r = sync(&admin).await;
    assert_eq!(r["status"], "applied", "{r}");
    assert!(r["changes"][0]["diff"].as_str().unwrap().contains("nginx.d"));
}

#[sqlx::test]
async fn a_directory_source_is_edited_in_place(pool: PgPool) {
    let dir = tempfile::tempdir().unwrap();
    let mut st = state(pool, vec![Strategy::Error], None);
    st.content = ContentConfig { dir: dir.path().join("content"), allow_tenant_git: false, allow_file: true, poll: false };
    let admin = admin_client(st).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    let root = dir.path().join("content/repo");
    write(&root, "tenants/acme/policies/tenant/base.yaml", &policy("base", "", "/etc/base"));
    admin.call("POST", "/v1/content/sources", Some(json!({ "name": "repo", "kind": "directory", "location": "repo", "writable": true }))).await;
    sync(&admin).await;
    let body = json!({ "message": "add", "changes": [
        { "path": "tenants/acme/variables/tenant.yaml", "content": "vars:\n  A: 1\n" },
        { "path": "tenants/acme/policies/tenant/base.yaml", "delete": true },
    ] });
    let (s, out) = admin.call("POST", "/v1/content/sources/repo/commits", Some(body)).await;
    assert_eq!(s, S::CREATED, "{out}");
    assert_eq!(out["branch"], Value::Null);
    assert_eq!(out["files"], 2);
    assert!(root.join("tenants/acme/variables/tenant.yaml").exists() && !root.join("tenants/acme/policies/tenant/base.yaml").exists());
    // Paths that leave the tree are refused.
    for path in ["../x", "tenants/../../x", ".git/config", "/etc/passwd"] {
        let r = admin.call("POST", "/v1/content/sources/repo/commits", Some(json!({ "message": "x", "changes": [{ "path": path, "content": "x" }] }))).await;
        assert_eq!(r.0, S::UNPROCESSABLE_ENTITY, "{path}");
    }
    assert_eq!(sync(&admin).await["status"], "applied");
}

fn copy_tree(from: &Path, to: &Path) {
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            fs::create_dir_all(&target).unwrap();
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// The template shipped in deploy/repository-template is itself valid: it syncs without a single complaint,
/// and once its examples are activated they become what they say.
#[sqlx::test]
async fn the_template_repository_is_valid(pool: PgPool) {
    let dir = tempfile::tempdir().unwrap();
    let mut st = state(pool, vec![Strategy::Error], None);
    st.content = ContentConfig { dir: dir.path().join("content"), allow_tenant_git: false, allow_file: true, poll: false };
    let admin = admin_client(st).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    let root = dir.path().join("content/repo/tenants/acme");
    fs::create_dir_all(&root).unwrap();
    copy_tree(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/repository-template"), &root);
    admin.call("POST", "/v1/content/sources", Some(json!({ "name": "repo", "kind": "directory", "location": "repo" }))).await;
    let r = sync(&admin).await;
    assert_eq!(r["status"], "unchanged", "an unmodified template has nothing to apply: {r}");

    // Activate the examples.
    fs::rename(root.join("variables/tenant.yaml.example"), root.join("variables/tenant.yaml")).unwrap();
    fs::rename(root.join("files/tenant/motd.txt.example"), root.join("files/tenant/motd.txt")).unwrap();
    let policy = fs::read_to_string(root.join("policies/tenant/baseline.yaml.example")).unwrap().replace("tenant: example", "tenant: acme");
    fs::write(root.join("policies/tenant/baseline.yaml"), policy).unwrap();
    let r = sync(&admin).await;
    assert_eq!(r["status"], "applied", "{r}");
    assert_eq!(r["changes"].as_array().unwrap().len(), 4, "{r}");
}
