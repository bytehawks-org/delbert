//! Policy lifecycle: optional four-eyes approval per tenant (docs/RBAC.md).

mod common;

use axum::http::StatusCode as S;
use common::{Client, admin_client, state};
use delbert_core::compile::Strategy;
use serde_json::{Value, json};
use sqlx::PgPool;

const PASSWORD: &str = "a-long-enough-password";

fn policy(file: &str) -> Value {
    json!({ "yaml": format!("apiVersion: delbert/v1\nkind: Policy\nmetadata: {{ name: p, tenant: acme }}\nspec:\n  resources:\n    - id: m\n      file: {{ path: {file} }}\n") })
}

async fn user(admin: &Client, name: &str, role: &str) -> Client {
    let a = json!([{ "role": role, "tenant": "acme" }]);
    assert_eq!(admin.call("POST", "/v1/users", Some(json!({ "username": name, "password": PASSWORD, "assignments": a }))).await.0, S::CREATED);
    admin.as_user(name, PASSWORD).await
}

async fn effective_path(c: &Client) -> Option<String> {
    let (s, b) = c.call("GET", "/v1/tenants/acme/agents/agent-1/effective", None).await;
    assert_eq!(s, S::OK, "{b}");
    let token = b["token"].as_str().unwrap();
    let payload = token.split('.').nth(1).unwrap();
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    let v: Value = serde_json::from_slice(&B64.decode(payload).unwrap()).unwrap();
    v["resources"].as_array().and_then(|r| r.first()).and_then(|r| r["file"]["path"].as_str().map(str::to_owned))
}

fn url(version: i64, step: &str) -> String {
    format!("/v1/tenants/acme/policies/p/versions/{version}/{step}")
}

#[sqlx::test]
async fn without_approval_versions_go_live_and_can_roll_back(pool: PgPool) {
    let admin = admin_client(state(pool, vec![Strategy::Error], None)).await;
    assert_eq!(admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await.0, S::CREATED);
    assert_eq!(admin.call("POST", "/v1/tenants/acme/agents", Some(json!({ "name": "agent-1" }))).await.0, S::CREATED);

    let (_, v1) = admin.call("POST", "/v1/tenants/acme/policies", Some(policy("/etc/one"))).await;
    assert_eq!(v1["live"], true);
    admin.call("POST", "/v1/tenants/acme/policies", Some(policy("/etc/two"))).await;
    assert_eq!(effective_path(&admin).await.as_deref(), Some("/etc/two"));

    // Submitting makes no sense here; rolling back to an older version does.
    assert_eq!(admin.call("POST", &url(2, "submit"), None).await.0, S::CONFLICT);
    assert_eq!(admin.call("POST", &url(2, "rollback"), None).await.0, S::CONFLICT);
    assert_eq!(admin.call("POST", &url(1, "rollback"), Some(json!({ "comment": "bad change" }))).await.0, S::NO_CONTENT);
    assert_eq!(effective_path(&admin).await.as_deref(), Some("/etc/one"));
    let (_, versions) = admin.call("GET", "/v1/tenants/acme/policies/p/versions", None).await;
    assert_eq!(versions[1]["active"], true);
    let (_, detail) = admin.call("GET", "/v1/tenants/acme/policies/p/versions/1", None).await;
    assert_eq!(detail["events"].as_array().unwrap().last().unwrap()["event"], "rolled_back");
    assert_eq!(detail["approval_required"], false);
}

#[sqlx::test]
async fn four_eyes_approval_gates_activation(pool: PgPool) {
    let admin = admin_client(state(pool, vec![Strategy::Error], None)).await;
    assert_eq!(admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await.0, S::CREATED);
    assert_eq!(admin.call("POST", "/v1/tenants/acme/agents", Some(json!({ "name": "agent-1" }))).await.0, S::CREATED);
    let (_, v) = admin.call("POST", "/v1/tenants/acme/policies", Some(policy("/etc/one"))).await;
    assert_eq!(v["version"], 1);
    let olivia = user(&admin, "olivia", "operator").await;
    let ann = user(&admin, "ann", "approver").await;
    let tina = user(&admin, "tina", "tenant-admin").await;

    // Switching the control on: a tenant-admin may, nobody weakens it but the platform.
    assert_eq!(tina.call("PUT", "/v1/tenants/acme/settings", Some(json!({ "approval_required": true }))).await.0, S::NO_CONTENT);
    assert_eq!(effective_path(&admin).await.as_deref(), Some("/etc/one")); // already live: untouched

    // A new version is a draft: not live until submitted, approved by someone else, activated.
    let (_, v2) = olivia.call("POST", "/v1/tenants/acme/policies", Some(policy("/etc/two"))).await;
    assert_eq!((v2["version"].clone(), v2["live"].clone()), (json!(2), json!(false)));
    assert_eq!(effective_path(&admin).await.as_deref(), Some("/etc/one"));
    assert_eq!(olivia.call("POST", &url(2, "approve"), None).await.0, S::FORBIDDEN); // no permission
    assert_eq!(ann.call("POST", &url(2, "approve"), None).await.0, S::CONFLICT); // not submitted
    assert_eq!(olivia.call("POST", &url(2, "activate"), None).await.0, S::CONFLICT); // not approved
    assert_eq!(olivia.call("POST", &url(2, "submit"), None).await.0, S::NO_CONTENT);
    assert_eq!(ann.call("POST", &url(2, "reject"), None).await.0, S::UNPROCESSABLE_ENTITY); // reason needed

    // The author and the submitter cannot review, administrators included.
    assert_eq!(tina.call("POST", &url(2, "approve"), None).await.0, S::NO_CONTENT); // tina is neither
    let (_, v3) = tina.call("POST", "/v1/tenants/acme/policies", Some(policy("/etc/three"))).await;
    assert_eq!(v3["version"], 3);
    assert_eq!(tina.call("POST", &url(3, "submit"), None).await.0, S::NO_CONTENT);
    assert_eq!(tina.call("POST", &url(3, "approve"), None).await.0, S::FORBIDDEN);
    assert_eq!(admin.call("POST", &url(3, "approve"), None).await.0, S::NO_CONTENT); // another person is fine
    assert_eq!(ann.call("POST", &url(3, "approve"), None).await.0, S::CONFLICT); // already approved

    // Approved version 2 goes live on activation; version 3 follows; a rollback needs an approver.
    assert_eq!(olivia.call("POST", &url(2, "activate"), None).await.0, S::NO_CONTENT);
    assert_eq!(effective_path(&admin).await.as_deref(), Some("/etc/two"));
    assert_eq!(olivia.call("POST", &url(3, "activate"), None).await.0, S::NO_CONTENT);
    assert_eq!(effective_path(&admin).await.as_deref(), Some("/etc/three"));
    assert_eq!(olivia.call("POST", &url(2, "rollback"), None).await.0, S::FORBIDDEN);
    assert_eq!(ann.call("POST", &url(1, "rollback"), None).await.0, S::CONFLICT); // v1 was never approved
    assert_eq!(ann.call("POST", &url(2, "rollback"), None).await.0, S::NO_CONTENT);
    assert_eq!(effective_path(&admin).await.as_deref(), Some("/etc/two"));

    // A rejected version can be fixed and resubmitted; it never goes live meanwhile.
    olivia.call("POST", "/v1/tenants/acme/policies", Some(policy("/etc/four"))).await;
    olivia.call("POST", &url(4, "submit"), None).await;
    assert_eq!(ann.call("POST", &url(4, "reject"), Some(json!({ "comment": "wrong path" }))).await.0, S::NO_CONTENT);
    assert_eq!(olivia.call("POST", &url(4, "activate"), None).await.0, S::CONFLICT);
    assert_eq!(olivia.call("POST", &url(4, "submit"), None).await.0, S::NO_CONTENT);

    // The control cannot be weakened while versions wait, nor by a tenant administrator.
    assert_eq!(tina.call("PUT", "/v1/tenants/acme/settings", Some(json!({ "approval_required": false }))).await.0, S::FORBIDDEN);
    assert_eq!(admin.call("PUT", "/v1/tenants/acme/settings", Some(json!({ "approval_required": false }))).await.0, S::CONFLICT);
    assert_eq!(ann.call("POST", &url(4, "approve"), None).await.0, S::NO_CONTENT);
    assert_eq!(admin.call("PUT", "/v1/tenants/acme/settings", Some(json!({ "approval_required": false }))).await.0, S::NO_CONTENT);

    // Every step is in the audit trail, which stays consistent.
    let (_, chain) = admin.call("GET", "/v1/audit/verify", None).await;
    assert_eq!(chain["first_bad"], Value::Null);
}

#[sqlx::test]
async fn dry_run_validation_checks_without_storing_or_auditing(pool: PgPool) {
    let admin = admin_client(state(pool, vec![Strategy::Error], None)).await;
    assert_eq!(admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await.0, S::CREATED);
    let (_, before) = admin.call("GET", "/v1/audit/verify", None).await;

    let (s, ok) = admin.call("POST", "/v1/tenants/acme/policies/validate", Some(policy("/etc/one"))).await;
    assert_eq!((s, ok["name"].as_str(), ok["next_version"].as_i64(), ok["approval_required"].as_bool()), (S::OK, Some("p"), Some(1), Some(false)));

    // Nothing was stored, and the dry run left no audit event.
    assert_eq!(admin.call("GET", "/v1/tenants/acme/policies", None).await.1, json!([]));
    assert_eq!(admin.call("GET", "/v1/audit/verify", None).await.1["events"], before["events"]);

    // Same errors as a save; the version counter follows the stored versions.
    assert_eq!(admin.call("POST", "/v1/tenants/acme/policies/validate", Some(json!({ "yaml": "nonsense: [" }))).await.0, S::UNPROCESSABLE_ENTITY);
    admin.call("POST", "/v1/tenants/acme/policies", Some(policy("/etc/one"))).await;
    assert_eq!(admin.call("POST", "/v1/tenants/acme/policies/validate", Some(policy("/etc/two"))).await.1["next_version"], 2);

    // A viewer cannot use it (it needs `policies:write`).
    let viewer = user(&admin, "vera", "viewer").await;
    assert_eq!(viewer.call("POST", "/v1/tenants/acme/policies/validate", Some(policy("/etc/two"))).await.0, S::FORBIDDEN);
}

#[sqlx::test]
async fn a_policy_that_was_never_activated_can_be_listed(pool: PgPool) {
    let admin = admin_client(state(pool, vec![Strategy::Error], None)).await;
    assert_eq!(admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await.0, S::CREATED);
    assert_eq!(admin.call("PUT", "/v1/tenants/acme/settings", Some(json!({ "approval_required": true }))).await.0, S::NO_CONTENT);
    assert_eq!(admin.call("POST", "/v1/tenants/acme/policies", Some(policy("/etc/one"))).await.1["live"], false);

    let (s, versions) = admin.call("GET", "/v1/tenants/acme/policies/p/versions", None).await;
    assert_eq!((s, versions[0]["active"].as_bool(), versions[0]["state"].as_str()), (S::OK, Some(false), Some("draft")));
    let (s, detail) = admin.call("GET", "/v1/tenants/acme/policies/p/versions/1", None).await;
    assert_eq!((s, detail["approval_required"].as_bool()), (S::OK, Some(true)));
}
