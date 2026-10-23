//! API integration tests. Need PostgreSQL: set DATABASE_URL (see README);
//! `sqlx::test` creates an isolated database for every test.

mod common;

use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use common::{ADMIN_PASSWORD, Client, admin_client, signing_key, state};
use delbert_core::compile::Strategy;
use delbert_wire::{Expect, Verifier};
use serde_json::{Value, json};
use sqlx::PgPool;

fn policy(name: &str, extra_spec: &str, resources: &str) -> Value {
    json!({ "yaml": format!(
        "apiVersion: delbert/v1\nkind: Policy\nmetadata: {{ name: {name}, tenant: acme }}\nspec:\n{extra_spec}  resources:\n{resources}"
    ) })
}

const MOTD_A: &str = "    - id: motd\n      copy: { content: \"hello\\n\", dest: /etc/motd }\n";
const MOTD_B: &str = "    - id: motd\n      copy: { content: \"other\\n\", dest: /etc/motd }\n";
const OTHER: &str = "    - id: marker\n      file: { path: /etc/marker }\n";

async fn setup(c: &Client) {
    assert_eq!(c.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await.0, StatusCode::CREATED);
    let (s, _) = c.call("POST", "/v1/tenants/acme/agents", Some(json!({ "name": "agent-1", "groups": ["web"] }))).await;
    assert_eq!(s, StatusCode::CREATED);
}

fn verify(token: &str) -> delbert_wire::EffectivePolicy {
    let mut v = Verifier::default();
    v.add_key("k1", &B64.encode(signing_key().verifying_key().to_bytes())).unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    v.verify(token, &Expect { tenant: "acme", agent: "agent-1", now }, |_| None).unwrap()
}

// --- authentication and RBAC ------------------------------------------------------------

#[sqlx::test]
async fn authentication_basics(pool: PgPool) {
    let admin = admin_client(state(pool, vec![Strategy::Error], None)).await;
    let anon = Client { token: None, ..admin.clone() };

    assert_eq!(anon.call("GET", "/v1/tenants", None).await.0, StatusCode::UNAUTHORIZED);
    let bad = Client { token: Some("nonsense".into()), ..admin.clone() };
    assert_eq!(bad.call("GET", "/v1/tenants", None).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(anon.login("admin", "wrong-password-123").await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(anon.login("ghost", "whatever-password").await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(anon.call("GET", "/healthz", None).await.0, StatusCode::OK);

    let (s, me) = admin.call("GET", "/v1/me", None).await;
    assert_eq!((s, me["username"].as_str()), (StatusCode::OK, Some("admin")));

    // Logout invalidates the token.
    assert_eq!(admin.call("POST", "/v1/auth/logout", None).await.0, StatusCode::NO_CONTENT);
    assert_eq!(admin.call("GET", "/v1/me", None).await.0, StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn api_documentation_is_served_and_can_be_disabled(pool: PgPool) {
    let admin = admin_client(state(pool.clone(), vec![], None)).await;
    let anon = Client { token: None, ..admin.clone() };
    let (s, doc) = anon.call("GET", "/openapi.json", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(doc["paths"]["/v1/tenants"].is_object() && doc["components"]["securitySchemes"]["bearer"].is_object());
    assert!(doc["paths"].as_object().unwrap().len() >= 15);

    let mut off = state(pool, vec![], None);
    off.docs = false;
    let anon = Client { app: delbert_core::api::router(off), token: None };
    assert_eq!(anon.call("GET", "/openapi.json", None).await.0, StatusCode::NOT_FOUND);
}

#[sqlx::test]
async fn rbac_roles_users_and_safeguards(pool: PgPool) {
    let admin = admin_client(state(pool, vec![Strategy::Error], None)).await;
    setup(&admin).await;

    // Built-in roles exist; unknown permissions and duplicate users are refused.
    let (_, roles) = admin.call("GET", "/v1/roles", None).await;
    let names: Vec<&str> = roles.as_array().unwrap().iter().map(|r| r["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["admin", "auditor", "operator"]);
    assert_eq!(admin.call("POST", "/v1/roles", Some(json!({ "name": "x-role", "permissions": ["fly"] }))).await.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(admin.call("PUT", "/v1/roles/admin", Some(json!({ "permissions": ["read"] }))).await.0, StatusCode::CONFLICT);

    // Users: weak passwords and unknown roles are rejected.
    let new = |name: &str, role: &str| json!({ "username": name, "password": "a-long-enough-password", "roles": [role] });
    assert_eq!(admin.call("POST", "/v1/users", Some(json!({ "username": "weak", "password": "short", "roles": [] }))).await.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(admin.call("POST", "/v1/users", Some(new("ghost-role", "nope"))).await.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(admin.call("POST", "/v1/users", Some(new("olivia", "operator"))).await.0, StatusCode::CREATED);
    assert_eq!(admin.call("POST", "/v1/users", Some(new("olivia", "operator"))).await.0, StatusCode::CONFLICT);
    assert_eq!(admin.call("POST", "/v1/users", Some(new("alice", "auditor"))).await.0, StatusCode::CREATED);

    let operator = admin.as_user("olivia", "a-long-enough-password").await;
    let auditor = admin.as_user("alice", "a-long-enough-password").await;

    // Operator: manages agents and policies, nothing about users or tenants.
    assert_eq!(operator.call("POST", "/v1/tenants/acme/policies", Some(policy("p", "", OTHER))).await.0, StatusCode::CREATED);
    assert_eq!(operator.call("GET", "/v1/users", None).await.0, StatusCode::FORBIDDEN);
    assert_eq!(operator.call("POST", "/v1/tenants", Some(json!({ "name": "other" }))).await.0, StatusCode::FORBIDDEN);
    assert_eq!(operator.call("GET", "/v1/audit/verify", None).await.0, StatusCode::FORBIDDEN);

    // Auditor: read-only plus the audit.
    assert_eq!(auditor.call("GET", "/v1/tenants/acme/policies", None).await.0, StatusCode::OK);
    assert_eq!(auditor.call("GET", "/v1/audit/verify", None).await.0, StatusCode::OK);
    assert_eq!(auditor.call("POST", "/v1/tenants/acme/policies", Some(policy("q", "", OTHER))).await.0, StatusCode::FORBIDDEN);
    assert_eq!(auditor.call("GET", "/v1/tenants/acme/agents/agent-1/effective", None).await.0, StatusCode::FORBIDDEN);

    // Custom role: policies only, no agents.
    assert_eq!(admin.call("POST", "/v1/roles", Some(json!({ "name": "policy-editor", "permissions": ["read", "policies:write"] }))).await.0, StatusCode::CREATED);
    assert_eq!(admin.call("PUT", "/v1/users/alice", Some(json!({ "roles": ["policy-editor"] }))).await.0, StatusCode::NO_CONTENT);
    assert_eq!(auditor.call("POST", "/v1/tenants/acme/policies", Some(policy("q", "", OTHER))).await.0, StatusCode::CREATED);
    assert_eq!(auditor.call("POST", "/v1/tenants/acme/agents", Some(json!({ "name": "a2" }))).await.0, StatusCode::FORBIDDEN);
    // A role in use cannot be deleted; built-ins neither.
    assert_eq!(admin.call("DELETE", "/v1/roles/policy-editor", None).await.0, StatusCode::CONFLICT);
    assert_eq!(admin.call("DELETE", "/v1/roles/admin", None).await.0, StatusCode::CONFLICT);

    // Deactivating a user kills its access; a new password kills its sessions.
    assert_eq!(admin.call("PUT", "/v1/users/olivia", Some(json!({ "active": false }))).await.0, StatusCode::NO_CONTENT);
    assert_eq!(operator.call("GET", "/v1/me", None).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(admin.login("olivia", "a-long-enough-password").await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(admin.call("PUT", "/v1/users/alice", Some(json!({ "password": "another-long-password" }))).await.0, StatusCode::NO_CONTENT);
    assert_eq!(auditor.call("GET", "/v1/me", None).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(admin.login("alice", "another-long-password").await.0, StatusCode::OK);

    // The last administrator cannot be removed, deactivated or demoted.
    assert_eq!(admin.call("DELETE", "/v1/users/admin", None).await.0, StatusCode::CONFLICT);
    assert_eq!(admin.call("PUT", "/v1/users/admin", Some(json!({ "active": false }))).await.0, StatusCode::CONFLICT);
    assert_eq!(admin.call("PUT", "/v1/users/admin", Some(json!({ "roles": [] }))).await.0, StatusCode::CONFLICT);
    assert_eq!(admin.call("GET", "/v1/me", None).await.0, StatusCode::OK);

    // Authentication and administration events are in the audit trail.
    let (_, v) = admin.call("GET", "/v1/audit/verify", None).await;
    assert_eq!(v["first_bad"], Value::Null);
    let _ = ADMIN_PASSWORD;
}

// --- policies ------------------------------------------------------------------------------

#[sqlx::test]
async fn compile_sign_and_audit_flow(pool: PgPool) {
    let c = admin_client(state(pool, vec![Strategy::Error], None)).await;
    setup(&c).await;

    assert_eq!(c.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await.0, StatusCode::CONFLICT);

    for (name, spec, res) in [("base", "", MOTD_A), ("other", "", OTHER), ("db-only", "  target: { groups: [db] }\n", MOTD_B)] {
        let (s, _) = c.call("POST", "/v1/tenants/acme/policies", Some(policy(name, spec, res))).await;
        assert_eq!(s, StatusCode::CREATED);
    }

    // The db-only policy does not target this agent: no conflict, two resources.
    let (s, body) = c.call("GET", "/v1/tenants/acme/agents/agent-1/effective", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["version"], 1);
    assert_eq!(body["conflicts"], json!([]));
    let eff = verify(body["token"].as_str().unwrap());
    assert_eq!(eff.resources.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), vec!["base/motd", "other/marker"]);

    // Asking again does not bump the version.
    assert_eq!(c.call("GET", "/v1/tenants/acme/agents/agent-1/effective", None).await.1["version"], 1);

    // Moving the agent into `db` creates a conflict on /etc/motd: fail closed.
    assert_eq!(c.call("PUT", "/v1/tenants/acme/agents/agent-1", Some(json!({ "groups": ["web", "db"] }))).await.0, StatusCode::NO_CONTENT);
    let (_, conflicted) = c.call("GET", "/v1/tenants/acme/agents/agent-1/effective", None).await;
    assert_eq!(conflicted["version"], 2);
    assert_eq!(conflicted["conflicts"][0]["resolution"], "error: neither applied");
    assert_eq!(verify(conflicted["token"].as_str().unwrap()).resources.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), vec!["other/marker"]);

    // Deactivating a policy changes the compiled content again.
    assert_eq!(c.call("DELETE", "/v1/tenants/acme/policies/db-only", None).await.0, StatusCode::NO_CONTENT);
    let (_, healed) = c.call("GET", "/v1/tenants/acme/agents/agent-1/effective", None).await;
    assert_eq!((healed["version"].clone(), healed["conflicts"].clone()), (json!(3), json!([])));

    let (s, v) = c.call("GET", "/v1/audit/verify", None).await;
    assert_eq!((s, v["first_bad"].clone()), (StatusCode::OK, Value::Null));
    assert!(v["events"].as_u64().unwrap() >= 10, "{v}");
}

#[sqlx::test]
async fn priority_strategy_resolves_the_conflict(pool: PgPool) {
    let c = admin_client(state(pool, vec![Strategy::Priority, Strategy::Error], None)).await;
    setup(&c).await;
    c.call("POST", "/v1/tenants/acme/policies", Some(policy("low", "  priority: 1\n", MOTD_A))).await;
    c.call("POST", "/v1/tenants/acme/policies", Some(policy("high", "  priority: 10\n", MOTD_B))).await;
    let (_, body) = c.call("GET", "/v1/tenants/acme/agents/agent-1/effective", None).await;
    assert_eq!(body["conflicts"][0]["resolution"], "priority: kept high/motd");
    assert_eq!(verify(body["token"].as_str().unwrap()).resources.len(), 1);
}

#[sqlx::test]
async fn invalid_policies_are_rejected_and_versions_are_kept(pool: PgPool) {
    let c = admin_client(state(pool, vec![Strategy::Error], None)).await;
    setup(&c).await;

    let wrong_tenant = json!({ "yaml": "apiVersion: delbert/v1\nkind: Policy\nmetadata: { name: p, tenant: other }\nspec:\n  resources: []\n" });
    assert_eq!(c.call("POST", "/v1/tenants/acme/policies", Some(wrong_tenant)).await.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(c.call("POST", "/v1/tenants/acme/policies", Some(json!({ "yaml": "not: [valid" }))).await.0, StatusCode::UNPROCESSABLE_ENTITY);
    let conditional = policy("cond", "  target: { when: \"facts.os_id == 'debian'\" }\n", OTHER);
    assert_eq!(c.call("POST", "/v1/tenants/acme/policies", Some(conditional)).await.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(c.call("POST", "/v1/tenants/nope/policies", Some(policy("p", "", OTHER))).await.0, StatusCode::NOT_FOUND);
    // Names that would break NATS subjects are refused.
    assert_eq!(c.call("POST", "/v1/tenants", Some(json!({ "name": "a.b" }))).await.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(c.call("POST", "/v1/tenants/acme/agents", Some(json!({ "name": "x.y" }))).await.0, StatusCode::UNPROCESSABLE_ENTITY);

    c.call("POST", "/v1/tenants/acme/policies", Some(policy("p", "", OTHER))).await;
    let (_, second) = c.call("POST", "/v1/tenants/acme/policies", Some(policy("p", "", MOTD_A))).await;
    assert_eq!(second["version"], 2);
    let (_, got) = c.call("GET", "/v1/tenants/acme/policies/p", None).await;
    assert_eq!(got["version"], 2);
    assert!(got["yaml"].as_str().unwrap().contains("/etc/motd"));
}
