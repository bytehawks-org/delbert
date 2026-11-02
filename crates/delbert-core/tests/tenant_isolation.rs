//! Adversarial test of tenant isolation: a user whose every role is scoped to tenant `acme`
//! tries every tenant-scoped route of tenant `beta`. Nothing may answer with data or succeed,
//! and the audit trail she can read must not mention `beta`.

mod common;

use axum::http::StatusCode as S;
use common::{Client, admin_client, state};
use delbert_core::compile::Strategy;
use serde_json::{Value, json};
use sqlx::PgPool;

const PASSWORD: &str = "a-long-enough-password";
const YAML: &str = "apiVersion: delbert/v1\nkind: Policy\nmetadata: { name: base, tenant: beta }\nspec:\n  target: { groups: [web] }\n  resources:\n    - id: d\n      file: { path: /etc/beta, state: directory, mode: \"0755\" }\n";

async fn user(admin: &Client, name: &str, role: &str, tenant: &str) -> Client {
    let (s, b) = admin.call("POST", "/v1/users", Some(json!({ "username": name, "password": PASSWORD, "assignments": [{ "role": role, "tenant": tenant }] }))).await;
    assert_eq!(s, S::CREATED, "{b}");
    admin.as_user(name, PASSWORD).await
}

#[sqlx::test]
async fn a_user_of_one_tenant_reaches_nothing_of_another(pool: PgPool) {
    let admin = admin_client(state(pool.clone(), vec![Strategy::Error], None)).await;
    for t in ["acme", "beta"] {
        assert_eq!(admin.call("POST", "/v1/tenants", Some(json!({ "name": t }))).await.0, S::CREATED);
    }
    // Content of the victim tenant.
    assert_eq!(admin.call("POST", "/v1/tenants/beta/agents", Some(json!({ "name": "b1" }))).await.0, S::CREATED);
    assert_eq!(admin.call("POST", "/v1/tenants/beta/policies", Some(json!({ "yaml": YAML }))).await.0, S::CREATED);
    assert_eq!(admin.call("PUT", "/v1/tenants/beta/secrets/db", Some(json!({ "value": "hunter2" }))).await.0, S::NO_CONTENT);
    assert_eq!(admin.call("POST", "/v1/tenants/beta/enrollment-keys", Some(json!({ "groups": ["web"] }))).await.0, S::OK.max(S::CREATED));
    admin.raw("PUT", "/v1/tenants/beta/artifacts/f.txt", vec![("content-type", "application/octet-stream".into())], b"beta-only".to_vec()).await;

    // The strongest tenant-scoped roles, on acme only.
    let attackers = [user(&admin, "tadmin", "tenant-admin", "acme").await, user(&admin, "oper", "operator", "acme").await];

    let reads = [
        "/v1/tenants/beta/agents", "/v1/tenants/beta/agents/b1", "/v1/tenants/beta/agents/b1/effective", "/v1/tenants/beta/agents/b1/render",
        "/v1/tenants/beta/agents/b1/variables", "/v1/tenants/beta/artifacts", "/v1/tenants/beta/artifacts/f.txt", "/v1/tenants/beta/assignments",
        "/v1/tenants/beta/deliveries", "/v1/tenants/beta/enrollment-keys", "/v1/tenants/beta/policies", "/v1/tenants/beta/policies/base",
        "/v1/tenants/beta/policies/base/versions", "/v1/tenants/beta/policies/base/versions/1", "/v1/tenants/beta/secrets", "/v1/tenants/beta/settings",
        "/v1/tenants/beta/variables",
    ];
    let writes: [(&str, &str, Option<Value>); 12] = [
        ("POST", "/v1/tenants/beta/agents", Some(json!({ "name": "evil" }))),
        ("DELETE", "/v1/tenants/beta/agents/b1", None),
        ("POST", "/v1/tenants/beta/policies", Some(json!({ "yaml": YAML }))),
        ("POST", "/v1/tenants/beta/policies/validate", Some(json!({ "yaml": YAML }))),
        ("POST", "/v1/tenants/beta/policies/base/versions/1/activate", None),
        ("POST", "/v1/tenants/beta/policies/base/versions/1/approve", None),
        ("PUT", "/v1/tenants/beta/secrets/db", Some(json!({ "value": "evil" }))),
        ("DELETE", "/v1/tenants/beta/secrets/db", None),
        ("POST", "/v1/tenants/beta/enrollment-keys", Some(json!({ "groups": ["web"] }))),
        ("PUT", "/v1/tenants/beta/assignments/tadmin", Some(json!({ "roles": ["tenant-admin"] }))),
        ("PUT", "/v1/tenants/beta/settings", Some(json!({ "approval_required": false }))),
        ("DELETE", "/v1/tenants/beta", None),
    ];
    for c in &attackers {
        for uri in reads {
            let (s, body) = c.call("GET", uri, None).await;
            // 405: the route has no GET at all. Anything else but "not found" would be a leak.
            assert!(s == S::NOT_FOUND || s == S::METHOD_NOT_ALLOWED, "GET {uri} answered {s}: {body}");
        }
        for (method, uri, body) in &writes {
            let (s, b) = c.call(method, uri, body.clone()).await;
            assert!(s == S::NOT_FOUND || s == S::FORBIDDEN, "{method} {uri} answered {s}: {b}");
        }
        // Cross-tenant users and platform data stay out of reach too.
        for uri in ["/v1/users", "/v1/proxies", "/v1/sso/providers", "/v1/audit/verify", "/v1/audit/anchors"] {
            let s = c.call("GET", uri, None).await.0;
            assert!(s == S::FORBIDDEN || s == S::NOT_FOUND, "GET {uri} answered {s}");
        }
        let (_, tenants) = c.call("GET", "/v1/tenants", None).await;
        assert_eq!(tenants.as_array().unwrap().len(), 1, "{tenants}");
    }

    // The victim is unchanged.
    let (_, policies) = admin.call("GET", "/v1/tenants/beta/policies", None).await;
    assert_eq!(policies.as_array().unwrap().len(), 1);
    let (_, agents) = admin.call("GET", "/v1/tenants/beta/agents", None).await;
    assert_eq!(agents.as_array().unwrap().len(), 1);
    assert_eq!(admin.call("GET", "/v1/tenants/beta/secrets", None).await.1.to_string().contains("hunter2"), false, "secret values are never listed");

    // An auditor scoped to acme sees acme's events only, in the list and in the export.
    let aud = user(&admin, "aud", "auditor", "acme").await;
    admin.call("POST", "/v1/tenants/acme/agents", Some(json!({ "name": "a1" }))).await;
    let (s, events) = aud.call("GET", "/v1/audit?limit=1000", None).await;
    assert_eq!(s, S::OK, "{events}");
    let list = events["events"].as_array().unwrap();
    assert!(!list.is_empty());
    assert!(list.iter().all(|e| e["tenant"] == "acme"), "foreign events: {events}");
    let (s, body) = aud.call("GET", "/v1/audit?tenant=beta", None).await;
    assert!(s == S::NOT_FOUND || s == S::FORBIDDEN || body["events"].as_array().is_some_and(|e| e.is_empty()), "{s} {body}");
    let (s, export) = aud.text("GET", "/v1/audit/export").await;
    assert_eq!(s, S::OK);
    assert!(!export.contains("\"tenant\":\"beta\"") && !export.contains("beta"), "export leaks beta: {export}");
}

/// Tenant and agent names become NATS subject tokens (`delbert.report.<tenant>.<agent>`, matched by
/// two-token wildcards): a dot, a wildcard or a separator in either would shift or widen the subject.
#[sqlx::test]
async fn names_that_would_break_bus_subjects_are_refused(pool: PgPool) {
    let admin = admin_client(state(pool, vec![Strategy::Error], None)).await;
    assert_eq!(admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await.0, S::CREATED);
    for bad in ["acme.eu", "a*", "a>", "a b", "a:b", "a/b", ""] {
        assert_eq!(admin.call("POST", "/v1/tenants", Some(json!({ "name": bad }))).await.0, S::UNPROCESSABLE_ENTITY, "tenant {bad:?}");
        assert_eq!(admin.call("POST", "/v1/tenants/acme/agents", Some(json!({ "name": bad }))).await.0, S::UNPROCESSABLE_ENTITY, "agent {bad:?}");
    }
}
