//! Tenant-scoped RBAC (docs/RBAC.md): scopes, masking of unreachable tenants, delegation.

mod common;

use axum::http::StatusCode;
use axum::http::StatusCode as S;
const CREATED: S = S::CREATED;
const FORBIDDEN: S = S::FORBIDDEN;
const NOT_FOUND: S = S::NOT_FOUND;
const NO_CONTENT: S = S::NO_CONTENT;
const OK: S = S::OK;
const UNPROCESSABLE_ENTITY: S = S::UNPROCESSABLE_ENTITY;
use common::{Client, admin_client, state};
use delbert_core::compile::Strategy;
use serde_json::json;
use sqlx::PgPool;

const PASSWORD: &str = "a-long-enough-password";

async fn user(admin: &Client, name: &str, assignments: serde_json::Value) -> Client {
    let (s, b) = admin.call("POST", "/v1/users", Some(json!({ "username": name, "password": PASSWORD, "assignments": assignments }))).await;
    assert_eq!(s, CREATED, "{b}");
    admin.as_user(name, PASSWORD).await
}

async fn status(c: &Client, method: &str, uri: &str, body: Option<serde_json::Value>) -> StatusCode {
    c.call(method, uri, body).await.0
}

#[sqlx::test]
async fn roles_are_scoped_to_tenants(pool: PgPool) {
    let admin = admin_client(state(pool, vec![Strategy::Error], None)).await;
    for t in ["acme", "beta"] {
        assert_eq!(status(&admin, "POST", "/v1/tenants", Some(json!({ "name": t }))).await, CREATED);
    }
    let olivia = user(&admin, "olivia", json!([{ "role": "operator", "tenant": "acme" }])).await;
    let vera = user(&admin, "vera", json!([{ "role": "viewer" }])).await;
    let nobody = user(&admin, "nobody", json!([])).await;

    // A tenant-scoped operator sees and changes only her tenant; the other one looks missing.
    let (_, tenants) = olivia.call("GET", "/v1/tenants", None).await;
    assert_eq!(tenants.as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect::<Vec<_>>(), ["acme"]);
    assert_eq!(status(&olivia, "POST", "/v1/tenants/acme/agents", Some(json!({ "name": "a1" }))).await, CREATED);
    assert_eq!(status(&olivia, "GET", "/v1/tenants/beta/agents", None).await, NOT_FOUND);
    assert_eq!(status(&olivia, "POST", "/v1/tenants/beta/agents", Some(json!({ "name": "a1" }))).await, NOT_FOUND);
    // Inside the tenant the permission set still applies; global-only actions are out of reach.
    assert_eq!(status(&olivia, "PUT", "/v1/tenants/acme/secrets/db", Some(json!({ "value": "x" }))).await, FORBIDDEN);
    assert_eq!(status(&olivia, "POST", "/v1/tenants", Some(json!({ "name": "c" }))).await, FORBIDDEN);
    assert_eq!(status(&olivia, "GET", "/v1/proxies", None).await, FORBIDDEN);
    assert_eq!(status(&olivia, "GET", "/v1/users", None).await, FORBIDDEN);
    let (_, me) = olivia.call("GET", "/v1/me", None).await;
    assert_eq!(me["tenants"]["acme"].as_array().unwrap().contains(&json!("agents:write")), true);
    assert_eq!(me["permissions"], json!([]));

    // The permission catalog follows the role list's gate and marks the global-only ones.
    assert_eq!(status(&olivia, "GET", "/v1/permissions", None).await, FORBIDDEN);
    let (code, catalog) = admin.call("GET", "/v1/permissions", None).await;
    assert_eq!(code, OK);
    let entry = |p: &str| catalog.as_array().unwrap().iter().find(|e| e["permission"] == p).unwrap().clone();
    assert_eq!(entry("users:write")["global_only"], json!(true));
    assert_eq!(entry("agents:write")["global_only"], json!(false));

    // A global viewer reads every tenant and writes nothing.
    assert_eq!(status(&vera, "GET", "/v1/tenants/beta/agents", None).await, OK);
    assert_eq!(status(&vera, "GET", "/v1/proxies", None).await, OK);
    assert_eq!(status(&vera, "POST", "/v1/tenants/beta/agents", Some(json!({ "name": "a1" }))).await, FORBIDDEN);

    // Without any role the tenants are invisible, not forbidden.
    assert_eq!(status(&nobody, "GET", "/v1/tenants/acme/agents", None).await, NOT_FOUND);
    assert_eq!(status(&nobody, "GET", "/v1/tenants", None).await, OK);

    // Roles only go where their scope allows.
    let put = |roles: serde_json::Value| json!({ "assignments": roles });
    assert_eq!(status(&admin, "PUT", "/v1/users/nobody", Some(put(json!([{ "role": "operator" }])))).await, UNPROCESSABLE_ENTITY);
    assert_eq!(status(&admin, "PUT", "/v1/users/nobody", Some(put(json!([{ "role": "platform-admin", "tenant": "acme" }])))).await, UNPROCESSABLE_ENTITY);
    assert_eq!(status(&admin, "PUT", "/v1/users/nobody", Some(put(json!([{ "role": "operator", "tenant": "ghost" }])))).await, UNPROCESSABLE_ENTITY);
    assert_eq!(status(&admin, "PUT", "/v1/users/nobody", Some(put(json!([{ "role": "auditor", "tenant": "beta" }])))).await, NO_CONTENT);
    assert_eq!(status(&nobody, "GET", "/v1/tenants/beta/agents", None).await, OK);
    assert_eq!(status(&nobody, "GET", "/v1/tenants/acme/agents", None).await, NOT_FOUND);
}

#[sqlx::test]
async fn tenant_admins_delegate_within_their_tenant(pool: PgPool) {
    let admin = admin_client(state(pool, vec![Strategy::Error], None)).await;
    for t in ["acme", "beta"] {
        assert_eq!(status(&admin, "POST", "/v1/tenants", Some(json!({ "name": t }))).await, CREATED);
    }
    let tina = user(&admin, "tina", json!([{ "role": "tenant-admin", "tenant": "acme" }])).await;
    let olivia = user(&admin, "olivia", json!([{ "role": "operator", "tenant": "acme" }])).await;
    let newbie = user(&admin, "newbie", json!([])).await;
    assert_eq!(status(&admin, "POST", "/v1/roles", Some(json!({ "name": "agents-all", "permissions": ["agents:*"], "scope": "tenant" }))).await, CREATED);

    let grant = |t: &str, roles: serde_json::Value| (format!("/v1/tenants/{t}/assignments/newbie"), json!({ "roles": roles }));
    let (uri, body) = grant("acme", json!(["operator"]));
    assert_eq!(status(&tina, "PUT", &uri, Some(body)).await, NO_CONTENT);
    assert_eq!(status(&newbie, "GET", "/v1/tenants/acme/agents", None).await, OK);

    // Not beyond the tenant, not beyond what the delegate holds, not without the permission.
    let (uri, body) = grant("beta", json!(["operator"]));
    assert_eq!(status(&tina, "PUT", &uri, Some(body)).await, NOT_FOUND);
    let (uri, body) = grant("acme", json!(["platform-admin"]));
    assert_eq!(status(&tina, "PUT", &uri, Some(body)).await, FORBIDDEN);
    let (uri, body) = grant("acme", json!(["agents-all"]));
    assert_eq!(status(&tina, "PUT", &uri, Some(body.clone())).await, FORBIDDEN);
    assert_eq!(status(&admin, "PUT", &uri, Some(body)).await, NO_CONTENT);
    let (uri, body) = grant("acme", json!(["operator"]));
    assert_eq!(status(&olivia, "PUT", &uri, Some(body)).await, FORBIDDEN);
    assert_eq!(status(&tina, "POST", "/v1/tenants", Some(json!({ "name": "c" }))).await, FORBIDDEN);

    let (s, list) = tina.call("GET", "/v1/tenants/acme/assignments", None).await;
    assert_eq!(s, OK);
    assert!(list.as_array().unwrap().iter().any(|a| a["username"] == "newbie" && a["role"] == "agents-all"));
    // Removing the tenant removes its assignments with it (no dangling grants).
    let (uri, _) = grant("acme", json!([]));
    assert_eq!(status(&tina, "PUT", &uri, Some(json!({ "roles": [] }))).await, NO_CONTENT);
    assert_eq!(status(&newbie, "GET", "/v1/tenants/acme/agents", None).await, NOT_FOUND);
}
