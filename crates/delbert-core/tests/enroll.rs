//! Enrollment with pre-shared keys.

mod common;

use axum::http::StatusCode;
use common::{Client, admin_client, state};
use delbert_core::compile::Strategy;
use serde_json::{Value, json};
use sqlx::PgPool;

fn request(psk: &Value, agent: &str) -> Value {
    let (_, csr_pem) = delbert_pki::new_identity(agent).unwrap();
    let enc = age::x25519::Identity::generate().to_public().to_string();
    json!({ "psk": psk, "agent_name": agent, "csr_pem": csr_pem, "enc_public_key": enc })
}

#[sqlx::test]
async fn enrollment_keys_limits_and_certificates(pool: PgPool) {
    let admin = admin_client(state(pool.clone(), vec![Strategy::Error], None)).await;
    let anon = Client { token: None, ..admin.clone() };
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;

    let (s, k) = admin.call("POST", "/v1/tenants/acme/enrollment-keys", Some(json!({ "max_uses": 2, "groups": ["web"] }))).await;
    assert_eq!(s, StatusCode::CREATED);
    assert!(k["key"].as_str().unwrap().starts_with("dlb_"));

    // The key is shown once; listing never reveals it.
    let (_, list) = admin.call("GET", "/v1/tenants/acme/enrollment-keys", None).await;
    assert_eq!(list[0]["uses"], 0);
    assert!(list[0].get("key").is_none());

    // Enrolling: the Core decides subject and identity, and hands out trust anchors.
    let (s, resp) = anon.call("POST", "/v1/enroll", Some(request(&k["key"], "agent-1"))).await;
    assert_eq!(s, StatusCode::OK, "{resp}");
    assert_eq!(resp["tenant"], "acme");
    assert!(resp["cert_pem"].as_str().unwrap().contains("BEGIN CERTIFICATE"));
    assert!(resp["ca_pem"].as_str().unwrap().contains("BEGIN CERTIFICATE"));
    assert_eq!(resp["signing_keys"][0].as_str().unwrap().split(' ').next(), Some("k1"));
    let der = x509_parser::pem::parse_x509_pem(resp["cert_pem"].as_str().unwrap().as_bytes()).unwrap().1.contents;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
    assert_eq!(cert.subject().to_string(), "CN=agent-1");

    // The agent exists with the key's groups, enrolled.
    let (_, agents) = admin.call("GET", "/v1/tenants/acme/agents", None).await;
    assert_eq!(agents[0]["name"], "agent-1");
    assert_eq!(agents[0]["groups"], json!(["web"]));

    // Same agent again: conflict. Another agent: second use. Third use: exhausted.
    assert_eq!(anon.call("POST", "/v1/enroll", Some(request(&k["key"], "agent-1"))).await.0, StatusCode::CONFLICT);
    assert_eq!(anon.call("POST", "/v1/enroll", Some(request(&k["key"], "agent-2"))).await.0, StatusCode::OK);
    assert_eq!(anon.call("POST", "/v1/enroll", Some(request(&k["key"], "agent-3"))).await.0, StatusCode::UNAUTHORIZED);

    // Unknown, revoked and expired keys all look the same.
    assert_eq!(anon.call("POST", "/v1/enroll", Some(request(&json!("dlb_nope"), "agent-4"))).await.0, StatusCode::UNAUTHORIZED);
    let (_, k2) = admin.call("POST", "/v1/tenants/acme/enrollment-keys", Some(json!({}))).await;
    assert_eq!(admin.call("DELETE", &format!("/v1/tenants/acme/enrollment-keys/{}", k2["id"].as_str().unwrap()), None).await.0, StatusCode::NO_CONTENT);
    assert_eq!(anon.call("POST", "/v1/enroll", Some(request(&k2["key"], "agent-5"))).await.0, StatusCode::UNAUTHORIZED);
    let (_, k3) = admin.call("POST", "/v1/tenants/acme/enrollment-keys", Some(json!({}))).await;
    sqlx::query("UPDATE enrollment_keys SET expires_at = now() - interval '1 minute' WHERE id = $1::uuid").bind(k3["id"].as_str().unwrap()).execute(&pool).await.unwrap();
    assert_eq!(anon.call("POST", "/v1/enroll", Some(request(&k3["key"], "agent-6"))).await.0, StatusCode::UNAUTHORIZED);

    // Bad input and bad parameters.
    let (_, k4) = admin.call("POST", "/v1/tenants/acme/enrollment-keys", Some(json!({}))).await;
    assert_eq!(anon.call("POST", "/v1/enroll", Some(request(&k4["key"], "a.b"))).await.0, StatusCode::UNPROCESSABLE_ENTITY);
    let mut bad = request(&k4["key"], "agent-7");
    bad["enc_public_key"] = json!("not-an-age-key");
    assert_eq!(anon.call("POST", "/v1/enroll", Some(bad)).await.0, StatusCode::UNPROCESSABLE_ENTITY);
    let mut bad = request(&k4["key"], "agent-7");
    bad["csr_pem"] = json!("garbage");
    assert_eq!(anon.call("POST", "/v1/enroll", Some(bad)).await.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(admin.call("POST", "/v1/tenants/acme/enrollment-keys", Some(json!({ "ttl_hours": 100_000 }))).await.0, StatusCode::UNPROCESSABLE_ENTITY);
    // The failed attempts did not consume the key.
    assert_eq!(anon.call("POST", "/v1/enroll", Some(request(&k4["key"], "agent-7"))).await.0, StatusCode::OK);

    // Only administrators of agents create keys; the audit chain covers all of it.
    admin.call("POST", "/v1/users", Some(json!({ "username": "alice", "password": "a-long-enough-password", "roles": ["auditor"] }))).await;
    let auditor = admin.as_user("alice", "a-long-enough-password").await;
    assert_eq!(auditor.call("POST", "/v1/tenants/acme/enrollment-keys", Some(json!({}))).await.0, StatusCode::FORBIDDEN);
    let (_, v) = admin.call("GET", "/v1/audit/verify", None).await;
    assert_eq!(v["first_bad"], Value::Null);
}

#[sqlx::test]
async fn enrollment_is_disabled_without_a_ca(pool: PgPool) {
    let mut st = state(pool, vec![], None);
    st.pki = None;
    let admin = admin_client(st).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    let (_, k) = admin.call("POST", "/v1/tenants/acme/enrollment-keys", Some(json!({}))).await;
    let anon = Client { token: None, ..admin.clone() };
    assert_eq!(anon.call("POST", "/v1/enroll", Some(request(&k["key"], "agent-1"))).await.0, StatusCode::SERVICE_UNAVAILABLE);
}
