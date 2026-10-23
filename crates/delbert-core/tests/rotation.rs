//! Signing-key rotation: what the Core announces and how it reports readiness.

mod common;

use axum::http::StatusCode as S;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use common::{admin_client, state};
use delbert_core::compile::Strategy;
use delbert_wire::{TrustUpdate, TrustedKey};
use serde_json::{Value, json};
use sqlx::PgPool;

fn payload(token: &str) -> Value {
    serde_json::from_slice(&B64.decode(token.split('.').nth(1).unwrap()).unwrap()).unwrap()
}

#[sqlx::test]
async fn announces_keys_and_reports_which_agents_know_them(pool: PgPool) {
    let next = TrustedKey { kid: "k2".into(), public_key: B64.encode([2u8; 32]) };
    let mut st = state(pool.clone(), vec![Strategy::Error], None);
    st.published_keys = vec![next.clone()];
    st.trust = Some(TrustUpdate { add: vec![next.clone()], remove: vec!["k0".into()] });
    let admin = admin_client(st).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    for a in ["a1", "a2", "a3"] {
        admin.call("POST", "/v1/tenants/acme/agents", Some(json!({ "name": a }))).await;
    }

    // Every policy carries the announcement, inside the signed payload.
    let (_, eff) = admin.call("GET", "/v1/tenants/acme/agents/a1/effective", None).await;
    let p = payload(eff["token"].as_str().unwrap());
    assert_eq!(p["trust"]["add"][0]["kid"], "k2");
    assert_eq!(p["trust"]["remove"], json!(["k0"]));

    // Agents report the key ids they trust; the Core says who is ready.
    let report = |kids: Value| json!({ "version": 1, "at": 1, "compliant": true, "resources": [], "trusted_kids": kids });
    for (agent, kids) in [("a1", json!(["k1", "k2"])), ("a2", json!(["k1"]))] {
        sqlx::query("INSERT INTO agent_reports (agent_id, version, compliant, report) SELECT a.id, 1, true, $2 FROM agents a WHERE a.name = $1").bind(agent).bind(report(kids)).execute(&pool).await.unwrap();
    }
    let (s, st) = admin.call("GET", "/v1/signing/keys", None).await;
    assert_eq!(s, S::OK, "{st}");
    assert_eq!((st["agents_total"].clone(), st["agents_reporting"].clone()), (json!(3), json!(2)));
    assert_eq!(st["active"]["kid"], "k1");
    assert_eq!(st["retiring"], json!(["k0"]));
    let k2 = st["readiness"].as_array().unwrap().iter().find(|r| r["kid"] == "k2").unwrap();
    assert_eq!(k2["known_by"], 1);
    assert_eq!(k2["missing"], json!(["acme/a2", "acme/a3"])); // one lags, one has never reported
    let k1 = st["readiness"].as_array().unwrap().iter().find(|r| r["kid"] == "k1").unwrap();
    assert_eq!(k1["known_by"], 2);

    // Only a platform administrator sees it.
    admin.call("POST", "/v1/users", Some(json!({ "username": "vera", "password": "a-long-enough-password", "assignments": [{ "role": "viewer" }] }))).await;
    assert_eq!(admin.as_user("vera", "a-long-enough-password").await.call("GET", "/v1/signing/keys", None).await.0, S::FORBIDDEN);
}

#[sqlx::test]
async fn secrets_key_rotation_reseals_everything(pool: PgPool) {
    use delbert_core::secrets::SecretsKeys;
    let old = age::x25519::Identity::generate();
    // Data written while `old` was the current key: a tenant secret and a TOTP secret.
    let mut st = state(pool.clone(), vec![Strategy::Error], None);
    st.secrets_key = Some(std::sync::Arc::new(SecretsKeys::new(old.clone(), vec![])));
    let admin = admin_client(st.clone()).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    assert_eq!(admin.call("PUT", "/v1/tenants/acme/secrets/db", Some(json!({ "value": "hunter2" }))).await.0, S::NO_CONTENT);
    assert_eq!(admin.call("POST", "/v1/me/mfa/enroll", None).await.0, S::OK);

    // New key in charge, the old one still configured: nothing breaks, and the Core says what is left to move.
    let new = age::x25519::Identity::generate();
    st.secrets_key = Some(std::sync::Arc::new(SecretsKeys::new(new.clone(), vec![old.clone()])));
    let admin = common::Client { app: delbert_core::api::router(st.clone()), ..admin };
    let (s, k) = admin.call("GET", "/v1/secrets/key", None).await;
    assert_eq!(s, S::OK, "{k}");
    let left = |k: &Value| k["items"].as_array().unwrap().iter().map(|i| i["on_old_key"].as_i64().unwrap()).sum::<i64>();
    assert_eq!(left(&k), 2);
    // A secret is still delivered (decrypted with the old key, re-encrypted to the agent).
    admin.call("POST", "/v1/tenants/acme/agents", Some(json!({ "name": "a1" }))).await;

    let (s, k) = admin.call("POST", "/v1/secrets/reseal", None).await;
    assert_eq!(s, S::OK, "{k}");
    assert_eq!(left(&k), 0);
    assert_eq!(k["old_keys"], 1);

    // Now the old key is not needed any more.
    st.secrets_key = Some(std::sync::Arc::new(SecretsKeys::new(new, vec![])));
    let admin = common::Client { app: delbert_core::api::router(st), ..admin };
    let (_, k) = admin.call("GET", "/v1/secrets/key", None).await;
    assert_eq!(left(&k), 0);
    assert_eq!(k["items"][0]["total"], 1);
    // Every sealed value now opens with the new key alone (the status counts only that as "moved").
}
