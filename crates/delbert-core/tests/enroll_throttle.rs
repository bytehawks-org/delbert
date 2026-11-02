//! The unauthenticated enrollment endpoints: failures are throttled per address, audited in a
//! bounded way, and the rejected key never reaches the trail (docs/SECURITY-REVIEW.md F-02).

mod common;

use axum::http::StatusCode as S;
use common::{Client, admin_client, enroll_agent, state};
use delbert_core::compile::Strategy;
use serde_json::{Value, json};
use sqlx::PgPool;

fn bad_enroll(key: &str) -> Value {
    let (_, csr) = delbert_pki::new_identity("a1").unwrap();
    json!({ "psk": key, "agent_name": "a1", "csr_pem": csr, "enc_public_key": age::x25519::Identity::generate().to_public().to_string() })
}

async fn from(c: &Client, ip: &str, uri: &str, body: &Value) -> S {
    let anon = Client { token: None, ..c.clone() };
    anon.raw("POST", uri, vec![("content-type", "application/json".into()), ("x-forwarded-for", ip.into())], body.to_string().into_bytes()).await.0
}

async fn count(admin: &Client, action: &str) -> usize {
    admin.call("GET", &format!("/v1/audit?action={action}&limit=1000"), None).await.1["events"].as_array().unwrap().len()
}

#[sqlx::test]
async fn failed_agent_enrollments_are_throttled_audited_once_and_bounded(pool: PgPool) {
    let mut st = state(pool, vec![Strategy::Error], None);
    st.auth.trust_forwarded = true;
    let admin = admin_client(st).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    let secret = "dlb_this-is-a-wrong-key-that-must-not-be-logged";

    for _ in 0..10 {
        assert_eq!(from(&admin, "192.0.2.1", "/v1/enroll", &bad_enroll(secret)).await, S::UNAUTHORIZED);
    }
    assert_eq!(count(&admin, "enroll.denied").await, 10);

    // Past the ceiling: 429, one `enroll.throttled` event, nothing more however many follow.
    for _ in 0..5 {
        assert_eq!(from(&admin, "192.0.2.1", "/v1/enroll", &bad_enroll(secret)).await, S::TOO_MANY_REQUESTS);
    }
    assert_eq!((count(&admin, "enroll.denied").await, count(&admin, "enroll.throttled").await), (10, 1));

    // A throttled address is refused even with a valid key (the key is not even looked at)...
    let (_, key) = admin.call("POST", "/v1/tenants/acme/enrollment-keys", Some(json!({ "groups": ["web"] }))).await;
    assert_eq!(from(&admin, "192.0.2.1", "/v1/enroll", &bad_enroll(key["key"].as_str().unwrap())).await, S::TOO_MANY_REQUESTS);
    // ...while another address is unaffected and can enroll.
    assert_eq!(from(&admin, "192.0.2.2", "/v1/enroll", &bad_enroll(key["key"].as_str().unwrap())).await, S::OK);

    // The wrong key is nowhere in the trail or its export, and the chain is intact.
    let (_, export) = admin.text("GET", "/v1/audit/export").await;
    assert!(!export.contains("this-is-a-wrong-key"), "the rejected key leaked into the audit export");
    assert!(export.contains("192.0.2.1"), "the source address is on record");
    assert_eq!(admin.call("GET", "/v1/audit/verify", None).await.1["first_bad"], Value::Null);
}

#[sqlx::test]
async fn an_anonymous_flood_from_many_addresses_cannot_grow_the_trail_without_bound(pool: PgPool) {
    let mut st = state(pool.clone(), vec![Strategy::Error], None);
    st.auth.trust_forwarded = true;
    let admin = admin_client(st).await;
    // 260 different addresses, one failure each: all answered 401, but only the first 200 are audited.
    for i in 0..260 {
        assert_eq!(from(&admin, &format!("198.51.100.{}", i % 250 + (i / 250)), "/v1/enroll", &bad_enroll("dlb_x")).await, S::UNAUTHORIZED);
    }
    let n = count(&admin, "enroll.denied").await;
    assert!((200..=215).contains(&n), "audited {n} of 260 failures");
}

#[sqlx::test]
async fn proxy_enrollment_is_throttled_too(pool: PgPool) {
    let mut st = state(pool, vec![Strategy::Error], None);
    st.auth.trust_forwarded = true;
    let admin = admin_client(st).await;
    let (_, csr) = delbert_pki::new_identity("site").unwrap();
    let body = json!({ "name": "branch", "psk": "dlb_nope", "csr_pem": csr });
    for _ in 0..10 {
        assert_eq!(from(&admin, "203.0.113.9", "/v1/proxies/enroll", &body).await, S::UNAUTHORIZED);
    }
    assert_eq!(from(&admin, "203.0.113.9", "/v1/proxies/enroll", &body).await, S::TOO_MANY_REQUESTS);
    assert_eq!((count(&admin, "enroll.denied").await, count(&admin, "enroll.throttled").await), (10, 1));
}

#[sqlx::test]
async fn legitimate_enrollment_is_unaffected(pool: PgPool) {
    let admin = admin_client(state(pool, vec![Strategy::Error], None)).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    let _ = enroll_agent(&admin, "acme", "agent-1").await;
    assert_eq!(count(&admin, "enroll.denied").await, 0);
}
