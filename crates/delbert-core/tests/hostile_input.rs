//! Hostile request bodies must be refused cheaply (docs/SECURITY-REVIEW.md F-10): deeply nested
//! YAML made the parser run for minutes on one request.

mod common;

use std::time::{Duration, Instant};

use axum::http::StatusCode as S;
use common::{admin_client, state};
use delbert_core::compile::Strategy;
use serde_json::json;
use sqlx::PgPool;

#[sqlx::test]
async fn deeply_nested_yaml_is_refused_fast_on_every_policy_entry_point(pool: PgPool) {
    let admin = admin_client(state(pool, vec![Strategy::Error], None)).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    let bomb = format!("apiVersion: delbert/v1\nkind: Policy\nmetadata: {{ name: x, tenant: acme }}\nspec:\n  vars:\n    deep: {}\n", "[".repeat(1_500_000));
    for (method, uri) in [("POST", "/v1/tenants/acme/policies"), ("POST", "/v1/tenants/acme/policies/validate")] {
        let started = Instant::now();
        let (s, body) = admin.call(method, uri, Some(json!({ "yaml": bomb }))).await;
        assert_eq!(s, S::UNPROCESSABLE_ENTITY, "{uri}: {body}");
        assert!(body.to_string().contains("too complex"), "{body}");
        assert!(started.elapsed() < Duration::from_secs(3), "{uri} took {:?}", started.elapsed());
    }
}

/// PostgreSQL cannot store NUL bytes: they must come back as a client error, never a 500, wherever
/// they enter (path, query, JSON body) and whichever statement they reach first.
#[sqlx::test]
async fn nul_bytes_never_cause_a_server_error(pool: PgPool) {
    let admin = admin_client(state(pool, vec![Strategy::Error], None)).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    admin.call("POST", "/v1/tenants/acme/agents", Some(json!({ "name": "a1" }))).await;
    let nul = "x\u{0}y";
    let cases: Vec<(&str, String, Option<serde_json::Value>)> = vec![
        ("POST", "/v1/tenants".into(), Some(json!({ "name": nul }))),
        ("POST", "/v1/tenants/acme/agents".into(), Some(json!({ "name": nul }))),
        ("POST", "/v1/tenants/acme/agents".into(), Some(json!({ "name": "a2", "groups": [nul] }))),
        ("POST", "/v1/tenants/acme/policies".into(), Some(json!({ "yaml": format!("apiVersion: delbert/v1\nkind: Policy\nmetadata: {{ name: p, tenant: acme }}\nspec:\n  vars: {{ k: \"{nul}\" }}\n  resources: []\n") }))),
        ("POST", "/v1/tenants/acme/policies/validate".into(), Some(json!({ "yaml": nul }))),
        ("PUT", "/v1/tenants/acme/secrets/a%00b".into(), Some(json!({ "value": "v" }))),
        ("PUT", "/v1/tenants/acme/secrets/db".into(), Some(json!({ "value": nul }))),
        ("PUT", "/v1/tenants/acme/artifacts/a%00b".into(), None),
        ("GET", "/v1/tenants/acme/policies/a%00b".into(), None),
        ("GET", "/v1/tenants/acme/policies/a%00b/versions/1".into(), None),
        ("DELETE", "/v1/tenants/acme/agents/a%00b".into(), None),
        ("DELETE", "/v1/tenants/acme/enrollment-keys/a%00b".into(), None),
        ("POST", "/v1/tenants/acme/enrollment-keys".into(), Some(json!({ "groups": [nul] }))),
        ("PUT", "/v1/tenants/acme/variables/a%00b".into(), Some(json!({ "value": "v" }))),
        ("POST", "/v1/users".into(), Some(json!({ "username": nul, "password": "a-long-enough-password" }))),
        ("POST", "/v1/auth/login".into(), Some(json!({ "username": nul, "password": nul }))),
        ("GET", "/v1/audit?actor=a%00b&action=x%00".into(), None),
        ("GET", "/v1/audit?tenant=a%00b".into(), None),
        ("POST", "/v1/enroll".into(), Some(json!({ "psk": nul, "agent_name": "a1", "csr_pem": "x", "enc_public_key": "y" }))),
        ("POST", "/v1/proxies".into(), Some(json!({ "name": nul, "dns_names": ["p.example.com"] }))),
        ("POST", "/v1/content/sources".into(), Some(json!({ "name": nul, "kind": "directory", "location": "x" }))),
    ];
    for (method, uri, body) in cases {
        let (s, b) = admin.call(method, &uri, body.clone()).await;
        assert!(s.as_u16() < 500, "{method} {uri} {body:?} answered {s}: {b}");
    }
}

/// ASVS 8.2.1 / 14.4: API answers (data, errors, downloads) are not cacheable, sniffable or framable;
/// the Swagger UI, which is a page, is left alone.
#[sqlx::test]
async fn api_answers_carry_security_headers(pool: PgPool) {
    use axum::http::{Request, header};
    use tower::ServiceExt;
    let admin = admin_client(state(pool, vec![Strategy::Error], None)).await;
    for (uri, auth) in [("/v1/me", true), ("/v1/me", false), ("/healthz", false), ("/v1/nope", true)] {
        let mut req = Request::builder().uri(uri);
        if auth {
            req = req.header(header::AUTHORIZATION, format!("Bearer {}", admin.token.clone().unwrap()));
        }
        let resp = admin.app.clone().oneshot(req.body(axum::body::Body::empty()).unwrap()).await.unwrap();
        let h = resp.headers();
        assert_eq!(h.get("cache-control").map(|v| v.to_str().unwrap()), Some("no-store"), "{uri}");
        assert_eq!(h.get("x-content-type-options").map(|v| v.to_str().unwrap()), Some("nosniff"), "{uri}");
        assert!(h.get("content-security-policy").unwrap().to_str().unwrap().contains("frame-ancestors 'none'"), "{uri}");
    }
    let resp = admin.app.clone().oneshot(Request::builder().uri("/openapi.json").body(axum::body::Body::empty()).unwrap()).await.unwrap();
    assert!(resp.headers().get("content-security-policy").is_none(), "the documentation routes keep their own headers");
}
