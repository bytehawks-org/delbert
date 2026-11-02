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
