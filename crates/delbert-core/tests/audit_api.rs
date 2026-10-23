//! Audit browsing and export: filters, pagination, scoping, offline verifiability.

mod common;

use axum::http::StatusCode as S;
use common::{Client, admin_client, state};
use delbert_core::compile::Strategy;
use serde_json::json;
use sqlx::PgPool;

async fn user(admin: &Client, name: &str, assignments: serde_json::Value) -> Client {
    let body = json!({ "username": name, "password": "a-long-enough-password", "assignments": assignments });
    assert_eq!(admin.call("POST", "/v1/users", Some(body)).await.0, S::CREATED);
    admin.as_user(name, "a-long-enough-password").await
}

#[sqlx::test]
async fn browse_filter_page_scope_and_export(pool: PgPool) {
    let admin = admin_client(state(pool, vec![Strategy::Error], None)).await;
    for t in ["acme", "beta"] {
        admin.call("POST", "/v1/tenants", Some(json!({ "name": t }))).await;
        for a in ["a1", "a2"] {
            admin.call("POST", &format!("/v1/tenants/{t}/agents"), Some(json!({ "name": a }))).await;
        }
    }
    let auditor = user(&admin, "alice", json!([{ "role": "auditor", "tenant": "acme" }])).await;
    let viewer = user(&admin, "vera", json!([{ "role": "viewer" }])).await;

    // Newest first, paged by keyset; the pages tile the whole trail without overlap.
    let (s, page) = admin.call("GET", "/v1/audit?limit=3", None).await;
    assert_eq!(s, S::OK);
    let first: Vec<i64> = page["events"].as_array().unwrap().iter().map(|e| e["seq"].as_i64().unwrap()).collect();
    assert!(first.windows(2).all(|w| w[0] > w[1]) && first.len() == 3);
    let next = page["next"].as_i64().unwrap();
    assert_eq!(next, *first.last().unwrap());
    let (_, older) = admin.call("GET", &format!("/v1/audit?limit=1000&before={next}"), None).await;
    assert!(older["events"].as_array().unwrap().iter().all(|e| e["seq"].as_i64().unwrap() < next));
    assert!(older["next"].is_null());

    // Filters.
    let (_, created) = admin.call("GET", "/v1/audit?action=agent.create&tenant=beta", None).await;
    let created = created["events"].as_array().unwrap();
    assert_eq!(created.len(), 2);
    assert!(created.iter().all(|e| e["tenant"] == "beta" && e["target"].is_string()));
    let (_, prefixed) = admin.call("GET", "/v1/audit?action=tenant.*", None).await;
    assert_eq!(prefixed["events"].as_array().unwrap().len(), 2);
    let (_, none) = admin.call("GET", "/v1/audit?actor=nobody", None).await;
    assert!(none["events"].as_array().unwrap().is_empty());

    // Scoping: a tenant auditor sees her tenant only; other tenants look missing; no platform events.
    let (_, mine) = auditor.call("GET", "/v1/audit?limit=1000", None).await;
    let mine = mine["events"].as_array().unwrap();
    assert!(!mine.is_empty() && mine.iter().all(|e| e["tenant"] == "acme"));
    assert_eq!(auditor.call("GET", "/v1/audit?tenant=beta", None).await.0, S::NOT_FOUND);
    // A viewer has no audit permission at all.
    assert_eq!(viewer.call("GET", "/v1/audit", None).await.0, S::FORBIDDEN);
    assert_eq!(viewer.call("GET", "/v1/audit/export", None).await.0, S::FORBIDDEN);

    // Export: NDJSON, oldest first, complete, and it recomputes to the same chain tip.
    let before_export = admin.call("GET", "/v1/audit/verify", None).await.1["events"].as_i64().unwrap();
    let (s, raw) = admin.text("GET", "/v1/audit/export").await;
    assert_eq!(s, S::OK);
    let lines: Vec<serde_json::Value> = raw.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    // The export records itself first, so it contains its own event as the last line.
    assert_eq!(lines.len() as i64, before_export + 1);
    assert_eq!(lines.last().unwrap()["action"], "audit.export");
    assert!(lines.windows(2).all(|w| w[0]["seq"].as_i64() < w[1]["seq"].as_i64() && w[1]["prev_hash"] == w[0]["hash"]));
    // The export itself is in the trail, and the tenant auditor's export is limited to her tenant.
    let (_, exp) = admin.call("GET", "/v1/audit?action=audit.export", None).await;
    assert_eq!(exp["events"].as_array().unwrap().len(), 1);
    let (_, mine) = auditor.text("GET", "/v1/audit/export").await;
    assert!(mine.lines().all(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["tenant"] == "acme"));
}
