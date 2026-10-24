//! Fleet overview: counts and the agents that need attention, scoped to the caller's tenants.

mod common;

use axum::http::StatusCode;
use common::{admin_client, state};
use delbert_core::compile::Strategy;
use serde_json::json;
use sqlx::PgPool;

#[sqlx::test]
async fn the_overview_counts_the_fleet_and_respects_tenant_scope(pool: PgPool) {
    let admin = admin_client(state(pool.clone(), vec![Strategy::Error], None)).await;
    for t in ["acme", "beta"] {
        assert_eq!(admin.call("POST", "/v1/tenants", Some(json!({ "name": t }))).await.0, StatusCode::CREATED);
    }
    for (t, a) in [("acme", "ok-1"), ("acme", "silent-1"), ("acme", "old-1"), ("beta", "drift-1")] {
        assert_eq!(admin.call("POST", &format!("/v1/tenants/{t}/agents"), Some(json!({ "name": a }))).await.0, StatusCode::CREATED);
    }
    // ok-1 reported compliant a moment ago, drift-1 reported a drift, old-1 reported an hour ago, silent-1 never did.
    let report = |name: &'static str, compliant: bool, age: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query(&format!("INSERT INTO agent_reports (agent_id, version, compliant, report, received_at) SELECT id, 1, $2, '{{}}', now() - interval '{age}' FROM agents WHERE name = $1"))
                .bind(name)
                .bind(compliant)
                .execute(&pool)
                .await
                .unwrap();
        }
    };
    report("ok-1", true, "10 seconds").await;
    report("drift-1", false, "20 seconds").await;
    report("old-1", true, "1 hour").await;

    let (status, all) = admin.call("GET", "/v1/overview", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!((all["tenants"].as_i64(), all["agents"].as_i64()), (Some(2), Some(4)));
    assert_eq!((all["compliant"].as_i64(), all["drifted"].as_i64(), all["silent"].as_i64()), (Some(1), Some(1), Some(2)), "{all}");
    // Drifted first, then the silent ones, the longest silent (never reported) first.
    let order: Vec<String> = all["attention"].as_array().unwrap().iter().map(|a| format!("{}/{}:{}", a["tenant"].as_str().unwrap(), a["name"].as_str().unwrap(), a["state"].as_str().unwrap())).collect();
    assert_eq!(order, ["beta/drift-1:drifted", "acme/silent-1:silent", "acme/old-1:silent"]);

    // A longer window makes the hour-old report current again.
    let (_, wide) = admin.call("GET", "/v1/overview?stale_secs=7200", None).await;
    assert_eq!((wide["compliant"].as_i64(), wide["silent"].as_i64()), (Some(2), Some(1)));

    // A tenant-scoped user sees only their tenant; an archived tenant disappears from the totals.
    assert_eq!(admin.call("POST", "/v1/users", Some(json!({ "username": "olivia", "password": "a-long-enough-password", "assignments": [{ "role": "operator", "tenant": "acme" }] }))).await.0, StatusCode::CREATED);
    let olivia = admin.as_user("olivia", "a-long-enough-password").await;
    let (_, mine) = olivia.call("GET", "/v1/overview", None).await;
    assert_eq!((mine["tenants"].as_i64(), mine["agents"].as_i64(), mine["drifted"].as_i64()), (Some(1), Some(3), Some(0)), "{mine}");
    for a in ["drift-1"] {
        admin.call("DELETE", &format!("/v1/tenants/beta/agents/{a}"), None).await;
    }
    assert_eq!(admin.call("DELETE", "/v1/tenants/beta", None).await.0, StatusCode::NO_CONTENT);
    let (_, after) = admin.call("GET", "/v1/overview", None).await;
    assert_eq!((after["tenants"].as_i64(), after["agents"].as_i64()), (Some(1), Some(3)));
}
