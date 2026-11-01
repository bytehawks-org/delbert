//! Host facts reported by agents. Needs PostgreSQL and NATS (skipped silently without NATS_URL).

use std::time::Duration;

use delbert_core::{
    bus::{self, Bus},
    compile::Strategy,
};
use serde_json::{Value, json};
use sqlx::PgPool;

mod common;

use common::{admin_client, enroll_agent, state};

fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

#[sqlx::test]
async fn facts_ride_on_reports_and_follow_the_agent(pool: PgPool) {
    let Ok(url) = std::env::var("NATS_URL") else {
        eprintln!("NATS_URL not set: skipping");
        return;
    };
    let client = async_nats::connect(&url).await.expect("NATS reachable");
    let app_state = state(pool.clone(), vec![Strategy::Error], Some(Bus::from_client(client.clone())));
    tokio::spawn(bus::serve(app_state.clone()));
    let c = admin_client(app_state).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    c.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    let key = enroll_agent(&c, "acme", "agent-1").await.key_pem;

    let send = |report: Value| {
        let client = client.clone();
        let proof = delbert_pki::authn::prove(&key, "report", "acme", "agent-1", &report, unix_now()).unwrap();
        async move { client.publish("delbert.report.acme.agent-1", json!({ "proof": proof, "report": report }).to_string().into()).await.unwrap() }
    };
    let agent = || async {
        let (_, agents) = c.call("GET", "/v1/tenants/acme/agents", None).await;
        agents[0].clone()
    };
    let c_ref = &c;
    let wait_for = |at: i64| async move {
        let c = c_ref;
        for _ in 0..30 {
            let (_, agents) = c.call("GET", "/v1/tenants/acme/agents", None).await;
            if agents[0]["reported_at"].as_i64().is_some() && agents[0]["facts_at"].as_i64().unwrap_or(0) >= at {
                return agents[0].clone();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Value::Null
    };

    // No facts yet.
    assert_eq!(agent().await["facts"], Value::Null);

    // A report with facts: the known keys are stored, the rest (and the oversized) is not.
    let facts = json!({ "os_family": "debian", "distribution": "ubuntu", "os_version": "24.04", "kernel": "6.8.0", "hostname": "web01", "domain": "example.com",
                        "ips": ["10.0.0.5", "bogus"], "machine_id": "must-not-be-kept" });
    send(json!({ "version": 1, "at": unix_now(), "compliant": true, "resources": [], "facts": facts })).await;
    let seen = wait_for(1).await;
    assert_eq!(seen["facts"]["distribution"], "ubuntu", "{seen}");
    assert_eq!(seen["facts"]["ips"], json!(["10.0.0.5"]));
    assert!(seen["facts"].get("machine_id").is_none());

    // The stored report does not carry them twice.
    let stored: Value = sqlx::query_scalar("SELECT report FROM agent_reports").fetch_one(&pool).await.unwrap();
    assert!(stored.get("facts").is_none(), "{stored}");

    // A later report without facts replaces the report but keeps the facts.
    send(json!({ "version": 2, "at": unix_now() + 1, "compliant": false, "resources": [] })).await;
    for _ in 0..30 {
        if agent().await["reported_version"] == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let seen = agent().await;
    assert_eq!(seen["reported_version"], 2);
    assert_eq!(seen["facts"]["hostname"], "web01");

    // They go away with the agent.
    assert_eq!(c.call("DELETE", "/v1/tenants/acme/agents/agent-1", None).await.0, axum::http::StatusCode::NO_CONTENT);
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM agent_reports").fetch_one(&pool).await.unwrap();
    assert_eq!(left, 0);
    client.drain().await.ok();
}
