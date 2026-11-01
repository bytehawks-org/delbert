//! Inconsistent agents and the forced release of a quarantined version (docs/REMEDIATION.md).

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use common::{Client, admin_client, enroll_agent, signing_key, state};
use delbert_core::{
    bus::{self, Bus},
    compile::Strategy,
};
use delbert_wire::{Expect, Verifier};
use serde_json::{Value, json};
use sqlx::PgPool;

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

fn verify(token: &str) -> delbert_wire::EffectivePolicy {
    let mut v = Verifier::default();
    v.add_key("k1", &B64.encode(signing_key().verifying_key().to_bytes())).unwrap();
    v.verify(token, &Expect { tenant: "acme", agent: "agent-1", now: now() }, |_| None).unwrap()
}

fn remediation(failed: i64, at: i64) -> Value {
    json!({ "state": "rolled_back", "failed_version": failed, "running_version": failed - 1, "resource": "web", "reason": "nginx is in the failed state",
            "at": at, "steps": ["nginx: stopped cleanly after 1 s", "re-applied the last known good policy v4"], "forced_kill": false })
}

async fn report(pool: &PgPool, remediation: Value, at: i64) {
    sqlx::query("INSERT INTO agent_reports (agent_id, version, compliant, report) SELECT id, 4, false, $1 FROM agents WHERE name = 'agent-1' \
                 ON CONFLICT (agent_id) DO UPDATE SET report = $1, received_at = now()")
        .bind(json!({ "version": 4, "at": at, "compliant": false, "resources": [], "remediation": remediation }))
        .execute(pool)
        .await
        .unwrap();
}

async fn agent(c: &Client) -> Value {
    c.call("GET", "/v1/tenants/acme/agents", None).await.1[0].clone()
}

async fn token(c: &Client) -> delbert_wire::EffectivePolicy {
    verify(c.call("GET", "/v1/tenants/acme/agents/agent-1/effective", None).await.1["token"].as_str().unwrap())
}

#[sqlx::test]
async fn an_inconsistent_agent_is_released_by_a_signed_audited_decision(pool: PgPool) {
    let admin = admin_client(state(pool.clone(), vec![Strategy::Error], None)).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    enroll_agent(&admin, "acme", "agent-1").await;
    let force = |c: &Client, version: i64| {
        let c = c.clone();
        async move { c.call("POST", "/v1/tenants/acme/agents/agent-1/remediation/force", Some(json!({ "version": version, "note": "disk was full, freed it" }))).await.0 }
    };

    // Healthy: nothing to release.
    assert_eq!(agent(&admin).await["remediation"], Value::Null);
    assert_eq!(force(&admin, 5).await, StatusCode::CONFLICT);

    // The agent reports a rollback: the Core shows it and counts it.
    report(&pool, remediation(5, now()), now()).await;
    let a = agent(&admin).await;
    assert_eq!(a["remediation"]["failed_version"], 5);
    assert_eq!(a["remediation"]["steps"].as_array().unwrap().len(), 2);
    assert_eq!(a["force_pending"], false);
    let overview = admin.call("GET", "/v1/overview", None).await.1;
    assert_eq!(overview["inconsistent"], 1, "{overview}");
    assert_eq!(overview["attention"][0]["state"], "inconsistent");
    assert!(token(&admin).await.force.is_none());

    // Only for the version that is quarantined, and only with the permission.
    assert_eq!(force(&admin, 4).await, StatusCode::CONFLICT);
    let op = admin.call("POST", "/v1/users", Some(json!({ "username": "olivia", "password": "correct horse battery", "assignments": [{ "role": "operator", "tenant": "acme" }] }))).await;
    assert_eq!(op.0, StatusCode::CREATED, "{}", op.1);
    let olivia = admin.as_user("olivia", "correct horse battery").await;
    assert_eq!(force(&olivia, 5).await, StatusCode::FORBIDDEN);
    assert!(token(&admin).await.force.is_none());

    // The decision is signed into the agent's policy, audited with its reason, and pending until obeyed.
    assert_eq!(force(&admin, 5).await, StatusCode::NO_CONTENT);
    let forced = token(&admin).await.force.expect("signed force");
    assert_eq!(forced.version, 5);
    assert!(agent(&admin).await["force_pending"].as_bool().unwrap());
    let (_, audit) = admin.call("GET", "/v1/audit?action=remediation.force", None).await;
    assert_eq!(audit["events"][0]["details"]["note"], "disk was full, freed it");
    assert_eq!(audit["events"][0]["actor"], "admin");

    // Withdrawn before the agent obeys it.
    assert_eq!(admin.call("DELETE", "/v1/tenants/acme/agents/agent-1/remediation/force", None).await.0, StatusCode::NO_CONTENT);
    assert!(token(&admin).await.force.is_none());
    assert_eq!(admin.call("DELETE", "/v1/tenants/acme/agents/agent-1/remediation/force", None).await.0, StatusCode::NOT_FOUND);

    // Each decision has its own id.
    force(&admin, 5).await;
    assert_ne!(token(&admin).await.force.unwrap().id, forced.id);

    // The agent obeyed and failed again: a newer quarantine, the old decision is not pending any more.
    report(&pool, remediation(5, now() + 60), now() + 60).await;
    assert!(!agent(&admin).await["force_pending"].as_bool().unwrap());
}

#[sqlx::test]
async fn a_consistent_report_ends_the_release_and_remediation_events_reach_the_trail(pool: PgPool) {
    let Ok(url) = std::env::var("NATS_URL") else {
        eprintln!("NATS_URL not set: skipping");
        return;
    };
    let client = async_nats::connect(&url).await.expect("NATS reachable");
    let app_state = state(pool.clone(), vec![Strategy::Error], Some(Bus::from_client(client.clone())));
    tokio::spawn(bus::serve(app_state.clone()));
    let admin = admin_client(app_state).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    let key = enroll_agent(&admin, "acme", "agent-1").await.key_pem;
    report(&pool, remediation(5, now()), now()).await;
    admin.call("POST", "/v1/tenants/acme/agents/agent-1/remediation/force", Some(json!({ "version": 5 }))).await;
    assert!(token(&admin).await.force.is_some());

    // The agent applied the version again and is consistent: no `remediation` in the report.
    let body = json!({ "version": 5, "at": now() + 1, "compliant": true, "resources": [], "remediation": null });
    let proof = delbert_pki::authn::prove(&key, "report", "acme", "agent-1", &body, now()).unwrap();
    client.publish("delbert.report.acme.agent-1", json!({ "proof": proof, "report": body }).to_string().into()).await.unwrap();
    for _ in 0..30 {
        if token(&admin).await.force.is_none() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(token(&admin).await.force.is_none(), "the release is over once the agent is consistent");
    assert_eq!(agent(&admin).await["remediation"], Value::Null);

    // The events the agent sends are classified.
    let events = json!([
        { "id": "0123456789abcdef", "kind": "policy.rolled_back", "at": now(), "resource": "web", "version": 5, "detail": "v5 failed" },
        { "id": "0123456789abcdee", "kind": "service.stop_forced", "at": now(), "resource": "web", "version": 5, "detail": "SIGKILL" },
    ]);
    let proof = delbert_pki::authn::prove(&key, "event", "acme", "agent-1", &events, now()).unwrap();
    let anon = Client { token: None, ..admin.clone() };
    let sent = anon.raw("POST", "/v1/agent/acme/agent-1/events", vec![("content-type", "application/json".into())], serde_json::to_vec(&json!({ "proof": proof, "events": events })).unwrap()).await;
    assert_eq!(sent.0, StatusCode::OK);
    let (_, audit) = admin.call("GET", "/v1/audit?action=agent.*", None).await;
    let actions: Vec<&str> = audit["events"].as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
    assert!(actions.contains(&"agent.policy.rolled_back") && actions.contains(&"agent.service.stop_forced"), "{actions:?}");
    client.drain().await.ok();
}
