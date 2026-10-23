//! NATS integration test. Needs PostgreSQL (DATABASE_URL) and NATS (NATS_URL);
//! it is skipped silently when NATS_URL is not set.

use std::time::Duration;

use delbert_core::{
    bus::{self, Bus},
    compile::Strategy,
};
use delbert_wire::{Expect, Verifier};
use futures::StreamExt;
use serde_json::{Value, json};
use sqlx::PgPool;

mod common;

use common::{admin_client, enroll_agent, signing_key, state};

fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

#[sqlx::test]
async fn notify_pull_and_report_over_nats(pool: PgPool) {
    let Ok(url) = std::env::var("NATS_URL") else {
        eprintln!("NATS_URL not set: skipping");
        return;
    };
    let client = async_nats::connect(&url).await.expect("NATS reachable");
    let app_state = state(pool, vec![Strategy::Error], Some(Bus::from_client(client.clone())));
    tokio::spawn(bus::serve(app_state.clone()));
    let c = admin_client(app_state).await;
    tokio::time::sleep(Duration::from_millis(500)).await; // let the subscriptions register

    c.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    let key_pem = enroll_agent(&c, "acme", "agent-1").await.key_pem; // also creates the agent, in group "web"
    let other_key = enroll_agent(&c, "acme", "agent-2").await.key_pem;
    let proof = |key: &str, kind: &str, agent: &str, body: &Value| delbert_pki::authn::prove(key, kind, "acme", agent, body, unix_now()).unwrap();

    // Creating a policy notifies the tenant's agents.
    let mut notifications = client.subscribe("delbert.notify.acme.agent-1").await.unwrap();
    let yaml = "apiVersion: delbert/v1\nkind: Policy\nmetadata: { name: p, tenant: acme }\nspec:\n  resources:\n    - id: f\n      file: { path: /etc/f }\n";
    c.call("POST", "/v1/tenants/acme/policies", Some(json!({ "yaml": yaml }))).await;
    let note = tokio::time::timeout(Duration::from_secs(3), notifications.next()).await.expect("notification").unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&note.payload).unwrap()["event"], "policy-changed");

    // The agent pulls the signed policy over request/reply, proving who it is.
    let ask = |agent: &str, proof: delbert_pki::authn::Proof| {
        let client = client.clone();
        let subject = format!("delbert.req.acme.{agent}.effective");
        async move {
            let reply = tokio::time::timeout(Duration::from_secs(5), client.request(subject, serde_json::to_vec(&proof).unwrap().into())).await.unwrap().unwrap();
            serde_json::from_slice::<Value>(&reply.payload).unwrap()
        }
    };
    // No proof, a proof of another agent, a proof for another kind, and a stale one are all refused.
    let nothing = tokio::time::timeout(Duration::from_secs(5), client.request("delbert.req.acme.agent-1.effective", "".into())).await.unwrap().unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&nothing.payload).unwrap()["error"], "unauthorized");
    assert_eq!(ask("agent-1", proof(&other_key, "req", "agent-1", &Value::Null)).await["error"], "unauthorized");
    assert_eq!(ask("agent-1", proof(&key_pem, "report", "agent-1", &Value::Null)).await["error"], "unauthorized");
    let stale = delbert_pki::authn::prove(&key_pem, "req", "acme", "agent-1", &Value::Null, unix_now() - 3_600).unwrap();
    assert_eq!(ask("agent-1", stale).await["error"], "unauthorized");
    let body = ask("agent-1", proof(&key_pem, "req", "agent-1", &Value::Null)).await;
    let mut verifier = Verifier::default();
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    verifier.add_key("k1", &B64.encode(signing_key().verifying_key().to_bytes())).unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let eff = verifier.verify(body["token"].as_str().unwrap(), &Expect { tenant: "acme", agent: "agent-1", now }, |_| None).unwrap();
    assert_eq!(eff.resources[0].id, "p/f");

    // Unknown agents get an error, not a policy.
    assert!(ask("ghost", proof(&key_pem, "req", "ghost", &Value::Null)).await["error"].is_string());

    // Reports end up on the agent record; reports for unknown agents are ignored.
    let report = json!({ "version": 1, "compliant": true, "resources": [] });
    let forged = json!({ "version": 99, "compliant": true, "resources": [] });
    let envelope = |agent: &str, key: &str, signed_body: &Value, sent_body: &Value| json!({ "proof": proof(key, "report", agent, signed_body), "report": sent_body }).to_string();
    // Unsigned, signed by someone else, tampered after signing, for an unknown agent: all dropped.
    client.publish("delbert.report.acme.agent-1", json!({ "report": forged }).to_string().into()).await.unwrap();
    client.publish("delbert.report.acme.agent-1", envelope("agent-1", &other_key, &forged, &forged).into()).await.unwrap();
    client.publish("delbert.report.acme.agent-1", envelope("agent-1", &key_pem, &report, &forged).into()).await.unwrap();
    client.publish("delbert.report.acme.ghost", envelope("ghost", &key_pem, &report, &report).into()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (_, agents) = c.call("GET", "/v1/tenants/acme/agents", None).await;
    assert_eq!(agents[0]["compliant"], Value::Null, "forged reports must not be stored: {agents}");
    client.publish("delbert.report.acme.agent-1", envelope("agent-1", &key_pem, &report, &report).into()).await.unwrap();
    let mut seen = Value::Null;
    for _ in 0..30 {
        let (_, agents) = c.call("GET", "/v1/tenants/acme/agents", None).await;
        seen = agents[0].clone();
        if seen["compliant"] == true {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(seen["compliant"], true, "{seen}");

    // Renewal rotates the key. The request is proven with the CURRENT key and carries a CSR for a new one.
    let (new_key, csr) = delbert_pki::new_identity("agent-1").unwrap();
    let renew = |key: &str, csr: &str| {
        let client = client.clone();
        let proof = delbert_pki::authn::prove(key, "renew", "acme", "agent-1", &json!({ "csr_pem": csr }), unix_now()).unwrap();
        let payload = json!({ "proof": proof, "csr_pem": csr }).to_string();
        async move {
            let reply = tokio::time::timeout(Duration::from_secs(5), client.request("delbert.req.acme.agent-1.renew", payload.into())).await.unwrap().unwrap();
            serde_json::from_slice::<Value>(&reply.payload).unwrap()
        }
    };
    assert_eq!(renew(&other_key, &csr).await["error"], "unauthorized", "someone else's key cannot renew");
    let renewed = renew(&key_pem, &csr).await;
    assert!(renewed["cert_pem"].as_str().unwrap().contains("BEGIN CERTIFICATE"), "{renewed}");
    // The reply could have been lost: until the new key is used, the old one still works...
    let still = ask("agent-1", proof(&key_pem, "req", "agent-1", &Value::Null)).await;
    assert!(still["token"].is_string(), "previous key accepted: {still}");
    // ...and the first proof with the new key retires it.
    assert!(ask("agent-1", proof(&new_key, "req", "agent-1", &Value::Null)).await["token"].is_string());
    assert_eq!(ask("agent-1", proof(&key_pem, "req", "agent-1", &Value::Null)).await["error"], "unauthorized");
    assert_eq!(seen["reported_version"], 1);
}
