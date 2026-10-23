//! Tenant secrets (encrypted per agent) and pinned artifacts.

mod common;

use age::secrecy::ExposeSecret as _;
use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}};
use common::{Client, admin_client, enroll_agent, signing_key, state};
use delbert_core::compile::Strategy;
use delbert_wire::{EffectivePolicy, Expect, Verifier};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

fn verify(token: &str, agent: &str) -> EffectivePolicy {
    let mut v = Verifier::default();
    v.add_key("k1", &URL_SAFE_NO_PAD.encode(signing_key().verifying_key().to_bytes())).unwrap();
    v.verify(token, &Expect { tenant: "acme", agent, now: now() }, |_| None).unwrap()
}

fn policy(name: &str, spec: &str, resources: &str) -> Value {
    json!({ "yaml": format!("apiVersion: delbert/v1\nkind: Policy\nmetadata: {{ name: {name}, tenant: acme }}\nspec:\n{spec}  resources:\n{resources}") })
}

const TEMPLATE: &str = "    - id: db\n      template: { src: \"artifact://db.j2\", dest: /etc/db.conf }\n";

#[sqlx::test]
async fn secrets_are_write_only_and_encrypted_for_the_target_agent(pool: PgPool) {
    let admin = admin_client(state(pool.clone(), vec![Strategy::Error], None)).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    let a1 = enroll_agent(&admin, "acme", "agent-1").await;
    let a2 = enroll_agent(&admin, "acme", "agent-2").await;

    // Only holders of secrets:write set them; nobody reads them back.
    admin.call("POST", "/v1/users", Some(json!({ "username": "olivia", "password": "a-long-enough-password", "assignments": [{ "role": "operator", "tenant": "acme" }] }))).await;
    let operator = admin.as_user("olivia", "a-long-enough-password").await;
    assert_eq!(operator.call("PUT", "/v1/tenants/acme/secrets/db", Some(json!({ "value": "x" }))).await.0, StatusCode::FORBIDDEN);
    assert_eq!(admin.call("PUT", "/v1/tenants/acme/secrets/db", Some(json!({ "value": "hunter2" }))).await.0, StatusCode::NO_CONTENT);
    let (_, list) = admin.call("GET", "/v1/tenants/acme/secrets", None).await;
    assert_eq!(list[0]["name"], "db");
    assert!(!list.to_string().contains("hunter2"));

    // At rest the value is not readable from the database.
    let stored: Vec<u8> = sqlx::query_scalar("SELECT ciphertext FROM secrets WHERE name = 'db'").fetch_one(&pool).await.unwrap();
    assert!(!String::from_utf8_lossy(&stored).contains("hunter2"));

    // The policy names the secret; the effective policy carries it encrypted to each agent.
    let spec = "  secrets: [db, nope]\n";
    assert_eq!(admin.call("POST", "/v1/tenants/acme/policies", Some(policy("p", spec, "    - id: f\n      file: { path: /etc/f }\n"))).await.0, StatusCode::CREATED);
    let (_, issued1) = admin.call("GET", "/v1/tenants/acme/agents/agent-1/effective", None).await;
    let (_, issued2) = admin.call("GET", "/v1/tenants/acme/agents/agent-2/effective", None).await;
    let (eff1, eff2) = (verify(issued1["token"].as_str().unwrap(), "agent-1"), verify(issued2["token"].as_str().unwrap(), "agent-2"));
    assert_eq!(eff1.secrets.keys().collect::<Vec<_>>(), vec!["db"]);

    let open = |id: &age::x25519::Identity, eff: &EffectivePolicy| age::decrypt(id, &STANDARD.decode(&eff.secrets["db"]).unwrap());
    assert_eq!(open(&a1.age, &eff1).unwrap(), b"hunter2");
    assert_eq!(open(&a2.age, &eff2).unwrap(), b"hunter2");
    assert!(open(&a2.age, &eff1).is_err() && open(&a1.age, &eff2).is_err(), "ciphertext is bound to its agent");
    assert!(!issued1["token"].to_string().contains("hunter2"));
    assert_eq!(issued1["conflicts"][0]["what"], "secret 'nope'");

    // Re-issuing keeps the version although age output is randomized; a new value bumps it.
    let (_, again) = admin.call("GET", "/v1/tenants/acme/agents/agent-1/effective", None).await;
    assert_eq!(again["version"], issued1["version"]);
    admin.call("PUT", "/v1/tenants/acme/secrets/db", Some(json!({ "value": "rotated" }))).await;
    let (_, rotated) = admin.call("GET", "/v1/tenants/acme/agents/agent-1/effective", None).await;
    assert_eq!(rotated["version"].as_i64().unwrap(), issued1["version"].as_i64().unwrap() + 1);
    let eff = verify(rotated["token"].as_str().unwrap(), "agent-1");
    assert_eq!(open(&a1.age, &eff).unwrap(), b"rotated");

    assert_eq!(admin.call("DELETE", "/v1/tenants/acme/secrets/db", None).await.0, StatusCode::NO_CONTENT);
    assert_eq!(admin.call("DELETE", "/v1/tenants/acme/secrets/db", None).await.0, StatusCode::NOT_FOUND);
    let (_, v) = admin.call("GET", "/v1/audit/verify", None).await;
    assert_eq!(v["first_bad"], Value::Null);
    let audit: String = sqlx::query_scalar("SELECT string_agg(details::text, ' ') FROM audit_events").fetch_one(&pool).await.unwrap();
    assert!(!audit.contains("hunter2") && !audit.contains("rotated"), "secret values never reach the audit trail");
    let _ = a1.age.to_string().expose_secret();
}

#[sqlx::test]
async fn artifacts_are_versioned_pinned_and_served_only_to_proven_agents(pool: PgPool) {
    let admin = admin_client(state(pool, vec![Strategy::Error], None)).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    let a1 = enroll_agent(&admin, "acme", "agent-1").await;
    let a2 = enroll_agent(&admin, "acme", "agent-2").await;

    // A policy using a missing artifact is left out and reported.
    admin.call("POST", "/v1/tenants/acme/policies", Some(policy("p", "", TEMPLATE))).await;
    let (_, none) = admin.call("GET", "/v1/tenants/acme/agents/agent-1/effective", None).await;
    assert_eq!(none["conflicts"][0]["what"], "artifact 'db.j2'");
    assert!(verify(none["token"].as_str().unwrap(), "agent-1").resources.is_empty());

    // Upload: new version, same content again is a no-op, changed content is a new version.
    let up = |body: &'static [u8]| admin.raw("PUT", "/v1/tenants/acme/artifacts/db.j2", vec![("content-type", "application/octet-stream".into())], body.to_vec());
    let (s, b) = up(b"password={{ secrets.db }}\n").await;
    let v1: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!((s, v1["version"].clone()), (StatusCode::CREATED, json!(1)));
    let (s, b) = up(b"password={{ secrets.db }}\n").await;
    assert_eq!((s, serde_json::from_slice::<Value>(&b).unwrap()["version"].clone()), (StatusCode::OK, json!(1)));
    let sha1 = v1["sha256"].as_str().unwrap().to_owned();
    assert_eq!(sha1, Sha256::digest(b"password={{ secrets.db }}\n").iter().map(|b| format!("{b:02x}")).collect::<String>());

    // The effective policy pins the hash and the version moves when the artifact changes.
    let (_, pinned) = admin.call("GET", "/v1/tenants/acme/agents/agent-1/effective", None).await;
    let eff = verify(pinned["token"].as_str().unwrap(), "agent-1");
    assert_eq!(eff.artifacts["db.j2"].sha256, sha1);
    assert_eq!(pinned["conflicts"], json!([]));
    let (s, b) = up(b"password={{ secrets.db }}\n# v2\n").await;
    assert_eq!(s, StatusCode::CREATED);
    let sha2 = serde_json::from_slice::<Value>(&b).unwrap()["sha256"].as_str().unwrap().to_owned();
    let (_, moved) = admin.call("GET", "/v1/tenants/acme/agents/agent-1/effective", None).await;
    assert_eq!(moved["version"].as_i64().unwrap(), pinned["version"].as_i64().unwrap() + 1);
    assert_eq!(verify(moved["token"].as_str().unwrap(), "agent-1").artifacts["db.j2"].sha256, sha2);

    // Download by hash needs the agent's proof; the old version is still there.
    let anon = Client { token: None, ..admin.clone() };
    let download = |agent: &str, key: &str, name: &str, sha: &str, proof_agent: &str| {
        let proof = delbert_pki::authn::prove(key, "artifact", "acme", proof_agent, &Value::String(format!("{name}:{sha}")), now()).unwrap();
        let header = format!("Delbert-Agent {}", STANDARD.encode(serde_json::to_vec(&proof).unwrap()));
        anon.raw("GET", format!("/v1/agent/acme/{agent}/artifacts/{name}?sha256={sha}"), vec![("authorization", header)], vec![])
    };
    let (s, body) = download("agent-1", &a1.key_pem, "db.j2", &sha1, "agent-1").await;
    assert_eq!((s, body), (StatusCode::OK, b"password={{ secrets.db }}\n".to_vec()));
    assert_eq!(download("agent-1", &a1.key_pem, "db.j2", &sha2, "agent-1").await.0, StatusCode::OK);
    assert_eq!(download("agent-1", &a1.key_pem, "db.j2", &"00".repeat(32), "agent-1").await.0, StatusCode::NOT_FOUND);
    assert_eq!(download("agent-1", &a2.key_pem, "db.j2", &sha1, "agent-1").await.0, StatusCode::UNAUTHORIZED); // someone else's key
    assert_eq!(download("agent-1", &a1.key_pem, "db.j2", &sha1, "agent-2").await.0, StatusCode::UNAUTHORIZED); // proof for another agent
    assert_eq!(anon.raw("GET", format!("/v1/agent/acme/agent-1/artifacts/db.j2?sha256={sha1}"), vec![], vec![]).await.0, StatusCode::UNAUTHORIZED);
    // A proof for one artifact is useless for another hash (it signs name and hash).
    let proof = delbert_pki::authn::prove(&a1.key_pem, "artifact", "acme", "agent-1", &Value::String(format!("db.j2:{sha1}")), now()).unwrap();
    let header = format!("Delbert-Agent {}", STANDARD.encode(serde_json::to_vec(&proof).unwrap()));
    assert_eq!(anon.raw("GET", format!("/v1/agent/acme/agent-1/artifacts/db.j2?sha256={sha2}"), vec![("authorization", header)], vec![]).await.0, StatusCode::UNAUTHORIZED);

    let (_, list) = admin.call("GET", "/v1/tenants/acme/artifacts", None).await;
    assert_eq!((list[0]["name"].clone(), list[0]["version"].clone()), (json!("db.j2"), json!(2)));
}
