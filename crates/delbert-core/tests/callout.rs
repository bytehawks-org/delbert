//! Authorization callout decisions: who may connect to NATS, and with which subjects.

mod common;

use common::{admin_client, enroll_agent, state};
use delbert_core::{bus_auth::{self, agent_permissions, core_permissions}, compile::Strategy};
use serde_json::json;
use sqlx::PgPool;

#[sqlx::test]
async fn certificates_map_to_confined_permissions_and_revocation_works(pool: PgPool) {
    let st = state(pool.clone(), vec![Strategy::Error], None);
    let ca = st.pki.clone().unwrap();
    let admin = admin_client(st).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    let a1 = enroll_agent(&admin, "acme", "agent-1").await;

    // An enrolled agent gets exactly its own subjects.
    let (name, perms) = bus_auth::decide(&pool, &a1.cert_pem).await.unwrap();
    assert_eq!(name, "agent:acme/agent-1");
    assert_eq!(perms, agent_permissions("acme", "agent-1"));

    // The Core's component certificate gets the Core permissions; other components get nothing.
    let core = ca.issue_client("core-nats", "urn:delbert:component:core-nats", 1).unwrap();
    assert_eq!(bus_auth::decide(&pool, &core.cert_pem).await.unwrap().1, core_permissions());
    let other = ca.issue_client("intruder", "urn:delbert:component:intruder", 1).unwrap();
    assert!(bus_auth::decide(&pool, &other.cert_pem).await.is_err());
    // Server certificates and garbage carry no identity.
    assert!(bus_auth::decide(&pool, ca.issue_server("nats", &["nats".into()], 1).unwrap().cert_pem.as_str()).await.is_err());
    assert!(bus_auth::decide(&pool, "garbage").await.is_err());

    // A valid certificate for an agent that is not on record is refused (e.g. a forged name).
    let (_, csr) = delbert_pki::new_identity("ghost").unwrap();
    let ghost = ca.sign_csr(&csr, "ghost", &delbert_pki::agent_uri("acme", "ghost"), 1).unwrap();
    assert!(bus_auth::decide(&pool, &ghost.cert_pem).await.is_err());

    // Same name, different key (a certificate issued before the agent was re-created): refused.
    let (_, csr) = delbert_pki::new_identity("agent-1").unwrap();
    let stale = ca.sign_csr(&csr, "agent-1", &delbert_pki::agent_uri("acme", "agent-1"), 1).unwrap();
    assert!(bus_auth::decide(&pool, &stale.cert_pem).await.is_err());

    // While a renewal is unconfirmed the previous key still works; once retired it does not.
    sqlx::query("UPDATE agents SET previous_public_key = public_key, public_key = $1").bind(&stale.public_key).execute(&pool).await.unwrap();
    assert!(bus_auth::decide(&pool, &a1.cert_pem).await.is_ok(), "previous key accepted");
    assert!(bus_auth::decide(&pool, &stale.cert_pem).await.is_ok(), "new key accepted");
    sqlx::query("UPDATE agents SET previous_public_key = NULL").execute(&pool).await.unwrap();
    assert!(bus_auth::decide(&pool, &a1.cert_pem).await.is_err(), "retired key refused");

    // Deleting the agent revokes it.
    assert!(bus_auth::decide(&pool, &stale.cert_pem).await.is_ok());
    admin.call("DELETE", "/v1/tenants/acme/agents/agent-1", None).await;
    assert!(bus_auth::decide(&pool, &stale.cert_pem).await.is_err());
}
