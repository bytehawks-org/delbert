//! Adversarial tests of the audit trail: what a database insider (or a compromised Core)
//! can and cannot do without being noticed. The hash chain alone proves consistency, not
//! completeness; the signed anchors (migration 0026) close that gap.

mod common;

use delbert_core::audit::{self, NewEvent};
use delbert_wire::Signer;
use ed25519_dalek::SigningKey;
use serde_json::json;
use sqlx::PgPool;

fn signer(seed: u8, kid: &str) -> Signer {
    Signer::new(SigningKey::from_bytes(&[seed; 32]), kid)
}

fn keys_of(s: &Signer) -> delbert_wire::Verifier {
    audit::anchor_keys(Some(s), &[])
}

async fn add(pool: &PgPool, action: &str) {
    let mut tx = pool.begin().await.unwrap();
    audit::append(&mut tx, &NewEvent { tenant_id: None, actor: "test", action, target: None, outcome: "ok", details: json!({}) }).await.unwrap();
    tx.commit().await.unwrap();
}

/// What a database administrator can do: switch the append-only triggers off.
async fn insider(pool: &PgPool) {
    sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER USER").execute(pool).await.unwrap();
}

#[sqlx::test]
async fn without_anchors_dropping_the_newest_events_goes_unnoticed(pool: PgPool) {
    for a in ["a", "b", "c", "d"] {
        add(&pool, a).await;
    }
    insider(&pool).await;
    sqlx::query("DELETE FROM audit_events WHERE seq > 2").execute(&pool).await.unwrap();
    // The known limit of a bare hash chain: a truncated chain is still a valid chain.
    let v = audit::verify(&pool, &audit::anchor_keys(None, &[])).await.unwrap();
    assert_eq!((v.events, v.first_bad, v.anchors, v.first_bad_anchor), (2, None, 0, None));
}

#[sqlx::test]
async fn anchors_expose_truncation_of_the_tail(pool: PgPool) {
    let s = signer(1, "k1");
    for a in ["a", "b", "c", "d"] {
        add(&pool, a).await;
    }
    let anchor = audit::create_anchor(&pool, &s).await.unwrap().expect("anchor");
    assert_eq!((anchor.seq, anchor.events), (4, 4));
    let v = audit::verify(&pool, &keys_of(&s)).await.unwrap();
    assert_eq!((v.events, v.first_bad, v.anchors, v.first_bad_anchor), (4, None, 1, None));

    insider(&pool).await;
    sqlx::query("DELETE FROM audit_events WHERE seq > 2").execute(&pool).await.unwrap();
    let v = audit::verify(&pool, &keys_of(&s)).await.unwrap();
    assert_eq!(v.first_bad, None, "the shortened chain is internally consistent");
    assert_eq!(v.first_bad_anchor, Some(anchor.id), "but it no longer reaches the anchored head");
}

#[sqlx::test]
async fn anchors_expose_a_complete_rewrite_with_recomputed_hashes(pool: PgPool) {
    let s = signer(1, "k1");
    for a in ["a", "b", "c"] {
        add(&pool, a).await;
    }
    let anchor = audit::create_anchor(&pool, &s).await.unwrap().unwrap();

    // The insider erases history and writes a different one through the real append path:
    // every hash is valid and the chain verifies on its own.
    insider(&pool).await;
    sqlx::query("TRUNCATE audit_events").execute(&pool).await.unwrap();
    for a in ["x", "y", "z"] {
        add(&pool, a).await;
    }
    let v = audit::verify(&pool, &keys_of(&s)).await.unwrap();
    assert_eq!((v.events, v.first_bad), (3, None));
    assert_eq!(v.first_bad_anchor, Some(anchor.id));
}

#[sqlx::test]
async fn forged_or_unknown_anchors_fail_closed(pool: PgPool) {
    let s = signer(1, "k1");
    add(&pool, "a").await;
    let anchor = audit::create_anchor(&pool, &s).await.unwrap().unwrap();

    // Checked with other keys, or with none at all: not trusted.
    for keys in [keys_of(&signer(2, "k1")), audit::anchor_keys(None, &[]), keys_of(&signer(1, "other-kid"))] {
        assert_eq!(audit::verify(&pool, &keys).await.unwrap().first_bad_anchor, Some(anchor.id));
    }

    // An anchor signed by an attacker's key (not the Core's) is rejected, even with a valid-looking row.
    let attacker = signer(9, "k1");
    sqlx::query("ALTER TABLE audit_anchors DISABLE TRIGGER USER").execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM audit_anchors").execute(&pool).await.unwrap();
    sqlx::query("ALTER TABLE audit_anchors ENABLE TRIGGER USER").execute(&pool).await.unwrap();
    audit::create_anchor(&pool, &attacker).await.unwrap().unwrap();
    assert!(audit::verify(&pool, &keys_of(&s)).await.unwrap().first_bad_anchor.is_some());
}

#[sqlx::test]
async fn a_tampered_anchor_row_is_detected(pool: PgPool) {
    let s = signer(1, "k1");
    for a in ["a", "b", "c"] {
        add(&pool, a).await;
    }
    audit::create_anchor(&pool, &s).await.unwrap().unwrap();
    sqlx::query("ALTER TABLE audit_anchors DISABLE TRIGGER USER").execute(&pool).await.unwrap();
    // Pretend the head was an earlier event: the signature no longer covers these fields.
    sqlx::query("UPDATE audit_anchors SET seq = 2, events = 2").execute(&pool).await.unwrap();
    assert!(audit::verify(&pool, &keys_of(&s)).await.unwrap().first_bad_anchor.is_some());
}

#[sqlx::test]
async fn anchors_survive_a_signing_key_rotation(pool: PgPool) {
    let old = signer(1, "k1");
    add(&pool, "a").await;
    audit::create_anchor(&pool, &old).await.unwrap().unwrap();
    add(&pool, "b").await;
    let new = signer(2, "k2");
    audit::create_anchor(&pool, &new).await.unwrap().unwrap();

    // The old key is still published: both anchors check out.
    let published = [delbert_wire::TrustedKey { kid: "k1".into(), public_key: old.public_key_b64() }];
    let v = audit::verify(&pool, &audit::anchor_keys(Some(&new), &published)).await.unwrap();
    assert_eq!((v.anchors, v.first_bad_anchor), (2, None));
    // Once it is dropped, its anchor cannot be trusted any more (and says so).
    assert!(audit::verify(&pool, &keys_of(&new)).await.unwrap().first_bad_anchor.is_some());
}

#[sqlx::test]
async fn anchoring_is_idempotent_and_skips_an_empty_chain(pool: PgPool) {
    let s = signer(1, "k1");
    assert!(audit::create_anchor(&pool, &s).await.unwrap().is_none());
    add(&pool, "a").await;
    assert!(audit::create_anchor(&pool, &s).await.unwrap().is_some());
    assert!(audit::create_anchor(&pool, &s).await.unwrap().is_none(), "same head, nothing new to attest");
    add(&pool, "b").await;
    assert!(audit::create_anchor(&pool, &s).await.unwrap().is_some());
    assert_eq!(audit::anchors(&pool, 10).await.unwrap().len(), 2);
}

#[sqlx::test]
async fn anchors_cannot_be_modified_by_the_runtime_role_or_the_triggers(pool: PgPool) {
    add(&pool, "a").await;
    audit::create_anchor(&pool, &signer(1, "k1")).await.unwrap().unwrap();
    for statement in ["UPDATE audit_anchors SET seq = 1", "DELETE FROM audit_anchors", "TRUNCATE audit_anchors"] {
        // The owner is stopped by the trigger...
        let err = sqlx::query(statement).execute(&pool).await.unwrap_err().to_string();
        assert!(err.contains("append-only"), "{statement}: {err}");
        // ...the runtime role does not even have the privilege.
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL ROLE delbert_app").execute(&mut *tx).await.unwrap();
        let err = sqlx::query(statement).execute(&mut *tx).await.unwrap_err().to_string();
        assert!(err.contains("permission denied"), "{statement}: {err}");
    }
}

#[sqlx::test]
async fn api_anchors_verify_and_permissions(pool: PgPool) {
    use axum::http::StatusCode as S;
    let admin = common::admin_client(common::state(pool.clone(), vec![delbert_core::compile::Strategy::Error], None)).await;
    let (s, v) = admin.call("GET", "/v1/audit/verify", None).await;
    assert_eq!((s, v["anchors"].as_u64(), v["first_bad_anchor"].is_null()), (S::OK, Some(0), true));

    let (s, a) = admin.call("POST", "/v1/audit/anchors", None).await;
    assert_eq!(s, S::OK, "{a}");
    assert_eq!(a["kid"], "k1");
    let (_, list) = admin.call("GET", "/v1/audit/anchors", None).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    let (_, v) = admin.call("GET", "/v1/audit/verify", None).await;
    // The anchoring itself is an audited event after the anchor: the chain moved on, the anchor still matches.
    assert_eq!((v["anchors"].as_u64(), v["first_bad_anchor"].is_null(), v["first_bad"].is_null()), (Some(1), true, true));
    let (_, events) = admin.call("GET", "/v1/audit?action=audit.anchor", None).await;
    assert_eq!(events["events"].as_array().unwrap().len(), 1);

    // Tenant-scoped users and auditors cannot read or create anchors.
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    let (s, _) = admin.call("POST", "/v1/users", Some(json!({ "username": "aud", "password": "a-long-enough-password", "assignments": [{ "role": "auditor", "tenant": "acme" }] }))).await;
    assert_eq!(s, S::CREATED);
    let aud = admin.as_user("aud", "a-long-enough-password").await;
    assert_eq!(aud.call("GET", "/v1/audit/anchors", None).await.0, S::FORBIDDEN);
    assert_eq!(aud.call("POST", "/v1/audit/anchors", None).await.0, S::FORBIDDEN);
    assert_eq!(aud.call("GET", "/v1/audit/verify", None).await.0, S::FORBIDDEN);
}
