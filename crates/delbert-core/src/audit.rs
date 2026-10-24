//! Append-only, hash-chained audit trail (docs/ABSTRACT.md §6).
//!
//! Each event stores `hash = SHA-256(prev_hash || JCS(event fields))`, so any
//! later modification or removal breaks the chain. Appends are serialized by an
//! advisory lock, inside the same transaction as the change being audited.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{
    PgPool, Postgres, Transaction,
    types::{
        Uuid,
        chrono::{DateTime, Utc},
    },
};

/// Arbitrary constant identifying the audit chain lock ("DELB").
const LOCK_KEY: i64 = 0x44454c42;

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("event cannot be canonicalized: {0}")]
    Canon(#[from] delbert_wire::canonical::CanonError),
}

pub struct NewEvent<'a> {
    pub tenant_id: Option<Uuid>,
    pub actor: &'a str,
    pub action: &'a str,
    pub target: Option<&'a str>,
    pub outcome: &'a str,
    /// Integers, strings, booleans, arrays and objects only (no floats).
    pub details: Value,
}

#[allow(clippy::too_many_arguments)]
fn event_hash(
    prev: Option<&[u8]>,
    at: DateTime<Utc>,
    tenant_id: Option<Uuid>,
    actor: &str,
    action: &str,
    target: Option<&str>,
    outcome: &str,
    details: &Value,
) -> Result<Vec<u8>, AuditError> {
    let body = json!({
        "occurred_at": at.timestamp_micros(),
        "tenant_id": tenant_id.map(|t| t.to_string()),
        "actor": actor,
        "action": action,
        "target": target,
        "outcome": outcome,
        "details": details,
    });
    let mut hasher = Sha256::new();
    if let Some(prev) = prev {
        hasher.update(prev);
    }
    hasher.update(delbert_wire::canonical::to_vec(&body)?);
    Ok(hasher.finalize().to_vec())
}

/// Append an event; returns its sequence number.
pub async fn append(tx: &mut Transaction<'_, Postgres>, ev: &NewEvent<'_>) -> Result<i64, AuditError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(LOCK_KEY).execute(&mut **tx).await?;
    let prev: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetch_optional(&mut **tx).await?;

    // PostgreSQL stores microseconds: hash exactly what will be stored.
    let micros = Utc::now().timestamp_micros();
    let at = DateTime::from_timestamp_micros(micros).expect("valid timestamp");
    let hash = event_hash(prev.as_deref(), at, ev.tenant_id, ev.actor, ev.action, ev.target, ev.outcome, &ev.details)?;

    let seq = sqlx::query_scalar(
        "INSERT INTO audit_events (occurred_at, tenant_id, actor, action, target, outcome, details, prev_hash, hash) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING seq",
    )
    .bind(at)
    .bind(ev.tenant_id)
    .bind(ev.actor)
    .bind(ev.action)
    .bind(ev.target)
    .bind(ev.outcome)
    .bind(&ev.details)
    .bind(prev)
    .bind(hash)
    .fetch_one(&mut **tx)
    .await?;
    // Delivered when the transaction commits: the live status stream (stream.rs).
    sqlx::query(&crate::stream::notify_sql("audit")).bind(ev.tenant_id).execute(&mut **tx).await?;
    Ok(seq)
}

#[derive(sqlx::FromRow)]
struct Row {
    seq: i64,
    occurred_at: DateTime<Utc>,
    tenant_id: Option<Uuid>,
    actor: String,
    action: String,
    target: Option<String>,
    outcome: String,
    details: Value,
    prev_hash: Option<Vec<u8>>,
    hash: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
pub struct Verification {
    pub events: u64,
    /// Sequence number of the first event that does not match the chain.
    pub first_bad: Option<i64>,
}

/// Recompute the whole chain and report the first inconsistency.
pub async fn verify(pool: &PgPool) -> Result<Verification, AuditError> {
    let (mut events, mut last_seq, mut expected_prev): (u64, i64, Option<Vec<u8>>) = (0, 0, None);
    loop {
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT seq, occurred_at, tenant_id, actor, action, target, outcome, details, prev_hash, hash \
             FROM audit_events WHERE seq > $1 ORDER BY seq LIMIT 1000",
        )
        .bind(last_seq)
        .fetch_all(pool)
        .await?;
        if rows.is_empty() {
            return Ok(Verification { events, first_bad: None });
        }
        for r in rows {
            let recomputed =
                event_hash(r.prev_hash.as_deref(), r.occurred_at, r.tenant_id, &r.actor, &r.action, r.target.as_deref(), &r.outcome, &r.details)?;
            if r.prev_hash != expected_prev || r.hash != recomputed {
                return Ok(Verification { events, first_bad: Some(r.seq) });
            }
            events += 1;
            last_seq = r.seq;
            expected_prev = Some(r.hash);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn add(pool: &PgPool, action: &str) {
        let mut tx = pool.begin().await.unwrap();
        append(&mut tx, &NewEvent { tenant_id: None, actor: "test", action, target: None, outcome: "ok", details: json!({"n": 1}) })
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    #[sqlx::test]
    async fn chain_verifies_and_detects_tampering(pool: PgPool) {
        assert_eq!(verify(&pool).await.unwrap(), Verification { events: 0, first_bad: None });
        for a in ["a", "b", "c"] {
            add(&pool, a).await;
        }
        assert_eq!(verify(&pool).await.unwrap(), Verification { events: 3, first_bad: None });

        // The append-only triggers block normal tampering...
        assert!(sqlx::query("UPDATE audit_events SET actor = 'evil' WHERE seq = 2").execute(&pool).await.is_err());
        assert!(sqlx::query("DELETE FROM audit_events WHERE seq = 2").execute(&pool).await.is_err());

        // ...and if a superuser bypasses them, the hash chain still exposes it.
        sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER USER").execute(&pool).await.unwrap();
        sqlx::query("UPDATE audit_events SET actor = 'evil' WHERE seq = 2").execute(&pool).await.unwrap();
        let v = verify(&pool).await.unwrap();
        assert_eq!(v.first_bad, Some(2));
    }

    #[sqlx::test]
    async fn concurrent_appends_keep_a_single_chain(pool: PgPool) {
        let tasks: Vec<_> = (0..8)
            .map(|i| {
                let pool = pool.clone();
                tokio::spawn(async move { add(&pool, &format!("e{i}")).await })
            })
            .collect();
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(verify(&pool).await.unwrap(), Verification { events: 8, first_bad: None });
    }
}
