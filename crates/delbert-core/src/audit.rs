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
    /// Signed anchors checked against the chain.
    pub anchors: u64,
    /// Id of the first anchor that does not match: a bad signature, a missing or different
    /// event at its position (truncation, rewrite) or a different event count.
    pub first_bad_anchor: Option<i64>,
}

/// Domain separation of anchor signatures from every other use of the signing key.
const ANCHOR_DOMAIN: &str = "delbert-audit-anchor-v1";

/// The exact bytes an anchor signs: JCS of its fields (hash as lowercase hex).
fn anchor_document(seq: i64, hash: &[u8], events: i64, at: DateTime<Utc>, kid: &str) -> Result<Vec<u8>, AuditError> {
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    Ok(delbert_wire::canonical::to_vec(&json!({ "v": 1, "seq": seq, "hash": hex, "events": events, "at": at.timestamp_micros(), "kid": kid }))?)
}

/// A signed anchor of the chain head, as stored and exported.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
pub struct Anchor {
    pub id: i64,
    /// Microseconds since the Unix epoch, as signed.
    pub at_micros: i64,
    pub seq: i64,
    /// Lowercase hex of the head event's hash.
    pub hash: String,
    pub events: i64,
    pub kid: String,
    /// Detached Ed25519 signature (base64url); verify with the published key `kid`.
    pub signature: String,
}

#[derive(sqlx::FromRow)]
struct AnchorRow {
    id: i64,
    created_at: DateTime<Utc>,
    seq: i64,
    hash: Vec<u8>,
    events: i64,
    kid: String,
    signature: String,
}

impl AnchorRow {
    fn export(self) -> Anchor {
        Anchor {
            id: self.id,
            at_micros: self.created_at.timestamp_micros(),
            hash: self.hash.iter().map(|b| format!("{b:02x}")).collect(),
            seq: self.seq,
            events: self.events,
            kid: self.kid,
            signature: self.signature,
        }
    }
}

/// The public keys anchors may be checked against: the active signing key and the published
/// (previous or announced) ones, so anchors survive a signing-key rotation.
pub fn anchor_keys(signer: Option<&delbert_wire::Signer>, published: &[delbert_wire::TrustedKey]) -> delbert_wire::Verifier {
    let mut keys = delbert_wire::Verifier::default();
    for k in published {
        let _ = keys.add_key(&k.kid, &k.public_key);
    }
    if let Some(s) = signer {
        let _ = keys.add_key(s.kid(), &s.public_key_b64());
    }
    keys
}

/// Anchor the chain head every `every` (when a signing key is configured), forever.
pub async fn anchor_loop(pool: PgPool, signer: std::sync::Arc<delbert_wire::Signer>, every: std::time::Duration) {
    loop {
        match create_anchor(&pool, &signer).await {
            Ok(Some(a)) => tracing::info!(seq = a.seq, events = a.events, "audit chain anchored"),
            Ok(None) => {}
            Err(e) => tracing::error!("audit anchor failed: {e}"),
        }
        tokio::time::sleep(every).await;
    }
}

/// Sign the current head of the chain and store the anchor. Returns `None` when the chain is
/// empty or the newest anchor already covers the head (nothing new to attest).
pub async fn create_anchor(pool: &PgPool, signer: &delbert_wire::Signer) -> Result<Option<Anchor>, AuditError> {
    let mut tx = pool.begin().await?;
    // The same lock as `append`: the head cannot move while the anchor is made.
    sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(LOCK_KEY).execute(&mut *tx).await?;
    let head: Option<(i64, Vec<u8>)> = sqlx::query_as("SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetch_optional(&mut *tx).await?;
    let Some((seq, hash)) = head else { return Ok(None) };
    let last: Option<i64> = sqlx::query_scalar("SELECT seq FROM audit_anchors ORDER BY id DESC LIMIT 1").fetch_optional(&mut *tx).await?;
    if last == Some(seq) {
        return Ok(None);
    }
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events").fetch_one(&mut *tx).await?;
    let at = DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).expect("valid timestamp");
    let signature = signer.sign_detached(ANCHOR_DOMAIN, &anchor_document(seq, &hash, events, at, signer.kid())?);
    let row: AnchorRow = sqlx::query_as(
        "INSERT INTO audit_anchors (created_at, seq, hash, events, kid, signature) VALUES ($1, $2, $3, $4, $5, $6) \
         RETURNING id, created_at, seq, hash, events, kid, signature",
    )
    .bind(at)
    .bind(seq)
    .bind(&hash)
    .bind(events)
    .bind(signer.kid())
    .bind(&signature)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(row.export()))
}

/// The newest anchors first, at most `limit`.
pub async fn anchors(pool: &PgPool, limit: i64) -> Result<Vec<Anchor>, AuditError> {
    let rows: Vec<AnchorRow> =
        sqlx::query_as("SELECT id, created_at, seq, hash, events, kid, signature FROM audit_anchors ORDER BY id DESC LIMIT $1").bind(limit).fetch_all(pool).await?;
    Ok(rows.into_iter().map(AnchorRow::export).collect())
}

/// Every anchor must be validly signed and still describe the chain: the event at its
/// position has the anchored hash and exactly `events` events precede and include it.
async fn check_anchors(pool: &PgPool, keys: &delbert_wire::Verifier) -> Result<(u64, Option<i64>), AuditError> {
    let rows: Vec<AnchorRow> = sqlx::query_as("SELECT id, created_at, seq, hash, events, kid, signature FROM audit_anchors ORDER BY id").fetch_all(pool).await?;
    let mut checked = 0;
    for a in rows {
        let doc = anchor_document(a.seq, &a.hash, a.events, a.created_at, &a.kid)?;
        let signed = keys.verify_detached(&a.kid, ANCHOR_DOMAIN, &doc, &a.signature);
        let matches: Option<(Vec<u8>, i64)> =
            sqlx::query_as("SELECT hash, (SELECT count(*) FROM audit_events WHERE seq <= $1) FROM audit_events WHERE seq = $1").bind(a.seq).fetch_optional(pool).await?;
        if !signed || matches != Some((a.hash.clone(), a.events)) {
            return Ok((checked, Some(a.id)));
        }
        checked += 1;
    }
    Ok((checked, None))
}

/// Recompute the whole chain and report the first inconsistency, then check the signed
/// anchors against it (`keys` holds the public keys the anchors may be signed with).
pub async fn verify(pool: &PgPool, keys: &delbert_wire::Verifier) -> Result<Verification, AuditError> {
    let (events, first_bad) = verify_chain(pool).await?;
    let (anchors, first_bad_anchor) = check_anchors(pool, keys).await?;
    Ok(Verification { events, first_bad, anchors, first_bad_anchor })
}

async fn verify_chain(pool: &PgPool) -> Result<(u64, Option<i64>), AuditError> {
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
            return Ok((events, None));
        }
        for r in rows {
            let recomputed =
                event_hash(r.prev_hash.as_deref(), r.occurred_at, r.tenant_id, &r.actor, &r.action, r.target.as_deref(), &r.outcome, &r.details)?;
            if r.prev_hash != expected_prev || r.hash != recomputed {
                return Ok((events, Some(r.seq)));
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

    fn none() -> delbert_wire::Verifier {
        delbert_wire::Verifier::default()
    }

    async fn add(pool: &PgPool, action: &str) {
        let mut tx = pool.begin().await.unwrap();
        append(&mut tx, &NewEvent { tenant_id: None, actor: "test", action, target: None, outcome: "ok", details: json!({"n": 1}) })
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    #[sqlx::test]
    async fn chain_verifies_and_detects_tampering(pool: PgPool) {
        assert_eq!(verify(&pool, &none()).await.unwrap(), Verification { events: 0, first_bad: None, anchors: 0, first_bad_anchor: None });
        for a in ["a", "b", "c"] {
            add(&pool, a).await;
        }
        assert_eq!(verify(&pool, &none()).await.unwrap(), Verification { events: 3, first_bad: None, anchors: 0, first_bad_anchor: None });

        // The append-only triggers block normal tampering...
        assert!(sqlx::query("UPDATE audit_events SET actor = 'evil' WHERE seq = 2").execute(&pool).await.is_err());
        assert!(sqlx::query("DELETE FROM audit_events WHERE seq = 2").execute(&pool).await.is_err());

        // ...and if a superuser bypasses them, the hash chain still exposes it.
        sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER USER").execute(&pool).await.unwrap();
        sqlx::query("UPDATE audit_events SET actor = 'evil' WHERE seq = 2").execute(&pool).await.unwrap();
        let v = verify(&pool, &none()).await.unwrap();
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
        assert_eq!(verify(&pool, &none()).await.unwrap(), Verification { events: 8, first_bad: None, anchors: 0, first_bad_anchor: None });
    }
}
