//! Per-action audit events reported by agents (docs/ABSTRACT.md §6).
//!
//! The compliance report is a state view (the latest one replaces the previous). This is the
//! event log: an agent says what it *did* (changed a resource, failed, applied or rejected a
//! policy) and the Core appends it to the hash-chained audit trail as `agent.<kind>`, actor
//! `agent:<tenant>/<agent>`. The agent's own clock goes into the details (`at`); the trail's
//! timestamp is the Core's.
//!
//! Delivery is at least once: the agent keeps a spool until acknowledged and a proxy keeps a
//! queue, so the same event can arrive twice. Events carry an id chosen by the agent and a second
//! delivery is dropped (`agent_event_ids`). A batch is `{proof, events}`; the proof (kind `event`)
//! covers the `events` array, so neither a proxy nor the network can alter or add events.
//!
//! An agent is trusted only about itself: a compromised one can add noise to the trail but not
//! more than [`MAX_PER_HOUR`] events per hour, and only under its own name.

use delbert_pki::authn::Proof;
use serde_json::{Value, json};

use crate::{
    api::AppState,
    audit::{self, NewEvent},
};

/// Largest batch an agent or proxy may send in one message.
pub const MAX_BATCH: usize = 100;
/// Events one agent may add per hour; the rest of a batch is acknowledged and dropped.
const MAX_PER_HOUR: i64 = 1000;
const MAX_DETAIL: usize = 500;

/// Event kind to (audit action, outcome).
fn classify(kind: &str) -> Option<(&'static str, &'static str)> {
    Some(match kind {
        "resource.changed" => ("agent.resource.changed", "ok"),
        "resource.failed" => ("agent.resource.failed", "failed"),
        "policy.applied" => ("agent.policy.applied", "ok"),
        "policy.rejected" => ("agent.policy.rejected", "denied"),
        "events.dropped" => ("agent.events.dropped", "failed"),
        _ => return None,
    })
}

fn is_event_id(id: &str) -> bool {
    (8..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn truncate(text: &str) -> String {
    text.chars().take(MAX_DETAIL).collect()
}

/// Verify the batch proof of `agent` as of `at` and append the new events to the audit trail.
/// Returns how many were stored (duplicates and invalid events are not), or `None` if the batch is
/// not authentic. Nothing is stored for an unauthentic batch.
pub(crate) async fn ingest(state: &AppState, tenant: &str, agent: &str, batch: &Value, at: i64) -> Option<usize> {
    let proof: Option<Proof> = serde_json::from_value(batch["proof"].clone()).ok();
    let events = batch["events"].as_array()?;
    if events.len() > MAX_BATCH || !crate::bus::proven_at(state, "event", tenant, agent, &batch["events"], proof.as_ref(), at).await {
        return None;
    }
    match store(state, tenant, agent, events).await {
        Ok(n) => Some(n),
        Err(e) => {
            tracing::error!("cannot store events of {tenant}/{agent}: {e}");
            None // the sender keeps them and retries
        }
    }
}

async fn store(state: &AppState, tenant: &str, agent: &str, events: &[Value]) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let mut tx = state.pool.begin().await?;
    let ids: Option<(sqlx::types::Uuid, sqlx::types::Uuid)> = sqlx::query_as("SELECT a.id, t.id FROM agents a JOIN tenants t ON t.id = a.tenant_id WHERE t.name = $1 AND a.name = $2")
        .bind(tenant)
        .bind(agent)
        .fetch_optional(&mut *tx)
        .await?;
    let Some((agent_id, tenant_id)) = ids else { return Ok(0) };
    let recent: i64 = sqlx::query_scalar("SELECT count(*) FROM agent_event_ids WHERE agent_id = $1 AND received_at > now() - interval '1 hour'").bind(agent_id).fetch_one(&mut *tx).await?;
    let mut room = (MAX_PER_HOUR - recent).max(0);
    let actor = format!("agent:{tenant}/{agent}");
    let mut stored = 0;
    for ev in events {
        let (Some(id), Some((action, outcome))) = (ev["id"].as_str().filter(|i| is_event_id(i)), ev["kind"].as_str().and_then(classify)) else { continue };
        if room == 0 {
            tracing::warn!("{actor} exceeded {MAX_PER_HOUR} events per hour: dropping the rest");
            break;
        }
        let new = sqlx::query("INSERT INTO agent_event_ids (agent_id, event_id) VALUES ($1, $2) ON CONFLICT DO NOTHING").bind(agent_id).bind(id).execute(&mut *tx).await?.rows_affected();
        if new == 0 {
            continue; // delivered before
        }
        room -= 1;
        let resource = ev["resource"].as_str().map(truncate);
        let details = json!({
            "event_id": id,
            "at": ev["at"].as_i64().unwrap_or(0),
            "version": ev["version"].as_i64(),
            "detail": ev["detail"].as_str().map(truncate).unwrap_or_default(),
        });
        audit::append(&mut tx, &NewEvent { tenant_id: Some(tenant_id), actor: &actor, action, target: resource.as_deref(), outcome, details }).await?;
        stored += 1;
    }
    tx.commit().await?;
    Ok(stored)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_known_kinds_and_sane_ids_pass() {
        assert_eq!(classify("resource.failed"), Some(("agent.resource.failed", "failed")));
        assert_eq!(classify("anything.else"), None);
        assert!(is_event_id("0123456789abcdef"));
        assert!(!is_event_id("short"));
        assert!(!is_event_id("has space in it"));
        assert!(!is_event_id(&"a".repeat(65)));
    }
}
