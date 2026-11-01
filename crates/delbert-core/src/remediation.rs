//! Release of a version that an agent rolled back (docs/REMEDIATION.md).
//!
//! When an update fails on a host and the policy asked for a rollback, the agent returns to its
//! last known good policy, quarantines the failed version and reports why (`remediation` in its
//! report). The Core keeps issuing the failed version: the agent is *inconsistent* with it until a
//! person has done what the host needs and decides to try again. That decision is a **force**:
//! the Core signs `{version, id}` into the agent's effective policy, the agent obeys each id once,
//! and the decision is audited with who made it and why.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::types::Uuid;
use utoipa::ToSchema;

use crate::{
    api::{ApiError, ApiResult, AppState},
    audit::{self, NewEvent},
    auth::Authn,
};

const MAX_NOTE: usize = 500;

#[derive(Deserialize, ToSchema)]
pub struct ForceBody {
    /// The quarantined version to apply again (the `failed_version` of the agent's `remediation`).
    pub version: i64,
    /// Why: what was corrected on the host. Goes to the audit trail.
    #[serde(default)]
    pub note: String,
}

/// Decide that the agent applies its quarantined version again.
#[utoipa::path(post, path = "/v1/tenants/{tenant}/agents/{agent}/remediation/force", tag = "agents", security(("bearer" = [])),
    params(("tenant" = String, Path), ("agent" = String, Path)), request_body = ForceBody,
    responses((status = 204), (status = 404), (status = 409, description = "The agent is not quarantined at that version"), (status = 422)))]
pub async fn force(State(st): State<AppState>, Authn(user): Authn, Path((tenant, agent)): Path<(String, String)>, Json(body): Json<ForceBody>) -> ApiResult<StatusCode> {
    let tid = user.tenant(&st.pool, &tenant, "agents:remediate").await?;
    if body.note.chars().count() > MAX_NOTE {
        return Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, format!("the note is at most {MAX_NOTE} characters")));
    }
    let row: Option<(Uuid, Option<Value>)> = sqlx::query_as(
        "SELECT a.id, CASE WHEN jsonb_typeof(r.report->'remediation') = 'object' THEN r.report->'remediation' END \
         FROM agents a LEFT JOIN agent_reports r ON r.agent_id = a.id WHERE a.tenant_id = $1 AND a.name = $2",
    )
    .bind(tid)
    .bind(&agent)
    .fetch_optional(&st.pool)
    .await?;
    let (agent_id, remediation) = row.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "agent not found".into()))?;
    let failed = remediation.as_ref().and_then(|r| r["failed_version"].as_i64());
    if failed != Some(body.version) {
        return Err(ApiError(StatusCode::CONFLICT, format!("the agent is not quarantined at version {} (reported: {})", body.version, failed.map_or("none".into(), |v| v.to_string()))));
    }
    let mut raw = [0u8; 16];
    OsRng.fill_bytes(&mut raw);
    let id: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let mut tx = st.pool.begin().await?;
    sqlx::query("UPDATE agents SET force_version = $2, force_id = $3, forced_by = $4, forced_at = now() WHERE id = $1")
        .bind(agent_id)
        .bind(body.version)
        .bind(&id)
        .bind(&user.username)
        .execute(&mut *tx)
        .await?;
    audit::append(&mut tx, &NewEvent { tenant_id: Some(tid), actor: &user.username, action: "remediation.force", target: Some(&agent), outcome: "ok", details: json!({ "version": body.version, "force_id": id, "note": body.note, "remediation": remediation }) }).await?;
    tx.commit().await?;
    crate::api::notify_agent(&st, &tenant, &agent).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Withdraw a force the agent has not obeyed yet.
#[utoipa::path(delete, path = "/v1/tenants/{tenant}/agents/{agent}/remediation/force", tag = "agents", security(("bearer" = [])),
    params(("tenant" = String, Path), ("agent" = String, Path)), responses((status = 204), (status = 404)))]
pub async fn cancel(State(st): State<AppState>, Authn(user): Authn, Path((tenant, agent)): Path<(String, String)>) -> ApiResult<StatusCode> {
    let tid = user.tenant(&st.pool, &tenant, "agents:remediate").await?;
    let mut tx = st.pool.begin().await?;
    let cleared = sqlx::query("UPDATE agents SET force_version = NULL, force_id = NULL, forced_by = NULL, forced_at = NULL WHERE tenant_id = $1 AND name = $2 AND force_id IS NOT NULL")
        .bind(tid)
        .bind(&agent)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if cleared == 0 {
        return Err(ApiError(StatusCode::NOT_FOUND, "no pending force for this agent".into()));
    }
    audit::append(&mut tx, &NewEvent { tenant_id: Some(tid), actor: &user.username, action: "remediation.force.cancel", target: Some(&agent), outcome: "ok", details: json!({}) }).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
