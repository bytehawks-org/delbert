//! Policy lifecycle: versions, optional four-eyes approval per tenant, activation, rollback.
//!
//! Versions are immutable. `policies.active_version` says which one the compiler uses, and
//! `policy_version_events` (append-only) records who submitted, approved, rejected, activated
//! or rolled back what. When a tenant has `approval_required`, a new version is a draft: it
//! must be submitted, approved by someone other than its author and submitter, and then
//! activated. Without approval it goes live on upload. See docs/RBAC.md.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Postgres, Transaction, types::Uuid};
use utoipa::ToSchema;

use crate::{
    api::{ApiError, ApiResult, AppState, notify_tenant},
    audit::{self, NewEvent},
    auth::{Authn, CurrentUser},
};

type Tx<'a> = Transaction<'a, Postgres>;

fn conflict(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::CONFLICT, msg.into())
}

// --- tenant settings -------------------------------------------------------------------

#[derive(Serialize, Deserialize, ToSchema)]
pub struct TenantSettings {
    /// New policy versions need approval by a second person before they go live.
    pub approval_required: bool,
}

#[utoipa::path(get, path = "/v1/tenants/{tenant}/settings", tag = "tenants", security(("bearer" = [])), params(("tenant" = String, Path)),
    responses((status = 200, body = TenantSettings), (status = 404)))]
pub async fn get_settings(State(st): State<AppState>, Authn(user): Authn, Path(tenant): Path<String>) -> ApiResult<Json<TenantSettings>> {
    let tid = user.tenant(&st.pool, &tenant, "tenants:read").await?;
    let approval_required = sqlx::query_scalar("SELECT approval_required FROM tenants WHERE id = $1").bind(tid).fetch_one(&st.pool).await?;
    Ok(Json(TenantSettings { approval_required }))
}

#[utoipa::path(put, path = "/v1/tenants/{tenant}/settings", tag = "tenants", security(("bearer" = [])), request_body = TenantSettings, params(("tenant" = String, Path)),
    responses((status = 204), (status = 403), (status = 404), (status = 409, description = "Versions are waiting for approval")))]
pub async fn put_settings(State(st): State<AppState>, Authn(user): Authn, Path(tenant): Path<String>, Json(body): Json<TenantSettings>) -> ApiResult<StatusCode> {
    let tid = user.tenant(&st.pool, &tenant, "tenants:settings").await?;
    let mut tx = st.pool.begin().await?;
    let current: bool = sqlx::query_scalar("SELECT approval_required FROM tenants WHERE id = $1 FOR UPDATE").bind(tid).fetch_one(&mut *tx).await?;
    if current && !body.approval_required {
        // Weakening the control is a platform decision, and never activates anything silently.
        user.require_global("tenants:settings")?;
        let waiting = count_submitted(&mut tx, tid).await?;
        if waiting > 0 {
            return Err(conflict(format!("{waiting} version(s) are waiting for approval: approve or reject them first")));
        }
    }
    sqlx::query("UPDATE tenants SET approval_required = $2 WHERE id = $1").bind(tid).bind(body.approval_required).execute(&mut *tx).await?;
    audit::append(&mut tx, &NewEvent { tenant_id: Some(tid), actor: &user.username, action: "tenant.settings", target: Some(&tenant), outcome: "ok", details: json!({ "approval_required": body.approval_required }) }).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn count_submitted(tx: &mut Tx<'_>, tid: Uuid) -> ApiResult<i64> {
    Ok(sqlx::query_scalar(
        "SELECT COUNT(*) FROM policy_versions v JOIN policies p ON p.id = v.policy_id WHERE p.tenant_id = $1 AND \
         (SELECT e.event FROM policy_version_events e WHERE e.policy_id = v.policy_id AND e.version = v.version \
          AND e.event IN ('submitted', 'approved', 'rejected') ORDER BY e.id DESC LIMIT 1) = 'submitted'",
    )
    .bind(tid)
    .fetch_one(&mut **tx)
    .await?)
}

// --- versions ----------------------------------------------------------------------------

#[derive(Serialize, ToSchema)]
pub struct VersionOut {
    pub version: i64,
    pub created_by: String,
    /// Unix seconds.
    pub created_at: i64,
    /// `draft`, `submitted`, `approved` or `rejected`.
    pub state: String,
    /// The version the compiler currently uses.
    pub active: bool,
}

#[derive(Serialize, ToSchema)]
pub struct VersionDetail {
    #[serde(flatten)]
    pub summary: VersionOut,
    pub yaml: String,
    pub events: Vec<EventOut>,
}

#[derive(Serialize, ToSchema)]
pub struct EventOut {
    pub event: String,
    pub actor: String,
    pub comment: Option<String>,
    pub at: i64,
}

#[derive(Deserialize, ToSchema, Default)]
pub struct Comment {
    #[serde(default)]
    pub comment: Option<String>,
}

#[utoipa::path(get, path = "/v1/tenants/{tenant}/policies/{name}/versions", tag = "policies", security(("bearer" = [])),
    params(("tenant" = String, Path), ("name" = String, Path)), responses((status = 200, body = Vec<VersionOut>), (status = 404)))]
pub async fn list_versions(State(st): State<AppState>, Authn(user): Authn, Path((tenant, name)): Path<(String, String)>) -> ApiResult<Json<Vec<VersionOut>>> {
    let tid = user.tenant(&st.pool, &tenant, "policies:read").await?;
    let rows: Vec<(i64, String, i64, Option<String>, bool)> = sqlx::query_as(
        "SELECT v.version, v.created_by, (EXTRACT(EPOCH FROM v.created_at))::bigint, \
           (SELECT e.event FROM policy_version_events e WHERE e.policy_id = v.policy_id AND e.version = v.version \
            AND e.event IN ('submitted', 'approved', 'rejected') ORDER BY e.id DESC LIMIT 1), \
           p.active_version = v.version \
         FROM policies p JOIN policy_versions v ON v.policy_id = p.id WHERE p.tenant_id = $1 AND p.name = $2 ORDER BY v.version DESC",
    )
    .bind(tid)
    .bind(&name)
    .fetch_all(&st.pool)
    .await?;
    if rows.is_empty() {
        return Err(ApiError(StatusCode::NOT_FOUND, "policy not found".into()));
    }
    Ok(Json(rows.into_iter().map(version_out).collect()))
}

fn version_out((version, created_by, created_at, state, active): (i64, String, i64, Option<String>, bool)) -> VersionOut {
    VersionOut { version, created_by, created_at, state: state.unwrap_or_else(|| "draft".into()), active }
}

#[utoipa::path(get, path = "/v1/tenants/{tenant}/policies/{name}/versions/{version}", tag = "policies", security(("bearer" = [])),
    params(("tenant" = String, Path), ("name" = String, Path), ("version" = i64, Path)), responses((status = 200, body = VersionDetail), (status = 404)))]
pub async fn get_version(State(st): State<AppState>, Authn(user): Authn, Path((tenant, name, version)): Path<(String, String, i64)>) -> ApiResult<Json<VersionDetail>> {
    let tid = user.tenant(&st.pool, &tenant, "policies:read").await?;
    let row: Option<(i64, String, i64, Option<String>, bool, String, Uuid)> = sqlx::query_as(
        "SELECT v.version, v.created_by, (EXTRACT(EPOCH FROM v.created_at))::bigint, \
           (SELECT e.event FROM policy_version_events e WHERE e.policy_id = v.policy_id AND e.version = v.version \
            AND e.event IN ('submitted', 'approved', 'rejected') ORDER BY e.id DESC LIMIT 1), \
           p.active_version = v.version, v.yaml, p.id \
         FROM policies p JOIN policy_versions v ON v.policy_id = p.id WHERE p.tenant_id = $1 AND p.name = $2 AND v.version = $3",
    )
    .bind(tid)
    .bind(&name)
    .bind(version)
    .fetch_optional(&st.pool)
    .await?;
    let (v, by, at, state, active, yaml, pid) = row.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "version not found".into()))?;
    let events: Vec<(String, String, Option<String>, i64)> = sqlx::query_as(
        "SELECT event, actor, comment, (EXTRACT(EPOCH FROM created_at))::bigint FROM policy_version_events WHERE policy_id = $1 AND version = $2 ORDER BY id",
    )
    .bind(pid)
    .bind(version)
    .fetch_all(&st.pool)
    .await?;
    Ok(Json(VersionDetail {
        summary: version_out((v, by, at, state, active)),
        yaml,
        events: events.into_iter().map(|(event, actor, comment, at)| EventOut { event, actor, comment, at }).collect(),
    }))
}

// --- transitions -------------------------------------------------------------------------

/// A version row locked for a transition.
struct Locked {
    policy_id: Uuid,
    created_by: String,
    state: Option<String>,
    active_version: Option<i64>,
    approval_required: bool,
}

async fn lock(tx: &mut Tx<'_>, tid: Uuid, name: &str, version: i64) -> ApiResult<Locked> {
    let row: Option<(Uuid, Option<i64>, bool)> = sqlx::query_as(
        "SELECT p.id, p.active_version, t.approval_required FROM policies p JOIN tenants t ON t.id = p.tenant_id \
         WHERE p.tenant_id = $1 AND p.name = $2 FOR UPDATE OF p",
    )
    .bind(tid)
    .bind(name)
    .fetch_optional(&mut **tx)
    .await?;
    let (policy_id, active_version, approval_required) = row.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "policy not found".into()))?;
    let created_by: String = sqlx::query_scalar("SELECT created_by FROM policy_versions WHERE policy_id = $1 AND version = $2")
        .bind(policy_id)
        .bind(version)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "version not found".into()))?;
    let state = state_of(tx, policy_id, version).await?;
    Ok(Locked { policy_id, created_by, state, active_version, approval_required })
}

async fn state_of(tx: &mut Tx<'_>, policy_id: Uuid, version: i64) -> ApiResult<Option<String>> {
    Ok(sqlx::query_scalar(
        "SELECT event FROM policy_version_events WHERE policy_id = $1 AND version = $2 AND event IN ('submitted', 'approved', 'rejected') ORDER BY id DESC LIMIT 1",
    )
    .bind(policy_id)
    .bind(version)
    .fetch_optional(&mut **tx)
    .await?)
}

pub(crate) async fn record(tx: &mut Tx<'_>, policy_id: Uuid, version: i64, event: &str, actor: &str, comment: Option<&str>) -> ApiResult<()> {
    sqlx::query("INSERT INTO policy_version_events (policy_id, version, event, actor, comment) VALUES ($1, $2, $3, $4, $5)")
        .bind(policy_id)
        .bind(version)
        .bind(event)
        .bind(actor)
        .bind(comment)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Make `version` the live one (shared by upload without approval, activate and rollback).
pub(crate) async fn set_active(tx: &mut Tx<'_>, policy_id: Uuid, version: i64, event: &str, actor: &str, comment: Option<&str>) -> ApiResult<()> {
    sqlx::query("UPDATE policies SET active_version = $2, active = true WHERE id = $1").bind(policy_id).bind(version).execute(&mut **tx).await?;
    record(tx, policy_id, version, event, actor, comment).await
}

#[derive(Clone, Copy)]
enum Step {
    Submit,
    Approve,
    Reject,
    Activate,
    Rollback,
}

impl Step {
    fn name(self) -> &'static str {
        match self {
            Step::Submit => "submit",
            Step::Approve => "approve",
            Step::Reject => "reject",
            Step::Activate => "activate",
            Step::Rollback => "rollback",
        }
    }

    fn permission(self) -> &'static str {
        match self {
            Step::Submit | Step::Activate => "policies:write",
            Step::Approve | Step::Reject | Step::Rollback => "policies:approve",
        }
    }
}

async fn transition(st: &AppState, user: &CurrentUser, tenant: &str, name: &str, version: i64, step: Step, comment: Option<String>) -> ApiResult<StatusCode> {
    let tid = user.tenant(&st.pool, tenant, step.permission()).await?;
    let comment = comment.map(|c| c.trim().to_owned()).filter(|c| !c.is_empty());
    let mut tx = st.pool.begin().await?;
    let l = lock(&mut tx, tid, name, version).await?;
    let state = l.state.as_deref();
    let needs = |ok: bool, msg: &str| if ok { Ok(()) } else { Err(conflict(msg.to_owned())) };

    match step {
        Step::Submit => {
            needs(l.approval_required, "this tenant does not require approval")?;
            needs(matches!(state, None | Some("rejected")), "only a draft or rejected version can be submitted")?;
            record(&mut tx, l.policy_id, version, "submitted", &user.username, comment.as_deref()).await?;
        }
        Step::Approve | Step::Reject => {
            needs(state == Some("submitted"), "the version is not submitted")?;
            if matches!(step, Step::Reject) && comment.is_none() {
                return Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, "a comment is required to reject".into()));
            }
            // Four eyes: not the author, not whoever submitted it; no override, not even for administrators.
            let submitter: Option<String> = sqlx::query_scalar("SELECT actor FROM policy_version_events WHERE policy_id = $1 AND version = $2 AND event = 'submitted' ORDER BY id DESC LIMIT 1")
                .bind(l.policy_id)
                .bind(version)
                .fetch_optional(&mut *tx)
                .await?;
            if user.username == l.created_by || submitter.as_deref() == Some(user.username.as_str()) {
                return Err(ApiError(StatusCode::FORBIDDEN, "the author or submitter of a version cannot review it".into()));
            }
            let event = if matches!(step, Step::Approve) { "approved" } else { "rejected" };
            record(&mut tx, l.policy_id, version, event, &user.username, comment.as_deref()).await?;
        }
        Step::Activate => {
            needs(l.active_version != Some(version), "the version is already active")?;
            needs(!l.approval_required || state == Some("approved"), "this tenant requires the version to be approved first")?;
            set_active(&mut tx, l.policy_id, version, "activated", &user.username, comment.as_deref()).await?;
        }
        Step::Rollback => {
            needs(l.active_version.is_some_and(|a| version < a), "a rollback targets a version older than the active one")?;
            if l.approval_required {
                // Only a version that was approved at some point can come back; the caller is an approver.
                let approved: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM policy_version_events WHERE policy_id = $1 AND version = $2 AND event = 'approved')")
                    .bind(l.policy_id)
                    .bind(version)
                    .fetch_one(&mut *tx)
                    .await?;
                needs(approved, "only a previously approved version can be rolled back to")?;
            }
            set_active(&mut tx, l.policy_id, version, "rolled_back", &user.username, comment.as_deref()).await?;
        }
    }
    audit::append(&mut tx, &NewEvent {
        tenant_id: Some(tid), actor: &user.username, action: &format!("policy.{}", step.name()), target: Some(name), outcome: "ok",
        details: json!({ "version": version, "comment": comment }),
    })
    .await?;
    tx.commit().await?;
    if matches!(step, Step::Activate | Step::Rollback) {
        notify_tenant(st, tenant, tid).await;
    }
    Ok(StatusCode::NO_CONTENT)
}

macro_rules! step_handler {
    ($fn:ident, $step:expr, $verb:literal, $perm:literal) => {
        #[utoipa::path(post, path = concat!("/v1/tenants/{tenant}/policies/{name}/versions/{version}/", $verb), tag = "policies", security(("bearer" = [])),
            request_body = Comment, params(("tenant" = String, Path), ("name" = String, Path), ("version" = i64, Path)),
            description = concat!("Requires `", $perm, "`."),
            responses((status = 204), (status = 403), (status = 404), (status = 409, description = "Not allowed in the current state")))]
        pub async fn $fn(
            State(st): State<AppState>,
            Authn(user): Authn,
            Path((tenant, name, version)): Path<(String, String, i64)>,
            body: Option<Json<Comment>>,
        ) -> ApiResult<StatusCode> {
            transition(&st, &user, &tenant, &name, version, $step, body.and_then(|Json(b)| b.comment)).await
        }
    };
}

step_handler!(submit, Step::Submit, "submit", "policies:write");
step_handler!(approve, Step::Approve, "approve", "policies:approve");
step_handler!(reject, Step::Reject, "reject", "policies:approve");
step_handler!(activate, Step::Activate, "activate", "policies:write");
step_handler!(rollback, Step::Rollback, "rollback", "policies:approve");
