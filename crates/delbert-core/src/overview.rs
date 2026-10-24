//! Fleet overview for the console's dashboard: totals and the agents that need a look, in one query
//! instead of one request per tenant (so it has no tenant limit). Limited to the tenants the caller
//! can reach.

use axum::{
    Json,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};
use sqlx::types::Uuid;
use utoipa::{IntoParams, ToSchema};

use crate::{
    api::{ApiResult, AppState},
    auth::Authn,
};

/// Agents listed under "needs attention".
const ATTENTION: i64 = 20;

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct OverviewQuery {
    /// An agent whose last report is older than this many seconds counts as silent (default 600, at least 30).
    pub stale_secs: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub struct AttentionAgent {
    pub tenant: String,
    pub name: String,
    /// `drifted` (reported, not compliant) or `silent` (never reported, or not for a while).
    pub state: String,
    /// Unix seconds of the last report.
    pub reported_at: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub struct Overview {
    pub tenants: i64,
    pub agents: i64,
    pub compliant: i64,
    pub drifted: i64,
    pub silent: i64,
    /// Drifted agents first, then the silent ones (longest silent first); at most 20.
    pub attention: Vec<AttentionAgent>,
}

#[utoipa::path(get, path = "/v1/overview", tag = "agents", security(("bearer" = [])), params(OverviewQuery), responses((status = 200, body = Overview)))]
pub async fn overview(State(st): State<AppState>, Authn(user): Authn, Query(q): Query<OverviewQuery>) -> ApiResult<Json<Overview>> {
    let stale = q.stale_secs.unwrap_or(600).max(30) as f64;
    // `None`: every tenant (global grant).
    let scope: Option<Vec<Uuid>> = user.tenants_with("agents:read");
    let tenants: i64 = sqlx::query_scalar("SELECT count(*) FROM tenants WHERE archived_at IS NULL AND ($1::uuid[] IS NULL OR id = ANY($1))").bind(&scope).fetch_one(&st.pool).await?;
    let (agents, compliant, drifted, silent): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT count(*), \
                count(*) FILTER (WHERE r.received_at > now() - make_interval(secs => $2) AND r.compliant), \
                count(*) FILTER (WHERE r.received_at > now() - make_interval(secs => $2) AND NOT r.compliant), \
                count(*) FILTER (WHERE r.received_at IS NULL OR r.received_at <= now() - make_interval(secs => $2)) \
         FROM agents a JOIN tenants t ON t.id = a.tenant_id LEFT JOIN agent_reports r ON r.agent_id = a.id \
         WHERE t.archived_at IS NULL AND ($1::uuid[] IS NULL OR a.tenant_id = ANY($1))",
    )
    .bind(&scope)
    .bind(stale)
    .fetch_one(&st.pool)
    .await?;
    let rows: Vec<(String, String, Option<bool>, Option<i64>)> = sqlx::query_as(
        "SELECT t.name, a.name, (r.received_at > now() - make_interval(secs => $2)) AS reported, (EXTRACT(EPOCH FROM r.received_at))::bigint \
         FROM agents a JOIN tenants t ON t.id = a.tenant_id LEFT JOIN agent_reports r ON r.agent_id = a.id \
         WHERE t.archived_at IS NULL AND ($1::uuid[] IS NULL OR a.tenant_id = ANY($1)) \
           AND (r.received_at IS NULL OR r.received_at <= now() - make_interval(secs => $2) OR NOT r.compliant) \
         ORDER BY COALESCE(r.received_at > now() - make_interval(secs => $2), false) DESC, r.received_at NULLS FIRST, t.name, a.name LIMIT $3",
    )
    .bind(&scope)
    .bind(stale)
    .bind(ATTENTION)
    .fetch_all(&st.pool)
    .await?;
    let attention = rows
        .into_iter()
        .map(|(tenant, name, reported, reported_at)| AttentionAgent { tenant, name, state: if reported == Some(true) { "drifted" } else { "silent" }.into(), reported_at })
        .collect();
    Ok(Json(Overview { tenants, agents, compliant, drifted, silent, attention }))
}
