//! Status of the policy signing key and of its rotation (docs/ROTATION.md): which keys the Core
//! signs with and announces, and which agents have learned them, from the key ids the agents
//! report.

use axum::{Json, extract::State};
use serde::Serialize;
use utoipa::ToSchema;

use crate::{
    api::{ApiResult, AppState},
    auth::Authn,
};

/// Reports older than this do not count as "the agent knows".
const FRESH_DAYS: i32 = 7;

#[derive(Serialize, ToSchema)]
pub struct KeyInfo {
    pub kid: String,
    pub public_key: String,
}

#[derive(Serialize, ToSchema)]
pub struct KeyReadiness {
    pub kid: String,
    /// Agents that reported knowing this key within the last 7 days.
    pub known_by: i64,
    /// Agents that have not (yet), up to 50, as `tenant/agent`.
    pub missing: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub struct SigningStatus {
    /// The key policies are signed with.
    pub active: Option<KeyInfo>,
    /// Keys announced to agents so they can switch to them.
    pub published: Vec<KeyInfo>,
    /// Key ids agents are told to forget.
    pub retiring: Vec<String>,
    /// Agents with a fresh report / all agents.
    pub agents_reporting: i64,
    pub agents_total: i64,
    pub readiness: Vec<KeyReadiness>,
}

#[utoipa::path(get, path = "/v1/signing/keys", tag = "system", security(("bearer" = [])), responses((status = 200, body = SigningStatus), (status = 403)))]
pub async fn status(State(st): State<AppState>, Authn(user): Authn) -> ApiResult<Json<SigningStatus>> {
    user.require_global("keys:read")?;
    let (agents_total,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM agents").fetch_one(&st.pool).await?;
    let (agents_reporting,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM agent_reports WHERE received_at > now() - make_interval(days => $1)").bind(FRESH_DAYS).fetch_one(&st.pool).await?;
    let mut kids: Vec<String> = st.signer.iter().map(|s| s.kid().to_owned()).chain(st.published_keys.iter().map(|k| k.kid.clone())).collect();
    kids.sort();
    kids.dedup();
    let mut readiness = Vec::new();
    for kid in kids {
        let known_by: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_reports WHERE received_at > now() - make_interval(days => $2) AND report->'trusted_kids' ? $1").bind(&kid).bind(FRESH_DAYS).fetch_one(&st.pool).await?;
        let missing: Vec<String> = sqlx::query_scalar(
            "SELECT t.name || '/' || a.name FROM agents a JOIN tenants t ON t.id = a.tenant_id LEFT JOIN agent_reports r ON r.agent_id = a.id \
             WHERE r.agent_id IS NULL OR r.received_at <= now() - make_interval(days => $2) OR NOT COALESCE(r.report->'trusted_kids' ? $1, false) ORDER BY 1 LIMIT 50",
        )
        .bind(&kid)
        .bind(FRESH_DAYS)
        .fetch_all(&st.pool)
        .await?;
        readiness.push(KeyReadiness { kid, known_by, missing });
    }
    Ok(Json(SigningStatus {
        active: st.signer.as_ref().map(|s| KeyInfo { kid: s.kid().to_owned(), public_key: s.public_key_b64() }),
        published: st.published_keys.iter().map(|k| KeyInfo { kid: k.kid.clone(), public_key: k.public_key.clone() }).collect(),
        retiring: st.trust.as_ref().map(|t| t.remove.clone()).unwrap_or_default(),
        agents_reporting,
        agents_total,
        readiness,
    }))
}
