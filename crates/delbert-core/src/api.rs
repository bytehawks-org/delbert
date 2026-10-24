//! REST API of the Core (JSON). Everything except `/healthz`, `/v1/auth/login`
//! and the API documentation requires a session token and the matching
//! permission (see `auth.rs`). Agents use the NATS path (`bus.rs`), not this API.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use delbert_wire::{EffectivePolicy, SCHEMA, Signer};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, types::Uuid};
use utoipa::ToSchema;

use crate::{
    audit::{self, NewEvent},
    approval,
    auth::{self, Authn},
    compile::{self, Conflict, PolicyInput, Strategy},
};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    /// Policy Signing Key for the `core` signing mode; `None` disables issuing.
    pub signer: Option<Arc<Signer>>,
    pub ttl_secs: i64,
    pub strategies: Arc<Vec<Strategy>>,
    /// Message bus for notifications; `None` runs the Core without NATS.
    pub bus: Option<crate::bus::Bus>,
    /// Serve `/openapi.json` and `/swagger-ui`.
    pub docs: bool,
    /// Core key that seals tenant secrets at rest; `None` disables the secret store.
    pub secrets_key: Option<Arc<crate::secrets::SecretsKeys>>,
    /// Internal CA for enrollment; `None` disables enrollment.
    pub pki: Option<Arc<dyn delbert_pki::CertificateAuthority>>,
    /// Validity of agent certificates, in days.
    pub agent_cert_days: i64,
    /// NATS URL handed to agents at enrollment.
    pub public_nats_url: Option<String>,
    /// Where artifact content lives (local directory or S3-compatible).
    pub blobs: crate::blobs::Blobs,
    pub auth: AuthConfig,
    /// CA rotation (docs/ROTATION.md): other CA certificates (PEM) agents and proxies must trust,
    /// fingerprints they must forget, and "renew certificates issued before" (Unix seconds).
    pub ca_rotation: CaRotation,
    /// Signing-key rotation to announce to agents in every policy (docs/ROTATION.md).
    pub trust: Option<delbert_wire::TrustUpdate>,
    /// Keys agents should know at enrollment besides the active one.
    pub published_keys: Vec<delbert_wire::TrustedKey>,
    pub content: ContentConfig,
    /// Whether new tenants require policy approval (`DELBERT_APPROVAL_DEFAULT`).
    pub approval_default: bool,
    /// Hints that something changed, for the live status stream (`stream.rs`).
    pub changes: tokio::sync::broadcast::Sender<crate::stream::Change>,
}

#[derive(Clone, Debug, Default)]
pub struct CaRotation {
    pub extra_cas: Vec<String>,
    pub retire: Vec<String>,
    pub renew_issued_before: Option<i64>,
}

impl AppState {
    /// PEM bundle handed to enrolling components: the active CA first, then the announced ones.
    pub fn ca_bundle(&self) -> Option<String> {
        let ca = self.pki.as_ref()?;
        Some(std::iter::once(ca.cert_pem()).chain(self.ca_rotation.extra_cas.iter().map(String::as_str)).map(|p| format!("{}\n", p.trim())).collect())
    }
}

/// Where content sources live and what they may reach.
#[derive(Clone, Debug)]
pub struct ContentConfig {
    /// `directory` sources are names under this directory; git mirrors are kept in `<dir>/.git-mirrors`.
    pub dir: std::path::PathBuf,
    /// Tenant administrators may define git sources (the Core then fetches from URLs they choose).
    pub allow_tenant_git: bool,
    /// Allow `file://` remotes (tests and air-gapped local repositories).
    pub allow_file: bool,
    /// Poll due sources in the background.
    pub poll: bool,
}

impl Default for ContentConfig {
    fn default() -> Self {
        ContentConfig { dir: std::path::PathBuf::from("./data/content"), allow_tenant_git: false, allow_file: false, poll: false }
    }
}

/// Browser-session and login policy (docs/RBAC.md).
#[derive(Clone, Debug)]
pub struct AuthConfig {
    /// Add `Secure` to the session cookie (turn off only for plain-HTTP development).
    pub cookie_secure: bool,
    /// Take the client address from `X-Forwarded-For` (only behind a trusted reverse proxy).
    pub trust_forwarded: bool,
    /// Who must have a second factor.
    pub mfa: MfaPolicy,
    /// Public base URL of the Core (`https://delbert.example.com`): single sign-on redirect URIs.
    pub public_url: Option<String>,
    /// Where the browser lands after single sign-on, with `?code=` to exchange for a session.
    pub ui_url: Option<String>,
    /// Who may still use a local password.
    pub local_login: LocalLogin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalLogin {
    All,
    /// Only users with a global role (break-glass administrators); everybody else signs in via SSO.
    Admins,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MfaPolicy {
    /// Optional for everybody.
    Optional,
    /// Required for users with a global role.
    Admins,
    /// Required for everybody.
    All,
}

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig { cookie_secure: true, trust_forwarded: false, mfa: MfaPolicy::Optional, public_url: None, ui_url: None, local_login: LocalLogin::All }
    }
}

// --- errors -------------------------------------------------------------------------

pub struct ApiError(pub StatusCode, pub String);

impl ApiError {
    fn new(status: StatusCode, msg: impl Into<String>) -> Self {
        ApiError(status, msg.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        if let Some(db) = e.as_database_error() {
            if db.is_unique_violation() {
                return ApiError::new(StatusCode::CONFLICT, "already exists");
            }
            if db.is_foreign_key_violation() {
                return ApiError::new(StatusCode::CONFLICT, "still in use");
            }
        }
        tracing::error!("database error: {e}");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }
}

impl From<audit::AuditError> for ApiError {
    fn from(e: audit::AuditError) -> Self {
        tracing::error!("audit error: {e}");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

// --- router ----------------------------------------------------------------------------

pub fn router(state: AppState) -> Router {
    let mut app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/auth/login", post(auth::login))
        .route("/v1/auth/logout", post(auth::logout))
        .route("/v1/content/sources", get(crate::content::list_sources).post(crate::content::create_source))
        .route("/v1/content/sources/{name}", get(crate::content::get_source).put(crate::content::update_source).delete(crate::content::delete_source))
        .route("/v1/content/sources/{name}/sync", post(crate::content::sync_now))
        .route("/v1/content/sources/{name}/snapshots", get(crate::content::list_snapshots))
        .route("/v1/content/sources/{name}/snapshots/{id}", get(crate::content::get_snapshot))
        .route("/v1/auth/mfa", post(auth::complete_mfa))
        .route("/v1/auth/sso/providers", get(crate::sso::public_providers))
        .route("/v1/auth/sso/exchange", post(crate::sso::exchange))
        .route("/v1/auth/sso/{provider}/login", get(crate::sso::start))
        .route("/v1/auth/sso/{provider}/callback", get(crate::sso::callback))
        .route("/v1/sso/providers", get(crate::sso::list_providers).post(crate::sso::create_provider))
        .route("/v1/sso/providers/{name}", get(crate::sso::get_provider).put(crate::sso::update_provider).delete(crate::sso::delete_provider))
        .route("/v1/sso/providers/{name}/test", post(crate::sso::test_provider))
        .route("/v1/me/mfa/enroll", post(auth::mfa_enroll))
        .route("/v1/me/mfa/confirm", post(auth::mfa_confirm))
        .route("/v1/me/mfa/disable", post(auth::mfa_disable))
        .route("/v1/me/tokens", get(auth::list_tokens).post(auth::create_token))
        .route("/v1/me/tokens/{id}", axum::routing::delete(auth::revoke_token))
        .route("/v1/me/sessions", get(auth::my_sessions))
        .route("/v1/me/sessions/{id}", axum::routing::delete(auth::revoke_session))
        .route("/v1/users/{username}/mfa", axum::routing::delete(auth::admin_reset_mfa))
        .route("/v1/users/{username}/sessions", axum::routing::delete(auth::admin_revoke_sessions))
        .route("/v1/stream", get(crate::stream::events))
        .route("/v1/overview", get(crate::overview::overview))
        .route("/v1/me", get(auth::me))
        .route("/v1/users", get(auth::list_users).post(auth::create_user))
        .route("/v1/users/{username}", put(auth::update_user).delete(auth::delete_user))
        .route("/v1/permissions", get(auth::list_permissions))
        .route("/v1/roles", get(auth::list_roles).post(auth::create_role))
        .route("/v1/roles/{name}", put(auth::update_role).delete(auth::delete_role))
        .route("/v1/tenants/{tenant}/assignments", get(auth::list_tenant_assignments))
        .route("/v1/tenants/{tenant}/assignments/{username}", put(auth::set_tenant_assignments))
        .route("/v1/enroll", post(crate::enroll::enroll))
        .route("/v1/proxies", get(crate::proxies::list_proxies).post(crate::proxies::create_proxy))
        .route("/v1/proxies/enroll", post(crate::proxies::enroll_proxy))
        .route("/v1/proxies/{site}/renew", post(crate::proxies::renew_proxy))
        .route("/v1/proxies/{name}", axum::routing::delete(crate::proxies::delete_proxy))
        .route("/v1/proxy/enroll-agent", post(crate::proxies::proxy_enroll_agent))
        .route("/v1/proxy/{site}/artifacts/{tenant}/{name}", get(crate::proxies::proxy_artifact))
        .route("/v1/secrets/key", get(crate::secrets::key_status))
        .route("/v1/secrets/reseal", post(crate::secrets::reseal))
        .route("/v1/tenants/{tenant}/secrets", get(crate::secrets::list_secrets))
        .route("/v1/tenants/{tenant}/secrets/{name}", put(crate::secrets::put_secret).delete(crate::secrets::delete_secret))
        .route("/v1/tenants/{tenant}/artifacts", get(crate::artifacts::list_artifacts))
        .route(
            "/v1/tenants/{tenant}/artifacts/{name}",
            put(crate::artifacts::put_artifact).layer(axum::extract::DefaultBodyLimit::max(crate::artifacts::MAX_ARTIFACT_BYTES + 1024)),
        )
        .route("/v1/agent/{tenant}/{agent}/artifacts/{name}", get(crate::artifacts::agent_download))
        .route("/v1/globals/artifacts", get(crate::artifacts::list_global_artifacts))
        .route("/v1/globals/variables", get(crate::variables::list_global))
        .route("/v1/globals/variables/{name}", put(crate::variables::put_global).delete(crate::variables::delete_global))
        .route("/v1/tenants/{tenant}/variables", get(crate::variables::list_variables))
        .route("/v1/tenants/{tenant}/variables/{name}", put(crate::variables::put_variable).delete(crate::variables::delete_variable))
        .route("/v1/tenants/{tenant}/agents/{agent}/variables", get(crate::variables::resolved))
        .route("/v1/tenants/{tenant}/agents/{agent}/render", get(crate::variables::render))
        .route(
            "/v1/globals/artifacts/{name}",
            put(crate::artifacts::put_global_artifact).layer(axum::extract::DefaultBodyLimit::max(crate::artifacts::MAX_ARTIFACT_BYTES + 1024)),
        )
        .route("/v1/tenants/{tenant}/enrollment-keys", get(crate::enroll::list_keys).post(crate::enroll::create_key))
        .route("/v1/tenants/{tenant}/enrollment-keys/{id}", axum::routing::delete(crate::enroll::revoke_key))
        .route("/v1/tenants", get(list_tenants).post(create_tenant))
        .route("/v1/tenants/{tenant}", axum::routing::delete(archive_tenant))
        .route("/v1/tenants/{tenant}/agents", get(list_agents).post(create_agent))
        .route("/v1/tenants/{tenant}/agents/{agent}", put(update_agent).delete(delete_agent))
        .route("/v1/tenants/{tenant}/agents/{agent}/effective", get(effective))
        .route("/v1/tenants/{tenant}/policies", get(list_policies).post(create_policy))
        .route("/v1/tenants/{tenant}/policies/validate", post(validate_policy_dry_run))
        .route("/v1/tenants/{tenant}/policies/{name}", get(get_policy).delete(delete_policy))
        .route("/v1/tenants/{tenant}/settings", get(approval::get_settings).put(approval::put_settings))
        .route("/v1/tenants/{tenant}/policies/{name}/versions", get(approval::list_versions))
        .route("/v1/tenants/{tenant}/policies/{name}/versions/{version}", get(approval::get_version))
        .route("/v1/tenants/{tenant}/policies/{name}/versions/{version}/submit", post(approval::submit))
        .route("/v1/tenants/{tenant}/policies/{name}/versions/{version}/approve", post(approval::approve))
        .route("/v1/tenants/{tenant}/policies/{name}/versions/{version}/reject", post(approval::reject))
        .route("/v1/tenants/{tenant}/policies/{name}/versions/{version}/activate", post(approval::activate))
        .route("/v1/tenants/{tenant}/policies/{name}/versions/{version}/rollback", post(approval::rollback))
        .route("/v1/signing/keys", get(crate::signing::status))
        .route("/v1/pki/ca", get(crate::signing::ca_status))
        .route("/v1/audit", get(crate::audit_api::list))
        .route("/v1/audit/export", get(crate::audit_api::export))
        .route("/v1/audit/verify", get(audit_verify));
    if state.docs {
        app = app.merge(crate::openapi::docs());
    }
    app.with_state(state)
}

#[utoipa::path(get, path = "/healthz", tag = "system", responses((status = 200, description = "OK"), (status = 503, description = "Database unavailable")))]
pub async fn healthz(State(st): State<AppState>) -> (StatusCode, Json<Value>) {
    match sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&st.pool).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => {
            tracing::error!("health check failed: {e}");
            (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "status": "database unavailable" })))
        }
    }
}

// --- helpers ---------------------------------------------------------------------------

/// Names used in URLs and signed policies.
fn valid_name(name: &str) -> bool {
    (1..=128).contains(&name.len()) && name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

/// Names that become NATS subject tokens (tenants, agents): no dots or wildcards.
pub(crate) fn check_token(name: &str, what: &str) -> ApiResult<()> {
    if valid_name(name) && !name.contains('.') {
        Ok(())
    } else {
        Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, format!("invalid {what} name (1-128 of letters, digits, - _)")))
    }
}

pub(crate) fn check_name(name: &str, what: &str) -> ApiResult<()> {
    if valid_name(name) {
        Ok(())
    } else {
        Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, format!("invalid {what} name (1-128 of letters, digits, - _ .)")))
    }
}

pub(crate) async fn tenant_id(pool: &PgPool, name: &str) -> ApiResult<Uuid> {
    sqlx::query_scalar("SELECT id FROM tenants WHERE name = $1 AND archived_at IS NULL")
        .bind(name)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "tenant not found"))
}

/// Tell one agent to pull again (best effort: the periodic pull is the safety net).
async fn notify_agent(st: &AppState, tenant: &str, agent: &str) {
    if let Some(bus) = &st.bus {
        bus.notify(tenant, agent).await;
    }
}

/// Tell the proxy that serves this agent (if any) that its list of agents changed.
pub(crate) async fn notify_proxy_of(st: &AppState, tenant: &str, agent: &str) {
    let Some(bus) = &st.bus else { return };
    let site: Result<Option<String>, _> = sqlx::query_scalar(
        "SELECT p.name FROM agents a JOIN tenants t ON t.id = a.tenant_id JOIN proxies p ON p.id = a.proxy_id WHERE t.name = $1 AND a.name = $2",
    )
    .bind(tenant)
    .bind(agent)
    .fetch_optional(&st.pool)
    .await;
    if let Ok(Some(site)) = site {
        bus.notify_proxy(&site).await;
    }
}

/// Policies are tenant-wide, so every agent of the tenant is told to pull.
pub(crate) async fn notify_tenant(st: &AppState, tenant: &str, tenant_id: Uuid) {
    let Some(bus) = &st.bus else { return };
    match sqlx::query_scalar::<_, String>("SELECT name FROM agents WHERE tenant_id = $1").bind(tenant_id).fetch_all(&st.pool).await {
        Ok(agents) => {
            for agent in agents {
                bus.notify(tenant, &agent).await;
            }
        }
        Err(e) => tracing::warn!("cannot list agents to notify: {e}"),
    }
}

/// A change that concerns every tenant (global artifacts and variables): all agents pull.
pub(crate) async fn notify_all(st: &AppState) {
    let Some(bus) = &st.bus else { return };
    match sqlx::query_as::<_, (String, String)>("SELECT t.name, a.name FROM agents a JOIN tenants t ON t.id = a.tenant_id WHERE t.archived_at IS NULL").fetch_all(&st.pool).await {
        Ok(agents) => {
            for (tenant, agent) in agents {
                bus.notify(&tenant, &agent).await;
            }
        }
        Err(e) => tracing::warn!("cannot list agents to notify: {e}"),
    }
}

// --- tenants ---------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
pub struct NewTenant {
    pub name: String,
}

#[derive(Serialize, ToSchema)]
pub struct TenantOut {
    pub id: String,
    pub name: String,
}

#[utoipa::path(post, path = "/v1/tenants", tag = "tenants", security(("bearer" = [])), request_body = NewTenant,
    responses((status = 201, body = TenantOut), (status = 409, description = "Already exists"), (status = 422)))]
pub async fn create_tenant(State(st): State<AppState>, Authn(user): Authn, Json(body): Json<NewTenant>) -> ApiResult<(StatusCode, Json<TenantOut>)> {
    user.require_global("tenants:create")?;
    check_token(&body.name, "tenant")?;
    let mut tx = st.pool.begin().await?;
    let id: Uuid = sqlx::query_scalar("INSERT INTO tenants (name, approval_required) VALUES ($1, $2) RETURNING id").bind(&body.name).bind(st.approval_default).fetch_one(&mut *tx).await?;
    audit::append(&mut tx, &NewEvent { tenant_id: Some(id), actor: &user.username, action: "tenant.create", target: Some(&body.name), outcome: "ok", details: json!({}) }).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(TenantOut { id: id.to_string(), name: body.name })))
}

/// Archives a tenant (see migration `0018`): it needs `tenants:delete`, a tenant without agents, and it
/// revokes what could still reach it (enrollment keys, tenant-scoped API tokens, role assignments)
/// and stops its tenant-owned content sources. Audit events and policy versions are kept.
#[utoipa::path(delete, path = "/v1/tenants/{tenant}", tag = "tenants", security(("bearer" = [])), params(("tenant" = String, Path)),
    responses((status = 204), (status = 403), (status = 404), (status = 409, description = "The tenant still has agents")))]
pub async fn archive_tenant(State(st): State<AppState>, Authn(user): Authn, Path(tenant): Path<String>) -> ApiResult<StatusCode> {
    user.require_global("tenants:delete")?;
    let tid = tenant_id(&st.pool, &tenant).await?;
    let mut tx = st.pool.begin().await?;
    sqlx::query("SELECT id FROM tenants WHERE id = $1 FOR UPDATE").bind(tid).execute(&mut *tx).await?;
    let agents: i64 = sqlx::query_scalar("SELECT count(*) FROM agents WHERE tenant_id = $1").bind(tid).fetch_one(&mut *tx).await?;
    if agents > 0 {
        return Err(ApiError::new(StatusCode::CONFLICT, format!("the tenant still has {agents} agent(s): delete them first")));
    }
    sqlx::query("UPDATE tenants SET archived_at = now() WHERE id = $1").bind(tid).execute(&mut *tx).await?;
    sqlx::query("UPDATE enrollment_keys SET revoked = true WHERE tenant_id = $1").bind(tid).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM api_tokens WHERE tenant_id = $1").bind(tid).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM user_roles WHERE tenant_id = $1").bind(tid).execute(&mut *tx).await?;
    sqlx::query("UPDATE content_sources SET enabled = false WHERE tenant_id = $1").bind(tid).execute(&mut *tx).await?;
    audit::append(&mut tx, &NewEvent { tenant_id: Some(tid), actor: &user.username, action: "tenant.archive", target: Some(&tenant), outcome: "ok", details: json!({}) }).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/v1/tenants", tag = "tenants", security(("bearer" = [])), responses((status = 200, body = Vec<TenantOut>)))]
pub async fn list_tenants(State(st): State<AppState>, Authn(user): Authn) -> ApiResult<Json<Vec<TenantOut>>> {
    // Only the tenants the caller can reach (all of them for a global grant).
    let rows: Vec<(Uuid, String)> = match user.tenants_with("tenants:read") {
        None => sqlx::query_as("SELECT id, name FROM tenants WHERE archived_at IS NULL ORDER BY name").fetch_all(&st.pool).await?,
        Some(ids) => sqlx::query_as("SELECT id, name FROM tenants WHERE id = ANY($1) AND archived_at IS NULL ORDER BY name").bind(ids).fetch_all(&st.pool).await?,
    };
    Ok(Json(rows.into_iter().map(|(id, name)| TenantOut { id: id.to_string(), name }).collect()))
}

// --- agents ----------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
pub struct NewAgent {
    pub name: String,
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct AgentUpdate {
    pub groups: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub struct AgentOut {
    pub name: String,
    pub groups: Vec<String>,
    /// Version of the last compiled policy for this agent.
    pub effective_version: i64,
    /// Version the agent reported applying.
    pub reported_version: Option<i64>,
    pub compliant: Option<bool>,
    /// Unix seconds of the last report.
    pub reported_at: Option<i64>,
    /// Proxy that serves this agent, if it enrolled through one.
    pub proxy: Option<String>,
}

#[utoipa::path(post, path = "/v1/tenants/{tenant}/agents", tag = "agents", security(("bearer" = [])), request_body = NewAgent,
    params(("tenant" = String, Path)), responses((status = 201, body = AgentOut), (status = 404), (status = 409), (status = 422)))]
pub async fn create_agent(State(st): State<AppState>, Authn(user): Authn, Path(tenant): Path<String>, Json(body): Json<NewAgent>) -> ApiResult<(StatusCode, Json<AgentOut>)> {
    check_token(&body.name, "agent")?;
    body.groups.iter().try_for_each(|g| check_name(g, "group"))?;
    let tid = user.tenant(&st.pool, &tenant, "agents:write").await?;
    let mut tx = st.pool.begin().await?;
    sqlx::query("INSERT INTO agents (tenant_id, name, groups) VALUES ($1, $2, $3)").bind(tid).bind(&body.name).bind(&body.groups).execute(&mut *tx).await?;
    audit::append(&mut tx, &NewEvent { tenant_id: Some(tid), actor: &user.username, action: "agent.create", target: Some(&body.name), outcome: "ok", details: json!({ "groups": body.groups }) }).await?;
    tx.commit().await?;
    notify_agent(&st, &tenant, &body.name).await;
    Ok((StatusCode::CREATED, Json(AgentOut { name: body.name, groups: body.groups, effective_version: 0, reported_version: None, compliant: None, reported_at: None, proxy: None })))
}

#[utoipa::path(get, path = "/v1/tenants/{tenant}/agents", tag = "agents", security(("bearer" = [])),
    params(("tenant" = String, Path)), responses((status = 200, body = Vec<AgentOut>), (status = 404)))]
pub async fn list_agents(State(st): State<AppState>, Authn(user): Authn, Path(tenant): Path<String>) -> ApiResult<Json<Vec<AgentOut>>> {
    let tid = user.tenant(&st.pool, &tenant, "agents:read").await?;
    let rows: Vec<(String, Vec<String>, i64, Option<i64>, Option<bool>, Option<i64>, Option<String>)> = sqlx::query_as(
        "SELECT a.name, a.groups, a.effective_version, r.version, r.compliant, (EXTRACT(EPOCH FROM r.received_at))::bigint, p.name \
         FROM agents a LEFT JOIN agent_reports r ON r.agent_id = a.id LEFT JOIN proxies p ON p.id = a.proxy_id WHERE a.tenant_id = $1 ORDER BY a.name",
    )
    .bind(tid)
    .fetch_all(&st.pool)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(name, groups, effective_version, reported_version, compliant, reported_at, proxy)| AgentOut { name, groups, effective_version, reported_version, compliant, reported_at, proxy })
            .collect(),
    ))
}

#[utoipa::path(put, path = "/v1/tenants/{tenant}/agents/{agent}", tag = "agents", security(("bearer" = [])), request_body = AgentUpdate,
    params(("tenant" = String, Path), ("agent" = String, Path)), responses((status = 204), (status = 404), (status = 422)))]
pub async fn update_agent(State(st): State<AppState>, Authn(user): Authn, Path((tenant, agent)): Path<(String, String)>, Json(body): Json<AgentUpdate>) -> ApiResult<StatusCode> {
    body.groups.iter().try_for_each(|g| check_name(g, "group"))?;
    let tid = user.tenant(&st.pool, &tenant, "agents:write").await?;
    let mut tx = st.pool.begin().await?;
    let n = sqlx::query("UPDATE agents SET groups = $3 WHERE tenant_id = $1 AND name = $2").bind(tid).bind(&agent).bind(&body.groups).execute(&mut *tx).await?.rows_affected();
    if n == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "agent not found"));
    }
    audit::append(&mut tx, &NewEvent { tenant_id: Some(tid), actor: &user.username, action: "agent.update", target: Some(&agent), outcome: "ok", details: json!({ "groups": body.groups }) }).await?;
    tx.commit().await?;
    notify_agent(&st, &tenant, &agent).await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(delete, path = "/v1/tenants/{tenant}/agents/{agent}", tag = "agents", security(("bearer" = [])),
    params(("tenant" = String, Path), ("agent" = String, Path)), responses((status = 204), (status = 404)))]
pub async fn delete_agent(State(st): State<AppState>, Authn(user): Authn, Path((tenant, agent)): Path<(String, String)>) -> ApiResult<StatusCode> {
    let tid = user.tenant(&st.pool, &tenant, "agents:write").await?;
    let site: Option<String> = sqlx::query_scalar("SELECT p.name FROM agents a JOIN proxies p ON p.id = a.proxy_id WHERE a.tenant_id = $1 AND a.name = $2").bind(tid).bind(&agent).fetch_optional(&st.pool).await?;
    let mut tx = st.pool.begin().await?;
    let n = sqlx::query("DELETE FROM agents WHERE tenant_id = $1 AND name = $2").bind(tid).bind(&agent).execute(&mut *tx).await?.rows_affected();
    if n == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "agent not found"));
    }
    audit::append(&mut tx, &NewEvent { tenant_id: Some(tid), actor: &user.username, action: "agent.delete", target: Some(&agent), outcome: "ok", details: json!({}) }).await?;
    tx.commit().await?;
    if let (Some(bus), Some(site)) = (&st.bus, site) {
        bus.notify_proxy(&site).await; // the site stops serving it
    }
    Ok(StatusCode::NO_CONTENT)
}

// --- policies --------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
pub struct NewPolicy {
    /// Policy in the YAML authoring format (docs/POLICY.md).
    pub yaml: String,
}

#[derive(Serialize, ToSchema)]
pub struct PolicyVersionOut {
    pub name: String,
    pub version: i64,
    /// `false` when the tenant requires approval: the version is a draft.
    pub live: bool,
}

#[derive(Serialize, ToSchema)]
pub struct PolicySummary {
    pub name: String,
    pub active: bool,
    pub latest_version: Option<i64>,
    /// Version the compiler uses; differs from the latest while a draft waits for approval.
    pub active_version: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub struct PolicyOut {
    pub name: String,
    pub active: bool,
    pub version: i64,
    pub yaml: String,
}

#[utoipa::path(post, path = "/v1/tenants/{tenant}/policies", tag = "policies", security(("bearer" = [])), request_body = NewPolicy,
    params(("tenant" = String, Path)), responses((status = 201, body = PolicyVersionOut), (status = 404), (status = 422, description = "Invalid policy")))]
pub async fn create_policy(State(st): State<AppState>, Authn(user): Authn, Path(tenant): Path<String>, Json(body): Json<NewPolicy>) -> ApiResult<(StatusCode, Json<PolicyVersionOut>)> {
    let tid = user.tenant(&st.pool, &tenant, "policies:write").await?;
    crate::content::ensure_unowned(&st.pool, tid, "policy", &parse_policy_name(&body.yaml)).await?;
    Ok((StatusCode::CREATED, Json(store_policy_version(&st, tid, &tenant, &body.yaml, &user.username).await?)))
}

#[derive(Serialize, ToSchema)]
pub struct PolicyCheck {
    pub name: String,
    /// Version a save would create.
    pub next_version: i64,
    /// A save creates a draft that needs approval (otherwise it goes live at once).
    pub approval_required: bool,
}

#[utoipa::path(post, path = "/v1/tenants/{tenant}/policies/validate", tag = "policies", security(("bearer" = [])), request_body = NewPolicy,
    description = "Runs the checks of a save without storing anything or writing audit events. Requires `policies:write`.",
    params(("tenant" = String, Path)), responses((status = 200, body = PolicyCheck), (status = 404), (status = 409, description = "Owned by a content source"), (status = 422, description = "Invalid policy")))]
pub async fn validate_policy_dry_run(State(st): State<AppState>, Authn(user): Authn, Path(tenant): Path<String>, Json(body): Json<NewPolicy>) -> ApiResult<Json<PolicyCheck>> {
    let tid = user.tenant(&st.pool, &tenant, "policies:write").await?;
    let name = validate_policy(&body.yaml, &tenant)?;
    crate::content::ensure_unowned(&st.pool, tid, "policy", &name).await?;
    let next_version: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(v.version), 0) + 1 FROM policies p JOIN policy_versions v ON v.policy_id = p.id WHERE p.tenant_id = $1 AND p.name = $2")
        .bind(tid)
        .bind(&name)
        .fetch_one(&st.pool)
        .await?;
    let approval_required: bool = sqlx::query_scalar("SELECT approval_required FROM tenants WHERE id = $1").bind(tid).fetch_one(&st.pool).await?;
    Ok(Json(PolicyCheck { name, next_version, approval_required }))
}

/// Parse and check a policy for a tenant; returns its name.
pub(crate) fn validate_policy(yaml: &str, tenant: &str) -> ApiResult<String> {
    let policy = delbert_policy::from_yaml(yaml).map_err(|e| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    if policy.metadata.tenant != tenant {
        return Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "metadata.tenant does not match the tenant"));
    }
    check_name(&policy.metadata.name, "policy")?;
    // Fail closed: a conditional policy must not silently apply everywhere.
    if policy.spec.target.when.is_some() {
        return Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "target.when is not supported yet"));
    }
    Ok(policy.metadata.name)
}

/// The name a policy YAML declares (empty when it does not parse: validation reports that later).
fn parse_policy_name(yaml: &str) -> String {
    delbert_policy::from_yaml(yaml).map(|p| p.metadata.name).unwrap_or_default()
}

/// Validate a policy YAML and store it as a new immutable version (live at once, or a draft when
/// the tenant requires approval). Shared by the API and content-source sync.
pub(crate) async fn store_policy_version(st: &AppState, tid: Uuid, tenant: &str, yaml: &str, actor: &str) -> ApiResult<PolicyVersionOut> {
    let name = validate_policy(yaml, tenant)?;

    let mut tx = st.pool.begin().await?;
    let approval_required: bool = sqlx::query_scalar("SELECT approval_required FROM tenants WHERE id = $1").bind(tid).fetch_one(&mut *tx).await?;
    // Upsert; a deactivated policy comes back only when a version is activated; the row lock serializes concurrent versions.
    let pid: Uuid = sqlx::query_scalar(
        "INSERT INTO policies (tenant_id, name) VALUES ($1, $2) ON CONFLICT (tenant_id, name) DO UPDATE SET active = policies.active RETURNING id",
    )
    .bind(tid)
    .bind(&name)
    .fetch_one(&mut *tx)
    .await?;
    let version: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(version), 0) + 1 FROM policy_versions WHERE policy_id = $1").bind(pid).fetch_one(&mut *tx).await?;
    sqlx::query("INSERT INTO policy_versions (policy_id, version, yaml, created_by) VALUES ($1, $2, $3, $4)")
        .bind(pid)
        .bind(version)
        .bind(yaml)
        .bind(actor)
        .execute(&mut *tx)
        .await?;
    // Without approval the version goes live at once; with it, it is a draft until activated.
    if !approval_required {
        approval::set_active(&mut tx, pid, version, "activated", actor, None).await?;
    }
    audit::append(&mut tx, &NewEvent { tenant_id: Some(tid), actor: actor, action: "policy.create", target: Some(&name), outcome: "ok", details: json!({ "version": version, "live": !approval_required }) }).await?;
    tx.commit().await?;
    if !approval_required {
        notify_tenant(st, tenant, tid).await;
    }
    Ok(PolicyVersionOut { name, version, live: !approval_required })
}

#[utoipa::path(get, path = "/v1/tenants/{tenant}/policies", tag = "policies", security(("bearer" = [])),
    params(("tenant" = String, Path)), responses((status = 200, body = Vec<PolicySummary>), (status = 404)))]
pub async fn list_policies(State(st): State<AppState>, Authn(user): Authn, Path(tenant): Path<String>) -> ApiResult<Json<Vec<PolicySummary>>> {
    let tid = user.tenant(&st.pool, &tenant, "policies:read").await?;
    let rows: Vec<(String, bool, Option<i64>, Option<i64>)> = sqlx::query_as(
        "SELECT p.name, p.active, (SELECT MAX(version) FROM policy_versions v WHERE v.policy_id = p.id), p.active_version FROM policies p WHERE p.tenant_id = $1 ORDER BY p.name",
    )
    .bind(tid)
    .fetch_all(&st.pool)
    .await?;
    Ok(Json(rows.into_iter().map(|(name, active, latest_version, active_version)| PolicySummary { name, active, latest_version, active_version }).collect()))
}

#[utoipa::path(get, path = "/v1/tenants/{tenant}/policies/{name}", tag = "policies", security(("bearer" = [])),
    params(("tenant" = String, Path), ("name" = String, Path)), responses((status = 200, body = PolicyOut), (status = 404)))]
pub async fn get_policy(State(st): State<AppState>, Authn(user): Authn, Path((tenant, name)): Path<(String, String)>) -> ApiResult<Json<PolicyOut>> {
    let tid = user.tenant(&st.pool, &tenant, "policies:read").await?;
    let row: Option<(bool, i64, String)> = sqlx::query_as(
        "SELECT p.active, v.version, v.yaml FROM policies p JOIN policy_versions v ON v.policy_id = p.id \
         WHERE p.tenant_id = $1 AND p.name = $2 ORDER BY v.version DESC LIMIT 1",
    )
    .bind(tid)
    .bind(&name)
    .fetch_optional(&st.pool)
    .await?;
    let (active, version, yaml) = row.ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "policy not found"))?;
    Ok(Json(PolicyOut { name, active, version, yaml }))
}

#[utoipa::path(delete, path = "/v1/tenants/{tenant}/policies/{name}", tag = "policies", security(("bearer" = [])),
    params(("tenant" = String, Path), ("name" = String, Path)), responses((status = 204), (status = 404)))]
pub async fn delete_policy(State(st): State<AppState>, Authn(user): Authn, Path((tenant, name)): Path<(String, String)>) -> ApiResult<StatusCode> {
    let tid = user.tenant(&st.pool, &tenant, "policies:write").await?;
    crate::content::ensure_unowned(&st.pool, tid, "policy", &name).await?;
    let mut tx = st.pool.begin().await?;
    let n = sqlx::query("UPDATE policies SET active = false WHERE tenant_id = $1 AND name = $2 AND active").bind(tid).bind(&name).execute(&mut *tx).await?.rows_affected();
    if n == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "active policy not found"));
    }
    audit::append(&mut tx, &NewEvent { tenant_id: Some(tid), actor: &user.username, action: "policy.deactivate", target: Some(&name), outcome: "ok", details: json!({}) }).await?;
    tx.commit().await?;
    notify_tenant(&st, &tenant, tid).await;
    Ok(StatusCode::NO_CONTENT)
}

// --- effective policy ------------------------------------------------------------------

#[derive(Serialize, ToSchema)]
pub struct Issued {
    /// Signed policy (JWS) for the agent.
    pub token: String,
    pub version: i64,
    pub conflicts: Vec<Conflict>,
}

#[utoipa::path(get, path = "/v1/tenants/{tenant}/agents/{agent}/effective", tag = "agents", security(("bearer" = [])),
    params(("tenant" = String, Path), ("agent" = String, Path)),
    responses((status = 200, body = Issued), (status = 404), (status = 503, description = "Signing key not configured")))]
pub async fn effective(State(st): State<AppState>, Authn(user): Authn, Path((tenant, agent)): Path<(String, String)>) -> ApiResult<Json<Issued>> {
    user.tenant(&st.pool, &tenant, "agents:preview").await?;
    Ok(Json(issue(&st, tenant, agent, &user.username).await?))
}

/// Compile the active policies that target an agent, with the artifact catalog (global and
/// tenant) and the agent's resolved variables applied. Shared by `issue` and the render preview.
pub(crate) async fn compile_for(st: &AppState, tid: Uuid, agent: &str, groups: &[String]) -> ApiResult<compile::Compiled> {
    let sources: Vec<(String, String)> = sqlx::query_as(
        "SELECT p.name, v.yaml FROM policies p \
         JOIN policy_versions v ON v.policy_id = p.id AND v.version = p.active_version \
         WHERE p.tenant_id = $1 AND p.active ORDER BY p.name",
    )
    .bind(tid)
    .fetch_all(&st.pool)
    .await?;

    let mut inputs = Vec::new();
    for (name, yaml) in sources {
        let p = delbert_policy::from_yaml(&yaml).map_err(|e| {
            tracing::error!("stored policy '{name}' no longer parses: {e}");
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "stored policy is invalid")
        })?;
        let targets = &p.spec.target.groups;
        if targets.is_empty() || targets.iter().any(|g| groups.contains(g)) {
            inputs.push(PolicyInput { name, priority: p.spec.priority.unwrap_or(0), secrets: p.spec.secrets, vars: p.spec.vars, resources: p.spec.resources });
        }
    }
    let catalog = crate::artifacts::catalog(st, tid).await?;
    let mut compiled = compile::compile(&inputs, &st.strategies, &catalog);
    delbert_policy::validate_resources(&compiled.resources).map_err(|e| {
        tracing::error!("compiled policy for {agent} is invalid: {e:?}");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "compiled policy is invalid")
    })?;

    let (resolved, conflicts) = crate::variables::resolve(st, tid, groups, agent).await?;
    crate::variables::overlay(&mut compiled, &resolved);
    compiled.conflicts.extend(conflicts);
    Ok(compiled)
}

/// Compile every active policy that targets the agent and sign the result.
/// Shared by the HTTP endpoint and the NATS responder (`actor` goes to the audit trail).
pub async fn issue(st: &AppState, tenant: String, agent: String, actor: &str) -> ApiResult<Issued> {
    let signer = st.signer.as_ref().ok_or_else(|| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "signing key not configured"))?;
    let tid = tenant_id(&st.pool, &tenant).await?;

    let mut tx = st.pool.begin().await?;
    let row: Option<(Uuid, Vec<String>, i64, Option<Vec<u8>>, Option<String>)> =
        sqlx::query_as("SELECT id, groups, effective_version, effective_hash, enc_public_key FROM agents WHERE tenant_id = $1 AND name = $2 FOR UPDATE")
            .bind(tid)
            .bind(&agent)
            .fetch_optional(&mut *tx)
            .await?;
    let (agent_id, groups, mut version, stored_hash, enc_key) = row.ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "agent not found"))?;

    let mut compiled = compile_for(st, tid, &agent, &groups).await?;

    // Secrets: decrypt with the Core key, re-encrypt to this agent only. Missing ones are reported.
    let wanted: Vec<String> = compiled.secrets.iter().cloned().collect();
    let plain = crate::secrets::load(st, tid, &wanted).await?;
    for name in wanted.iter().filter(|n| !plain.contains_key(*n)) {
        compiled.conflicts.push(Conflict { what: format!("secret '{name}'"), resources: vec![], resolution: "missing: not delivered".into() });
    }
    let mut sealed = std::collections::BTreeMap::new();
    let mut secret_digests = std::collections::BTreeMap::new();
    if !plain.is_empty() {
        let recipient = enc_key.as_deref().ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "agent has no encryption key (not enrolled)"))?;
        for (name, value) in &plain {
            use base64::Engine as _;
            let ciphertext = crate::secrets::seal_for_agent(recipient, value)?;
            sealed.insert(name.clone(), base64::engine::general_purpose::STANDARD.encode(ciphertext));
            // age output is randomized: the version tracks a digest of the plaintext instead.
            secret_digests.insert(name.clone(), Sha256::digest(value).iter().map(|b| format!("{b:02x}")).collect::<String>());
        }
    }

    // The version only moves when the compiled content changes.
    let content = serde_json::to_value((&compiled.vars, &compiled.resources, &compiled.artifacts, &secret_digests)).expect("serializable");
    let hash = Sha256::digest(delbert_wire::canonical::to_vec(&content).map_err(|e| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?).to_vec();
    if stored_hash.as_deref() != Some(&hash) {
        version += 1;
        sqlx::query("UPDATE agents SET effective_version = $2, effective_hash = $3 WHERE id = $1").bind(agent_id).bind(version).bind(&hash).execute(&mut *tx).await?;
        audit::append(
            &mut tx,
            &NewEvent {
                tenant_id: Some(tid),
                actor,
                action: "policy.issue",
                target: Some(&agent),
                outcome: if compiled.conflicts.is_empty() { "ok" } else { "conflicts" },
                details: json!({ "version": version, "resources": compiled.resources.len(), "conflicts": compiled.conflicts }),
            },
        )
        .await?;
    }
    tx.commit().await?;

    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
    let token = signer
        .sign(&EffectivePolicy {
            schema: SCHEMA.into(),
            tenant,
            agent,
            name: "effective".into(),
            version: version as u64,
            issued_at: now,
            expires_at: now + st.ttl_secs,
            vars: compiled.vars,
            artifacts: compiled.artifacts,
            secrets: sealed,
            resources: compiled.resources,
            trust: st.trust.clone(),
        })
        .map_err(|e| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    Ok(Issued { token, version, conflicts: compiled.conflicts })
}

#[utoipa::path(get, path = "/v1/audit/verify", tag = "audit", security(("bearer" = [])), responses((status = 200, body = audit::Verification)))]
pub async fn audit_verify(State(st): State<AppState>, Authn(user): Authn) -> ApiResult<Json<audit::Verification>> {
    user.require_global("audit:verify")?;
    Ok(Json(audit::verify(&st.pool).await?))
}
