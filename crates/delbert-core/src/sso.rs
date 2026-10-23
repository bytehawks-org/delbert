//! Single sign-on through OpenID Connect (authorization code flow with PKCE).
//!
//! The Core is the relying party. A login goes: `GET /v1/auth/sso/{provider}/login` redirects to
//! the identity provider; its callback lands on `/v1/auth/sso/{provider}/callback`, where the code
//! is exchanged and the ID token validated (signature, issuer, audience, expiry, nonce) by the
//! `openidconnect` crate. The user is found or created from the stable `sub`, the groups claim is
//! mapped to roles, and the browser is redirected to the UI with a one-time `code` that the front
//! end exchanges for a session (`POST /v1/auth/sso/exchange`), so no token travels in a URL.
//!
//! Safety rules: a local account with the same name is never taken over (login is refused), roles
//! written by a login replace only the previous login's roles, and disabled users stay out.

use std::collections::HashSet;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
    reqwest as oidc_reqwest,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgPool, types::Uuid};
use utoipa::ToSchema;

use crate::{
    api::{ApiError, ApiResult, AppState},
    audit::{self, NewEvent},
    auth::{Authn, ClientIp, LoginResponse, hash_token, new_token, open_session, set_session_cookie},
};

const STATE_MINUTES: i32 = 10;
const CODE_SECONDS: i32 = 60;

fn err(status: StatusCode, msg: impl Into<String>) -> ApiError {
    ApiError(status, msg.into())
}

// --- provider administration ---------------------------------------------------------------

#[derive(Serialize, Deserialize, ToSchema, Clone)]
pub struct Mapping {
    /// Group (or app role) name as it appears in the groups claim.
    pub group: String,
    pub role: String,
    /// Tenant the role applies to; absent = global.
    pub tenant: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct ProviderBody {
    /// Slug used in URLs; ignored on update.
    #[serde(default)]
    pub name: String,
    pub display_name: String,
    /// Issuer URL; `<issuer>/.well-known/openid-configuration` must exist.
    pub issuer: String,
    pub client_id: String,
    /// Absent on update keeps the stored secret; a public client has none.
    pub client_secret: Option<String>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(default)]
    pub groups_claim: Option<String>,
    #[serde(default)]
    pub require_mapping: Option<bool>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub mappings: Vec<Mapping>,
}

#[derive(Serialize, ToSchema)]
pub struct ProviderOut {
    pub name: String,
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    pub has_client_secret: bool,
    pub scopes: Vec<String>,
    pub groups_claim: String,
    pub require_mapping: bool,
    pub enabled: bool,
    pub mappings: Vec<Mapping>,
    /// Register this redirect URI at the identity provider.
    pub redirect_uri: Option<String>,
}

#[derive(sqlx::FromRow)]
struct ProviderRow {
    id: Uuid,
    name: String,
    display_name: String,
    issuer: String,
    client_id: String,
    client_secret: Option<Vec<u8>>,
    scopes: Vec<String>,
    groups_claim: String,
    require_mapping: bool,
    enabled: bool,
}

const COLUMNS: &str = "id, name, display_name, issuer, client_id, client_secret, scopes, groups_claim, require_mapping, enabled";

fn redirect_uri(st: &AppState, name: &str) -> Option<String> {
    st.auth.public_url.as_ref().map(|u| format!("{}/v1/auth/sso/{name}/callback", u.trim_end_matches('/')))
}

async fn mappings_of(pool: &PgPool, provider: Uuid) -> ApiResult<Vec<Mapping>> {
    let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT m.group_name, r.name, t.name FROM sso_mappings m JOIN roles r ON r.id = m.role_id LEFT JOIN tenants t ON t.id = m.tenant_id \
         WHERE m.provider_id = $1 ORDER BY m.group_name, r.name, t.name NULLS FIRST",
    )
    .bind(provider)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(group, role, tenant)| Mapping { group, role, tenant }).collect())
}

async fn provider_out(st: &AppState, r: ProviderRow) -> ApiResult<ProviderOut> {
    Ok(ProviderOut {
        mappings: mappings_of(&st.pool, r.id).await?,
        redirect_uri: redirect_uri(st, &r.name),
        has_client_secret: r.client_secret.is_some(),
        name: r.name,
        display_name: r.display_name,
        issuer: r.issuer,
        client_id: r.client_id,
        scopes: r.scopes,
        groups_claim: r.groups_claim,
        require_mapping: r.require_mapping,
        enabled: r.enabled,
    })
}

fn check_issuer(st: &AppState, issuer: &str) -> ApiResult<()> {
    let url = url_scheme(issuer);
    match url {
        Some("https") => Ok(()),
        Some("http") if !st.auth.cookie_secure => Ok(()),
        _ => Err(err(StatusCode::UNPROCESSABLE_ENTITY, "issuer must be an https:// URL")),
    }
}

fn url_scheme(u: &str) -> Option<&str> {
    u.split_once("://").map(|(s, _)| s)
}

/// Replace the mappings of a provider after checking roles, tenants and role scopes.
async fn set_mappings(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, provider: Uuid, mappings: &[Mapping]) -> ApiResult<()> {
    sqlx::query("DELETE FROM sso_mappings WHERE provider_id = $1").bind(provider).execute(&mut **tx).await?;
    for m in mappings {
        if m.group.trim().is_empty() {
            return Err(err(StatusCode::UNPROCESSABLE_ENTITY, "mapping group must not be empty"));
        }
        let role: Option<(Uuid, String)> = sqlx::query_as("SELECT id, scope FROM roles WHERE name = $1").bind(&m.role).fetch_optional(&mut **tx).await?;
        let (role_id, scope) = role.ok_or_else(|| err(StatusCode::UNPROCESSABLE_ENTITY, format!("unknown role '{}'", m.role)))?;
        let tenant_id: Option<Uuid> = match &m.tenant {
            Some(t) => Some(sqlx::query_scalar("SELECT id FROM tenants WHERE name = $1").bind(t).fetch_optional(&mut **tx).await?.ok_or_else(|| err(StatusCode::UNPROCESSABLE_ENTITY, format!("unknown tenant '{t}'")))?),
            None => None,
        };
        let fits = scope == "any" || (m.tenant.is_none() && scope == "global") || (m.tenant.is_some() && scope == "tenant");
        if !fits {
            return Err(err(StatusCode::UNPROCESSABLE_ENTITY, format!("role '{}' (scope {scope}) cannot be mapped {}", m.role, if m.tenant.is_some() { "to a tenant" } else { "globally" })));
        }
        sqlx::query("INSERT INTO sso_mappings (provider_id, group_name, role_id, tenant_id) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING").bind(provider).bind(m.group.trim()).bind(role_id).bind(tenant_id).execute(&mut **tx).await?;
    }
    Ok(())
}

#[utoipa::path(get, path = "/v1/sso/providers", tag = "sso", security(("bearer" = [])), responses((status = 200, body = Vec<ProviderOut>)))]
pub async fn list_providers(State(st): State<AppState>, Authn(user): Authn) -> ApiResult<Json<Vec<ProviderOut>>> {
    user.require_global("sso:read")?;
    let rows: Vec<ProviderRow> = sqlx::query_as(&format!("SELECT {COLUMNS} FROM sso_providers ORDER BY name")).fetch_all(&st.pool).await?;
    let mut out = Vec::new();
    for r in rows {
        out.push(provider_out(&st, r).await?);
    }
    Ok(Json(out))
}

#[utoipa::path(get, path = "/v1/sso/providers/{name}", tag = "sso", security(("bearer" = [])), params(("name" = String, Path)), responses((status = 200, body = ProviderOut), (status = 404)))]
pub async fn get_provider(State(st): State<AppState>, Authn(user): Authn, Path(name): Path<String>) -> ApiResult<Json<ProviderOut>> {
    user.require_global("sso:read")?;
    let r: Option<ProviderRow> = sqlx::query_as(&format!("SELECT {COLUMNS} FROM sso_providers WHERE name = $1")).bind(&name).fetch_optional(&st.pool).await?;
    Ok(Json(provider_out(&st, r.ok_or_else(|| err(StatusCode::NOT_FOUND, "provider not found"))?).await?))
}

#[utoipa::path(post, path = "/v1/sso/providers", tag = "sso", security(("bearer" = [])), request_body = ProviderBody,
    responses((status = 201, body = ProviderOut), (status = 409), (status = 422)))]
pub async fn create_provider(State(st): State<AppState>, Authn(user): Authn, Json(body): Json<ProviderBody>) -> ApiResult<(StatusCode, Json<ProviderOut>)> {
    user.require_global("sso:write")?;
    crate::api::check_token(&body.name, "provider")?;
    check_issuer(&st, &body.issuer)?;
    let key = st.secrets_key.as_ref().ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "SSO needs DELBERT_SECRETS_KEY_FILE"))?;
    let secret = body.client_secret.as_deref().filter(|s| !s.is_empty()).map(|s| crate::secrets::seal(key, s.as_bytes())).transpose()?;
    let scopes = body.scopes.clone().unwrap_or_else(|| vec!["openid".into(), "profile".into(), "email".into()]);
    if !scopes.iter().any(|s| s == "openid") {
        return Err(err(StatusCode::UNPROCESSABLE_ENTITY, "scopes must include 'openid'"));
    }
    let mut tx = st.pool.begin().await?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO sso_providers (name, display_name, issuer, client_id, client_secret, scopes, groups_claim, require_mapping, enabled) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
    )
    .bind(&body.name)
    .bind(&body.display_name)
    .bind(body.issuer.trim_end_matches('/'))
    .bind(&body.client_id)
    .bind(secret)
    .bind(&scopes)
    .bind(body.groups_claim.as_deref().unwrap_or("groups"))
    .bind(body.require_mapping.unwrap_or(true))
    .bind(body.enabled.unwrap_or(true))
    .fetch_one(&mut *tx)
    .await?;
    set_mappings(&mut tx, id, &body.mappings).await?;
    audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &user.username, action: "sso.create", target: Some(&body.name), outcome: "ok", details: json!({ "issuer": body.issuer, "mappings": body.mappings.len() }) }).await?;
    tx.commit().await?;
    let r: ProviderRow = sqlx::query_as(&format!("SELECT {COLUMNS} FROM sso_providers WHERE id = $1")).bind(id).fetch_one(&st.pool).await?;
    Ok((StatusCode::CREATED, Json(provider_out(&st, r).await?)))
}

#[utoipa::path(put, path = "/v1/sso/providers/{name}", tag = "sso", security(("bearer" = [])), request_body = ProviderBody, params(("name" = String, Path)),
    responses((status = 204), (status = 404), (status = 422)))]
pub async fn update_provider(State(st): State<AppState>, Authn(user): Authn, Path(name): Path<String>, Json(body): Json<ProviderBody>) -> ApiResult<StatusCode> {
    user.require_global("sso:write")?;
    check_issuer(&st, &body.issuer)?;
    let key = st.secrets_key.as_ref().ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "SSO needs DELBERT_SECRETS_KEY_FILE"))?;
    let mut tx = st.pool.begin().await?;
    let id: Uuid = sqlx::query_scalar("SELECT id FROM sso_providers WHERE name = $1 FOR UPDATE").bind(&name).fetch_optional(&mut *tx).await?.ok_or_else(|| err(StatusCode::NOT_FOUND, "provider not found"))?;
    sqlx::query("UPDATE sso_providers SET display_name = $2, issuer = $3, client_id = $4 WHERE id = $1").bind(id).bind(&body.display_name).bind(body.issuer.trim_end_matches('/')).bind(&body.client_id).execute(&mut *tx).await?;
    if let Some(secret) = body.client_secret.as_deref() {
        let sealed = (!secret.is_empty()).then(|| crate::secrets::seal(key, secret.as_bytes())).transpose()?;
        sqlx::query("UPDATE sso_providers SET client_secret = $2 WHERE id = $1").bind(id).bind(sealed).execute(&mut *tx).await?;
    }
    if let Some(v) = &body.scopes {
        if !v.iter().any(|s| s == "openid") {
            return Err(err(StatusCode::UNPROCESSABLE_ENTITY, "scopes must include 'openid'"));
        }
        sqlx::query("UPDATE sso_providers SET scopes = $2 WHERE id = $1").bind(id).bind(v).execute(&mut *tx).await?;
    }
    if let Some(v) = &body.groups_claim {
        sqlx::query("UPDATE sso_providers SET groups_claim = $2 WHERE id = $1").bind(id).bind(v).execute(&mut *tx).await?;
    }
    if let Some(v) = body.require_mapping {
        sqlx::query("UPDATE sso_providers SET require_mapping = $2 WHERE id = $1").bind(id).bind(v).execute(&mut *tx).await?;
    }
    if let Some(v) = body.enabled {
        sqlx::query("UPDATE sso_providers SET enabled = $2 WHERE id = $1").bind(id).bind(v).execute(&mut *tx).await?;
    }
    set_mappings(&mut tx, id, &body.mappings).await?;
    audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &user.username, action: "sso.update", target: Some(&name), outcome: "ok", details: json!({ "mappings": body.mappings.len(), "enabled": body.enabled }) }).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(delete, path = "/v1/sso/providers/{name}", tag = "sso", security(("bearer" = [])), params(("name" = String, Path)),
    responses((status = 204), (status = 404), (status = 409, description = "Users still belong to it")))]
pub async fn delete_provider(State(st): State<AppState>, Authn(user): Authn, Path(name): Path<String>) -> ApiResult<StatusCode> {
    user.require_global("sso:write")?;
    let mut tx = st.pool.begin().await?;
    let n = sqlx::query("DELETE FROM sso_providers WHERE name = $1").bind(&name).execute(&mut *tx).await?.rows_affected();
    if n == 0 {
        return Err(err(StatusCode::NOT_FOUND, "provider not found"));
    }
    audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &user.username, action: "sso.delete", target: Some(&name), outcome: "ok", details: json!({}) }).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, ToSchema)]
pub struct TestResult {
    pub ok: bool,
    pub detail: String,
}

#[utoipa::path(post, path = "/v1/sso/providers/{name}/test", tag = "sso", security(("bearer" = [])), params(("name" = String, Path)),
    responses((status = 200, body = TestResult), (status = 404)))]
pub async fn test_provider(State(st): State<AppState>, Authn(user): Authn, Path(name): Path<String>) -> ApiResult<Json<TestResult>> {
    user.require_global("sso:write")?;
    let p = load_provider(&st, &name, false).await?;
    Ok(Json(match client_for(&st, &p).await {
        Ok(_) => TestResult { ok: true, detail: "discovery and keys fetched".into() },
        Err(e) => TestResult { ok: false, detail: e.1 },
    }))
}

// --- login ---------------------------------------------------------------------------------

#[derive(Serialize, ToSchema)]
pub struct PublicProvider {
    pub name: String,
    pub display_name: String,
}

#[utoipa::path(get, path = "/v1/auth/sso/providers", tag = "auth", responses((status = 200, body = Vec<PublicProvider>)))]
pub async fn public_providers(State(st): State<AppState>) -> ApiResult<Json<Vec<PublicProvider>>> {
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT name, display_name FROM sso_providers WHERE enabled ORDER BY display_name").fetch_all(&st.pool).await?;
    Ok(Json(rows.into_iter().map(|(name, display_name)| PublicProvider { name, display_name }).collect()))
}

async fn load_provider(st: &AppState, name: &str, must_be_enabled: bool) -> ApiResult<ProviderRow> {
    let r: Option<ProviderRow> = sqlx::query_as(&format!("SELECT {COLUMNS} FROM sso_providers WHERE name = $1")).bind(name).fetch_optional(&st.pool).await?;
    r.filter(|p| p.enabled || !must_be_enabled).ok_or_else(|| err(StatusCode::NOT_FOUND, "provider not found"))
}

fn http_client() -> Result<oidc_reqwest::Client, ApiError> {
    // No redirects: following them is an SSRF vector the OIDC specification does not need.
    oidc_reqwest::ClientBuilder::new().redirect(oidc_reqwest::redirect::Policy::none()).timeout(std::time::Duration::from_secs(15)).build().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn client_for(st: &AppState, p: &ProviderRow) -> Result<CoreClient<openidconnect::EndpointSet, openidconnect::EndpointNotSet, openidconnect::EndpointNotSet, openidconnect::EndpointNotSet, openidconnect::EndpointMaybeSet, openidconnect::EndpointMaybeSet>, ApiError> {
    let http = http_client()?;
    let issuer = IssuerUrl::new(p.issuer.clone()).map_err(|e| err(StatusCode::BAD_GATEWAY, format!("invalid issuer: {e}")))?;
    let meta = CoreProviderMetadata::discover_async(issuer, &http).await.map_err(|e| err(StatusCode::BAD_GATEWAY, format!("discovery failed: {e}")))?;
    let secret = match (&p.client_secret, &st.secrets_key) {
        (Some(sealed), Some(key)) => Some(ClientSecret::new(String::from_utf8_lossy(&crate::secrets::open(key, sealed)?).into_owned())),
        _ => None,
    };
    let uri = redirect_uri(st, &p.name).ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "DELBERT_PUBLIC_URL is not set"))?;
    Ok(CoreClient::from_provider_metadata(meta, ClientId::new(p.client_id.clone()), secret).set_redirect_uri(RedirectUrl::new(uri).map_err(|e| err(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?))
}

#[utoipa::path(get, path = "/v1/auth/sso/{provider}/login", tag = "auth", params(("provider" = String, Path)),
    responses((status = 303, description = "Redirect to the identity provider"), (status = 404)))]
pub async fn start(State(st): State<AppState>, Path(provider): Path<String>) -> ApiResult<Redirect> {
    let p = load_provider(&st, &provider, true).await?;
    let client = client_for(&st, &p).await?;
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut req = client.authorize_url(AuthenticationFlow::<CoreResponseType>::AuthorizationCode, CsrfToken::new_random, Nonce::new_random).set_pkce_challenge(challenge);
    for s in p.scopes.iter().filter(|s| *s != "openid") {
        req = req.add_scope(Scope::new(s.clone()));
    }
    let (url, state, nonce) = req.url();
    sqlx::query("INSERT INTO sso_states (state_hash, provider_id, nonce, pkce_verifier) VALUES ($1, $2, $3, $4)")
        .bind(hash_token(state.secret()))
        .bind(p.id)
        .bind(nonce.secret())
        .bind(verifier.secret())
        .execute(&st.pool)
        .await?;
    sqlx::query("DELETE FROM sso_states WHERE created_at < now() - make_interval(mins => $1)").bind(STATE_MINUTES).execute(&st.pool).await?;
    Ok(Redirect::to(url.as_str()))
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// Why a login was refused, for the audit trail and (briefly) the redirect.
fn refuse(st: &AppState, reason: &str) -> Response {
    let base = st.auth.ui_url.clone().unwrap_or_else(|| "/".into());
    let sep = if base.contains('?') { '&' } else { '?' };
    Redirect::to(&format!("{base}{sep}sso_error={}", reason.replace(' ', "+"))).into_response()
}

#[utoipa::path(get, path = "/v1/auth/sso/{provider}/callback", tag = "auth", params(("provider" = String, Path)),
    responses((status = 303, description = "Redirect to the UI with ?code= (or ?sso_error=)")))]
pub async fn callback(State(st): State<AppState>, ClientIp(ip): ClientIp, Path(provider): Path<String>, Query(q): Query<CallbackQuery>) -> ApiResult<Response> {
    let audit_denied = |reason: String| {
        let (st, provider, ip) = (st.clone(), provider.clone(), ip.clone());
        async move {
            if let Ok(mut tx) = st.pool.begin().await {
                let _ = audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &format!("sso:{provider}"), action: "auth.sso", target: None, outcome: "denied", details: json!({ "reason": reason, "ip": ip }) }).await;
                let _ = tx.commit().await;
            }
        }
    };
    if let Some(e) = &q.error {
        audit_denied(format!("{e}: {}", q.error_description.clone().unwrap_or_default())).await;
        return Ok(refuse(&st, "the identity provider refused the login"));
    }
    let (Some(code), Some(state)) = (q.code, q.state) else { return Ok(refuse(&st, "invalid callback")) };

    // The state is single use and bound to this provider.
    let p = load_provider(&st, &provider, true).await?;
    let stored: Option<(String, String)> = sqlx::query_as(
        "DELETE FROM sso_states WHERE state_hash = $1 AND provider_id = $2 AND created_at > now() - make_interval(mins => $3) RETURNING nonce, pkce_verifier",
    )
    .bind(hash_token(&state))
    .bind(p.id)
    .bind(STATE_MINUTES)
    .fetch_optional(&st.pool)
    .await?;
    let Some((nonce, verifier)) = stored else {
        audit_denied("unknown or expired state".into()).await;
        return Ok(refuse(&st, "login expired, try again"));
    };

    let identity = match fetch_identity(&st, &p, &code, &nonce, &verifier).await {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!("SSO login via {provider} failed: {}", e.1);
            audit_denied(e.1).await;
            return Ok(refuse(&st, "the identity token was not accepted"));
        }
    };
    match provision(&st, &p, &identity).await {
        Ok(user_id) => {
            let code = new_token();
            sqlx::query("INSERT INTO sso_codes (code_hash, user_id, expires_at) VALUES ($1, $2, now() + make_interval(secs => $3))").bind(hash_token(&code)).bind(user_id).bind(CODE_SECONDS as f64).execute(&st.pool).await?;
            sqlx::query("DELETE FROM sso_codes WHERE expires_at < now()").execute(&st.pool).await?;
            let mut tx = st.pool.begin().await?;
            audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &identity.username, action: "auth.sso", target: Some(&provider), outcome: "ok", details: json!({ "ip": ip, "groups": identity.groups.len() }) }).await?;
            tx.commit().await?;
            let base = st.auth.ui_url.clone().unwrap_or_else(|| "/".into());
            let sep = if base.contains('?') { '&' } else { '?' };
            Ok(Redirect::to(&format!("{base}{sep}code={code}")).into_response())
        }
        Err(e) => {
            audit_denied(format!("{}: {}", identity.username, e.1)).await;
            Ok(refuse(&st, &e.1))
        }
    }
}

struct Identity {
    subject: String,
    username: String,
    groups: HashSet<String>,
}

async fn fetch_identity(st: &AppState, p: &ProviderRow, code: &str, nonce: &str, verifier: &str) -> Result<Identity, ApiError> {
    let client = client_for(st, p).await?;
    let http = http_client()?;
    let token = client
        .exchange_code(AuthorizationCode::new(code.to_owned()))
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("token endpoint missing: {e}")))?
        .set_pkce_verifier(PkceCodeVerifier::new(verifier.to_owned()))
        .request_async(&http)
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("code exchange failed: {e}")))?;
    let id_token = openidconnect::TokenResponse::id_token(&token).ok_or_else(|| err(StatusCode::BAD_GATEWAY, "no ID token in the response"))?;
    let nonce = Nonce::new(nonce.to_owned());
    // Signature, issuer, audience, expiry and nonce are checked here.
    let claims = id_token.claims(&client.id_token_verifier(), &nonce).map_err(|e| err(StatusCode::BAD_GATEWAY, format!("ID token rejected: {e}")))?;
    let subject = claims.subject().as_str().to_owned();
    let username = claims
        .preferred_username()
        .map(|u| u.as_str().to_owned())
        .or_else(|| claims.email().map(|e| e.as_str().to_owned()))
        .unwrap_or_else(|| subject.clone());

    // The groups claim is not a standard one: read it from the (already verified) token payload.
    let raw = id_token.to_string();
    let payload = raw.split('.').nth(1).and_then(|s| data_encoding::BASE64URL_NOPAD.decode(s.trim_end_matches('=').as_bytes()).ok()).and_then(|b| serde_json::from_slice::<Value>(&b).ok()).unwrap_or(Value::Null);
    let groups = match &payload[&p.groups_claim] {
        Value::Array(a) => a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect(),
        Value::String(s) => HashSet::from([s.clone()]),
        _ => HashSet::new(),
    };
    Ok(Identity { subject, username, groups })
}

fn sanitize_username(raw: &str) -> String {
    let s: String = raw.chars().map(|c| if c.is_ascii_alphanumeric() || "._-@".contains(c) { c } else { '_' }).take(64).collect();
    if s.len() < 3 { format!("sso_{s}") } else { s }
}

/// Find or create the user for this identity and replace the roles the last login gave them.
async fn provision(st: &AppState, p: &ProviderRow, id: &Identity) -> Result<Uuid, ApiError> {
    let mut tx = st.pool.begin().await?;
    // Which roles do the user's groups give?
    let groups: Vec<String> = id.groups.iter().cloned().collect();
    let granted: Vec<(Uuid, Option<Uuid>)> = sqlx::query_as("SELECT role_id, tenant_id FROM sso_mappings WHERE provider_id = $1 AND group_name = ANY($2)").bind(p.id).bind(&groups).fetch_all(&mut *tx).await?;
    if granted.is_empty() && p.require_mapping {
        // Someone removed from every group loses what earlier logins gave them, not just the next login.
        sqlx::query("DELETE FROM user_roles WHERE source = $3 AND user_id IN (SELECT id FROM users WHERE sso_provider_id = $1 AND sso_subject = $2)")
            .bind(p.id)
            .bind(&id.subject)
            .bind(format!("sso:{}", p.name))
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Err(err(StatusCode::FORBIDDEN, "none of your groups is allowed to sign in"));
    }

    let existing: Option<(Uuid, bool)> = sqlx::query_as("SELECT id, active FROM users WHERE sso_provider_id = $1 AND sso_subject = $2 FOR UPDATE").bind(p.id).bind(&id.subject).fetch_optional(&mut *tx).await?;
    let user_id = match existing {
        Some((uid, active)) => {
            if !active {
                return Err(err(StatusCode::FORBIDDEN, "this account is disabled"));
            }
            uid
        }
        None => {
            let username = sanitize_username(&id.username);
            // A name that already exists is never adopted: linking by name would let anyone who can set
            // that attribute at the identity provider take over a local (possibly administrator) account.
            let taken: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)").bind(&username).fetch_one(&mut *tx).await?;
            if taken {
                return Err(err(StatusCode::CONFLICT, "an account with this name already exists; ask an administrator"));
            }
            // '!' is not a valid password hash: this account has no local password.
            let uid: Uuid = sqlx::query_scalar("INSERT INTO users (username, password_hash, sso_provider_id, sso_subject) VALUES ($1, '!sso', $2, $3) RETURNING id").bind(&username).bind(p.id).bind(&id.subject).fetch_one(&mut *tx).await?;
            audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &format!("sso:{}", p.name), action: "user.create", target: Some(&username), outcome: "ok", details: json!({ "sso": p.name }) }).await?;
            uid
        }
    };
    let source = format!("sso:{}", p.name);
    sqlx::query("DELETE FROM user_roles WHERE user_id = $1 AND source = $2").bind(user_id).bind(&source).execute(&mut *tx).await?;
    for (role_id, tenant_id) in granted {
        sqlx::query("INSERT INTO user_roles (user_id, role_id, tenant_id, source) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING").bind(user_id).bind(role_id).bind(tenant_id).bind(&source).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(user_id)
}

#[derive(Deserialize, ToSchema)]
pub struct ExchangeBody {
    pub code: String,
    /// Also set the session cookie and return a CSRF token.
    #[serde(default)]
    pub cookie: bool,
}

#[utoipa::path(post, path = "/v1/auth/sso/exchange", tag = "auth", request_body = ExchangeBody,
    responses((status = 200, body = LoginResponse), (status = 401, description = "Unknown, used or expired code")))]
pub async fn exchange(State(st): State<AppState>, ClientIp(ip): ClientIp, headers: HeaderMap, Json(body): Json<ExchangeBody>) -> ApiResult<Response> {
    let user: Option<Uuid> = sqlx::query_scalar("DELETE FROM sso_codes WHERE code_hash = $1 AND expires_at > now() RETURNING user_id").bind(hash_token(&body.code)).fetch_optional(&st.pool).await?;
    let user = user.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid or expired code"))?;
    // The account may have been disabled in the meantime.
    let active: bool = sqlx::query_scalar("SELECT active FROM users WHERE id = $1").bind(user).fetch_one(&st.pool).await?;
    if !active {
        return Err(err(StatusCode::UNAUTHORIZED, "invalid or expired code"));
    }
    let ua = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).map(|v| v.chars().take(200).collect::<String>());
    let login = open_session(&st, user, &ip, ua, body.cookie).await?;
    let token = login.token.clone();
    let mut resp = Json(login).into_response();
    if body.cookie {
        set_session_cookie(&st, &mut resp, &token);
    }
    Ok(resp)
}
