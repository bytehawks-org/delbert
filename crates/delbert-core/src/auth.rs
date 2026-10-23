//! Local users, customizable roles (RBAC) and API sessions.
//!
//! * Passwords: Argon2id. Session tokens: 32 random bytes, only their SHA-256 is stored.
//! * A role is a set of `resource:action` permission strings; `*` grants everything and
//!   `resource:*` every action on a resource.
//! * A user holds roles through assignments: global, or scoped to one tenant (docs/RBAC.md).
//!   Permissions in `GLOBAL_ONLY` are never granted by a tenant-scoped assignment.
//! * The last active holder of a global `*` cannot be removed, deactivated or deleted.
//!
//! Not done yet (docs/ROADMAP.md): SSO (OIDC/SAML), LDAP, MFA, login throttling/captcha.

use std::collections::{BTreeMap, HashMap, HashSet};

use axum::response::IntoResponse;
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::{OsRng, RngCore}},
};
use axum::{
    Json,
    extract::{FromRequestParts, Path, State},
    http::{StatusCode, header, request::Parts},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, types::Uuid};
use utoipa::ToSchema;

use crate::{
    api::{ApiError, ApiResult, AppState, MfaPolicy},
    audit::{self, NewEvent},
};

/// Every permission a role may contain (besides `*` and `resource:*`).
pub const PERMISSIONS: [&str; 28] = [
    "tenants:read", "tenants:create", "tenants:delete", "tenants:settings",
    "agents:read", "agents:write", "agents:enroll", "agents:preview",
    "policies:read", "policies:write", "policies:approve",
    "secrets:read", "secrets:write",
    "artifacts:read", "artifacts:write",
    "proxies:read", "proxies:write",
    "users:read", "users:write",
    "roles:read", "roles:write", "roles:assign",
    "audit:read", "audit:export", "audit:verify",
    "tokens:manage",
    "sso:read", "sso:write",
];

/// Permissions that only a global assignment can grant (they are not about one tenant).
pub const GLOBAL_ONLY: [&str; 11] = [
    "tenants:create", "tenants:delete", "proxies:read", "proxies:write", "users:read", "users:write", "roles:read", "roles:write", "audit:verify", "sso:read", "sso:write",
];

/// `*`, the exact permission or `resource:*`.
fn grants(set: &HashSet<String>, permission: &str) -> bool {
    set.contains("*") || set.contains(permission) || permission.split_once(':').is_some_and(|(resource, _)| set.contains(&format!("{resource}:*")))
}

const SESSION_HOURS: i64 = 8;
const MIN_PASSWORD: usize = 12;

// --- passwords and tokens ---------------------------------------------------------------

fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default().hash_password(password.as_bytes(), &salt).map(|h| h.to_string()).map_err(|e| anyhow::anyhow!("hashing failed: {e}"))
}

fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok())
}

/// Hashing is CPU heavy: keep it off the async workers.
async fn hash_blocking(password: String) -> ApiResult<String> {
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .ok()
        .and_then(Result::ok)
        .ok_or_else(|| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into()))
}

fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

fn check_password(password: &str) -> ApiResult<()> {
    if password.chars().count() < MIN_PASSWORD {
        return Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, format!("password must be at least {MIN_PASSWORD} characters")));
    }
    Ok(())
}

fn check_username(name: &str) -> ApiResult<()> {
    if (3..=64).contains(&name.len()) && name.chars().all(|c| c.is_ascii_alphanumeric() || "._-@".contains(c)) {
        Ok(())
    } else {
        Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, "invalid username (3-64 of letters, digits, . _ - @)".into()))
    }
}

// --- current user ------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CurrentUser {
    pub id: Uuid,
    pub username: String,
    /// Permissions of the global assignments.
    pub global: HashSet<String>,
    /// Permissions of the assignments scoped to one tenant.
    pub scoped: HashMap<Uuid, HashSet<String>>,
    pub session_id: Uuid,
    /// Authenticated with an API token (which can never manage tokens, MFA or sessions).
    pub via_token: bool,
    /// The user has confirmed a second factor.
    pub mfa_enrolled: bool,
    token_hash: Vec<u8>,
}

impl CurrentUser {
    /// Does the user hold `permission`, globally or (unless it is global-only) for `tenant`?
    pub fn can(&self, permission: &str, tenant: Option<Uuid>) -> bool {
        if grants(&self.global, permission) {
            return true;
        }
        match tenant {
            Some(t) if !GLOBAL_ONLY.contains(&permission) => self.scoped.get(&t).is_some_and(|set| grants(set, permission)),
            _ => false,
        }
    }

    /// `Ok` if the user holds `permission` through a global assignment; 403 otherwise.
    pub fn require_global(&self, permission: &str) -> ApiResult<()> {
        if grants(&self.global, permission) { Ok(()) } else { Err(forbidden(permission)) }
    }

    /// Resolve a tenant by name and check `permission` on it. A tenant the user has no role in
    /// at all looks missing (404), so tenant names cannot be probed.
    pub async fn tenant(&self, pool: &PgPool, name: &str, permission: &str) -> ApiResult<Uuid> {
        let tid = crate::api::tenant_id(pool, name).await?;
        if self.can(permission, Some(tid)) {
            Ok(tid)
        } else if self.global.is_empty() && !self.scoped.contains_key(&tid) {
            Err(ApiError(StatusCode::NOT_FOUND, "tenant not found".into()))
        } else {
            Err(forbidden(permission))
        }
    }

    /// Tenants on which `permission` is held: `None` = all of them.
    pub fn tenants_with(&self, permission: &str) -> Option<Vec<Uuid>> {
        if grants(&self.global, permission) {
            return None;
        }
        let allowed = !GLOBAL_ONLY.contains(&permission);
        Some(self.scoped.iter().filter(|(_, set)| allowed && grants(set, permission)).map(|(t, _)| *t).collect())
    }
}

fn forbidden(permission: &str) -> ApiError {
    ApiError(StatusCode::FORBIDDEN, format!("missing permission '{permission}'"))
}

pub const COOKIE: &str = "delbert_session";
/// A session unused for this long ends.
const IDLE_MINUTES: i32 = 30;
/// Time to give the second factor after the password.
const PENDING_MINUTES: i32 = 5;

/// How much of a session a handler accepts.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Need {
    /// Password and, if enabled, second factor given; MFA enrolment done when the policy requires it.
    Full,
    /// Like `Full` but allowed while MFA enrolment is still missing (the endpoints that fix that).
    Enrolling,
    /// A session still waiting for its second factor (only `POST /v1/auth/mfa`).
    Pending,
}

fn cookie_value(parts: &Parts) -> Option<String> {
    let all = parts.headers.get(header::COOKIE)?.to_str().ok()?;
    all.split(';').filter_map(|c| c.trim().strip_prefix(&format!("{COOKIE}="))).next().map(str::to_owned)
}

async fn authenticate(parts: &Parts, st: &AppState, need: Need) -> Result<CurrentUser, ApiError> {
    let unauthorized = || ApiError(StatusCode::UNAUTHORIZED, "missing or invalid session".into());
    let bearer = parts.headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer "));
    let (token, via_cookie) = match (bearer, cookie_value(parts)) {
        (Some(t), _) => (t.to_owned(), false),
        (None, Some(c)) => (c, true),
        _ => return Err(unauthorized()),
    };
    let hash = token_hash(&token);
    if token.starts_with(TOKEN_PREFIX) {
        return if need == Need::Full { authenticate_token(st, &hash).await } else { Err(ApiError(StatusCode::FORBIDDEN, "API tokens cannot be used here".into())) };
    }
    let row: Option<(Uuid, String, Uuid, bool, Option<Vec<u8>>, bool, bool)> = sqlx::query_as(
        "SELECT u.id, u.username, s.id, s.mfa_ok, s.csrf_hash, u.totp_enabled, u.sso_provider_id IS NOT NULL FROM sessions s JOIN users u ON u.id = s.user_id \
         WHERE s.token_hash = $1 AND s.expires_at > now() AND s.last_seen > now() - make_interval(mins => $2) AND u.active",
    )
    .bind(&hash)
    .bind(IDLE_MINUTES)
    .fetch_optional(&st.pool)
    .await?;
    let (id, username, session_id, mfa_ok, csrf_hash, totp_enabled, is_sso) = row.ok_or_else(unauthorized)?;

    // A pending session is good for nothing but the second factor; a full one is not for that.
    if (need == Need::Pending) == mfa_ok {
        return Err(if mfa_ok { ApiError(StatusCode::CONFLICT, "no second factor is pending".into()) } else { ApiError(StatusCode::UNAUTHORIZED, "second factor required: POST /v1/auth/mfa".into()) });
    }
    // Browser cookies are ambient credentials: unsafe methods must prove intent with the CSRF token.
    if via_cookie && !matches!(parts.method, axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS) {
        let ok = parts.headers.get("x-csrf-token").and_then(|v| v.to_str().ok()).is_some_and(|t| csrf_hash.as_deref() == Some(token_hash(t).as_slice()));
        if !ok {
            return Err(ApiError(StatusCode::FORBIDDEN, "missing or invalid CSRF token".into()));
        }
    }
    sqlx::query("UPDATE sessions SET last_seen = now() WHERE id = $1 AND last_seen < now() - interval '1 minute'").bind(session_id).execute(&st.pool).await?;

    let (global, scoped) = load_permissions(&st.pool, id).await?;
    let user = CurrentUser { id, username, global, scoped, session_id, via_token: false, mfa_enrolled: totp_enabled, token_hash: hash };

    // Single-sign-on users authenticate (and do MFA) at their identity provider.
    let must_have_mfa = !is_sso && match st.auth.mfa {
        MfaPolicy::Optional => false,
        MfaPolicy::Admins => !user.global.is_empty(),
        MfaPolicy::All => true,
    };
    if need == Need::Full && must_have_mfa && !totp_enabled {
        return Err(ApiError(StatusCode::FORBIDDEN, "multi-factor authentication is required: enroll with POST /v1/me/mfa/enroll".into()));
    }
    Ok(user)
}

type Permissions = (HashSet<String>, HashMap<Uuid, HashSet<String>>);

/// What the user's role assignments grant: global permissions and per-tenant ones.
async fn load_permissions(pool: &PgPool, user_id: Uuid) -> ApiResult<Permissions> {
    let rows: Vec<(Option<Uuid>, String)> = sqlx::query_as(
        "SELECT ur.tenant_id, unnest(r.permissions) FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = $1",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    let mut global = HashSet::new();
    let mut scoped: HashMap<Uuid, HashSet<String>> = HashMap::new();
    for (tenant, permission) in rows {
        match tenant {
            None => global.insert(permission),
            Some(t) => scoped.entry(t).or_default().insert(permission),
        };
    }
    // A tenant-scoped assignment without permissions still counts as "has a role there".
    let empty: Vec<Uuid> = sqlx::query_scalar("SELECT DISTINCT tenant_id FROM user_roles WHERE user_id = $1 AND tenant_id IS NOT NULL").bind(user_id).fetch_all(pool).await?;
    for t in empty {
        scoped.entry(t).or_default();
    }
    Ok((global, scoped))
}

pub const TOKEN_PREFIX: &str = "dlb_";

/// An API token acts as its owner, reduced to the token's permissions and, if set, to one tenant.
/// The owner's rights are read at every use, so a token never outlives or exceeds them.
async fn authenticate_token(st: &AppState, hash: &[u8]) -> Result<CurrentUser, ApiError> {
    let unauthorized = || ApiError(StatusCode::UNAUTHORIZED, "missing or invalid session".into());
    let row: Option<(Uuid, Uuid, String, Option<Uuid>, Vec<String>)> = sqlx::query_as(
        "SELECT t.id, u.id, u.username, t.tenant_id, t.permissions FROM api_tokens t JOIN users u ON u.id = t.user_id \
         WHERE t.token_hash = $1 AND t.expires_at > now() AND u.active",
    )
    .bind(hash)
    .fetch_optional(&st.pool)
    .await?;
    let (token_id, id, username, tenant, allowed) = row.ok_or_else(unauthorized)?;
    sqlx::query("UPDATE api_tokens SET last_used = now() WHERE id = $1 AND (last_used IS NULL OR last_used < now() - interval '1 minute')").bind(token_id).execute(&st.pool).await?;
    let allowed: HashSet<String> = allowed.into_iter().collect();
    let keep = |set: HashSet<String>| -> HashSet<String> { set.into_iter().filter(|p| grants(&allowed, p) || (p == "*" && allowed.contains("*"))).collect() };
    // A permission survives when the token's list covers it; the owner's wildcards are narrowed
    // to the token's own entries.
    let narrow = |set: &HashSet<String>| -> HashSet<String> {
        if set.contains("*") {
            allowed.clone()
        } else {
            keep(set.clone())
        }
    };
    let (global, scoped) = load_permissions(&st.pool, id).await?;
    let (global, scoped) = match tenant {
        None => (narrow(&global), scoped.into_iter().map(|(t, s)| (t, narrow(&s))).collect()),
        Some(t) => {
            // Inside one tenant: what the owner holds there, globally or scoped, never a global-only permission.
            let mut both = narrow(&global);
            both.extend(scoped.get(&t).map(narrow).unwrap_or_default());
            both.retain(|p| p == "*" || !GLOBAL_ONLY.contains(&p.as_str()));
            (HashSet::new(), HashMap::from([(t, both)]))
        }
    };
    Ok(CurrentUser { id, username, global, scoped, session_id: token_id, via_token: true, mfa_enrolled: true, token_hash: hash.to_vec() })
}

/// Extractor: a valid, unexpired, non-idle session of an active user who completed login.
pub struct Authn(pub CurrentUser);

impl FromRequestParts<AppState> for Authn {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, ApiError> {
        authenticate(parts, st, Need::Full).await.map(Authn)
    }
}

/// Like [`Authn`] but usable while MFA enrolment is still pending: profile, MFA enrolment, logout.
pub struct AuthnEnrolling(pub CurrentUser);

impl FromRequestParts<AppState> for AuthnEnrolling {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, ApiError> {
        authenticate(parts, st, Need::Enrolling).await.map(AuthnEnrolling)
    }
}

/// A session that passed the password and waits for the second factor.
pub struct AuthnPending(pub CurrentUser);

impl FromRequestParts<AppState> for AuthnPending {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, ApiError> {
        authenticate(parts, st, Need::Pending).await.map(AuthnPending)
    }
}

/// Client address, for throttling and the session list.
pub struct ClientIp(pub String);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, Self::Rejection> {
        let forwarded = st.auth.trust_forwarded.then(|| parts.headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).and_then(|v| v.split(',').next())).flatten();
        let ip = forwarded
            .map(|v| v.trim().to_owned())
            .or_else(|| parts.extensions.get::<axum::extract::ConnectInfo<std::net::SocketAddr>>().map(|c| c.0.ip().to_string()))
            .unwrap_or_else(|| "unknown".into());
        Ok(ClientIp(ip))
    }
}

// --- bootstrap ---------------------------------------------------------------------------

/// Create the first administrator when the database has no users.
pub async fn bootstrap_admin(pool: &PgPool, password: Option<&str>) -> anyhow::Result<()> {
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users").fetch_one(pool).await?;
    if users > 0 {
        return Ok(());
    }
    let password = password.ok_or_else(|| anyhow::anyhow!("no users exist: set DELBERT_BOOTSTRAP_ADMIN_PASSWORD to create the first administrator"))?;
    if password.chars().count() < MIN_PASSWORD {
        anyhow::bail!("DELBERT_BOOTSTRAP_ADMIN_PASSWORD must be at least {MIN_PASSWORD} characters");
    }
    let owned = password.to_owned();
    let hash = tokio::task::spawn_blocking(move || hash_password(&owned)).await??;
    let mut tx = pool.begin().await?;
    let id: Uuid = sqlx::query_scalar("INSERT INTO users (username, password_hash) VALUES ('admin', $1) RETURNING id").bind(hash).fetch_one(&mut *tx).await?;
    sqlx::query("INSERT INTO user_roles (user_id, role_id) SELECT $1, id FROM roles WHERE name = 'platform-admin'").bind(id).execute(&mut *tx).await?;
    audit::append(&mut tx, &NewEvent { tenant_id: None, actor: "system", action: "user.bootstrap", target: Some("admin"), outcome: "ok", details: json!({}) }).await?;
    tx.commit().await?;
    tracing::warn!("created the initial administrator 'admin'; change its password");
    Ok(())
}

// --- login / logout / me -----------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    /// Also set the session as an `HttpOnly` cookie and return a CSRF token (for browsers).
    #[serde(default)]
    pub cookie: bool,
}

#[derive(Serialize, ToSchema)]
pub struct LoginResponse {
    pub token: String,
    /// Unix seconds. While `mfa_required`, the time left to give the second factor.
    pub expires_at: i64,
    /// The password was right but a TOTP or recovery code must follow (`POST /v1/auth/mfa`).
    pub mfa_required: bool,
    /// Cookie sessions: send it as `X-CSRF-Token` on every unsafe request.
    pub csrf_token: Option<String>,
}

/// Real hash of a throwaway password, so unknown users cost the same time as wrong passwords.
fn dummy_hash() -> &'static str {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DUMMY.get_or_init(|| hash_password("timing-equalizer-password").expect("hashing works"))
}

/// Failed attempts tolerated in the window: per (user, address), per address, per user.
const WINDOW_MINUTES: i32 = 15;
const MAX_PER_PAIR: i64 = 5;
const MAX_PER_IP: i64 = 30;
const MAX_PER_USER: i64 = 20;

/// Is this login blocked by the throttle? Counting per (user, address) keeps a stranger from
/// locking the real user out; the per-address and per-user ceilings still stop spraying and
/// slow distributed guessing.
async fn throttled(pool: &PgPool, username: &str, ip: &str) -> ApiResult<bool> {
    let (pair, by_ip, by_user): (i64, i64, i64) = sqlx::query_as(
        "SELECT COUNT(*) FILTER (WHERE username = $1 AND ip = $2), COUNT(*) FILTER (WHERE ip = $2), COUNT(*) FILTER (WHERE username = $1) \
         FROM login_attempts WHERE NOT success AND at > now() - make_interval(mins => $3) AND (username = $1 OR ip = $2)",
    )
    .bind(username)
    .bind(ip)
    .bind(WINDOW_MINUTES)
    .fetch_one(pool)
    .await?;
    Ok(pair >= MAX_PER_PAIR || by_ip >= MAX_PER_IP || by_user >= MAX_PER_USER)
}

async fn record_attempt(pool: &PgPool, username: &str, ip: &str, success: bool) -> ApiResult<()> {
    sqlx::query("INSERT INTO login_attempts (username, ip, success) VALUES ($1, $2, $3)").bind(username).bind(ip).bind(success).execute(pool).await?;
    if success {
        sqlx::query("DELETE FROM login_attempts WHERE username = $1 AND ip = $2").bind(username).bind(ip).execute(pool).await?;
    }
    sqlx::query("DELETE FROM login_attempts WHERE at < now() - interval '1 day'").execute(pool).await?;
    Ok(())
}

fn too_many() -> ApiError {
    ApiError(StatusCode::TOO_MANY_REQUESTS, format!("too many failed attempts: try again in {WINDOW_MINUTES} minutes"))
}

fn cookie_header(st: &AppState, token: &str, max_age: i64) -> header::HeaderValue {
    let secure = if st.auth.cookie_secure { "; Secure" } else { "" };
    header::HeaderValue::from_str(&format!("{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{secure}")).expect("cookie is ASCII")
}

fn random_token() -> String {
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    B64.encode(raw)
}

#[utoipa::path(post, path = "/v1/auth/login", tag = "auth", request_body = LoginRequest,
    responses((status = 200, body = LoginResponse), (status = 401, description = "Invalid credentials"), (status = 429, description = "Too many failed attempts")))]
pub async fn login(State(st): State<AppState>, ClientIp(ip): ClientIp, headers: axum::http::HeaderMap, Json(body): Json<LoginRequest>) -> ApiResult<axum::response::Response> {
    if throttled(&st.pool, &body.username, &ip).await? {
        let mut tx = st.pool.begin().await?;
        audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &body.username, action: "auth.login", target: None, outcome: "throttled", details: json!({ "ip": ip }) }).await?;
        tx.commit().await?;
        return Err(too_many());
    }
    let row: Option<(Uuid, String, bool, bool)> =
        sqlx::query_as("SELECT id, password_hash, active, totp_enabled FROM users WHERE username = $1").bind(&body.username).fetch_optional(&st.pool).await?;
    let (hash, known) = match &row {
        Some((_, h, _, _)) => (h.clone(), true),
        None => (dummy_hash().to_string(), false),
    };
    let password = body.password.clone();
    let matches = tokio::task::spawn_blocking(move || verify_password(&password, &hash)).await.unwrap_or(false);
    let ok = matches && known && row.as_ref().is_some_and(|r| r.2);

    let mut tx = st.pool.begin().await?;
    if !ok {
        record_attempt(&st.pool, &body.username, &ip, false).await?;
        audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &body.username, action: "auth.login", target: None, outcome: "denied", details: json!({ "ip": ip }) }).await?;
        tx.commit().await?;
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid credentials".into()));
    }
    let (user_id, mfa) = row.map(|r| (r.0, r.3)).expect("checked above");
    // With SSO in charge, only break-glass administrators (users with a global role) keep a local password.
    if st.auth.local_login == crate::api::LocalLogin::Admins {
        let admin: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM user_roles WHERE user_id = $1 AND tenant_id IS NULL)").bind(user_id).fetch_one(&st.pool).await?;
        if !admin {
            record_attempt(&st.pool, &body.username, &ip, false).await?;
            audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &body.username, action: "auth.login", target: None, outcome: "denied", details: json!({ "ip": ip, "reason": "local login is limited to administrators" }) }).await?;
            tx.commit().await?;
            return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid credentials".into()));
        }
    }
    // With MFA the password alone only opens a short pending session; the attempt counts as
    // successful only after the second factor.
    if !mfa {
        record_attempt(&st.pool, &body.username, &ip, true).await?;
    }

    let token = random_token();
    let csrf = body.cookie.then(random_token);
    let user_agent = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).map(|v| v.chars().take(200).collect::<String>());
    let expires_at: i64 = sqlx::query_scalar(
        "INSERT INTO sessions (token_hash, user_id, expires_at, csrf_hash, mfa_ok, ip, user_agent) \
         VALUES ($1, $2, now() + CASE WHEN $4 THEN make_interval(mins => $6) ELSE make_interval(hours => $5) END, $3, NOT $4, $7, $8) \
         RETURNING (EXTRACT(EPOCH FROM expires_at))::bigint",
    )
    .bind(token_hash(&token))
    .bind(user_id)
    .bind(csrf.as_deref().map(token_hash))
    .bind(mfa)
    .bind(SESSION_HOURS as i32)
    .bind(PENDING_MINUTES)
    .bind(&ip)
    .bind(user_agent)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM sessions WHERE expires_at < now() OR last_seen < now() - make_interval(mins => $1)").bind(IDLE_MINUTES).execute(&mut *tx).await?;
    audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &body.username, action: "auth.login", target: None, outcome: if mfa { "mfa-pending" } else { "ok" }, details: json!({ "ip": ip, "cookie": body.cookie }) }).await?;
    tx.commit().await?;

    // The cookie lives as long as a full session; the short pending lifetime is enforced server-side.
    let max_age = SESSION_HOURS * 3600;
    let mut resp = Json(LoginResponse { token: token.clone(), expires_at, mfa_required: mfa, csrf_token: csrf }).into_response();
    if body.cookie {
        resp.headers_mut().insert(header::SET_COOKIE, cookie_header(&st, &token, max_age));
    }
    Ok(resp)
}

#[derive(Deserialize, ToSchema)]
pub struct MfaCode {
    /// A 6-digit TOTP code or an unused recovery code.
    pub code: String,
}

/// Check a TOTP or recovery code for the user; consumes what it accepts.
pub(crate) async fn check_second_factor(st: &AppState, user_id: Uuid, code: &str) -> ApiResult<bool> {
    let key = st.secrets_key.as_ref().ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, "MFA needs DELBERT_SECRETS_KEY_FILE".into()))?;
    let mut tx = st.pool.begin().await?;
    let row: Option<(Option<Vec<u8>>, i64)> = sqlx::query_as("SELECT totp_secret, totp_last_step FROM users WHERE id = $1 FOR UPDATE").bind(user_id).fetch_optional(&mut *tx).await?;
    let Some((Some(sealed), last_step)) = row else { return Ok(false) };
    let secret = crate::secrets::open(key, &sealed)?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
    if let Some(step) = crate::totp::verify(&secret, code, now, last_step) {
        sqlx::query("UPDATE users SET totp_last_step = $2 WHERE id = $1").bind(user_id).bind(step).execute(&mut *tx).await?;
        tx.commit().await?;
        return Ok(true);
    }
    // Recovery codes are single use.
    let normalized: String = code.trim().to_ascii_lowercase().replace('-', "");
    let used = sqlx::query("DELETE FROM user_recovery_codes WHERE user_id = $1 AND code_hash = $2").bind(user_id).bind(token_hash(&normalized)).execute(&mut *tx).await?.rows_affected();
    tx.commit().await?;
    Ok(used > 0)
}

#[utoipa::path(post, path = "/v1/auth/mfa", tag = "auth", security(("bearer" = [])), request_body = MfaCode,
    responses((status = 200, body = LoginResponse), (status = 401, description = "Wrong code"), (status = 429)))]
pub async fn complete_mfa(State(st): State<AppState>, ClientIp(ip): ClientIp, AuthnPending(user): AuthnPending, Json(body): Json<MfaCode>) -> ApiResult<axum::response::Response> {
    if throttled(&st.pool, &user.username, &ip).await? {
        return Err(too_many());
    }
    if !check_second_factor(&st, user.id, &body.code).await? {
        record_attempt(&st.pool, &user.username, &ip, false).await?;
        let mut tx = st.pool.begin().await?;
        audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &user.username, action: "auth.mfa", target: None, outcome: "denied", details: json!({ "ip": ip }) }).await?;
        tx.commit().await?;
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid code".into()));
    }
    record_attempt(&st.pool, &user.username, &ip, true).await?;
    let expires_at: i64 = sqlx::query_scalar(
        "UPDATE sessions SET mfa_ok = true, expires_at = now() + make_interval(hours => $2) WHERE id = $1 RETURNING (EXTRACT(EPOCH FROM expires_at))::bigint",
    )
    .bind(user.session_id)
    .bind(SESSION_HOURS as i32)
    .fetch_one(&st.pool)
    .await?;
    let mut tx = st.pool.begin().await?;
    audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &user.username, action: "auth.mfa", target: None, outcome: "ok", details: json!({ "ip": ip }) }).await?;
    tx.commit().await?;
    // The session token and cookie stay the same; only the server-side state changed.
    Ok(Json(LoginResponse { token: String::new(), expires_at, mfa_required: false, csrf_token: None }).into_response())
}

#[utoipa::path(post, path = "/v1/auth/logout", tag = "auth", security(("bearer" = [])), responses((status = 204)))]
pub async fn logout(State(st): State<AppState>, AuthnEnrolling(user): AuthnEnrolling) -> ApiResult<axum::response::Response> {
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1").bind(&user.token_hash).execute(&st.pool).await?;
    let mut resp = StatusCode::NO_CONTENT.into_response();
    resp.headers_mut().insert(header::SET_COOKIE, cookie_header(&st, "", 0));
    Ok(resp)
}

/// A role held by a user, globally (`tenant` absent) or for one tenant.
#[derive(Serialize, Deserialize, ToSchema, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Assignment {
    pub role: String,
    pub tenant: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct Me {
    pub username: String,
    /// Permissions of the global assignments (they apply to every tenant).
    pub permissions: Vec<String>,
    pub assignments: Vec<Assignment>,
    /// Permissions granted by tenant-scoped assignments, per tenant name.
    pub tenants: BTreeMap<String, Vec<String>>,
    /// A second factor is set up.
    pub mfa_enabled: bool,
}

async fn assignments_of(pool: &PgPool, user_id: Uuid) -> ApiResult<Vec<Assignment>> {
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT r.name, t.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id LEFT JOIN tenants t ON t.id = ur.tenant_id WHERE ur.user_id = $1 ORDER BY t.name NULLS FIRST, r.name",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(role, tenant)| Assignment { role, tenant }).collect())
}

#[utoipa::path(get, path = "/v1/me", tag = "auth", security(("bearer" = [])), responses((status = 200, body = Me)))]
pub async fn me(State(st): State<AppState>, AuthnEnrolling(user): AuthnEnrolling) -> ApiResult<Json<Me>> {
    let names: Vec<(Uuid, String)> = sqlx::query_as("SELECT id, name FROM tenants").fetch_all(&st.pool).await?;
    let names: HashMap<Uuid, String> = names.into_iter().collect();
    let sorted = |set: &HashSet<String>| {
        let mut v: Vec<String> = set.iter().cloned().collect();
        v.sort();
        v
    };
    let tenants = user.scoped.iter().filter_map(|(t, set)| names.get(t).map(|n| (n.clone(), sorted(set)))).collect();
    Ok(Json(Me { permissions: sorted(&user.global), assignments: assignments_of(&st.pool, user.id).await?, tenants, mfa_enabled: user.mfa_enrolled, username: user.username }))
}

// --- users ---------------------------------------------------------------------------------

#[derive(Serialize, ToSchema)]
pub struct UserOut {
    pub username: String,
    pub active: bool,
    pub assignments: Vec<Assignment>,
}

#[derive(Deserialize, ToSchema)]
pub struct NewUser {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub assignments: Vec<Assignment>,
}

#[derive(Deserialize, ToSchema)]
pub struct UserUpdate {
    pub password: Option<String>,
    pub active: Option<bool>,
    /// Replaces the whole set of assignments when present.
    pub assignments: Option<Vec<Assignment>>,
}

/// Insert one assignment after checking that the role exists and fits the scope.
async fn assign(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, user_id: Uuid, a: &Assignment) -> ApiResult<()> {
    let role: Option<(Uuid, String)> = sqlx::query_as("SELECT id, scope FROM roles WHERE name = $1").bind(&a.role).fetch_optional(&mut **tx).await?;
    let (role_id, scope) = role.ok_or_else(|| ApiError(StatusCode::UNPROCESSABLE_ENTITY, format!("unknown role '{}'", a.role)))?;
    let tenant_id: Option<Uuid> = match &a.tenant {
        Some(name) => Some(sqlx::query_scalar("SELECT id FROM tenants WHERE name = $1").bind(name).fetch_optional(&mut **tx).await?.ok_or_else(|| ApiError(StatusCode::UNPROCESSABLE_ENTITY, format!("unknown tenant '{name}'")))?),
        None => None,
    };
    let fits = match (&a.tenant, scope.as_str()) {
        (_, "any") | (None, "global") | (Some(_), "tenant") => true,
        _ => false,
    };
    if !fits {
        let wanted = if a.tenant.is_some() { "a tenant" } else { "the whole platform" };
        return Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, format!("role '{}' (scope {scope}) cannot be assigned to {wanted}", a.role)));
    }
    sqlx::query("INSERT INTO user_roles (user_id, role_id, tenant_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING").bind(user_id).bind(role_id).bind(tenant_id).execute(&mut **tx).await?;
    Ok(())
}

async fn set_assignments(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, user_id: Uuid, assignments: &[Assignment]) -> ApiResult<()> {
    sqlx::query("DELETE FROM user_roles WHERE user_id = $1 AND source = 'manual'").bind(user_id).execute(&mut **tx).await?;
    for a in assignments {
        assign(tx, user_id, a).await?;
    }
    Ok(())
}

/// At least one active user must keep a global `*`.
async fn ensure_admin_remains(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>) -> ApiResult<()> {
    let admins: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT u.id) FROM users u JOIN user_roles ur ON ur.user_id = u.id JOIN roles r ON r.id = ur.role_id \
         WHERE u.active AND ur.tenant_id IS NULL AND '*' = ANY (r.permissions)",
    )
    .fetch_one(&mut **tx)
    .await?;
    if admins == 0 {
        return Err(ApiError(StatusCode::CONFLICT, "this would leave no active administrator".into()));
    }
    Ok(())
}

#[utoipa::path(get, path = "/v1/users", tag = "users", security(("bearer" = [])), responses((status = 200, body = Vec<UserOut>)))]
pub async fn list_users(State(st): State<AppState>, Authn(user): Authn) -> ApiResult<Json<Vec<UserOut>>> {
    user.require_global("users:read")?;
    let users: Vec<(Uuid, String, bool)> = sqlx::query_as("SELECT id, username, active FROM users ORDER BY username").fetch_all(&st.pool).await?;
    let mut out = Vec::with_capacity(users.len());
    for (id, username, active) in users {
        out.push(UserOut { username, active, assignments: assignments_of(&st.pool, id).await? });
    }
    Ok(Json(out))
}

#[utoipa::path(post, path = "/v1/users", tag = "users", security(("bearer" = [])), request_body = NewUser,
    responses((status = 201, body = UserOut), (status = 409, description = "Already exists"), (status = 422)))]
pub async fn create_user(State(st): State<AppState>, Authn(user): Authn, Json(body): Json<NewUser>) -> ApiResult<(StatusCode, Json<UserOut>)> {
    user.require_global("users:write")?;
    check_username(&body.username)?;
    check_password(&body.password)?;
    let hash = hash_blocking(body.password).await?;
    let mut tx = st.pool.begin().await?;
    let id: Uuid = sqlx::query_scalar("INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id").bind(&body.username).bind(hash).fetch_one(&mut *tx).await?;
    set_assignments(&mut tx, id, &body.assignments).await?;
    audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &user.username, action: "user.create", target: Some(&body.username), outcome: "ok", details: json!({ "assignments": body.assignments }) }).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(UserOut { username: body.username, active: true, assignments: body.assignments })))
}

#[utoipa::path(put, path = "/v1/users/{username}", tag = "users", security(("bearer" = [])), request_body = UserUpdate,
    params(("username" = String, Path)), responses((status = 204), (status = 404), (status = 409, description = "Would leave no administrator")))]
pub async fn update_user(State(st): State<AppState>, Authn(user): Authn, Path(username): Path<String>, Json(body): Json<UserUpdate>) -> ApiResult<StatusCode> {
    user.require_global("users:write")?;
    let hash = match &body.password {
        Some(p) => {
            check_password(p)?;
            Some(hash_blocking(p.clone()).await?)
        }
        None => None,
    };
    let mut tx = st.pool.begin().await?;
    let id: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE username = $1 FOR UPDATE").bind(&username).fetch_optional(&mut *tx).await?.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "user not found".into()))?;
    if let Some(hash) = hash {
        sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1").bind(id).bind(hash).execute(&mut *tx).await?;
        // A new password invalidates the user's sessions.
        sqlx::query("DELETE FROM sessions WHERE user_id = $1").bind(id).execute(&mut *tx).await?;
    }
    if let Some(active) = body.active {
        sqlx::query("UPDATE users SET active = $2 WHERE id = $1").bind(id).bind(active).execute(&mut *tx).await?;
    }
    if let Some(assignments) = &body.assignments {
        set_assignments(&mut tx, id, assignments).await?;
    }
    ensure_admin_remains(&mut tx).await?;
    audit::append(&mut tx, &NewEvent {
        tenant_id: None, actor: &user.username, action: "user.update", target: Some(&username), outcome: "ok",
        details: json!({ "password_changed": body.password.is_some(), "active": body.active, "assignments": body.assignments }),
    })
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(delete, path = "/v1/users/{username}", tag = "users", security(("bearer" = [])),
    params(("username" = String, Path)), responses((status = 204), (status = 404), (status = 409)))]
pub async fn delete_user(State(st): State<AppState>, Authn(user): Authn, Path(username): Path<String>) -> ApiResult<StatusCode> {
    user.require_global("users:write")?;
    let mut tx = st.pool.begin().await?;
    let n = sqlx::query("DELETE FROM users WHERE username = $1").bind(&username).execute(&mut *tx).await?.rows_affected();
    if n == 0 {
        return Err(ApiError(StatusCode::NOT_FOUND, "user not found".into()));
    }
    ensure_admin_remains(&mut tx).await?;
    audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &user.username, action: "user.delete", target: Some(&username), outcome: "ok", details: json!({}) }).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- roles ---------------------------------------------------------------------------------

#[derive(Serialize, ToSchema)]
pub struct RoleOut {
    pub name: String,
    pub permissions: Vec<String>,
    pub builtin: bool,
    /// `global`, `tenant` or `any`: where the role may be assigned.
    pub scope: String,
}

#[derive(Deserialize, ToSchema)]
pub struct RoleBody {
    /// Required on create; ignored on update (the name is in the path).
    #[serde(default)]
    pub name: String,
    pub permissions: Vec<String>,
    /// `global`, `tenant` or `any` (default).
    #[serde(default = "default_scope")]
    pub scope: String,
}

fn default_scope() -> String {
    "any".into()
}

fn check_scope(scope: &str) -> ApiResult<()> {
    if ["global", "tenant", "any"].contains(&scope) { Ok(()) } else { Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, "scope must be global, tenant or any".into())) }
}

fn check_permissions(permissions: &[String]) -> ApiResult<()> {
    let known = |p: &str| p == "*" || PERMISSIONS.contains(&p) || p.strip_suffix(":*").is_some_and(|r| PERMISSIONS.iter().any(|k| k.split_once(':').is_some_and(|(res, _)| res == r)));
    match permissions.iter().find(|p| !known(p)) {
        Some(p) => Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, format!("unknown permission '{p}' (known: {})", PERMISSIONS.join(", ")))),
        None => Ok(()),
    }
}

#[utoipa::path(get, path = "/v1/roles", tag = "roles", security(("bearer" = [])), responses((status = 200, body = Vec<RoleOut>)))]
pub async fn list_roles(State(st): State<AppState>, Authn(user): Authn) -> ApiResult<Json<Vec<RoleOut>>> {
    // Delegated administrators need the list to pick roles for their tenant.
    if !user.can("roles:read", None) && !user.scoped.values().any(|set| grants(set, "roles:assign")) {
        return Err(forbidden("roles:read"));
    }
    let rows: Vec<(String, Vec<String>, bool, String)> = sqlx::query_as("SELECT name, permissions, builtin, scope FROM roles ORDER BY name").fetch_all(&st.pool).await?;
    Ok(Json(rows.into_iter().map(|(name, permissions, builtin, scope)| RoleOut { name, permissions, builtin, scope }).collect()))
}

#[utoipa::path(post, path = "/v1/roles", tag = "roles", security(("bearer" = [])), request_body = RoleBody,
    responses((status = 201, body = RoleOut), (status = 409), (status = 422)))]
pub async fn create_role(State(st): State<AppState>, Authn(user): Authn, Json(body): Json<RoleBody>) -> ApiResult<(StatusCode, Json<RoleOut>)> {
    user.require_global("roles:write")?;
    check_username(&body.name)?;
    check_permissions(&body.permissions)?;
    check_scope(&body.scope)?;
    let mut tx = st.pool.begin().await?;
    sqlx::query("INSERT INTO roles (name, permissions, scope) VALUES ($1, $2, $3)").bind(&body.name).bind(&body.permissions).bind(&body.scope).execute(&mut *tx).await?;
    audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &user.username, action: "role.create", target: Some(&body.name), outcome: "ok", details: json!({ "permissions": body.permissions, "scope": body.scope }) }).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(RoleOut { name: body.name, permissions: body.permissions, builtin: false, scope: body.scope })))
}

#[utoipa::path(put, path = "/v1/roles/{name}", tag = "roles", security(("bearer" = [])), request_body = RoleBody,
    params(("name" = String, Path)), responses((status = 204), (status = 404), (status = 409, description = "Built-in role")))]
pub async fn update_role(State(st): State<AppState>, Authn(user): Authn, Path(name): Path<String>, Json(body): Json<RoleBody>) -> ApiResult<StatusCode> {
    user.require_global("roles:write")?;
    check_permissions(&body.permissions)?;
    check_scope(&body.scope)?;
    let mut tx = st.pool.begin().await?;
    let builtin: bool = sqlx::query_scalar("SELECT builtin FROM roles WHERE name = $1 FOR UPDATE").bind(&name).fetch_optional(&mut *tx).await?.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "role not found".into()))?;
    if builtin {
        return Err(ApiError(StatusCode::CONFLICT, "built-in roles cannot be changed".into()));
    }
    sqlx::query("UPDATE roles SET permissions = $2, scope = $3 WHERE name = $1").bind(&name).bind(&body.permissions).bind(&body.scope).execute(&mut *tx).await?;
    ensure_admin_remains(&mut tx).await?;
    audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &user.username, action: "role.update", target: Some(&name), outcome: "ok", details: json!({ "permissions": body.permissions }) }).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(delete, path = "/v1/roles/{name}", tag = "roles", security(("bearer" = [])),
    params(("name" = String, Path)), responses((status = 204), (status = 404), (status = 409, description = "Built-in or in use")))]
pub async fn delete_role(State(st): State<AppState>, Authn(user): Authn, Path(name): Path<String>) -> ApiResult<StatusCode> {
    user.require_global("roles:write")?;
    let mut tx = st.pool.begin().await?;
    let builtin: bool = sqlx::query_scalar("SELECT builtin FROM roles WHERE name = $1").bind(&name).fetch_optional(&mut *tx).await?.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "role not found".into()))?;
    if builtin {
        return Err(ApiError(StatusCode::CONFLICT, "built-in roles cannot be deleted".into()));
    }
    sqlx::query("DELETE FROM roles WHERE name = $1").bind(&name).execute(&mut *tx).await?; // FK violation -> 409 if assigned
    audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &user.username, action: "role.delete", target: Some(&name), outcome: "ok", details: json!({}) }).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- delegated assignments (per tenant) ----------------------------------------------------

#[derive(Serialize, ToSchema)]
pub struct TenantAssignment {
    pub username: String,
    pub role: String,
}

#[derive(Deserialize, ToSchema)]
pub struct TenantRoles {
    /// Replaces the user's roles in this tenant.
    pub roles: Vec<String>,
}

#[utoipa::path(get, path = "/v1/tenants/{tenant}/assignments", tag = "roles", security(("bearer" = [])), params(("tenant" = String, Path)),
    responses((status = 200, body = Vec<TenantAssignment>), (status = 404)))]
pub async fn list_tenant_assignments(State(st): State<AppState>, Authn(user): Authn, Path(tenant): Path<String>) -> ApiResult<Json<Vec<TenantAssignment>>> {
    let tid = user.tenant(&st.pool, &tenant, "roles:assign").await?;
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT u.username, r.name FROM user_roles ur JOIN users u ON u.id = ur.user_id JOIN roles r ON r.id = ur.role_id WHERE ur.tenant_id = $1 ORDER BY u.username, r.name",
    )
    .bind(tid)
    .fetch_all(&st.pool)
    .await?;
    Ok(Json(rows.into_iter().map(|(username, role)| TenantAssignment { username, role }).collect()))
}

/// A delegated administrator may only hand out what they hold themselves in that tenant.
fn covers(user: &CurrentUser, tenant: Uuid, permission: &str) -> bool {
    let mut held = user.global.clone();
    held.extend(user.scoped.get(&tenant).into_iter().flatten().cloned());
    held.contains("*") || held.contains(permission) || (!permission.ends_with('*') && grants(&held, permission)) || GLOBAL_ONLY.contains(&permission)
}

#[utoipa::path(put, path = "/v1/tenants/{tenant}/assignments/{username}", tag = "roles", security(("bearer" = [])), request_body = TenantRoles,
    params(("tenant" = String, Path), ("username" = String, Path)), responses((status = 204), (status = 403), (status = 404), (status = 422)))]
pub async fn set_tenant_assignments(
    State(st): State<AppState>,
    Authn(user): Authn,
    Path((tenant, username)): Path<(String, String)>,
    Json(body): Json<TenantRoles>,
) -> ApiResult<StatusCode> {
    let tid = user.tenant(&st.pool, &tenant, "roles:assign").await?;
    let mut tx = st.pool.begin().await?;
    let uid: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE username = $1 FOR UPDATE").bind(&username).fetch_optional(&mut *tx).await?.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "user not found".into()))?;
    for role in &body.roles {
        let perms: Vec<String> = sqlx::query_scalar("SELECT permissions FROM roles WHERE name = $1").bind(role).fetch_optional(&mut *tx).await?.ok_or_else(|| ApiError(StatusCode::UNPROCESSABLE_ENTITY, format!("unknown role '{role}'")))?;
        if let Some(p) = perms.iter().find(|p| !covers(&user, tid, p)) {
            return Err(ApiError(StatusCode::FORBIDDEN, format!("cannot grant '{p}': you do not hold it in this tenant")));
        }
    }
    sqlx::query("DELETE FROM user_roles WHERE user_id = $1 AND tenant_id = $2 AND source = 'manual'").bind(uid).bind(tid).execute(&mut *tx).await?;
    for role in &body.roles {
        assign(&mut tx, uid, &Assignment { role: role.clone(), tenant: Some(tenant.clone()) }).await?;
    }
    audit::append(&mut tx, &NewEvent { tenant_id: Some(tid), actor: &user.username, action: "assignment.set", target: Some(&username), outcome: "ok", details: json!({ "roles": body.roles }) }).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- MFA enrolment and sessions -----------------------------------------------------------

#[derive(Serialize, ToSchema)]
pub struct MfaEnrollment {
    /// Base32 secret to type into an authenticator app.
    pub secret: String,
    /// `otpauth://` URI to render as a QR code.
    pub otpauth_uri: String,
}

#[utoipa::path(post, path = "/v1/me/mfa/enroll", tag = "auth", security(("bearer" = [])),
    responses((status = 200, body = MfaEnrollment), (status = 409, description = "Already enabled"), (status = 503)))]
pub async fn mfa_enroll(State(st): State<AppState>, AuthnEnrolling(user): AuthnEnrolling) -> ApiResult<Json<MfaEnrollment>> {
    let key = st.secrets_key.as_ref().ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, "MFA needs DELBERT_SECRETS_KEY_FILE".into()))?;
    if user.mfa_enrolled {
        return Err(ApiError(StatusCode::CONFLICT, "MFA is already enabled".into()));
    }
    let mut secret = [0u8; 20];
    OsRng.fill_bytes(&mut secret);
    let sealed = crate::secrets::seal(key, &secret)?;
    sqlx::query("UPDATE users SET totp_secret = $2, totp_last_step = 0 WHERE id = $1").bind(user.id).bind(sealed).execute(&st.pool).await?;
    Ok(Json(MfaEnrollment { secret: crate::totp::secret_to_base32(&secret), otpauth_uri: crate::totp::uri("Delbert", &user.username, &secret) }))
}

#[derive(Serialize, ToSchema)]
pub struct RecoveryCodes {
    /// Shown once; each works one time in place of a TOTP code.
    pub recovery_codes: Vec<String>,
}

#[utoipa::path(post, path = "/v1/me/mfa/confirm", tag = "auth", security(("bearer" = [])), request_body = MfaCode,
    responses((status = 200, body = RecoveryCodes), (status = 401, description = "Wrong code"), (status = 409)))]
pub async fn mfa_confirm(State(st): State<AppState>, AuthnEnrolling(user): AuthnEnrolling, Json(body): Json<MfaCode>) -> ApiResult<Json<RecoveryCodes>> {
    if user.mfa_enrolled {
        return Err(ApiError(StatusCode::CONFLICT, "MFA is already enabled".into()));
    }
    // Only a TOTP code confirms; recovery codes do not exist yet.
    if !check_second_factor(&st, user.id, &body.code).await? {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid code (call /v1/me/mfa/enroll first)".into()));
    }
    let mut codes = Vec::new();
    let mut tx = st.pool.begin().await?;
    sqlx::query("DELETE FROM user_recovery_codes WHERE user_id = $1").bind(user.id).execute(&mut *tx).await?;
    for _ in 0..10 {
        let mut raw = [0u8; 10];
        OsRng.fill_bytes(&mut raw);
        let c = data_encoding::BASE32_NOPAD.encode(&raw).to_ascii_lowercase();
        let code = format!("{}-{}", &c[..8], &c[8..]);
        sqlx::query("INSERT INTO user_recovery_codes (user_id, code_hash) VALUES ($1, $2)").bind(user.id).bind(token_hash(&code.replace('-', ""))).execute(&mut *tx).await?;
        codes.push(code);
    }
    sqlx::query("UPDATE users SET totp_enabled = true WHERE id = $1").bind(user.id).execute(&mut *tx).await?;
    audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &user.username, action: "mfa.enable", target: Some(&user.username), outcome: "ok", details: json!({}) }).await?;
    tx.commit().await?;
    Ok(Json(RecoveryCodes { recovery_codes: codes }))
}

#[derive(Deserialize, ToSchema)]
pub struct MfaDisable {
    pub password: String,
    pub code: String,
}

#[utoipa::path(post, path = "/v1/me/mfa/disable", tag = "auth", security(("bearer" = [])), request_body = MfaDisable,
    responses((status = 204), (status = 401), (status = 409, description = "MFA is mandatory for this user")))]
pub async fn mfa_disable(State(st): State<AppState>, AuthnEnrolling(user): AuthnEnrolling, Json(body): Json<MfaDisable>) -> ApiResult<StatusCode> {
    let hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1").bind(user.id).fetch_one(&st.pool).await?;
    let password = body.password.clone();
    if !tokio::task::spawn_blocking(move || verify_password(&password, &hash)).await.unwrap_or(false) || !check_second_factor(&st, user.id, &body.code).await? {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid password or code".into()));
    }
    if st.auth.mfa == MfaPolicy::All || (st.auth.mfa == MfaPolicy::Admins && !user.global.is_empty()) {
        return Err(ApiError(StatusCode::CONFLICT, "MFA is mandatory for this account".into()));
    }
    reset_mfa(&st, user.id, &user.username, &user.username).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn reset_mfa(st: &AppState, user_id: Uuid, target: &str, actor: &str) -> ApiResult<()> {
    let mut tx = st.pool.begin().await?;
    sqlx::query("UPDATE users SET totp_secret = NULL, totp_enabled = false, totp_last_step = 0 WHERE id = $1").bind(user_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM user_recovery_codes WHERE user_id = $1").bind(user_id).execute(&mut *tx).await?;
    audit::append(&mut tx, &NewEvent { tenant_id: None, actor, action: "mfa.disable", target: Some(target), outcome: "ok", details: json!({}) }).await?;
    tx.commit().await?;
    Ok(())
}

#[utoipa::path(delete, path = "/v1/users/{username}/mfa", tag = "users", security(("bearer" = [])), params(("username" = String, Path)),
    responses((status = 204), (status = 404)))]
pub async fn admin_reset_mfa(State(st): State<AppState>, Authn(user): Authn, Path(username): Path<String>) -> ApiResult<StatusCode> {
    user.require_global("users:write")?;
    let id: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE username = $1").bind(&username).fetch_optional(&st.pool).await?.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "user not found".into()))?;
    reset_mfa(&st, id, &username, &user.username).await?;
    // The account must enrol again: its sessions end.
    sqlx::query("DELETE FROM sessions WHERE user_id = $1").bind(id).execute(&st.pool).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, ToSchema)]
pub struct SessionOut {
    pub id: String,
    pub current: bool,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    /// Unix seconds.
    pub created_at: i64,
    pub last_seen: i64,
}

#[utoipa::path(get, path = "/v1/me/sessions", tag = "auth", security(("bearer" = [])), responses((status = 200, body = Vec<SessionOut>)))]
pub async fn my_sessions(State(st): State<AppState>, AuthnEnrolling(user): AuthnEnrolling) -> ApiResult<Json<Vec<SessionOut>>> {
    let rows: Vec<(Uuid, Option<String>, Option<String>, i64, i64)> = sqlx::query_as(
        "SELECT id, ip, user_agent, (EXTRACT(EPOCH FROM created_at))::bigint, (EXTRACT(EPOCH FROM last_seen))::bigint FROM sessions \
         WHERE user_id = $1 AND mfa_ok AND expires_at > now() ORDER BY created_at DESC",
    )
    .bind(user.id)
    .fetch_all(&st.pool)
    .await?;
    Ok(Json(rows.into_iter().map(|(id, ip, user_agent, created_at, last_seen)| SessionOut { current: id == user.session_id, id: id.to_string(), ip, user_agent, created_at, last_seen }).collect()))
}

#[utoipa::path(delete, path = "/v1/me/sessions/{id}", tag = "auth", security(("bearer" = [])), params(("id" = String, Path)),
    responses((status = 204), (status = 404)))]
pub async fn revoke_session(State(st): State<AppState>, AuthnEnrolling(user): AuthnEnrolling, Path(id): Path<String>) -> ApiResult<StatusCode> {
    let id: Uuid = id.parse().map_err(|_| ApiError(StatusCode::NOT_FOUND, "session not found".into()))?;
    let n = sqlx::query("DELETE FROM sessions WHERE id = $1 AND user_id = $2").bind(id).bind(user.id).execute(&st.pool).await?.rows_affected();
    if n == 0 { Err(ApiError(StatusCode::NOT_FOUND, "session not found".into())) } else { Ok(StatusCode::NO_CONTENT) }
}

#[utoipa::path(delete, path = "/v1/users/{username}/sessions", tag = "users", security(("bearer" = [])), params(("username" = String, Path)),
    responses((status = 204), (status = 404)))]
pub async fn admin_revoke_sessions(State(st): State<AppState>, Authn(user): Authn, Path(username): Path<String>) -> ApiResult<StatusCode> {
    user.require_global("users:write")?;
    let id: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE username = $1").bind(&username).fetch_optional(&st.pool).await?.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "user not found".into()))?;
    sqlx::query("DELETE FROM sessions WHERE user_id = $1").bind(id).execute(&st.pool).await?;
    let mut tx = st.pool.begin().await?;
    audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &user.username, action: "session.revoke-all", target: Some(&username), outcome: "ok", details: json!({}) }).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- API tokens ----------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
pub struct NewToken {
    pub name: String,
    /// Permissions the token may use; each must be held by its owner (in the tenant, if given).
    pub permissions: Vec<String>,
    /// Restrict the token to one tenant.
    pub tenant: Option<String>,
    /// Lifetime in days, 1 to 365 (tokens always expire).
    pub expires_in_days: i64,
}

#[derive(Serialize, ToSchema)]
pub struct TokenCreated {
    pub id: String,
    /// Shown once.
    pub token: String,
    pub expires_at: i64,
}

#[derive(Serialize, ToSchema)]
pub struct TokenOut {
    pub id: String,
    pub name: String,
    pub tenant: Option<String>,
    pub permissions: Vec<String>,
    pub expires_at: i64,
    pub last_used: Option<i64>,
}

#[utoipa::path(post, path = "/v1/me/tokens", tag = "auth", security(("bearer" = [])), request_body = NewToken,
    responses((status = 201, body = TokenCreated), (status = 403), (status = 409, description = "Name in use"), (status = 422)))]
pub async fn create_token(State(st): State<AppState>, Authn(user): Authn, Json(body): Json<NewToken>) -> ApiResult<(StatusCode, Json<TokenCreated>)> {
    if user.via_token {
        return Err(ApiError(StatusCode::FORBIDDEN, "an API token cannot create tokens".into()));
    }
    if !user.can("tokens:manage", None) && !user.scoped.values().any(|s| grants(s, "tokens:manage")) {
        return Err(forbidden("tokens:manage"));
    }
    check_username(&body.name)?;
    check_permissions(&body.permissions)?;
    if body.permissions.is_empty() || !(1..=365).contains(&body.expires_in_days) {
        return Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, "permissions must not be empty and expires_in_days must be 1-365".into()));
    }
    let tenant_id = match &body.tenant {
        Some(t) => Some(user.tenant(&st.pool, t, "tokens:manage").await?),
        None => None,
    };
    // A token can never exceed its owner: every permission must be held literally (wildcards only if the owner has the same wildcard).
    for p in &body.permissions {
        if tenant_id.is_some() && GLOBAL_ONLY.contains(&p.as_str()) {
            return Err(ApiError(StatusCode::FORBIDDEN, format!("'{p}' is a platform-wide permission: a tenant token cannot carry it")));
        }
        let held = match tenant_id {
            Some(t) => covers(&user, t, p),
            None => user.global.contains("*") || user.global.contains(p) || (!p.ends_with('*') && grants(&user.global, p)),
        };
        if !held {
            return Err(ApiError(StatusCode::FORBIDDEN, format!("you do not hold '{p}'{}", if tenant_id.is_some() { " in that tenant" } else { " globally" })));
        }
    }
    let token = format!("{TOKEN_PREFIX}{}", random_token());
    let mut tx = st.pool.begin().await?;
    let (id, expires_at): (Uuid, i64) = sqlx::query_as(
        "INSERT INTO api_tokens (user_id, name, token_hash, tenant_id, permissions, expires_at) VALUES ($1, $2, $3, $4, $5, now() + make_interval(days => $6)) \
         RETURNING id, (EXTRACT(EPOCH FROM expires_at))::bigint",
    )
    .bind(user.id)
    .bind(&body.name)
    .bind(token_hash(&token))
    .bind(tenant_id)
    .bind(&body.permissions)
    .bind(body.expires_in_days as i32)
    .fetch_one(&mut *tx)
    .await?;
    audit::append(&mut tx, &NewEvent { tenant_id, actor: &user.username, action: "token.create", target: Some(&body.name), outcome: "ok", details: json!({ "permissions": body.permissions, "expires_in_days": body.expires_in_days }) }).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(TokenCreated { id: id.to_string(), token, expires_at })))
}

#[utoipa::path(get, path = "/v1/me/tokens", tag = "auth", security(("bearer" = [])), responses((status = 200, body = Vec<TokenOut>)))]
pub async fn list_tokens(State(st): State<AppState>, Authn(user): Authn) -> ApiResult<Json<Vec<TokenOut>>> {
    let rows: Vec<(Uuid, String, Option<String>, Vec<String>, i64, Option<i64>)> = sqlx::query_as(
        "SELECT k.id, k.name, t.name, k.permissions, (EXTRACT(EPOCH FROM k.expires_at))::bigint, (EXTRACT(EPOCH FROM k.last_used))::bigint \
         FROM api_tokens k LEFT JOIN tenants t ON t.id = k.tenant_id WHERE k.user_id = $1 ORDER BY k.created_at DESC",
    )
    .bind(user.id)
    .fetch_all(&st.pool)
    .await?;
    Ok(Json(rows.into_iter().map(|(id, name, tenant, permissions, expires_at, last_used)| TokenOut { id: id.to_string(), name, tenant, permissions, expires_at, last_used }).collect()))
}

#[utoipa::path(delete, path = "/v1/me/tokens/{id}", tag = "auth", security(("bearer" = [])), params(("id" = String, Path)),
    responses((status = 204), (status = 404)))]
pub async fn revoke_token(State(st): State<AppState>, Authn(user): Authn, Path(id): Path<String>) -> ApiResult<StatusCode> {
    if user.via_token {
        return Err(ApiError(StatusCode::FORBIDDEN, "an API token cannot revoke tokens".into()));
    }
    let id: Uuid = id.parse().map_err(|_| ApiError(StatusCode::NOT_FOUND, "token not found".into()))?;
    let mut tx = st.pool.begin().await?;
    let name: Option<String> = sqlx::query_scalar("DELETE FROM api_tokens WHERE id = $1 AND user_id = $2 RETURNING name").bind(id).bind(user.id).fetch_optional(&mut *tx).await?;
    let name = name.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "token not found".into()))?;
    audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &user.username, action: "token.revoke", target: Some(&name), outcome: "ok", details: json!({}) }).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Open a full session for a user who authenticated elsewhere (single sign-on). Returns the
/// bearer token, its expiry and the CSRF token when a cookie session is wanted.
pub(crate) async fn open_session(st: &AppState, user_id: Uuid, ip: &str, user_agent: Option<String>, cookie: bool) -> ApiResult<LoginResponse> {
    let token = random_token();
    let csrf = cookie.then(random_token);
    let expires_at: i64 = sqlx::query_scalar(
        "INSERT INTO sessions (token_hash, user_id, expires_at, csrf_hash, mfa_ok, ip, user_agent) \
         VALUES ($1, $2, now() + make_interval(hours => $3), $4, true, $5, $6) RETURNING (EXTRACT(EPOCH FROM expires_at))::bigint",
    )
    .bind(token_hash(&token))
    .bind(user_id)
    .bind(SESSION_HOURS as i32)
    .bind(csrf.as_deref().map(token_hash))
    .bind(ip)
    .bind(user_agent)
    .fetch_one(&st.pool)
    .await?;
    Ok(LoginResponse { token, expires_at, mfa_required: false, csrf_token: csrf })
}

pub(crate) fn set_session_cookie(st: &AppState, resp: &mut axum::response::Response, token: &str) {
    resp.headers_mut().insert(header::SET_COOKIE, cookie_header(st, token, SESSION_HOURS * 3600));
}

pub(crate) fn hash_token(token: &str) -> Vec<u8> {
    token_hash(token)
}

pub(crate) fn new_token() -> String {
    random_token()
}
