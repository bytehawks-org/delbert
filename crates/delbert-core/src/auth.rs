//! Local users, customizable roles (RBAC) and API sessions.
//!
//! * Passwords: Argon2id. Session tokens: 32 random bytes, only their SHA-256 is stored.
//! * A role is a set of permission strings; `*` grants everything.
//! * The last active holder of `*` cannot be removed, deactivated or deleted.
//!
//! Not done yet (docs/ROADMAP.md): SSO (OIDC/SAML), LDAP, MFA, login throttling/captcha.

use std::collections::HashSet;

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
    api::{ApiError, ApiResult, AppState},
    audit::{self, NewEvent},
};

/// Every permission a role may contain.
pub const PERMISSIONS: [&str; 10] =
    ["*", "read", "tenants:write", "agents:write", "policies:write", "secrets:write", "proxies:write", "effective:issue", "audit:read", "users:admin"];

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
    pub permissions: HashSet<String>,
    token_hash: Vec<u8>,
}

impl CurrentUser {
    /// `Ok` if the user holds `permission` (or `*`); 403 otherwise.
    pub fn require(&self, permission: &str) -> ApiResult<()> {
        if self.permissions.contains("*") || self.permissions.contains(permission) {
            Ok(())
        } else {
            Err(ApiError(StatusCode::FORBIDDEN, format!("missing permission '{permission}'")))
        }
    }
}

/// Extractor: a valid, unexpired session of an active user.
pub struct Authn(pub CurrentUser);

impl FromRequestParts<AppState> for Authn {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, ApiError> {
        let unauthorized = || ApiError(StatusCode::UNAUTHORIZED, "missing or invalid bearer token".into());
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(unauthorized)?;
        let hash = token_hash(token);
        let user: Option<(Uuid, String)> = sqlx::query_as(
            "SELECT u.id, u.username FROM sessions s JOIN users u ON u.id = s.user_id \
             WHERE s.token_hash = $1 AND s.expires_at > now() AND u.active",
        )
        .bind(&hash)
        .fetch_optional(&st.pool)
        .await?;
        let (id, username) = user.ok_or_else(unauthorized)?;
        let permissions: Vec<String> = sqlx::query_scalar(
            "SELECT unnest(r.permissions) FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = $1",
        )
        .bind(id)
        .fetch_all(&st.pool)
        .await?;
        Ok(Authn(CurrentUser { id, username, permissions: permissions.into_iter().collect(), token_hash: hash }))
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
    sqlx::query("INSERT INTO user_roles (user_id, role_id) SELECT $1, id FROM roles WHERE name = 'admin'").bind(id).execute(&mut *tx).await?;
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
}

#[derive(Serialize, ToSchema)]
pub struct LoginResponse {
    pub token: String,
    /// Unix seconds.
    pub expires_at: i64,
}

/// Real hash of a throwaway password, so unknown users cost the same time as wrong passwords.
fn dummy_hash() -> &'static str {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DUMMY.get_or_init(|| hash_password("timing-equalizer-password").expect("hashing works"))
}

#[utoipa::path(post, path = "/v1/auth/login", tag = "auth", request_body = LoginRequest,
    responses((status = 200, body = LoginResponse), (status = 401, description = "Invalid credentials")))]
pub async fn login(State(st): State<AppState>, Json(body): Json<LoginRequest>) -> ApiResult<Json<LoginResponse>> {
    let row: Option<(Uuid, String, bool)> =
        sqlx::query_as("SELECT id, password_hash, active FROM users WHERE username = $1").bind(&body.username).fetch_optional(&st.pool).await?;
    let (hash, known) = match &row {
        Some((_, h, _)) => (h.clone(), true),
        None => (dummy_hash().to_string(), false),
    };
    let password = body.password.clone();
    let matches = tokio::task::spawn_blocking(move || verify_password(&password, &hash)).await.unwrap_or(false);
    let ok = matches && known && row.as_ref().is_some_and(|r| r.2);

    let mut tx = st.pool.begin().await?;
    if !ok {
        audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &body.username, action: "auth.login", target: None, outcome: "denied", details: json!({}) }).await?;
        tx.commit().await?;
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid credentials".into()));
    }
    let user_id = row.map(|r| r.0).expect("checked above");

    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let token = B64.encode(raw);
    let expires_at: i64 = sqlx::query_scalar(
        "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, now() + make_interval(hours => $3)) RETURNING (EXTRACT(EPOCH FROM expires_at))::bigint",
    )
    .bind(token_hash(&token))
    .bind(user_id)
    .bind(SESSION_HOURS as i32)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM sessions WHERE expires_at < now()").execute(&mut *tx).await?;
    audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &body.username, action: "auth.login", target: None, outcome: "ok", details: json!({}) }).await?;
    tx.commit().await?;
    Ok(Json(LoginResponse { token, expires_at }))
}

#[utoipa::path(post, path = "/v1/auth/logout", tag = "auth", security(("bearer" = [])), responses((status = 204)))]
pub async fn logout(State(st): State<AppState>, Authn(user): Authn) -> ApiResult<StatusCode> {
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1").bind(&user.token_hash).execute(&st.pool).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, ToSchema)]
pub struct Me {
    pub username: String,
    pub permissions: Vec<String>,
}

#[utoipa::path(get, path = "/v1/me", tag = "auth", security(("bearer" = [])), responses((status = 200, body = Me)))]
pub async fn me(Authn(user): Authn) -> Json<Me> {
    let mut permissions: Vec<String> = user.permissions.into_iter().collect();
    permissions.sort();
    Json(Me { username: user.username, permissions })
}

// --- users ---------------------------------------------------------------------------------

#[derive(Serialize, ToSchema)]
pub struct UserOut {
    pub username: String,
    pub active: bool,
    pub roles: Vec<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct NewUser {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct UserUpdate {
    pub password: Option<String>,
    pub active: Option<bool>,
    /// Replaces the whole set of roles when present.
    pub roles: Option<Vec<String>>,
}

async fn set_roles(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, user_id: Uuid, roles: &[String]) -> ApiResult<()> {
    sqlx::query("DELETE FROM user_roles WHERE user_id = $1").bind(user_id).execute(&mut **tx).await?;
    for role in roles {
        let n = sqlx::query("INSERT INTO user_roles (user_id, role_id) SELECT $1, id FROM roles WHERE name = $2").bind(user_id).bind(role).execute(&mut **tx).await?.rows_affected();
        if n == 0 {
            return Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, format!("unknown role '{role}'")));
        }
    }
    Ok(())
}

/// At least one active user must keep the `*` permission.
async fn ensure_admin_remains(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>) -> ApiResult<()> {
    let admins: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT u.id) FROM users u JOIN user_roles ur ON ur.user_id = u.id JOIN roles r ON r.id = ur.role_id \
         WHERE u.active AND '*' = ANY (r.permissions)",
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
    user.require("users:admin")?;
    let rows: Vec<(String, bool, Vec<String>)> = sqlx::query_as(
        "SELECT u.username, u.active, COALESCE(array_agg(r.name ORDER BY r.name) FILTER (WHERE r.name IS NOT NULL), '{}') \
         FROM users u LEFT JOIN user_roles ur ON ur.user_id = u.id LEFT JOIN roles r ON r.id = ur.role_id GROUP BY u.id ORDER BY u.username",
    )
    .fetch_all(&st.pool)
    .await?;
    Ok(Json(rows.into_iter().map(|(username, active, roles)| UserOut { username, active, roles }).collect()))
}

#[utoipa::path(post, path = "/v1/users", tag = "users", security(("bearer" = [])), request_body = NewUser,
    responses((status = 201, body = UserOut), (status = 409, description = "Already exists"), (status = 422)))]
pub async fn create_user(State(st): State<AppState>, Authn(user): Authn, Json(body): Json<NewUser>) -> ApiResult<(StatusCode, Json<UserOut>)> {
    user.require("users:admin")?;
    check_username(&body.username)?;
    check_password(&body.password)?;
    let hash = hash_blocking(body.password).await?;
    let mut tx = st.pool.begin().await?;
    let id: Uuid = sqlx::query_scalar("INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id").bind(&body.username).bind(hash).fetch_one(&mut *tx).await?;
    set_roles(&mut tx, id, &body.roles).await?;
    audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &user.username, action: "user.create", target: Some(&body.username), outcome: "ok", details: json!({ "roles": body.roles }) }).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(UserOut { username: body.username, active: true, roles: body.roles })))
}

#[utoipa::path(put, path = "/v1/users/{username}", tag = "users", security(("bearer" = [])), request_body = UserUpdate,
    params(("username" = String, Path)), responses((status = 204), (status = 404), (status = 409, description = "Would leave no administrator")))]
pub async fn update_user(State(st): State<AppState>, Authn(user): Authn, Path(username): Path<String>, Json(body): Json<UserUpdate>) -> ApiResult<StatusCode> {
    user.require("users:admin")?;
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
    if let Some(roles) = &body.roles {
        set_roles(&mut tx, id, roles).await?;
    }
    ensure_admin_remains(&mut tx).await?;
    audit::append(&mut tx, &NewEvent {
        tenant_id: None, actor: &user.username, action: "user.update", target: Some(&username), outcome: "ok",
        details: json!({ "password_changed": body.password.is_some(), "active": body.active, "roles": body.roles }),
    })
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(delete, path = "/v1/users/{username}", tag = "users", security(("bearer" = [])),
    params(("username" = String, Path)), responses((status = 204), (status = 404), (status = 409)))]
pub async fn delete_user(State(st): State<AppState>, Authn(user): Authn, Path(username): Path<String>) -> ApiResult<StatusCode> {
    user.require("users:admin")?;
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
}

#[derive(Deserialize, ToSchema)]
pub struct RoleBody {
    /// Required on create; ignored on update (the name is in the path).
    #[serde(default)]
    pub name: String,
    pub permissions: Vec<String>,
}

fn check_permissions(permissions: &[String]) -> ApiResult<()> {
    match permissions.iter().find(|p| !PERMISSIONS.contains(&p.as_str())) {
        Some(p) => Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, format!("unknown permission '{p}' (known: {})", PERMISSIONS.join(", ")))),
        None => Ok(()),
    }
}

#[utoipa::path(get, path = "/v1/roles", tag = "roles", security(("bearer" = [])), responses((status = 200, body = Vec<RoleOut>)))]
pub async fn list_roles(State(st): State<AppState>, Authn(user): Authn) -> ApiResult<Json<Vec<RoleOut>>> {
    user.require("users:admin")?;
    let rows: Vec<(String, Vec<String>, bool)> = sqlx::query_as("SELECT name, permissions, builtin FROM roles ORDER BY name").fetch_all(&st.pool).await?;
    Ok(Json(rows.into_iter().map(|(name, permissions, builtin)| RoleOut { name, permissions, builtin }).collect()))
}

#[utoipa::path(post, path = "/v1/roles", tag = "roles", security(("bearer" = [])), request_body = RoleBody,
    responses((status = 201, body = RoleOut), (status = 409), (status = 422)))]
pub async fn create_role(State(st): State<AppState>, Authn(user): Authn, Json(body): Json<RoleBody>) -> ApiResult<(StatusCode, Json<RoleOut>)> {
    user.require("users:admin")?;
    check_username(&body.name)?;
    check_permissions(&body.permissions)?;
    let mut tx = st.pool.begin().await?;
    sqlx::query("INSERT INTO roles (name, permissions) VALUES ($1, $2)").bind(&body.name).bind(&body.permissions).execute(&mut *tx).await?;
    audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &user.username, action: "role.create", target: Some(&body.name), outcome: "ok", details: json!({ "permissions": body.permissions }) }).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(RoleOut { name: body.name, permissions: body.permissions, builtin: false })))
}

#[utoipa::path(put, path = "/v1/roles/{name}", tag = "roles", security(("bearer" = [])), request_body = RoleBody,
    params(("name" = String, Path)), responses((status = 204), (status = 404), (status = 409, description = "Built-in role")))]
pub async fn update_role(State(st): State<AppState>, Authn(user): Authn, Path(name): Path<String>, Json(body): Json<RoleBody>) -> ApiResult<StatusCode> {
    user.require("users:admin")?;
    check_permissions(&body.permissions)?;
    let mut tx = st.pool.begin().await?;
    let builtin: bool = sqlx::query_scalar("SELECT builtin FROM roles WHERE name = $1 FOR UPDATE").bind(&name).fetch_optional(&mut *tx).await?.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "role not found".into()))?;
    if builtin {
        return Err(ApiError(StatusCode::CONFLICT, "built-in roles cannot be changed".into()));
    }
    sqlx::query("UPDATE roles SET permissions = $2 WHERE name = $1").bind(&name).bind(&body.permissions).execute(&mut *tx).await?;
    ensure_admin_remains(&mut tx).await?;
    audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &user.username, action: "role.update", target: Some(&name), outcome: "ok", details: json!({ "permissions": body.permissions }) }).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(delete, path = "/v1/roles/{name}", tag = "roles", security(("bearer" = [])),
    params(("name" = String, Path)), responses((status = 204), (status = 404), (status = 409, description = "Built-in or in use")))]
pub async fn delete_role(State(st): State<AppState>, Authn(user): Authn, Path(name): Path<String>) -> ApiResult<StatusCode> {
    user.require("users:admin")?;
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
