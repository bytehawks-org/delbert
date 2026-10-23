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

/// Every permission a role may contain (besides `*` and `resource:*`).
pub const PERMISSIONS: [&str; 26] = [
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
];

/// Permissions that only a global assignment can grant (they are not about one tenant).
pub const GLOBAL_ONLY: [&str; 9] =
    ["tenants:create", "tenants:delete", "proxies:read", "proxies:write", "users:read", "users:write", "roles:read", "roles:write", "audit:verify"];

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
        let rows: Vec<(Option<Uuid>, String)> = sqlx::query_as(
            "SELECT ur.tenant_id, unnest(r.permissions) FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = $1",
        )
        .bind(id)
        .fetch_all(&st.pool)
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
        let empty: Vec<Uuid> = sqlx::query_scalar("SELECT DISTINCT tenant_id FROM user_roles WHERE user_id = $1 AND tenant_id IS NOT NULL").bind(id).fetch_all(&st.pool).await?;
        for t in empty {
            scoped.entry(t).or_default();
        }
        Ok(Authn(CurrentUser { id, username, global, scoped, token_hash: hash }))
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
pub async fn me(State(st): State<AppState>, Authn(user): Authn) -> ApiResult<Json<Me>> {
    let names: Vec<(Uuid, String)> = sqlx::query_as("SELECT id, name FROM tenants").fetch_all(&st.pool).await?;
    let names: HashMap<Uuid, String> = names.into_iter().collect();
    let sorted = |set: &HashSet<String>| {
        let mut v: Vec<String> = set.iter().cloned().collect();
        v.sort();
        v
    };
    let tenants = user.scoped.iter().filter_map(|(t, set)| names.get(t).map(|n| (n.clone(), sorted(set)))).collect();
    Ok(Json(Me { permissions: sorted(&user.global), assignments: assignments_of(&st.pool, user.id).await?, tenants, username: user.username }))
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
    sqlx::query("DELETE FROM user_roles WHERE user_id = $1").bind(user_id).execute(&mut **tx).await?;
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
    sqlx::query("DELETE FROM user_roles WHERE user_id = $1 AND tenant_id = $2").bind(uid).bind(tid).execute(&mut *tx).await?;
    for role in &body.roles {
        assign(&mut tx, uid, &Assignment { role: role.clone(), tenant: Some(tenant.clone()) }).await?;
    }
    audit::append(&mut tx, &NewEvent { tenant_id: Some(tid), actor: &user.username, action: "assignment.set", target: Some(&username), outcome: "ok", details: json!({ "roles": body.roles }) }).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
