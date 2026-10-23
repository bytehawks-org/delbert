//! Tenant secrets (docs/ABSTRACT.md §3 "Dati sensibili").
//!
//! * Secrets are write-only through the API: values are never returned.
//! * At rest they are encrypted with the Core's age key (`DELBERT_SECRETS_KEY_FILE`).
//! * Policies only name the secrets they need (`spec.secrets`). When a policy is
//!   issued the Core decrypts the values and re-encrypts them to the target
//!   agent's own age key, so neither the broker, nor the Proxy, nor another agent
//!   can read them.

use std::str::FromStr;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::types::Uuid;
use utoipa::ToSchema;

use crate::{
    api::{ApiError, ApiResult, AppState, check_name, tenant_id},
    audit::{self, NewEvent},
    auth::Authn,
};

const MAX_SECRET_BYTES: usize = 64 * 1024;

fn unavailable() -> ApiError {
    ApiError(StatusCode::SERVICE_UNAVAILABLE, "secret store not configured (DELBERT_SECRETS_KEY_FILE)".into())
}

/// Encrypt for storage with the Core key.
pub fn seal(core_key: &age::x25519::Identity, value: &[u8]) -> Result<Vec<u8>, ApiError> {
    age::encrypt(&core_key.to_public(), value).map_err(|e| {
        tracing::error!("cannot seal secret: {e}");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
    })
}

pub fn open(core_key: &age::x25519::Identity, ciphertext: &[u8]) -> Result<Vec<u8>, ApiError> {
    age::decrypt(core_key, ciphertext).map_err(|e| {
        tracing::error!("cannot open secret: {e}");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
    })
}

/// Encrypt a value to an agent's age recipient.
pub fn seal_for_agent(recipient: &str, value: &[u8]) -> Result<Vec<u8>, ApiError> {
    let recipient = age::x25519::Recipient::from_str(recipient).map_err(|_| ApiError(StatusCode::CONFLICT, "agent has no valid encryption key".into()))?;
    age::encrypt(&recipient, value).map_err(|e| {
        tracing::error!("cannot encrypt for agent: {e}");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
    })
}

#[derive(Deserialize, ToSchema)]
pub struct SecretBody {
    pub value: String,
}

#[derive(Serialize, ToSchema)]
pub struct SecretOut {
    pub name: String,
    pub updated_by: String,
    /// Unix seconds.
    pub updated_at: i64,
}

#[utoipa::path(put, path = "/v1/tenants/{tenant}/secrets/{name}", tag = "secrets", security(("bearer" = [])), request_body = SecretBody,
    params(("tenant" = String, Path), ("name" = String, Path)), responses((status = 204), (status = 404), (status = 422), (status = 503)))]
pub async fn put_secret(State(st): State<AppState>, Authn(user): Authn, Path((tenant, name)): Path<(String, String)>, Json(body): Json<SecretBody>) -> ApiResult<StatusCode> {
    user.require("secrets:write")?;
    check_name(&name, "secret")?;
    if body.value.len() > MAX_SECRET_BYTES {
        return Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, "secret too large (64 KiB at most)".into()));
    }
    let key = st.secrets_key.as_ref().ok_or_else(unavailable)?;
    let tid = tenant_id(&st.pool, &tenant).await?;
    let ciphertext = seal(key, body.value.as_bytes())?;
    let mut tx = st.pool.begin().await?;
    sqlx::query(
        "INSERT INTO secrets (tenant_id, name, ciphertext, updated_by) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (tenant_id, name) DO UPDATE SET ciphertext = $3, updated_by = $4, updated_at = now()",
    )
    .bind(tid)
    .bind(&name)
    .bind(ciphertext)
    .bind(&user.username)
    .execute(&mut *tx)
    .await?;
    // The value itself is never audited.
    audit::append(&mut tx, &NewEvent { tenant_id: Some(tid), actor: &user.username, action: "secret.set", target: Some(&name), outcome: "ok", details: json!({}) }).await?;
    tx.commit().await?;
    crate::api::notify_tenant(&st, &tenant, tid).await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/v1/tenants/{tenant}/secrets", tag = "secrets", security(("bearer" = [])),
    params(("tenant" = String, Path)), responses((status = 200, description = "Names only; values are never returned", body = Vec<SecretOut>), (status = 404)))]
pub async fn list_secrets(State(st): State<AppState>, Authn(user): Authn, Path(tenant): Path<String>) -> ApiResult<Json<Vec<SecretOut>>> {
    user.require("read")?;
    let tid = tenant_id(&st.pool, &tenant).await?;
    let rows: Vec<(String, String, i64)> =
        sqlx::query_as("SELECT name, updated_by, (EXTRACT(EPOCH FROM updated_at))::bigint FROM secrets WHERE tenant_id = $1 ORDER BY name").bind(tid).fetch_all(&st.pool).await?;
    Ok(Json(rows.into_iter().map(|(name, updated_by, updated_at)| SecretOut { name, updated_by, updated_at }).collect()))
}

#[utoipa::path(delete, path = "/v1/tenants/{tenant}/secrets/{name}", tag = "secrets", security(("bearer" = [])),
    params(("tenant" = String, Path), ("name" = String, Path)), responses((status = 204), (status = 404)))]
pub async fn delete_secret(State(st): State<AppState>, Authn(user): Authn, Path((tenant, name)): Path<(String, String)>) -> ApiResult<StatusCode> {
    user.require("secrets:write")?;
    let tid = tenant_id(&st.pool, &tenant).await?;
    let mut tx = st.pool.begin().await?;
    let n = sqlx::query("DELETE FROM secrets WHERE tenant_id = $1 AND name = $2").bind(tid).bind(&name).execute(&mut *tx).await?.rows_affected();
    if n == 0 {
        return Err(ApiError(StatusCode::NOT_FOUND, "secret not found".into()));
    }
    audit::append(&mut tx, &NewEvent { tenant_id: Some(tid), actor: &user.username, action: "secret.delete", target: Some(&name), outcome: "ok", details: json!({}) }).await?;
    tx.commit().await?;
    crate::api::notify_tenant(&st, &tenant, tid).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Plaintext of the named secrets of a tenant; names that do not exist are missing from the result.
pub async fn load(st: &AppState, tenant_id: Uuid, names: &[String]) -> ApiResult<std::collections::BTreeMap<String, Vec<u8>>> {
    let mut out = std::collections::BTreeMap::new();
    if names.is_empty() {
        return Ok(out);
    }
    let key = st.secrets_key.as_ref().ok_or_else(unavailable)?;
    let rows: Vec<(String, Vec<u8>)> = sqlx::query_as("SELECT name, ciphertext FROM secrets WHERE tenant_id = $1 AND name = ANY($2)").bind(tenant_id).bind(names).fetch_all(&st.pool).await?;
    for (name, ciphertext) in rows {
        out.insert(name, open(key, &ciphertext)?);
    }
    Ok(out)
}
