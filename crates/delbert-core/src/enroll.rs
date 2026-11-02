//! Agent enrollment with pre-shared keys (docs/ABSTRACT.md §3).
//!
//! An administrator creates an enrollment key (expiring, limited uses, revocable).
//! The agent generates its keys locally and sends a CSR plus its age public key
//! together with the key; the Core returns a certificate signed by the Delbert CA
//! and the trust anchors (CA, policy signing keys).

use std::str::FromStr;

use argon2::password_hash::rand_core::{OsRng, RngCore};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::types::Uuid;
use utoipa::ToSchema;

use crate::{
    api::{ApiError, ApiResult, AppState, check_name, check_token},
    audit::{self, NewEvent},
    auth::Authn,
};

const DEFAULT_TTL_HOURS: i64 = 24;
const MAX_TTL_HOURS: i64 = 24 * 30;

fn key_hash(key: &str) -> Vec<u8> {
    Sha256::digest(key.as_bytes()).to_vec()
}

// --- enrollment keys -------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
pub struct NewEnrollmentKey {
    /// Validity in hours (default 24, at most 720).
    pub ttl_hours: Option<i64>,
    /// How many agents may enroll with it (default 1).
    pub max_uses: Option<i32>,
    /// Groups for agents created by enrollment.
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub struct EnrollmentKeyCreated {
    pub id: String,
    /// Shown only now: hand it to the installer.
    pub key: String,
    pub expires_at: i64,
    pub max_uses: i32,
}

#[derive(Serialize, ToSchema)]
pub struct EnrollmentKeyOut {
    pub id: String,
    pub uses: i32,
    pub max_uses: i32,
    pub expires_at: i64,
    pub revoked: bool,
    pub groups: Vec<String>,
}

#[utoipa::path(post, path = "/v1/tenants/{tenant}/enrollment-keys", tag = "enrollment", security(("bearer" = [])), request_body = NewEnrollmentKey,
    params(("tenant" = String, Path)), responses((status = 201, body = EnrollmentKeyCreated), (status = 404), (status = 422)))]
pub async fn create_key(State(st): State<AppState>, Authn(user): Authn, Path(tenant): Path<String>, Json(body): Json<NewEnrollmentKey>) -> ApiResult<(StatusCode, Json<EnrollmentKeyCreated>)> {
    let (ttl, max_uses) = (body.ttl_hours.unwrap_or(DEFAULT_TTL_HOURS), body.max_uses.unwrap_or(1));
    if !(1..=MAX_TTL_HOURS).contains(&ttl) || !(1..=10_000).contains(&max_uses) {
        return Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, format!("ttl_hours must be 1-{MAX_TTL_HOURS} and max_uses 1-10000")));
    }
    body.groups.iter().try_for_each(|g| check_name(g, "group"))?;
    let tid = user.tenant(&st.pool, &tenant, "agents:enroll").await?;

    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let key = format!("dlb_{}", B64.encode(raw));

    let mut tx = st.pool.begin().await?;
    let (id, expires_at): (Uuid, i64) = sqlx::query_as(
        "INSERT INTO enrollment_keys (tenant_id, secret_hash, groups, max_uses, expires_at, created_by) \
         VALUES ($1, $2, $3, $4, now() + make_interval(hours => $5), $6) RETURNING id, (EXTRACT(EPOCH FROM expires_at))::bigint",
    )
    .bind(tid)
    .bind(key_hash(&key))
    .bind(&body.groups)
    .bind(max_uses)
    .bind(ttl as i32)
    .bind(&user.username)
    .fetch_one(&mut *tx)
    .await?;
    audit::append(&mut tx, &NewEvent { tenant_id: Some(tid), actor: &user.username, action: "enrollment-key.create", target: Some(&id.to_string()), outcome: "ok", details: json!({ "max_uses": max_uses, "ttl_hours": ttl, "groups": body.groups }) }).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(EnrollmentKeyCreated { id: id.to_string(), key, expires_at, max_uses })))
}

#[utoipa::path(get, path = "/v1/tenants/{tenant}/enrollment-keys", tag = "enrollment", security(("bearer" = [])),
    params(("tenant" = String, Path)), responses((status = 200, body = Vec<EnrollmentKeyOut>), (status = 404)))]
pub async fn list_keys(State(st): State<AppState>, Authn(user): Authn, Path(tenant): Path<String>) -> ApiResult<Json<Vec<EnrollmentKeyOut>>> {
    let tid = user.tenant(&st.pool, &tenant, "agents:enroll").await?;
    let rows: Vec<(Uuid, i32, i32, i64, bool, Vec<String>)> = sqlx::query_as(
        "SELECT id, uses, max_uses, (EXTRACT(EPOCH FROM expires_at))::bigint, revoked, groups FROM enrollment_keys WHERE tenant_id = $1 ORDER BY created_at DESC",
    )
    .bind(tid)
    .fetch_all(&st.pool)
    .await?;
    Ok(Json(rows.into_iter().map(|(id, uses, max_uses, expires_at, revoked, groups)| EnrollmentKeyOut { id: id.to_string(), uses, max_uses, expires_at, revoked, groups }).collect()))
}

#[utoipa::path(delete, path = "/v1/tenants/{tenant}/enrollment-keys/{id}", tag = "enrollment", security(("bearer" = [])),
    params(("tenant" = String, Path), ("id" = String, Path)), responses((status = 204), (status = 404)))]
pub async fn revoke_key(State(st): State<AppState>, Authn(user): Authn, Path((tenant, id)): Path<(String, String)>) -> ApiResult<StatusCode> {
    let tid = user.tenant(&st.pool, &tenant, "agents:enroll").await?;
    let id: Uuid = id.parse().map_err(|_| ApiError(StatusCode::NOT_FOUND, "enrollment key not found".into()))?;
    let mut tx = st.pool.begin().await?;
    let n = sqlx::query("UPDATE enrollment_keys SET revoked = true WHERE id = $1 AND tenant_id = $2").bind(id).bind(tid).execute(&mut *tx).await?.rows_affected();
    if n == 0 {
        return Err(ApiError(StatusCode::NOT_FOUND, "enrollment key not found".into()));
    }
    audit::append(&mut tx, &NewEvent { tenant_id: Some(tid), actor: &user.username, action: "enrollment-key.revoke", target: Some(&id.to_string()), outcome: "ok", details: json!({}) }).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- enrollment -------------------------------------------------------------------------

#[derive(Serialize, Deserialize, ToSchema)]
pub struct EnrollRequest {
    /// Enrollment key from the installer.
    pub psk: String,
    pub agent_name: String,
    /// PEM CSR made by the agent with a locally generated Ed25519 key.
    pub csr_pem: String,
    /// age recipient (`age1...`) that policy secrets are encrypted to.
    pub enc_public_key: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct EnrollResponse {
    pub tenant: String,
    pub agent: String,
    pub cert_pem: String,
    pub ca_pem: String,
    /// Lines of `<kid> <base64 public key>` for the agent's trusted-keys file.
    pub signing_keys: Vec<String>,
    pub nats_url: Option<String>,
}

fn denied() -> ApiError {
    // One answer for unknown, expired, revoked and exhausted keys: no oracle.
    ApiError(StatusCode::UNAUTHORIZED, "invalid enrollment key".into())
}

// --- throttle and audit of failed enrollments (docs/SECURITY-REVIEW.md F-02) ---------------
//
// The enrollment endpoints are unauthenticated. Failures are counted per client address (or per
// proxy for agents enrolling through one); past `MAX_FAILURES` in `WINDOW_MINUTES` the key is
// refused with 429 *before* the enrollment key is even looked at, so a right key does not
// reveal itself to someone who is being throttled. Failures reach the audit trail (action
// `enroll.denied`) only up to `MAX_FAILURES` per key and `GLOBAL_AUDIT_CAP` overall per window,
// and a throttled key is recorded once (`enroll.throttled`): the append-only trail cannot be
// grown at will by an anonymous caller, yet the first attempts of a guessing run are always on record.

const WINDOW_MINUTES: i32 = 10;
const MAX_FAILURES: i64 = 10;
const GLOBAL_AUDIT_CAP: i64 = 200;

/// Refuse a throttled key (429). Call before looking at the enrollment key.
pub(crate) async fn check_throttle(pool: &sqlx::PgPool, key: &str, what: &str) -> ApiResult<()> {
    let failures: i64 = sqlx::query_scalar("SELECT count(*) FROM enroll_attempts WHERE key = $1 AND kind = 'failure' AND at > now() - make_interval(mins => $2)")
        .bind(key)
        .bind(WINDOW_MINUTES)
        .fetch_one(pool)
        .await?;
    if failures < MAX_FAILURES {
        return Ok(());
    }
    // Record the throttling once per window: the insert only happens when no row is there yet.
    let mut tx = pool.begin().await?;
    let first = sqlx::query(
        "INSERT INTO enroll_attempts (key, kind) SELECT $1, 'throttled' \
         WHERE NOT EXISTS (SELECT 1 FROM enroll_attempts WHERE key = $1 AND kind = 'throttled' AND at > now() - make_interval(mins => $2))",
    )
    .bind(key)
    .bind(WINDOW_MINUTES)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    if first {
        audit::append(&mut tx, &NewEvent { tenant_id: None, actor: "anonymous", action: "enroll.throttled", target: Some(what), outcome: "denied", details: json!({ "key": key, "failures": failures, "window_minutes": WINDOW_MINUTES }) }).await?;
    }
    tx.commit().await?;
    Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "too many failed enrollments from this address; try again later".into()))
}

/// Record a rejected enrollment key and answer 401 (the same answer for every reason). `what` is
/// the endpoint (`agent` / `proxy`); `name` the proxy name when one was given. The key itself is never stored.
pub(crate) async fn fail(pool: &sqlx::PgPool, key: &str, what: &str, name: Option<&str>) -> ApiError {
    match record_failure(pool, key, what, name).await {
        Ok(()) => denied(),
        Err(e) => e,
    }
}

async fn record_failure(pool: &sqlx::PgPool, key: &str, what: &str, name: Option<&str>) -> ApiResult<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("INSERT INTO enroll_attempts (key, kind) VALUES ($1, 'failure')").bind(key).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM enroll_attempts WHERE at < now() - interval '1 day'").execute(&mut *tx).await?;
    let (mine, all): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE key = $1), count(*) FROM enroll_attempts WHERE kind = 'failure' AND at > now() - make_interval(mins => $2)",
    )
    .bind(key)
    .bind(WINDOW_MINUTES)
    .fetch_one(&mut *tx)
    .await?;
    if mine <= MAX_FAILURES && all <= GLOBAL_AUDIT_CAP {
        audit::append(&mut tx, &NewEvent { tenant_id: None, actor: "anonymous", action: "enroll.denied", target: name.or(Some(what)), outcome: "denied", details: json!({ "key": key, "endpoint": what }) }).await?;
    }
    tx.commit().await?;
    Ok(())
}

#[utoipa::path(post, path = "/v1/enroll", tag = "enrollment", request_body = EnrollRequest,
    responses((status = 200, body = EnrollResponse), (status = 401, description = "Invalid enrollment key"), (status = 409, description = "Agent already enrolled"), (status = 422)))]
pub async fn enroll(State(st): State<AppState>, crate::auth::ClientIp(ip): crate::auth::ClientIp, Json(req): Json<EnrollRequest>) -> ApiResult<Json<EnrollResponse>> {
    Ok(Json(do_enroll(&st, req, None, &ip).await?))
}

/// Enrollment proper. `proxy_id` is set when the agent enrolls through a proxy, which then serves it.
/// `throttle_key` is the client address, or `proxy:<site>` for an enrollment relayed by a proxy.
pub async fn do_enroll(st: &AppState, req: EnrollRequest, proxy_id: Option<Uuid>, throttle_key: &str) -> ApiResult<EnrollResponse> {
    let ca = st.pki.as_ref().ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, "enrollment is not configured (no CA)".into()))?;
    check_token(&req.agent_name, "agent")?;
    check_throttle(&st.pool, throttle_key, "agent").await?;
    age::x25519::Recipient::from_str(&req.enc_public_key).map_err(|_| ApiError(StatusCode::UNPROCESSABLE_ENTITY, "enc_public_key is not an age recipient".into()))?;

    let mut tx = st.pool.begin().await?;
    let key: Option<(Uuid, Uuid, String, Vec<String>, i32, i32, bool, bool)> = sqlx::query_as(
        "SELECT k.id, k.tenant_id, t.name, k.groups, k.max_uses, k.uses, k.revoked, k.expires_at > now() \
         FROM enrollment_keys k JOIN tenants t ON t.id = k.tenant_id WHERE k.secret_hash = $1 FOR UPDATE OF k",
    )
    .bind(key_hash(&req.psk))
    .fetch_optional(&mut *tx)
    .await?;
    let Some((key_id, tid, tenant, groups, max_uses, uses, revoked, valid)) = key else {
        drop(tx);
        return Err(fail(&st.pool, throttle_key, "agent", None).await);
    };
    if revoked || !valid || uses >= max_uses {
        drop(tx);
        return Err(fail(&st.pool, throttle_key, "agent", None).await);
    }

    let existing: Option<(Uuid, bool)> =
        sqlx::query_as("SELECT id, public_key IS NOT NULL FROM agents WHERE tenant_id = $1 AND name = $2 FOR UPDATE").bind(tid).bind(&req.agent_name).fetch_optional(&mut *tx).await?;
    if existing.is_some_and(|(_, enrolled)| enrolled) {
        return Err(ApiError(StatusCode::CONFLICT, "agent is already enrolled (delete it to enroll again)".into()));
    }

    let days = st.agent_cert_days;
    let signed = ca
        .sign_csr(&req.csr_pem, &req.agent_name, &delbert_pki::agent_uri(&tenant, &req.agent_name), days)
        .map_err(|e| ApiError(StatusCode::UNPROCESSABLE_ENTITY, format!("invalid CSR: {e}")))?;

    match existing {
        Some((id, _)) => {
            sqlx::query("UPDATE agents SET public_key = $2, enc_public_key = $3, enrolled_at = now(), proxy_id = $4 WHERE id = $1").bind(id).bind(&signed.public_key).bind(&req.enc_public_key).bind(proxy_id).execute(&mut *tx).await?;
        }
        None => {
            sqlx::query("INSERT INTO agents (tenant_id, name, groups, public_key, enc_public_key, enrolled_at, proxy_id) VALUES ($1, $2, $3, $4, $5, now(), $6)")
                .bind(tid)
                .bind(&req.agent_name)
                .bind(&groups)
                .bind(&signed.public_key)
                .bind(&req.enc_public_key)
                .bind(proxy_id)
                .execute(&mut *tx)
                .await?;
        }
    }
    sqlx::query("UPDATE enrollment_keys SET uses = uses + 1 WHERE id = $1").bind(key_id).execute(&mut *tx).await?;
    audit::append(&mut tx, &NewEvent { tenant_id: Some(tid), actor: &format!("enrollment-key:{key_id}"), action: "agent.enroll", target: Some(&req.agent_name), outcome: "ok", details: json!({ "cert_days": days, "proxy": proxy_id.map(|p| p.to_string()) }) }).await?;
    tx.commit().await?;
    if proxy_id.is_some() {
        crate::api::notify_proxy_of(st, &tenant, &req.agent_name).await; // let the site know about its new agent
    }

    let signing_keys = trusted_key_lines(&st);
    Ok(EnrollResponse { tenant, agent: req.agent_name, cert_pem: signed.cert_pem, ca_pem: st.ca_bundle().unwrap_or_default(), signing_keys, nats_url: st.public_nats_url.clone() })
}

/// `<kid> <public key>` lines handed to a new agent: the active signing key and the published ones.
pub(crate) fn trusted_key_lines(st: &AppState) -> Vec<String> {
    let active = st.signer.iter().map(|s| format!("{} {}", s.kid(), s.public_key_b64()));
    let published = st.published_keys.iter().filter(|k| st.signer.as_ref().is_none_or(|s| s.kid() != k.kid)).map(|k| format!("{} {}", k.kid, k.public_key));
    active.chain(published).collect()
}
