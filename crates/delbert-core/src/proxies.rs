//! Proxy / relay servers for branch offices (docs/ABSTRACT.md §2).
//!
//! A proxy is the only component of a remote site that talks to the Core. Its agents talk to a
//! NATS server and an HTTPS endpoint run by the proxy; the proxy relays what they need and keeps
//! working when the link to the Core is down:
//!
//! * **Requests**: policy requests and certificate renewals of its agents are relayed on
//!   `delbert.proxy.<site>.relay`. The agent's own proof travels inside, so the Core verifies the
//!   agent exactly as if it were connected directly; the proxy adds its proof and may only relay
//!   for agents enrolled through it.
//! * **Allow-list**: `delbert.proxy.<site>.agents` returns the agents the proxy serves with their
//!   public keys, so the proxy can authorize them (and verify their proofs) while offline.
//! * **Reports** are queued by the proxy and forwarded in batches on `delbert.proxy.<site>.report`,
//!   each with the proof the agent made and the time the proxy received it.
//! * **Enrollment of agents** and **artifact downloads** go over HTTPS with the proxy's proof in
//!   `Authorization: Delbert-Proxy <base64 {site, proof}>`.

use argon2::password_hash::rand_core::{OsRng, RngCore};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64},
};
use delbert_pki::authn::{self, Proof};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::types::Uuid;
use utoipa::ToSchema;

use crate::{
    api::{ApiError, ApiResult, AppState, check_token, tenant_id},
    audit::{self, NewEvent},
    auth::Authn,
    enroll::{EnrollRequest, EnrollResponse},
};

/// Reports older than this are not accepted from a proxy's queue.
const MAX_REPORT_AGE_SECS: i64 = 14 * 24 * 3600;
const ENROLL_KEY_HOURS: i32 = 24;

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

fn unauthorized() -> ApiError {
    ApiError(StatusCode::UNAUTHORIZED, "invalid proxy proof".into())
}

// --- proxy authentication -----------------------------------------------------------------------

/// The proxy's id if `proof` shows that proxy `site` made `body`. Also records that it was seen.
async fn proxy_proven(state: &AppState, site: &str, kind: &str, body: &Value, proof: Option<&Proof>) -> Option<Uuid> {
    let proof = proof?;
    let row: Option<(Uuid, Option<Vec<u8>>)> = sqlx::query_as("SELECT id, public_key FROM proxies WHERE name = $1").bind(site).fetch_optional(&state.pool).await.ok()?;
    let (id, Some(key)) = row? else { return None };
    authn::check(&key, kind, "proxy", site, body, proof, now()).ok()?;
    let _ = sqlx::query("UPDATE proxies SET last_seen_at = now() WHERE id = $1").bind(id).execute(&state.pool).await;
    Some(id)
}

/// `Authorization: Delbert-Proxy <base64 {site, proof}>`
fn proxy_header(headers: &HeaderMap) -> Option<(String, Proof)> {
    let v: Value = serde_json::from_slice(&STANDARD.decode(headers.get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Delbert-Proxy ")?).ok()?).ok()?;
    Some((v["site"].as_str()?.to_owned(), serde_json::from_value(v["proof"].clone()).ok()?))
}

async fn serves(state: &AppState, proxy_id: Uuid, tenant: &str, agent: &str) -> bool {
    sqlx::query_scalar::<_, i32>("SELECT 1 FROM agents a JOIN tenants t ON t.id = a.tenant_id WHERE a.proxy_id = $1 AND t.name = $2 AND a.name = $3")
        .bind(proxy_id)
        .bind(tenant)
        .bind(agent)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten()
        .is_some()
}

// --- administration -----------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
pub struct NewProxy {
    /// Site name (letters, digits, - _).
    pub name: String,
    /// DNS names of the proxy's HTTPS and NATS endpoints, as agents will use them.
    pub dns_names: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub struct ProxyCreated {
    pub name: String,
    /// Shown only now: hand it to the proxy installer. Valid 24 hours, single use.
    pub key: String,
    pub expires_at: i64,
}

#[derive(Serialize, ToSchema)]
pub struct ProxyOut {
    pub name: String,
    pub dns_names: Vec<String>,
    pub enrolled: bool,
    pub agents: i64,
    /// Unix seconds of the last request from the proxy.
    pub last_seen: Option<i64>,
}

fn valid_dns(name: &str) -> bool {
    !name.is_empty() && name.len() <= 253 && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}

#[utoipa::path(post, path = "/v1/proxies", tag = "proxies", security(("bearer" = [])), request_body = NewProxy,
    responses((status = 201, body = ProxyCreated), (status = 409), (status = 422)))]
pub async fn create_proxy(State(st): State<AppState>, Authn(user): Authn, Json(body): Json<NewProxy>) -> ApiResult<(StatusCode, Json<ProxyCreated>)> {
    user.require_global("proxies:write")?;
    check_token(&body.name, "proxy")?;
    if body.dns_names.is_empty() || !body.dns_names.iter().all(|d| valid_dns(d)) {
        return Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, "dns_names must list at least one valid DNS name".into()));
    }
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let key = format!("dlp_{}", B64.encode(raw));
    let mut tx = st.pool.begin().await?;
    let expires_at: i64 = sqlx::query_scalar(
        "INSERT INTO proxies (name, dns_names, enroll_secret_hash, enroll_expires_at, created_by) VALUES ($1, $2, $3, now() + make_interval(hours => $4), $5) \
         RETURNING (EXTRACT(EPOCH FROM enroll_expires_at))::bigint",
    )
    .bind(&body.name)
    .bind(&body.dns_names)
    .bind(Sha256::digest(key.as_bytes()).to_vec())
    .bind(ENROLL_KEY_HOURS)
    .bind(&user.username)
    .fetch_one(&mut *tx)
    .await?;
    audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &user.username, action: "proxy.create", target: Some(&body.name), outcome: "ok", details: json!({ "dns_names": body.dns_names }) }).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(ProxyCreated { name: body.name, key, expires_at })))
}

#[utoipa::path(get, path = "/v1/proxies", tag = "proxies", security(("bearer" = [])), responses((status = 200, body = Vec<ProxyOut>)))]
pub async fn list_proxies(State(st): State<AppState>, Authn(user): Authn) -> ApiResult<Json<Vec<ProxyOut>>> {
    user.require_global("proxies:read")?;
    let rows: Vec<(String, Vec<String>, bool, i64, Option<i64>)> = sqlx::query_as(
        "SELECT p.name, p.dns_names, p.public_key IS NOT NULL, (SELECT COUNT(*) FROM agents a WHERE a.proxy_id = p.id), (EXTRACT(EPOCH FROM p.last_seen_at))::bigint FROM proxies p ORDER BY p.name",
    )
    .fetch_all(&st.pool)
    .await?;
    Ok(Json(rows.into_iter().map(|(name, dns_names, enrolled, agents, last_seen)| ProxyOut { name, dns_names, enrolled, agents, last_seen }).collect()))
}

#[utoipa::path(delete, path = "/v1/proxies/{name}", tag = "proxies", security(("bearer" = [])),
    params(("name" = String, Path)), responses((status = 204), (status = 404), (status = 409, description = "Agents are still assigned to it")))]
pub async fn delete_proxy(State(st): State<AppState>, Authn(user): Authn, Path(name): Path<String>) -> ApiResult<StatusCode> {
    user.require_global("proxies:write")?;
    let mut tx = st.pool.begin().await?;
    let n = sqlx::query("DELETE FROM proxies WHERE name = $1").bind(&name).execute(&mut *tx).await?.rows_affected(); // FK -> 409 while agents are assigned
    if n == 0 {
        return Err(ApiError(StatusCode::NOT_FOUND, "proxy not found".into()));
    }
    audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &user.username, action: "proxy.delete", target: Some(&name), outcome: "ok", details: json!({}) }).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- proxy enrollment ------------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
pub struct ProxyEnrollRequest {
    pub name: String,
    pub psk: String,
    /// PEM CSR made by the proxy with a locally generated Ed25519 key.
    pub csr_pem: String,
}

#[derive(Serialize, ToSchema)]
pub struct ProxyEnrollResponse {
    pub cert_pem: String,
    pub ca_pem: String,
    pub signing_keys: Vec<String>,
    /// NATS URL of the Core, for the proxy's own connection.
    pub nats_url: Option<String>,
    pub dns_names: Vec<String>,
}

#[utoipa::path(post, path = "/v1/proxies/enroll", tag = "proxies", request_body = ProxyEnrollRequest,
    responses((status = 200, body = ProxyEnrollResponse), (status = 401, description = "Invalid enrollment key"), (status = 422)))]
pub async fn enroll_proxy(State(st): State<AppState>, Json(req): Json<ProxyEnrollRequest>) -> ApiResult<Json<ProxyEnrollResponse>> {
    let ca = st.pki.as_ref().ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, "enrollment is not configured (no CA)".into()))?;
    let mut tx = st.pool.begin().await?;
    let row: Option<(Uuid, Vec<String>)> = sqlx::query_as(
        "SELECT id, dns_names FROM proxies WHERE name = $1 AND enroll_secret_hash = $2 AND enroll_expires_at > now() AND public_key IS NULL FOR UPDATE",
    )
    .bind(&req.name)
    .bind(Sha256::digest(req.psk.as_bytes()).to_vec())
    .fetch_optional(&mut *tx)
    .await?;
    let Some((id, dns_names)) = row else { return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid enrollment key".into())) };
    let signed = ca.sign_proxy_csr(&req.csr_pem, &req.name, &dns_names, st.agent_cert_days).map_err(|e| ApiError(StatusCode::UNPROCESSABLE_ENTITY, format!("invalid CSR: {e}")))?;
    sqlx::query("UPDATE proxies SET public_key = $2, enrolled_at = now(), enroll_secret_hash = NULL, enroll_expires_at = NULL WHERE id = $1").bind(id).bind(&signed.public_key).execute(&mut *tx).await?;
    audit::append(&mut tx, &NewEvent { tenant_id: None, actor: &format!("proxy-enrollment:{}", req.name), action: "proxy.enroll", target: Some(&req.name), outcome: "ok", details: json!({}) }).await?;
    tx.commit().await?;
    let signing_keys = st.signer.iter().map(|s| format!("{} {}", s.kid(), s.public_key_b64())).collect();
    Ok(Json(ProxyEnrollResponse { cert_pem: signed.cert_pem, ca_pem: ca.cert_pem().to_owned(), signing_keys, nats_url: st.public_nats_url.clone(), dns_names }))
}

// --- agents enrolling through a proxy ---------------------------------------------------------------

#[utoipa::path(post, path = "/v1/proxy/enroll-agent", tag = "proxies", request_body = EnrollRequest,
    params(("Authorization" = String, Header, description = "Delbert-Proxy <base64 {site, proof}>")),
    responses((status = 200, body = EnrollResponse), (status = 401)))]
pub async fn proxy_enroll_agent(State(st): State<AppState>, headers: HeaderMap, Json(body): Json<Value>) -> ApiResult<Json<EnrollResponse>> {
    let (site, proof) = proxy_header(&headers).ok_or_else(unauthorized)?;
    let proxy_id = proxy_proven(&st, &site, "enroll-agent", &body, Some(&proof)).await.ok_or_else(unauthorized)?;
    let req = EnrollRequest::deserialize(&body).map_err(|e| ApiError(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    Ok(Json(crate::enroll::do_enroll(&st, req, Some(proxy_id)).await?))
}

// --- artifacts through a proxy ------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ByHash {
    sha256: String,
}

#[utoipa::path(get, path = "/v1/proxy/{site}/artifacts/{tenant}/{name}", tag = "proxies",
    params(("site" = String, Path), ("tenant" = String, Path), ("name" = String, Path), ("sha256" = String, Query)),
    responses((status = 200, content_type = "application/octet-stream"), (status = 401), (status = 404)))]
pub async fn proxy_artifact(
    State(st): State<AppState>,
    Path((site, tenant, name)): Path<(String, String, String)>,
    Query(q): Query<ByHash>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    let (header_site, proof) = proxy_header(&headers).ok_or_else(unauthorized)?;
    let body = Value::String(format!("{tenant}:{name}:{}", q.sha256));
    if header_site != site || proxy_proven(&st, &site, "proxy-artifact", &body, Some(&proof)).await.is_none() {
        return Err(unauthorized());
    }
    let tid = tenant_id(&st.pool, &tenant).await?;
    let content: Option<Vec<u8>> = sqlx::query_scalar("SELECT content FROM artifacts WHERE tenant_id = $1 AND name = $2 AND sha256 = decode($3, 'hex') LIMIT 1")
        .bind(tid)
        .bind(&name)
        .bind(&q.sha256)
        .fetch_optional(&st.pool)
        .await
        .map_err(|_| ApiError(StatusCode::NOT_FOUND, "artifact not found".into()))?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], content.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "artifact not found".into()))?))
}

// --- NATS: relay, allow-list, reports ---------------------------------------------------------------------

/// A request of one of the proxy's agents, relayed by the proxy.
pub(crate) async fn relay(state: &AppState, site: &str, payload: &[u8]) -> Value {
    let denied = json!({ "error": "unauthorized" });
    let Ok(req) = serde_json::from_slice::<Value>(payload) else { return denied };
    let proof: Option<Proof> = serde_json::from_value(req["proof"].clone()).ok();
    let inner = &req["inner"];
    let Some(proxy_id) = proxy_proven(state, site, "relay", inner, proof.as_ref()).await else {
        tracing::warn!("rejected relay request with an invalid proof for proxy {site}");
        return denied;
    };
    let (Some(kind), Some(tenant), Some(agent)) = (inner["kind"].as_str(), inner["tenant"].as_str(), inner["agent"].as_str()) else { return denied };
    if !serves(state, proxy_id, tenant, agent).await {
        tracing::warn!("proxy {site} tried to relay for {tenant}/{agent}, which it does not serve");
        return denied;
    }
    let agent_payload = serde_json::to_vec(&inner["payload"]).unwrap_or_default();
    match kind {
        "effective" => crate::bus::effective_reply(state, tenant, agent, &agent_payload).await,
        "renew" => crate::bus::renew(state, tenant, agent, &agent_payload).await,
        _ => json!({ "error": "unknown request" }),
    }
}

/// The agents a proxy serves, with the keys it needs to authorize them while offline.
pub(crate) async fn agents(state: &AppState, site: &str, payload: &[u8]) -> Value {
    let denied = json!({ "error": "unauthorized" });
    let Ok(req) = serde_json::from_slice::<Value>(payload) else { return denied };
    let proof: Option<Proof> = serde_json::from_value(req["proof"].clone()).ok();
    let Some(proxy_id) = proxy_proven(state, site, "agents", &Value::Null, proof.as_ref()).await else { return denied };
    let rows: Result<Vec<(String, String, Vec<u8>, Option<Vec<u8>>)>, _> = sqlx::query_as(
        "SELECT t.name, a.name, a.public_key, a.previous_public_key FROM agents a JOIN tenants t ON t.id = a.tenant_id \
         WHERE a.proxy_id = $1 AND a.public_key IS NOT NULL ORDER BY t.name, a.name",
    )
    .bind(proxy_id)
    .fetch_all(&state.pool)
    .await;
    match rows {
        Ok(rows) => json!({
            "agents": rows.into_iter().map(|(tenant, agent, key, previous)| json!({
                "tenant": tenant, "agent": agent,
                "public_key": STANDARD.encode(key), "previous_public_key": previous.map(|k| STANDARD.encode(k)),
            })).collect::<Vec<_>>()
        }),
        Err(e) => {
            tracing::error!("cannot list the agents of proxy {site}: {e}");
            json!({ "error": "internal error" })
        }
    }
}

/// A batch of reports queued by the proxy: `{proof, inner: {reports: [{tenant, agent, received_at, envelope}]}}`.
/// Answers `{"accepted": n}` (how many were stored); the proxy then drops them from its queue.
pub(crate) async fn forwarded_reports(state: &AppState, site: &str, payload: &[u8]) -> Value {
    let Ok(req) = serde_json::from_slice::<Value>(payload) else { return json!({ "error": "malformed" }) };
    let proof: Option<Proof> = serde_json::from_value(req["proof"].clone()).ok();
    let inner = &req["inner"];
    let Some(proxy_id) = proxy_proven(state, site, "proxy-report", inner, proof.as_ref()).await else {
        tracing::warn!("report batch with an invalid proof from proxy {site} dropped");
        return json!({ "error": "unauthorized" });
    };
    let mut accepted = 0;
    let current = now();
    for item in inner["reports"].as_array().into_iter().flatten() {
        let (Some(tenant), Some(agent), Some(received_at)) = (item["tenant"].as_str(), item["agent"].as_str(), item["received_at"].as_i64()) else { continue };
        if received_at > current + authn::MAX_SKEW_SECS || received_at < current - MAX_REPORT_AGE_SECS || !serves(state, proxy_id, tenant, agent).await {
            continue; // dropped for good: the proxy must not keep retrying what the Core will never take
        }
        // The agent's proof is judged as of the moment the proxy received it.
        if crate::bus::ingest_report(state, tenant, agent, &item["envelope"], received_at).await {
            accepted += 1;
        } else {
            tracing::warn!("forwarded report of {tenant}/{agent} with an invalid proof dropped");
        }
    }
    json!({ "accepted": accepted })
}
