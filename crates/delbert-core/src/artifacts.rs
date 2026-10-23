//! Content-addressed artifacts: files that policies reference as
//! `artifact://<name>` (docs/POLICY.md). Versions are immutable. The compiled
//! policy pins the SHA-256 of the version in use; agents download it by hash over
//! HTTPS, authenticated with a proof of their identity key, and refuse anything
//! whose hash differs.
//!
//! Content lives in the object store (`blobs.rs`: local directory or S3-compatible), never in
//! PostgreSQL, which keeps only name, version, size and hash. Uploads are buffered in memory
//! (`MAX_ARTIFACT_BYTES`); downloads are streamed.

use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures::StreamExt;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use delbert_pki::authn::{self, Proof};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

use crate::{
    api::{ApiError, ApiResult, AppState, check_name, tenant_id},
    audit::{self, NewEvent},
    auth::Authn,
};

pub const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Serialize, ToSchema)]
pub struct ArtifactOut {
    pub name: String,
    pub version: i64,
    pub size: i64,
    pub sha256: String,
}

#[utoipa::path(put, path = "/v1/tenants/{tenant}/artifacts/{name}", tag = "artifacts", security(("bearer" = [])),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    params(("tenant" = String, Path), ("name" = String, Path)),
    responses((status = 201, description = "New version", body = ArtifactOut), (status = 200, description = "Same content as the latest version", body = ArtifactOut), (status = 413), (status = 422)))]
pub async fn put_artifact(State(st): State<AppState>, Authn(user): Authn, Path((tenant, name)): Path<(String, String)>, body: Bytes) -> ApiResult<(StatusCode, Json<ArtifactOut>)> {
    check_name(&name, "artifact")?;
    if body.len() > MAX_ARTIFACT_BYTES {
        return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE, "artifact too large (64 MiB at most)".into()));
    }
    let tid = user.tenant(&st.pool, &tenant, "artifacts:write").await?;
    let sha: Vec<u8> = Sha256::digest(&body).to_vec();

    let mut tx = st.pool.begin().await?;
    // Serialize uploads of the same name.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))").bind(format!("{tid}/{name}")).execute(&mut *tx).await?;
    let latest: Option<(i64, Vec<u8>)> = sqlx::query_as("SELECT version, sha256 FROM artifacts WHERE tenant_id = $1 AND name = $2 ORDER BY version DESC LIMIT 1").bind(tid).bind(&name).fetch_optional(&mut *tx).await?;
    if let Some((version, latest_sha)) = &latest {
        if *latest_sha == sha {
            return Ok((StatusCode::OK, Json(ArtifactOut { name, version: *version, size: body.len() as i64, sha256: hex(&sha) })));
        }
    }
    let version = latest.map_or(1, |(v, _)| v + 1);
    // Content first: an object without a row is harmless (and the same hash is idempotent),
    // a row without its object would break downloads.
    st.blobs.put(tid, &hex(&sha), body.clone()).await.map_err(blob_error)?;
    sqlx::query("INSERT INTO artifacts (tenant_id, name, version, sha256, size, created_by) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(tid)
        .bind(&name)
        .bind(version)
        .bind(&sha)
        .bind(body.len() as i64)
        .bind(&user.username)
        .execute(&mut *tx)
        .await?;
    audit::append(&mut tx, &NewEvent { tenant_id: Some(tid), actor: &user.username, action: "artifact.upload", target: Some(&name), outcome: "ok", details: json!({ "version": version, "size": body.len(), "sha256": hex(&sha) }) }).await?;
    tx.commit().await?;
    crate::api::notify_tenant(&st, &tenant, tid).await;
    Ok((StatusCode::CREATED, Json(ArtifactOut { name, version, size: body.len() as i64, sha256: hex(&sha) })))
}

#[utoipa::path(get, path = "/v1/tenants/{tenant}/artifacts", tag = "artifacts", security(("bearer" = [])),
    params(("tenant" = String, Path)), responses((status = 200, description = "Latest version of each artifact", body = Vec<ArtifactOut>), (status = 404)))]
pub async fn list_artifacts(State(st): State<AppState>, Authn(user): Authn, Path(tenant): Path<String>) -> ApiResult<Json<Vec<ArtifactOut>>> {
    let tid = user.tenant(&st.pool, &tenant, "artifacts:read").await?;
    Ok(Json(latest(&st, tid).await?.into_iter().map(|(name, version, size, sha256)| ArtifactOut { name, version, size, sha256 }).collect()))
}

/// Latest version of every artifact of a tenant: (name, version, size, hex sha256).
pub async fn latest(st: &AppState, tenant_id: sqlx::types::Uuid) -> Result<Vec<(String, i64, i64, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT DISTINCT ON (name) name, version, size, encode(sha256, 'hex') FROM artifacts WHERE tenant_id = $1 ORDER BY name, version DESC",
    )
    .bind(tenant_id)
    .fetch_all(&st.pool)
    .await
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Deserialize)]
pub struct ByHash {
    sha256: String,
}

/// Agent download: `Authorization: Delbert-Agent <base64 of the proof JSON>`.
#[utoipa::path(get, path = "/v1/agent/{tenant}/{agent}/artifacts/{name}", tag = "artifacts",
    params(("tenant" = String, Path), ("agent" = String, Path), ("name" = String, Path), ("sha256" = String, Query)),
    responses((status = 200, content_type = "application/octet-stream"), (status = 401), (status = 404)))]
pub async fn agent_download(
    State(st): State<AppState>,
    Path((tenant, agent, name)): Path<(String, String, String)>,
    Query(q): Query<ByHash>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let unauthorized = || ApiError(StatusCode::UNAUTHORIZED, "invalid agent proof".into());
    let proof: Proof = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Delbert-Agent "))
        .and_then(|v| B64.decode(v).ok())
        .and_then(|v| serde_json::from_slice(&v).ok())
        .ok_or_else(unauthorized)?;
    let body = Value::String(format!("{name}:{}", q.sha256));
    if !crate::bus::proven(&st, "artifact", &tenant, &agent, &body, Some(&proof)).await {
        return Err(unauthorized());
    }
    let _ = authn::MAX_SKEW_SECS; // documented window, enforced in `proven`
    let tid = tenant_id(&st.pool, &tenant).await?;
    content_response(&st, tid, &name, &q.sha256).await
}

pub(crate) fn blob_error(e: crate::blobs::BlobError) -> ApiError {
    tracing::error!("artifact store: {e}");
    ApiError(StatusCode::BAD_GATEWAY, "artifact store unavailable".into())
}

/// Stream the version of `name` with this hash, if the tenant has it. The bytes are hashed on
/// the way out: a corrupted object aborts the response instead of being served as valid.
pub(crate) async fn content_response(st: &AppState, tid: sqlx::types::Uuid, name: &str, sha256: &str) -> ApiResult<Response> {
    let not_found = || ApiError(StatusCode::NOT_FOUND, "artifact not found".into());
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(not_found());
    }
    let sha256 = sha256.to_ascii_lowercase();
    let known: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM artifacts WHERE tenant_id = $1 AND name = $2 AND sha256 = decode($3, 'hex'))").bind(tid).bind(name).bind(&sha256).fetch_one(&st.pool).await?;
    if !known {
        return Err(not_found());
    }
    let stream = st.blobs.get(tid, &sha256).await.map_err(blob_error)?.ok_or_else(|| {
        tracing::error!("artifact {sha256} is registered but missing from the store");
        not_found()
    })?;
    let hasher = std::sync::Arc::new(std::sync::Mutex::new(Sha256::new()));
    let h = hasher.clone();
    let body = stream
        .map(move |chunk| {
            let chunk = chunk.map_err(std::io::Error::other)?;
            h.lock().expect("hasher lock").update(&chunk);
            Ok::<_, std::io::Error>(chunk)
        })
        .chain(futures::stream::once(async move {
            let got = hex(&hasher.lock().expect("hasher lock").clone().finalize());
            if got == sha256 { Ok(bytes::Bytes::new()) } else { Err(std::io::Error::other("stored content does not match its hash")) }
        }));
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], Body::from_stream(body)).into_response())
}
