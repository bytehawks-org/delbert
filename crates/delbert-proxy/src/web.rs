//! HTTPS endpoint of the proxy for the agents of its site: enrollment relay and artifact cache.

use std::{fs, path::PathBuf, sync::Arc};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use delbert_pki::authn::Proof;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{allowlist::AllowList, hub::ProofMaker};

pub struct Web {
    pub core_url: String,
    pub site: String,
    pub http: reqwest::Client,
    pub proofs: ProofMaker,
    pub allow: AllowList,
    /// NATS URL of this site, handed to agents instead of the Core's.
    pub public_nats_url: String,
    pub artifact_dir: PathBuf,
}

fn error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn router(web: Arc<Web>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { Json(json!({ "status": "ok" })) }))
        .route("/v1/enroll", post(enroll))
        .route("/v1/agent/{tenant}/{agent}/artifacts/{name}", get(artifact))
        .with_state(web)
}

/// Agent enrollment: forwarded to the Core with the proxy's proof, so the agent becomes one of ours.
async fn enroll(State(web): State<Arc<Web>>, Json(body): Json<Value>) -> Response {
    let header = match web.proofs.header("enroll-agent", &body) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("cannot sign the enrollment: {e:#}");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };
    let resp = match web.http.post(format!("{}/v1/proxy/enroll-agent", web.core_url)).header("Authorization", header).json(&body).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("enrollment relay failed: {e}");
            return error(StatusCode::BAD_GATEWAY, "the Core is unreachable");
        }
    };
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut answer: Value = resp.json().await.unwrap_or_else(|_| json!({ "error": "unexpected reply from the Core" }));
    if status.is_success() {
        answer["nats_url"] = json!(web.public_nats_url); // agents talk to the site, not to the Core
    }
    (status, Json(answer)).into_response()
}

#[derive(Deserialize)]
struct ByHash {
    sha256: String,
}

/// Artifact download for an agent of the site, from the cache or (once) from the Core. Always checked against the hash.
async fn artifact(State(web): State<Arc<Web>>, Path((tenant, agent, name)): Path<(String, String, String)>, Query(q): Query<ByHash>, headers: HeaderMap) -> Response {
    let unauthorized = || error(StatusCode::UNAUTHORIZED, "invalid agent proof");
    let proof: Option<Proof> = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Delbert-Agent "))
        .and_then(|v| B64.decode(v).ok())
        .and_then(|v| serde_json::from_slice(&v).ok());
    let Some(proof) = proof else { return unauthorized() };
    if !web.allow.verify("artifact", &tenant, &agent, &Value::String(format!("{name}:{}", q.sha256)), &proof) {
        return unauthorized();
    }
    // The hash is both the cache key and the check: only hex, only 64 characters.
    if q.sha256.len() != 64 || !q.sha256.chars().all(|c| c.is_ascii_hexdigit()) || name.contains('/') || name.contains("..") {
        return error(StatusCode::BAD_REQUEST, "invalid artifact reference");
    }
    let cached = web.artifact_dir.join(&q.sha256);
    if let Ok(bytes) = fs::read(&cached) {
        if hex(&Sha256::digest(&bytes)) == q.sha256 {
            return ([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response();
        }
    }
    let body = Value::String(format!("{tenant}:{name}:{}", q.sha256));
    let header = match web.proofs.header("proxy-artifact", &body) {
        Ok(h) => h,
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    let url = format!("{}/v1/proxy/{}/artifacts/{tenant}/{name}?sha256={}", web.core_url, web.site, q.sha256);
    let resp = match web.http.get(url).header("Authorization", header).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("artifact fetch failed: {e}");
            return error(StatusCode::BAD_GATEWAY, "the Core is unreachable");
        }
    };
    if !resp.status().is_success() {
        return error(StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY), "artifact not available");
    }
    let Ok(bytes) = resp.bytes().await else { return error(StatusCode::BAD_GATEWAY, "interrupted download") };
    if hex(&Sha256::digest(&bytes)) != q.sha256 {
        tracing::error!("the Core returned content that does not match {}: not cached", q.sha256);
        return error(StatusCode::BAD_GATEWAY, "content does not match the requested hash");
    }
    let _ = fs::create_dir_all(&web.artifact_dir);
    if delbert_fs::write_private(&cached, &bytes).is_err() {
        tracing::warn!("cannot cache artifact {}", q.sha256);
    }
    ([(header::CONTENT_TYPE, "application/octet-stream")], bytes.to_vec()).into_response()
}
