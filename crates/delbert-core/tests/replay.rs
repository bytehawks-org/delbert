//! A captured agent proof cannot be presented twice (docs/SECURITY-REVIEW.md F-05).

mod common;

use axum::http::{Request, StatusCode as S};
use base64::Engine;
use common::{admin_client, enroll_agent, state};
use delbert_core::compile::Strategy;
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;

#[sqlx::test]
async fn a_replayed_artifact_proof_is_refused(pool: PgPool) {
    let admin = admin_client(state(pool, vec![Strategy::Error], None)).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    let agent = enroll_agent(&admin, "acme", "agent-1").await;
    let (s, up) = admin.raw("PUT", "/v1/tenants/acme/artifacts/f.txt", vec![("content-type", "application/octet-stream".into())], b"hello".to_vec()).await;
    assert_eq!(s, S::CREATED);
    let sha = serde_json::from_slice::<serde_json::Value>(&up).unwrap()["sha256"].as_str().unwrap().to_owned();

    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let header = |proof: &delbert_pki::authn::Proof| format!("Delbert-Agent {}", base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(proof).unwrap()));
    let get = |h: String| {
        let app = admin.app.clone();
        let uri = format!("/v1/agent/acme/agent-1/artifacts/f.txt?sha256={sha}");
        async move { app.oneshot(Request::builder().uri(uri).header("authorization", h).body(axum::body::Body::empty()).unwrap()).await.unwrap().status() }
    };
    let proof = |at| delbert_pki::authn::prove(&agent.key_pem, "artifact", "acme", "agent-1", &json!(format!("f.txt:{sha}")), at).unwrap();

    let captured = header(&proof(now));
    assert_eq!(get(captured.clone()).await, S::OK);
    assert_eq!(get(captured.clone()).await, S::UNAUTHORIZED, "the same proof twice");
    assert_eq!(get(captured).await, S::UNAUTHORIZED);
    // A fresh proof (new nonce) from the same agent is fine, as every download of a real agent is.
    assert_eq!(get(header(&proof(now))).await, S::OK);
}
