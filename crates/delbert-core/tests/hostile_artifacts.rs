//! Hostile artifact names, hashes and sizes (docs/SECURITY-REVIEW.md F-10): nothing may reach
//! the object store with a crafted key, nothing may answer 500, and the size limit holds.

mod common;

use axum::http::StatusCode as S;
use common::{admin_client, enroll_agent, state};
use delbert_core::compile::Strategy;
use serde_json::json;
use sqlx::PgPool;

#[sqlx::test]
async fn artifact_names_hashes_and_sizes_cannot_be_abused(pool: PgPool) {
    let admin = admin_client(state(pool, vec![Strategy::Error], None)).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "beta" }))).await;
    let octet = || vec![("content-type", "application/octet-stream".to_string())];
    let put = |tenant: &str, name: &str, body: Vec<u8>| admin.raw("PUT", format!("/v1/tenants/{tenant}/artifacts/{name}"), octet(), body);

    // Names that are not plain names are refused (never a 5xx), whatever the encoding.
    let long = "a".repeat(129);
    for name in ["..%2f..%2fetc%2fpasswd", "a%00b", "%20", "a%2Fb", "a%20b", "%C3%A9", long.as_str(), "%2e%2e%2f", "a%5Cb", "a;b", "a*"] {
        let (s, body) = put("acme", name, b"x".to_vec()).await;
        assert!(s == S::UNPROCESSABLE_ENTITY || s == S::NOT_FOUND || s == S::BAD_REQUEST, "name {name:?} answered {s}: {}", String::from_utf8_lossy(&body));
    }

    // A legitimate upload, then hashes crafted to leave the tenant's namespace or the store.
    let (s, up) = put("acme", "f.txt", b"hello".to_vec()).await;
    assert_eq!(s, S::CREATED);
    let sha = serde_json::from_slice::<serde_json::Value>(&up).unwrap()["sha256"].as_str().unwrap().to_owned();
    let agent = enroll_agent(&admin, "acme", "agent-1").await;
    let download = |sha: String| {
        let admin = admin.clone();
        let key = agent.key_pem.clone();
        async move {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
            let proof = delbert_pki::authn::prove(&key, "artifact", "acme", "agent-1", &json!(format!("f.txt:{sha}")), now).unwrap();
            let header = format!("Delbert-Agent {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, serde_json::to_vec(&proof).unwrap()));
            let req = axum::http::Request::builder().uri(format!("/v1/agent/acme/agent-1/artifacts/f.txt?sha256={sha}")).header("authorization", header).body(axum::body::Body::empty()).unwrap();
            tower::ServiceExt::oneshot(admin.app.clone(), req).await.unwrap().status()
        }
    };
    assert_eq!(download(sha.clone()).await, S::OK);
    for bad in ["../../etc/passwd", "%2e%2e%2f%2e%2e%2fx", "", "abc", &sha[..63], &format!("{sha}0"), &"g".repeat(64), &format!("../{}", &sha[..61])] {
        let s = download(bad.to_owned()).await;
        assert!(s == S::NOT_FOUND || s == S::BAD_REQUEST || s == S::UNAUTHORIZED, "hash {bad:?} answered {s}");
    }

    // Another tenant cannot read this tenant's content by knowing its hash (no cross-tenant dedupe leak).
    let (s, _) = admin.raw("GET", format!("/v1/tenants/beta/artifacts/f.txt?sha256={sha}"), vec![], vec![]).await;
    assert!(s == S::NOT_FOUND || s == S::METHOD_NOT_ALLOWED, "{s}");
    assert_eq!(admin.call("GET", "/v1/tenants/beta/artifacts", None).await.1, json!([]));

    // The size limit holds (64 MiB + a little): 413, not a crash or an out-of-memory.
    let (s, _) = put("acme", "huge.bin", vec![0u8; delbert_core::artifacts::MAX_ARTIFACT_BYTES + 4096]).await;
    assert_eq!(s, S::PAYLOAD_TOO_LARGE);
}
