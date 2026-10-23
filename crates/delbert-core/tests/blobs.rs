//! Artifact object store: local directory always; an S3-compatible service (Garage) when
//! `S3_TEST_ENDPOINT`, `S3_TEST_BUCKET`, `S3_TEST_ACCESS_KEY` and `S3_TEST_SECRET_KEY` are set.

mod common;

use axum::http::StatusCode as S;
use bytes::Bytes;
use common::{admin_client, state};
use delbert_core::{blobs::{Blobs, S3Config}, compile::Strategy};
use futures::TryStreamExt;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

fn random_tenant() -> sqlx::types::Uuid {
    let mut b = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    sqlx::types::Uuid::from_bytes(b)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

async fn read(blobs: &Blobs, tenant: sqlx::types::Uuid, sha: &str) -> Option<Vec<u8>> {
    let stream = blobs.get(tenant, sha).await.unwrap()?;
    Some(stream.try_collect::<Vec<Bytes>>().await.unwrap().concat())
}

async fn exercise(blobs: &Blobs) {
    blobs.probe().await.unwrap();
    let tenant = random_tenant();
    let content = Bytes::from(vec![7u8; 3 * 1024 * 1024]);
    let sha = hex(&Sha256::digest(&content));
    assert!(read(blobs, tenant, &sha).await.is_none());
    blobs.put(tenant, &sha, content.clone()).await.unwrap();
    blobs.put(tenant, &sha, content.clone()).await.unwrap(); // idempotent
    assert_eq!(read(blobs, tenant, &sha).await.unwrap(), content.to_vec());
    // Objects are per tenant: the same hash under another tenant does not exist.
    assert!(read(blobs, random_tenant(), &sha).await.is_none());
}

#[tokio::test]
async fn local_directory_store() {
    let dir = tempfile::tempdir().unwrap();
    exercise(&Blobs::local(dir.path().join("a/b")).unwrap()).await;
}

fn s3_from_env() -> Option<Blobs> {
    let var = |k: &str| std::env::var(k).ok();
    Some(Blobs::s3(S3Config {
        endpoint: var("S3_TEST_ENDPOINT")?,
        bucket: var("S3_TEST_BUCKET")?,
        region: "garage".into(),
        access_key: var("S3_TEST_ACCESS_KEY")?,
        secret_key: var("S3_TEST_SECRET_KEY")?,
    })
    .unwrap())
}

#[tokio::test]
async fn s3_compatible_store() {
    match s3_from_env() {
        Some(b) => exercise(&b).await,
        None => eprintln!("S3_TEST_* not set: skipping"),
    }
}

#[sqlx::test]
async fn artifacts_live_in_the_store_and_corruption_is_detected(pool: PgPool) {
    let mut st = state(pool.clone(), vec![Strategy::Error], None);
    if let Some(b) = s3_from_env() {
        st.blobs = b;
    }
    let blobs = st.blobs.clone();
    let admin = admin_client(st).await;
    admin.call("POST", "/v1/tenants", Some(json!({ "name": "acme" }))).await;
    let agent = common::enroll_agent(&admin, "acme", "agent-1").await;
    let content = vec![9u8; 2_000_000];
    let (s, body) = admin.raw("PUT", "/v1/tenants/acme/artifacts/big.bin", vec![("content-type", "application/octet-stream".into())], content.clone()).await;
    assert_eq!(s, S::CREATED);
    let sha = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["sha256"].as_str().unwrap().to_owned();

    // The bytes are in the store under the tenant; PostgreSQL has no content column.
    let tid: sqlx::types::Uuid = sqlx::query_scalar("SELECT id FROM tenants WHERE name = 'acme'").fetch_one(&pool).await.unwrap();
    assert_eq!(read(&blobs, tid, &sha).await.unwrap().len(), content.len());
    let has_content: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'artifacts' AND column_name = 'content')").fetch_one(&pool).await.unwrap();
    assert!(!has_content);

    let download = |sha: String| {
        let admin = admin.clone();
        let key = agent.key_pem.clone();
        async move {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
            let proof = delbert_pki::authn::prove(&key, "artifact", "acme", "agent-1", &json!(format!("big.bin:{sha}")), now).unwrap();
            let header = format!("Delbert-Agent {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, serde_json::to_vec(&proof).unwrap()));
            let req = axum::http::Request::builder().uri(format!("/v1/agent/acme/agent-1/artifacts/big.bin?sha256={sha}")).header("authorization", header).body(axum::body::Body::empty()).unwrap();
            let resp = tower::ServiceExt::oneshot(admin.app.clone(), req).await.unwrap();
            let status = resp.status();
            let body = http_body_util::BodyExt::collect(resp.into_body()).await.map(|b| b.to_bytes().len());
            (status, body.ok())
        }
    };
    assert_eq!(download(sha.clone()).await, (S::OK, Some(content.len())));

    // An object that no longer matches its hash is never served as valid: the body is aborted.
    blobs.put(tid, &sha, Bytes::from(vec![1u8; 2_000_000])).await.unwrap();
    assert_eq!(download(sha.clone()).await, (S::OK, None));
    // Objects the tenant has no metadata for are unknown, even when present in the store.
    let other = hex(&Sha256::digest(b"other"));
    blobs.put(tid, &other, Bytes::from_static(b"other")).await.unwrap();
    assert_eq!(download(other).await.0, S::NOT_FOUND);
}
