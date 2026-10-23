//! Object storage for artifact content: a local directory (single host, VM or a container
//! volume) or any S3-compatible service (Garage, MinIO, AWS). PostgreSQL never holds file
//! content, only the metadata (`artifacts`).
//!
//! Objects are keyed `artifacts/<tenant id>/<sha256>`: content-addressed, so a write is idempotent
//! and an object never changes. Every download is checked against the requested hash again,
//! whatever the backend returns.

use std::{path::PathBuf, sync::Arc};

use bytes::Bytes;
use futures::{Stream, StreamExt, TryStreamExt};
use object_store::{ObjectStore, PutPayload, aws::AmazonS3Builder, local::LocalFileSystem, memory::InMemory, path::Path};
use sqlx::types::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("object store error: {0}")]
    Store(#[from] object_store::Error),
    #[error("object store setup: {0}")]
    Setup(String),
}

#[derive(Clone)]
pub struct Blobs {
    store: Arc<dyn ObjectStore>,
    kind: &'static str,
}

/// S3 settings (path-style addressing, as Garage and MinIO expect).
pub struct S3Config {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
}

impl Blobs {
    pub fn local(dir: impl Into<PathBuf>) -> Result<Self, BlobError> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir).map_err(|e| BlobError::Setup(format!("{}: {e}", dir.display())))?;
        Ok(Blobs { store: Arc::new(LocalFileSystem::new_with_prefix(&dir)?), kind: "local" })
    }

    pub fn s3(c: S3Config) -> Result<Self, BlobError> {
        let store = AmazonS3Builder::new()
            .with_endpoint(&c.endpoint)
            .with_bucket_name(&c.bucket)
            .with_region(&c.region)
            .with_access_key_id(&c.access_key)
            .with_secret_access_key(&c.secret_key)
            .with_virtual_hosted_style_request(false)
            .with_allow_http(c.endpoint.starts_with("http://"))
            .build()?;
        Ok(Blobs { store: Arc::new(store), kind: "s3" })
    }

    /// Volatile store for tests.
    pub fn memory() -> Self {
        Blobs { store: Arc::new(InMemory::new()), kind: "memory" }
    }

    pub fn kind(&self) -> &'static str {
        self.kind
    }

    fn key(tenant: Uuid, sha256_hex: &str) -> Path {
        Path::from(format!("artifacts/{tenant}/{sha256_hex}"))
    }

    /// Store the content (a no-op in effect when it already exists).
    pub async fn put(&self, tenant: Uuid, sha256_hex: &str, content: Bytes) -> Result<(), BlobError> {
        self.store.put(&Self::key(tenant, sha256_hex), PutPayload::from_bytes(content)).await?;
        Ok(())
    }

    /// Stream the content. `Ok(None)` when it does not exist.
    pub async fn get(&self, tenant: Uuid, sha256_hex: &str) -> Result<Option<impl Stream<Item = Result<Bytes, BlobError>> + use<>>, BlobError> {
        match self.store.get(&Self::key(tenant, sha256_hex)).await {
            Ok(r) => Ok(Some(r.into_stream().map_err(BlobError::from).boxed())),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Reachability and credentials check at startup: reading a missing key must say "not found".
    pub async fn probe(&self) -> Result<(), BlobError> {
        match self.store.head(&Path::from("artifacts/.probe")).await {
            Ok(_) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}
