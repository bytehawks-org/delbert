//! The `get_url` verb: a file the agent downloads itself (docs/POLICY.md "Downloads").
//!
//! The policy pins the content with a mandatory SHA-256. A destination that already has that hash
//! is compliant without any request; otherwise the file is downloaded into memory, hashed, and
//! written (crash-safely) only if the hash matches. A wrong or tampered download changes nothing
//! on the host. TLS uses the system's trust store (this is not a Delbert endpoint).

use std::{fs, path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use delbert_policy::GetUrlSpec;
use sha2::{Digest, Sha256};

use crate::engine::Ctx;
use crate::fsutil::{Attrs, apply_attrs, attrs_drift, write_atomic};
use crate::verbs::{Check, Verb};

/// Largest download: the file is held in memory to be verified before anything is written.
const MAX_BYTES: usize = 256 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(900);

fn attrs(spec: &GetUrlSpec) -> Attrs<'_> {
    Attrs { owner: spec.owner.as_deref(), group: spec.group.as_deref(), mode: spec.mode.as_deref() }
}

fn hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Is the destination a regular file with the pinned content?
fn has_content(path: &Path, sha256: &str) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_file()) && fs::read(path).is_ok_and(|bytes| hex(&bytes) == sha256)
}

async fn fetch(url: &str) -> Result<Vec<u8>> {
    // The binary installs the provider at start; a library caller (and the tests) may not have.
    rustls::crypto::ring::default_provider().install_default().ok();
    let client = reqwest::Client::builder().connect_timeout(CONNECT_TIMEOUT).timeout(TOTAL_TIMEOUT).build()?;
    let mut response = client.get(url).send().await.with_context(|| format!("downloading {url}"))?;
    if !response.status().is_success() {
        bail!("downloading {url}: HTTP {}", response.status());
    }
    if response.content_length().is_some_and(|len| len > MAX_BYTES as u64) {
        bail!("{url} is larger than {} MiB", MAX_BYTES / (1024 * 1024));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.with_context(|| format!("downloading {url}"))? {
        if body.len() + chunk.len() > MAX_BYTES {
            bail!("{url} is larger than {} MiB", MAX_BYTES / (1024 * 1024));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Verbs are synchronous: wait for the download on the runtime the agent already has (the engine
/// runs on a blocking thread of it), or on a small one of its own (tests, plain callers).
fn download(url: &str) -> Result<Vec<u8>> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => tokio::task::block_in_place(|| handle.block_on(fetch(url))),
        Err(_) => tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(fetch(url)),
    }
}

impl Verb for GetUrlSpec {
    fn check(&self, ctx: &Ctx) -> Result<Check> {
        let path = ctx.path(&self.dest);
        let Ok(meta) = fs::symlink_metadata(&path) else { return Ok(Check::Drift(vec!["missing".into()])) };
        if !meta.is_file() {
            bail!("{} exists and is not a regular file", self.dest);
        }
        let mut drift = if has_content(&path, &self.sha256) { vec![] } else { vec!["content".to_string()] };
        drift.extend(attrs_drift(ctx, &meta, attrs(self))?);
        Ok(if drift.is_empty() { Check::Compliant } else { Check::Drift(drift) })
    }

    fn apply(&self, ctx: &Ctx) -> Result<()> {
        let path = ctx.path(&self.dest);
        if has_content(&path, &self.sha256) {
            return apply_attrs(ctx, &path, attrs(self));
        }
        let body = download(&self.url)?;
        let actual = hex(&body);
        if actual != self.sha256 {
            bail!("{} has SHA-256 {actual}, not the pinned one: nothing was written", self.url);
        }
        write_atomic(ctx, &path, &body, attrs(self))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };

    use super::*;

    /// A one-file HTTP server on a local port; returns its URL and how many requests it served.
    fn serve(body: &'static [u8], status: &'static str) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/file.bin", listener.local_addr().unwrap());
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = hits.clone();
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut request = [0u8; 2048];
                let _ = stream.read(&mut request);
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = write!(stream, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                let _ = stream.write_all(body);
            }
        });
        (url, hits)
    }

    fn spec(url: &str, sha256: String) -> GetUrlSpec {
        GetUrlSpec { url: url.into(), dest: "/opt/tool.bin".into(), sha256, owner: None, group: None, mode: Some("0755".into()) }
    }

    fn sandbox() -> (tempfile::TempDir, Ctx) {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("opt")).unwrap();
        let ctx = Ctx::new(tmp.path().to_path_buf(), "artifacts".into());
        (tmp, ctx)
    }

    #[test]
    fn a_file_with_the_pinned_hash_is_downloaded_once() {
        let (url, hits) = serve(b"binary content", "200 OK");
        let (tmp, ctx) = sandbox();
        let spec = spec(&url, hex(b"binary content"));
        assert_eq!(spec.check(&ctx).unwrap(), Check::Drift(vec!["missing".into()]));
        spec.apply(&ctx).unwrap();
        let file = tmp.path().join("opt/tool.bin");
        assert_eq!(fs::read(&file).unwrap(), b"binary content");
        assert_eq!(std::os::unix::fs::MetadataExt::mode(&fs::metadata(&file).unwrap()) & 0o777, 0o755);
        // Compliant from now on, and no further request is made.
        assert_eq!(spec.check(&ctx).unwrap(), Check::Compliant);
        spec.apply(&ctx).unwrap();
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        // Local changes are drift and are repaired from the source.
        fs::write(&file, "tampered").unwrap();
        assert_eq!(spec.check(&ctx).unwrap(), Check::Drift(vec!["content".into()]));
        spec.apply(&ctx).unwrap();
        assert_eq!(fs::read(&file).unwrap(), b"binary content");
    }

    #[test]
    fn a_download_that_does_not_match_or_fails_writes_nothing() {
        let (tmp, ctx) = sandbox();
        let (url, _) = serve(b"something else", "200 OK");
        let err = spec(&url, hex(b"binary content")).apply(&ctx).unwrap_err().to_string();
        assert!(err.contains("not the pinned one"), "{err}");
        let (url, _) = serve(b"not here", "404 Not Found");
        assert!(spec(&url, hex(b"not here")).apply(&ctx).unwrap_err().to_string().contains("HTTP 404"));
        assert_eq!(fs::read_dir(tmp.path().join("opt")).unwrap().count(), 0);
    }
}
