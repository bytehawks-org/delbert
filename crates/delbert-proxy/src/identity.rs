//! Proxy identity and enrollment.
//!
//! | File | Content |
//! |------|---------|
//! | `key.pem` (0600) | Ed25519 identity key |
//! | `cert.pem` | certificate signed by the Delbert CA: client identity towards the Core AND server certificate of the site's HTTPS and NATS |
//! | `ca.pem` | the Delbert CA |
//! | `local-issuer.seed` (0600), `local-issuer.pub` | nkey of the site's NATS authorization callout |
//! | `meta.json` | site, Core URL, the Core's NATS URL |

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub site: String,
    pub core_url: String,
    pub hub_nats_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Identity {
    pub dir: PathBuf,
    pub meta: Meta,
}

impl Identity {
    pub fn load(dir: &Path) -> Result<Self> {
        let meta = fs::read_to_string(dir.join("meta.json")).with_context(|| format!("no identity in {} (run `delbert-proxy enroll` first)", dir.display()))?;
        Ok(Identity { dir: dir.to_path_buf(), meta: serde_json::from_str(&meta)? })
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    pub fn key_pem(&self) -> Result<String> {
        fs::read_to_string(self.path("key.pem")).context("reading the identity key")
    }

    pub fn cert_pem(&self) -> Result<String> {
        fs::read_to_string(self.path("cert.pem")).context("reading the certificate")
    }

    pub fn local_issuer(&self) -> Result<nkeys::KeyPair> {
        let seed = fs::read_to_string(self.path("local-issuer.seed")).context("reading the local issuer seed")?;
        nkeys::KeyPair::from_seed(seed.trim()).map_err(|e| anyhow::anyhow!("invalid local issuer seed: {e}"))
    }
}

fn write_private(path: &Path, data: &str) -> Result<()> {
    fs::write(path, data)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[derive(Deserialize)]
struct EnrollResponse {
    cert_pem: String,
    ca_pem: String,
    nats_url: Option<String>,
}

pub struct EnrollArgs {
    pub core_url: String,
    pub ca_file: PathBuf,
    pub psk: String,
    pub site: String,
    pub identity_dir: PathBuf,
}

pub async fn enroll(args: EnrollArgs) -> Result<Identity> {
    if args.identity_dir.join("meta.json").exists() {
        bail!("{} already holds an identity; remove it first to enroll again", args.identity_dir.display());
    }
    let ca_pem = fs::read_to_string(&args.ca_file).with_context(|| format!("reading {}", args.ca_file.display()))?;
    let (key_pem, csr_pem) = delbert_pki::new_identity(&args.site)?;
    let client = reqwest::Client::builder().tls_certs_only([reqwest::Certificate::from_pem(ca_pem.as_bytes()).context("invalid CA file")?]).build()?;
    let resp = client
        .post(format!("{}/v1/proxies/enroll", args.core_url.trim_end_matches('/')))
        .json(&json!({ "name": args.site, "psk": args.psk, "csr_pem": csr_pem }))
        .send()
        .await
        .context("cannot reach the Core (check the URL and that the CA matches its certificate)")?;
    if !resp.status().is_success() {
        let status = resp.status();
        bail!("enrollment refused ({status}): {}", resp.text().await.unwrap_or_default());
    }
    let resp: EnrollResponse = resp.json().await.context("unexpected enrollment response")?;
    if resp.ca_pem.trim() != ca_pem.trim() {
        bail!("the Core returned a different CA than the one provided: refusing");
    }

    let dir = &args.identity_dir;
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    write_private(&dir.join("key.pem"), &key_pem)?;
    fs::write(dir.join("cert.pem"), &resp.cert_pem)?;
    fs::write(dir.join("ca.pem"), &ca_pem)?;
    // The site's NATS server delegates authorization to this proxy, with its own issuer key.
    let issuer = nkeys::KeyPair::new_account();
    write_private(&dir.join("local-issuer.seed"), &issuer.seed().map_err(|e| anyhow::anyhow!("{e}"))?)?;
    fs::write(dir.join("local-issuer.pub"), issuer.public_key())?;
    let meta = Meta { site: args.site, core_url: args.core_url.trim_end_matches('/').to_owned(), hub_nats_url: resp.nats_url };
    fs::write(dir.join("meta.json"), serde_json::to_string_pretty(&meta)?)?; // last: marks the identity as complete
    Identity::load(dir)
}
