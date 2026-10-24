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

/// Renew the certificate with a NEW key. The Core authenticates the request with the current key;
/// the new files are written aside and moved into place (certificate last), so an interruption
/// can be completed by [`recover`]. The caller must restart the proxy so that every connection
/// and the HTTPS listener use the new certificate.
pub async fn renew(id: &Identity) -> Result<()> {
    let ca_pem = fs::read_to_string(id.path("ca.pem")).context("reading ca.pem")?;
    let (key_pem, csr_pem) = delbert_pki::new_identity(&id.meta.site)?;
    let body = json!({ "csr_pem": csr_pem });
    let header = crate::hub::ProofMaker::new(id)?.header("proxy-renew", &body)?;
    let client = reqwest::Client::builder().tls_certs_only(reqwest::Certificate::from_pem_bundle(ca_pem.as_bytes()).context("invalid CA file")?).build()?;
    let resp = client
        .post(format!("{}/v1/proxies/{}/renew", id.meta.core_url, id.meta.site))
        .header("authorization", header)
        .json(&body)
        .send()
        .await
        .context("cannot reach the Core")?;
    if !resp.status().is_success() {
        let status = resp.status();
        bail!("renewal refused ({status}): {}", resp.text().await.unwrap_or_default());
    }
    #[derive(Deserialize)]
    struct Renewed {
        cert_pem: String,
        ca_pem: String,
    }
    let renewed: Renewed = resp.json().await.context("unexpected renewal response")?;
    // The Core's bundle follows its CA rotation (a CA announced, a retired one dropped). The channel
    // was verified with the CAs we have, and the result must still contain at least one of them.
    let known = delbert_pki::bundle::fingerprints(&ca_pem);
    let announced = delbert_pki::bundle::fingerprints(&renewed.ca_pem);
    let bundle = announced.iter().any(|f| known.contains(f)).then_some(renewed.ca_pem.as_str());
    write_private(&id.path("key.pem.new"), &key_pem)?;
    delbert_fs::write_public(&id.path("cert.pem.new"), renewed.cert_pem.as_bytes())?;
    if let Some(next) = bundle {
        delbert_fs::write_public(&id.path("ca.pem"), next.as_bytes())?;
    }
    recover(&id.dir)
}

/// Finish a renewal that was interrupted between the two renames.
pub fn recover(dir: &Path) -> Result<()> {
    let (key_new, cert_new) = (dir.join("key.pem.new"), dir.join("cert.pem.new"));
    if key_new.exists() && cert_new.exists() {
        fs::rename(&key_new, dir.join("key.pem"))?;
    }
    if cert_new.exists() {
        fs::rename(&cert_new, dir.join("cert.pem"))?;
    }
    let _ = fs::remove_file(&key_new); // a lone stale key is useless without its certificate
    Ok(())
}

/// Should the certificate be renewed now? When less than a third of its lifetime is left (or
/// `renew_before_secs`), and never within an hour of it being issued, so a threshold above the
/// lifetime cannot cause a renewal loop.
pub fn renewal_due(cert_pem: &str, now: i64, renew_before_secs: Option<i64>) -> bool {
    let Ok((not_before, not_after)) = delbert_pki::cert_validity(cert_pem) else { return false };
    if now - not_before < 3600 {
        return false;
    }
    (not_after - now) < renew_before_secs.unwrap_or((not_after - not_before) / 3)
}

fn write_private(path: &Path, data: &str) -> Result<()> {
    Ok(delbert_fs::write_private(path, data.as_bytes())?)
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
    let client = reqwest::Client::builder().tls_certs_only(reqwest::Certificate::from_pem_bundle(ca_pem.as_bytes()).context("invalid CA file")?).build()?;
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
    let announced = delbert_pki::bundle::fingerprints(&resp.ca_pem);
    if delbert_pki::bundle::fingerprints(&ca_pem).iter().any(|f| !announced.contains(f)) {
        bail!("the Core returned a different CA than the one provided: refusing");
    }

    let dir = &args.identity_dir;
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    write_private(&dir.join("key.pem"), &key_pem)?;
    delbert_fs::write_public(&dir.join("cert.pem"), resp.cert_pem.as_bytes())?;
    delbert_fs::write_public(&dir.join("ca.pem"), resp.ca_pem.as_bytes())?;
    // The site's NATS server delegates authorization to this proxy, with its own issuer key.
    let issuer = nkeys::KeyPair::new_account();
    write_private(&dir.join("local-issuer.seed"), &issuer.seed().map_err(|e| anyhow::anyhow!("{e}"))?)?;
    delbert_fs::write_public(&dir.join("local-issuer.pub"), issuer.public_key().as_bytes())?;
    let meta = Meta { site: args.site, core_url: args.core_url.trim_end_matches('/').to_owned(), hub_nats_url: resp.nats_url };
    delbert_fs::write_public(&dir.join("meta.json"), serde_json::to_string_pretty(&meta)?.as_bytes())?; // last: marks the identity as complete
    Identity::load(dir)
}

#[cfg(test)]
mod tests {
    use delbert_pki::CertificateAuthority as _;
    use super::*;

    #[test]
    fn an_interrupted_renewal_is_completed_and_a_lone_key_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        fs::write(p.join("key.pem"), "old-key").unwrap();
        fs::write(p.join("cert.pem"), "old-cert").unwrap();
        // Crash after both files were written aside: both move into place.
        fs::write(p.join("key.pem.new"), "new-key").unwrap();
        fs::write(p.join("cert.pem.new"), "new-cert").unwrap();
        recover(p).unwrap();
        assert_eq!((fs::read_to_string(p.join("key.pem")).unwrap(), fs::read_to_string(p.join("cert.pem")).unwrap()), ("new-key".into(), "new-cert".into()));
        // Crash after the key moved but before the certificate did: the certificate follows.
        fs::write(p.join("cert.pem.new"), "newer-cert").unwrap();
        recover(p).unwrap();
        assert_eq!(fs::read_to_string(p.join("cert.pem")).unwrap(), "newer-cert");
        // Crash before the certificate was written: the stale key is removed, the old pair stays.
        fs::write(p.join("key.pem.new"), "orphan").unwrap();
        recover(p).unwrap();
        assert!(!p.join("key.pem.new").exists());
        assert_eq!(fs::read_to_string(p.join("key.pem")).unwrap(), "new-key");
    }

    #[test]
    fn renewal_is_due_late_in_the_life_and_never_right_after_issuing() {
        let ca = delbert_pki::RcgenCa::create("Test CA", 30).unwrap();
        let (_, csr) = delbert_pki::new_identity("branch").unwrap();
        let cert = ca.sign_proxy_csr(&csr, "branch", &["branch.example.com".into()], 30).unwrap().cert_pem;
        let (not_before, not_after) = delbert_pki::cert_validity(&cert).unwrap();
        let life = not_after - not_before;
        assert!(!renewal_due(&cert, not_before + 600, None), "young certificate");
        assert!(!renewal_due(&cert, not_before + life / 2, None), "more than a third left");
        assert!(renewal_due(&cert, not_before + life * 3 / 4, None), "less than a third left");
        assert!(!renewal_due(&cert, not_before + 600, Some(life * 10)), "a huge threshold must not renew right after issuing");
        assert!(renewal_due(&cert, not_before + 7200, Some(life * 10)));
    }
}
