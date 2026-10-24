//! Agent identity and enrollment (docs/ABSTRACT.md §3).
//!
//! `enroll` generates the keys on this host, sends a CSR and an age public key
//! to the Core together with the pre-shared enrollment key, and stores the
//! result in the identity directory:
//!
//! | File | Content |
//! |------|---------|
//! | `key.pem` (0600) | Ed25519 identity key, never leaves the host |
//! | `cert.pem` | certificate signed by the Delbert CA (mTLS to NATS) |
//! | `ca.pem` | Delbert CA (trust anchor) |
//! | `enc.key` (0600) | age secret key for the secrets in policies |
//! | `trusted-keys.txt` | policy signing keys received at enrollment |
//! | `meta.json` | tenant, agent name, NATS URL |

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    str::FromStr,
};

use age::secrecy::ExposeSecret;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub tenant: String,
    pub agent: String,
    pub nats_url: Option<String>,
    /// HTTPS URL of the Core used at enrollment (artifact downloads).
    #[serde(default)]
    pub core_url: Option<String>,
}

/// An enrolled identity, loaded from disk.
#[derive(Debug, Clone)]
pub struct Identity {
    pub dir: PathBuf,
    pub meta: Meta,
}

impl Identity {
    pub fn load(dir: &Path) -> Result<Self> {
        let meta = fs::read_to_string(dir.join("meta.json")).with_context(|| format!("no identity in {} (run `delbert-agent enroll` first)", dir.display()))?;
        Ok(Identity { dir: dir.to_path_buf(), meta: serde_json::from_str(&meta)? })
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    pub fn key_pem(&self) -> Result<String> {
        fs::read_to_string(self.path("key.pem")).context("reading the identity key")
    }

    pub fn trusted_keys(&self) -> PathBuf {
        self.path("trusted-keys.txt")
    }

    /// The age identity that decrypts the policy secrets.
    pub fn age_identity(&self) -> Result<age::x25519::Identity> {
        let text = fs::read_to_string(self.path("enc.key")).context("reading enc.key")?;
        age::x25519::Identity::from_str(text.trim()).map_err(|e| anyhow::anyhow!("invalid enc.key: {e}"))
    }
}

/// Install a renewed key and certificate. Both are written aside first, then moved into
/// place (certificate last), so an interruption can be completed by [`recover`].
pub fn install_renewed(dir: &Path, key_pem: &str, cert_pem: &str) -> Result<()> {
    write_private(&dir.join("key.pem.new"), key_pem)?;
    delbert_fs::write_public(&dir.join("cert.pem.new"), cert_pem.as_bytes())?;
    recover(dir)
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

/// Should the certificate be renewed now? By default when less than a third of its lifetime
/// is left; `renew_before_secs` overrides that threshold.
pub fn renewal_due(cert_pem: &str, now: i64, renew_before_secs: Option<i64>) -> bool {
    let Ok((not_before, not_after)) = delbert_pki::cert_validity(cert_pem) else { return false };
    let remaining = not_after - now;
    remaining < renew_before_secs.unwrap_or((not_after - not_before) / 3)
}

fn write_private(path: &Path, data: &str) -> Result<()> {
    Ok(delbert_fs::write_private(path, data.as_bytes())?)
}

#[cfg(test)]
mod tests {
    use delbert_pki::CertificateAuthority as _;
    use super::*;

    #[test]
    fn renewal_threshold_and_override() {
        let ca = delbert_pki::RcgenCa::create("CA", 365).unwrap();
        let (_, csr) = delbert_pki::new_identity("a").unwrap();
        let cert = ca.sign_csr(&csr, "a", "urn:delbert:agent:t:a", 30).unwrap().cert_pem;
        let (_, not_after) = delbert_pki::cert_validity(&cert).unwrap();
        let day = 86_400;
        assert!(!renewal_due(&cert, not_after - 29 * day, None));
        assert!(!renewal_due(&cert, not_after - 11 * day, None));
        assert!(renewal_due(&cert, not_after - 9 * day, None), "less than a third left");
        assert!(renewal_due(&cert, not_after - 29 * day, Some(30 * day)), "override forces it");
        assert!(!renewal_due("garbage", 0, None));
    }

    #[test]
    fn interrupted_renewals_are_completed() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        fs::write(p.join("key.pem"), "old-key").unwrap();
        fs::write(p.join("cert.pem"), "old-cert").unwrap();
        install_renewed(p, "new-key", "new-cert").unwrap();
        assert_eq!((fs::read_to_string(p.join("key.pem")).unwrap(), fs::read_to_string(p.join("cert.pem")).unwrap()), ("new-key".into(), "new-cert".into()));
        assert!(!p.join("key.pem.new").exists() && !p.join("cert.pem.new").exists());

        // Crash after the key was moved but before the certificate was: finish the job.
        fs::write(p.join("cert.pem.new"), "newer-cert").unwrap();
        fs::write(p.join("key.pem"), "newer-key").unwrap();
        recover(p).unwrap();
        assert_eq!(fs::read_to_string(p.join("cert.pem")).unwrap(), "newer-cert");

        // Crash while writing the aside files (certificate missing): the old pair is untouched.
        fs::write(p.join("key.pem.new"), "half").unwrap();
        recover(p).unwrap();
        assert_eq!(fs::read_to_string(p.join("key.pem")).unwrap(), "newer-key");
        assert!(!p.join("key.pem.new").exists());
    }
}

#[derive(Deserialize)]
struct EnrollResponse {
    tenant: String,
    agent: String,
    cert_pem: String,
    ca_pem: String,
    signing_keys: Vec<String>,
    nats_url: Option<String>,
}

pub struct EnrollArgs {
    pub core_url: String,
    /// Delbert CA shipped with the installer: the only trust anchor for the HTTPS call.
    pub ca_file: PathBuf,
    pub psk: String,
    pub agent_name: String,
    pub identity_dir: PathBuf,
}

pub async fn enroll(args: EnrollArgs) -> Result<Identity> {
    if args.identity_dir.join("meta.json").exists() {
        bail!("{} already holds an identity; remove it first to enroll again", args.identity_dir.display());
    }
    let ca_pem = fs::read_to_string(&args.ca_file).with_context(|| format!("reading {}", args.ca_file.display()))?;

    // Keys are created here and the private parts stay here.
    let (key_pem, csr_pem) = delbert_pki::new_identity(&args.agent_name)?;
    let enc = age::x25519::Identity::generate();
    let enc_public = enc.to_public().to_string();

    let client = reqwest::Client::builder()
        .tls_certs_only(reqwest::Certificate::from_pem_bundle(ca_pem.as_bytes()).context("invalid CA file")?)
        .build()?;
    let resp = client
        .post(format!("{}/v1/enroll", args.core_url.trim_end_matches('/')))
        .json(&json!({ "psk": args.psk, "agent_name": args.agent_name, "csr_pem": csr_pem, "enc_public_key": enc_public }))
        .send()
        .await
        .context("cannot reach the Core (check the URL and that the CA matches its certificate)")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("enrollment refused ({status}): {body}");
    }
    let resp: EnrollResponse = resp.json().await.context("unexpected enrollment response")?;
    // The Core may announce more CAs (a rotation in progress) but must include every one we were given.
    let announced = delbert_pki::bundle::fingerprints(&resp.ca_pem);
    if delbert_pki::bundle::fingerprints(&ca_pem).iter().any(|f| !announced.contains(f)) {
        bail!("the Core returned a different CA than the one provided: refusing");
    }

    fs::create_dir_all(&args.identity_dir)?;
    fs::set_permissions(&args.identity_dir, fs::Permissions::from_mode(0o700))?;
    let dir = &args.identity_dir;
    write_private(&dir.join("key.pem"), &key_pem)?;
    write_private(&dir.join("enc.key"), enc.to_string().expose_secret())?;
    delbert_fs::write_public(&dir.join("cert.pem"), resp.cert_pem.as_bytes())?;
    delbert_fs::write_public(&dir.join("ca.pem"), resp.ca_pem.as_bytes())?;
    delbert_fs::write_public(&dir.join("trusted-keys.txt"), (resp.signing_keys.join("\n") + "\n").as_bytes())?;
    let meta = Meta { tenant: resp.tenant, agent: resp.agent, nats_url: resp.nats_url, core_url: Some(args.core_url.trim_end_matches('/').to_owned()) };
    delbert_fs::write_public(&dir.join("meta.json"), serde_json::to_string_pretty(&meta)?.as_bytes())?; // last: marks the identity as complete
    Identity::load(dir)
}
