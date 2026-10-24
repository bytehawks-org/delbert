//! Delbert internal PKI (docs/ABSTRACT.md §4) and agent request proofs.
//!
//! * [`CertificateAuthority`]: what the Core needs from a CA, so that the backend is swappable.
//!   [`RcgenCa`] is the implementation (rcgen + ring, no OpenSSL); it only issues leaf
//!   certificates (path length 0). [`ca::conformance`] is the checklist any other backend must pass.
//! * Agent identities are Ed25519 key pairs. The agent creates the key and a
//!   CSR locally, so the private key never leaves the host.
//! * [`authn`]: because NATS does not (yet) bind an agent to its subjects, every
//!   request and report carries a signature made with the agent's identity key.
//!
//! The interface is small on purpose: if the effort of owning a CA grows, the
//! same operations can be implemented on top of OpenSSL behind the trait (see `ca.rs`).

pub mod authn;
pub mod bundle;
pub mod ca;
pub mod rcgen_ca;

pub use ca::{BACKENDS, CertificateAuthority, load_backend};
pub use rcgen_ca::RcgenCa;

use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ED25519, SigningKey};

#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    #[error("certificate error: {0}")]
    Cert(#[from] rcgen::Error),
    #[error("only Ed25519 keys are accepted")]
    UnsupportedKey,
    #[error("invalid value: {0}")]
    Invalid(String),
}

/// A certificate and its private key, PEM encoded.
#[derive(Debug, Clone)]
pub struct Issued {
    pub cert_pem: String,
    pub key_pem: String,
}

/// A certificate issued from a CSR, plus the raw public key it certifies.
#[derive(Debug, Clone)]
pub struct SignedCsr {
    pub cert_pem: String,
    /// Raw 32-byte Ed25519 public key (used to verify [`authn`] proofs).
    pub public_key: Vec<u8>,
}

/// Identity URI embedded in agent certificates.
pub fn agent_uri(tenant: &str, agent: &str) -> String {
    format!("urn:delbert:agent:{tenant}:{agent}")
}

/// Who a certificate was issued to, read from its subject alternative name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertIdentity {
    Agent { tenant: String, agent: String, public_key: Vec<u8> },
    /// Infrastructure component such as the Core (`urn:delbert:component:<name>`).
    Component { name: String },
}

fn der_of(pem: &str) -> Result<Vec<u8>, PkiError> {
    x509_parser::pem::parse_x509_pem(pem.as_bytes()).map(|(_, p)| p.contents).map_err(|e| PkiError::Invalid(format!("not a PEM certificate: {e}")))
}

/// Identity carried by a certificate (the chain is assumed to be verified already, e.g. by NATS).
pub fn identity_from_pem(pem: &str) -> Result<CertIdentity, PkiError> {
    use x509_parser::prelude::*;
    let der = der_of(pem)?;
    let (_, cert) = X509Certificate::from_der(&der).map_err(|e| PkiError::Invalid(format!("unreadable certificate: {e}")))?;
    let san = cert.subject_alternative_name().ok().flatten().ok_or_else(|| PkiError::Invalid("certificate has no subject alternative name".into()))?;
    let uri = san
        .value
        .general_names
        .iter()
        .find_map(|n| match n {
            GeneralName::URI(u) if u.starts_with("urn:delbert:") => Some(u.to_string()),
            _ => None,
        })
        .ok_or_else(|| PkiError::Invalid("no Delbert identity URI".into()))?;
    if let Some(rest) = uri.strip_prefix("urn:delbert:agent:") {
        let (tenant, agent) = rest.split_once(':').ok_or_else(|| PkiError::Invalid("malformed agent URI".into()))?;
        return Ok(CertIdentity::Agent { tenant: tenant.into(), agent: agent.into(), public_key: cert.public_key().subject_public_key.data.to_vec() });
    }
    if let Some(name) = uri.strip_prefix("urn:delbert:component:") {
        return Ok(CertIdentity::Component { name: name.into() });
    }
    Err(PkiError::Invalid("unknown Delbert identity URI".into()))
}

/// Raw public key of a certificate (32 bytes for Ed25519).
pub fn public_key_from_pem(pem: &str) -> Option<Vec<u8>> {
    use x509_parser::prelude::*;
    let der = der_of(pem).ok()?;
    let (_, cert) = X509Certificate::from_der(&der).ok()?;
    Some(cert.public_key().subject_public_key.data.to_vec())
}

/// `(not_before, not_after)` of a certificate as Unix seconds.
pub fn cert_validity(pem: &str) -> Result<(i64, i64), PkiError> {
    use x509_parser::prelude::*;
    let der = der_of(pem)?;
    let (_, cert) = X509Certificate::from_der(&der).map_err(|e| PkiError::Invalid(format!("unreadable certificate: {e}")))?;
    Ok((cert.validity().not_before.timestamp(), cert.validity().not_after.timestamp()))
}

/// New agent identity: a private key (PEM, never leaves the host) and a CSR (PEM).
pub fn new_identity(common_name: &str) -> Result<(String, String), PkiError> {
    let key = KeyPair::generate_for(&PKCS_ED25519)?;
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, common_name);
    let csr = params.serialize_request(&key)?;
    Ok((key.serialize_pem(), csr.pem()?))
}

/// Sign `msg` with a PEM private key (Ed25519).
pub fn sign(key_pem: &str, msg: &[u8]) -> Result<Vec<u8>, PkiError> {
    Ok(KeyPair::from_pem(key_pem)?.sign(msg)?)
}

/// Verify an Ed25519 signature against a raw 32-byte public key.
pub fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let (Ok(key), Ok(sig)) = (<[u8; 32]>::try_from(public_key), ed25519_dalek::Signature::from_slice(sig)) else { return false };
    ed25519_dalek::VerifyingKey::from_bytes(&key).is_ok_and(|k| k.verify_strict(msg, &sig).is_ok())
}
