//! Delbert internal PKI (docs/ABSTRACT.md §4) and agent request proofs.
//!
//! * [`Ca`]: a CA that only issues leaf certificates (path length 0).
//! * Agent identities are Ed25519 key pairs. The agent creates the key and a
//!   CSR locally, so the private key never leaves the host.
//! * [`authn`]: because NATS does not (yet) bind an agent to its subjects, every
//!   request and report carries a signature made with the agent's identity key.
//!
//! The interface is small on purpose: if the effort of owning a CA grows, the
//! same operations can be implemented on top of OpenSSL behind this API.

pub mod authn;
pub mod bundle;

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    PKCS_ED25519, PublicKeyData, SanType, SigningKey, string::Ia5String,
};
use time::{Duration, OffsetDateTime};

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

pub struct Ca {
    cert_pem: String,
    key_pem: String,
}

fn validity(params: &mut CertificateParams, days: i64) {
    let now = OffsetDateTime::now_utc();
    // A little backdating tolerates small clock differences between hosts.
    params.not_before = now - Duration::minutes(5);
    params.not_after = now + Duration::days(days);
}

impl Ca {
    pub fn create(common_name: &str, valid_days: i64) -> Result<Self, PkiError> {
        let key = KeyPair::generate_for(&PKCS_ED25519)?;
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        validity(&mut params, valid_days);
        let cert = params.self_signed(&key)?;
        Ok(Ca { cert_pem: cert.pem(), key_pem: key.serialize_pem() })
    }

    /// Load an existing CA; fails if the certificate and key cannot be used as an issuer.
    pub fn load(cert_pem: &str, key_pem: &str) -> Result<Self, PkiError> {
        let ca = Ca { cert_pem: cert_pem.to_owned(), key_pem: key_pem.to_owned() };
        ca.issuer()?;
        Ok(ca)
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }

    fn issuer(&self) -> Result<Issuer<'static, KeyPair>, PkiError> {
        let key = KeyPair::from_pem(&self.key_pem)?;
        Ok(Issuer::from_ca_cert_pem(&self.cert_pem, key)?)
    }

    /// Server certificate (TLS server authentication) for the given DNS names.
    pub fn issue_server(&self, common_name: &str, dns_names: &[String], valid_days: i64) -> Result<Issued, PkiError> {
        let key = KeyPair::generate_for(&PKCS_ED25519)?;
        let mut params = CertificateParams::new(dns_names.to_vec())?;
        params.distinguished_name.push(DnType::CommonName, common_name);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.use_authority_key_identifier_extension = true; // strict verifiers (Python 3.13, ...) require it
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        validity(&mut params, valid_days);
        let cert = params.signed_by(&key, &self.issuer()?)?;
        Ok(Issued { cert_pem: cert.pem(), key_pem: key.serialize_pem() })
    }

    /// Client certificate for a component that holds its own key (e.g. the Core).
    pub fn issue_client(&self, common_name: &str, uri: &str, valid_days: i64) -> Result<Issued, PkiError> {
        let key = KeyPair::generate_for(&PKCS_ED25519)?;
        let params = client_params(common_name, uri, valid_days)?;
        let cert = params.signed_by(&key, &self.issuer()?)?;
        Ok(Issued { cert_pem: cert.pem(), key_pem: key.serialize_pem() })
    }

    /// Sign an agent's CSR. The subject and URI are chosen by the Core: whatever the CSR
    /// asks for is ignored, only its public key (proven by the CSR signature) is used.
    pub fn sign_csr(&self, csr_pem: &str, common_name: &str, uri: &str, valid_days: i64) -> Result<SignedCsr, PkiError> {
        let csr = CertificateSigningRequestParams::from_pem(csr_pem)?; // verifies the CSR signature
        if csr.public_key.algorithm() != &PKCS_ED25519 {
            return Err(PkiError::UnsupportedKey);
        }
        let params = client_params(common_name, uri, valid_days)?;
        let cert = params.signed_by(&csr.public_key, &self.issuer()?)?;
        Ok(SignedCsr { cert_pem: cert.pem(), public_key: csr.public_key.der_bytes().to_vec() })
    }

    /// Sign a proxy's CSR. The certificate serves both ways: as the proxy's identity towards the
    /// Core (client authentication, URI `urn:delbert:component:proxy:<site>`) and as the server
    /// certificate of the HTTPS endpoint and NATS server of its site (the given DNS names).
    pub fn sign_proxy_csr(&self, csr_pem: &str, site: &str, dns_names: &[String], valid_days: i64) -> Result<SignedCsr, PkiError> {
        let csr = CertificateSigningRequestParams::from_pem(csr_pem)?;
        if csr.public_key.algorithm() != &PKCS_ED25519 {
            return Err(PkiError::UnsupportedKey);
        }
        let mut params = client_params(&format!("proxy-{site}"), &format!("urn:delbert:component:proxy:{site}"), valid_days)?;
        for dns in dns_names {
            params.subject_alt_names.push(SanType::DnsName(Ia5String::try_from(dns.clone()).map_err(|e| PkiError::Invalid(e.to_string()))?));
        }
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth, ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.signed_by(&csr.public_key, &self.issuer()?)?;
        Ok(SignedCsr { cert_pem: cert.pem(), public_key: csr.public_key.der_bytes().to_vec() })
    }
}

fn client_params(common_name: &str, uri: &str, valid_days: i64) -> Result<CertificateParams, PkiError> {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, common_name);
    params.subject_alt_names = vec![SanType::URI(Ia5String::try_from(uri.to_owned()).map_err(|e| PkiError::Invalid(e.to_string()))?)];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.use_authority_key_identifier_extension = true;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    validity(&mut params, valid_days);
    Ok(params)
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

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::*;

    fn parse(pem: &str) -> Vec<u8> {
        ::x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap().1.contents
    }

    #[test]
    fn csr_flow_issues_a_certificate_the_ca_signed() {
        let ca = Ca::create("Delbert test CA", 365).unwrap();
        let (key_pem, csr_pem) = new_identity("whatever-the-agent-says").unwrap();
        let signed = ca.sign_csr(&csr_pem, "agent-1", &agent_uri("acme", "agent-1"), 30).unwrap();

        let der = parse(&signed.cert_pem);
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        // The Core decides the subject, not the CSR.
        assert_eq!(cert.subject().to_string(), "CN=agent-1");
        let san = cert.subject_alternative_name().unwrap().unwrap();
        assert!(matches!(&san.value.general_names[0], GeneralName::URI(u) if *u == "urn:delbert:agent:acme:agent-1"));
        let eku = cert.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.client_auth && !eku.server_auth);
        assert!(cert.get_extension_unique(&oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER).unwrap().is_some(), "AKI present");
        assert!(!cert.is_ca());

        let ca_der = parse(ca.cert_pem());
        let (_, ca_cert) = X509Certificate::from_der(&ca_der).unwrap();
        cert.verify_signature(Some(ca_cert.public_key())).expect("signed by the CA");
        assert!(ca_cert.is_ca());

        // The certified public key is the one that verifies the agent's signatures.
        let sig = sign(&key_pem, b"hello").unwrap();
        assert!(verify(&signed.public_key, b"hello", &sig));
        assert!(!verify(&signed.public_key, b"hellO", &sig));
    }

    #[test]
    fn identities_and_validity_are_read_back_from_certificates() {
        let ca = Ca::create("CA", 365).unwrap();
        let (_, csr) = new_identity("a").unwrap();
        let signed = ca.sign_csr(&csr, "agent-1", &agent_uri("acme", "agent-1"), 30).unwrap();
        assert_eq!(
            identity_from_pem(&signed.cert_pem).unwrap(),
            CertIdentity::Agent { tenant: "acme".into(), agent: "agent-1".into(), public_key: signed.public_key.clone() }
        );
        let (from, to) = cert_validity(&signed.cert_pem).unwrap();
        let now = ::time::OffsetDateTime::now_utc().unix_timestamp();
        assert!(from <= now && (to - now - 30 * 86_400).abs() < 60);

        let core = ca.issue_client("core-nats", "urn:delbert:component:core-nats", 30).unwrap();
        assert_eq!(identity_from_pem(&core.cert_pem).unwrap(), CertIdentity::Component { name: "core-nats".into() });
        // A server certificate carries no Delbert identity; garbage is an error, not a panic.
        let server = ca.issue_server("nats", &["nats".into()], 30).unwrap();
        assert!(identity_from_pem(&server.cert_pem).is_err() && identity_from_pem("garbage").is_err());
    }

    #[test]
    fn broken_or_foreign_csrs_are_refused() {
        let ca = Ca::create("CA", 365).unwrap();
        let (_, csr_pem) = new_identity("a").unwrap();
        // Flip a byte inside the base64 body: the proof of possession breaks.
        let mut bad = csr_pem.clone().into_bytes();
        let i = bad.iter().position(|b| *b == b'\n').unwrap() + 20;
        bad[i] = if bad[i] == b'A' { b'B' } else { b'A' };
        assert!(ca.sign_csr(&String::from_utf8(bad).unwrap(), "x", "urn:x", 1).is_err());
        assert!(ca.sign_csr("not a csr", "x", "urn:x", 1).is_err());

        let ecdsa = KeyPair::generate().unwrap(); // default algorithm is ECDSA P-256
        let csr = CertificateParams::default().serialize_request(&ecdsa).unwrap().pem().unwrap();
        assert!(matches!(ca.sign_csr(&csr, "x", "urn:x", 1), Err(PkiError::UnsupportedKey)));
    }

    #[test]
    fn ca_can_be_reloaded_and_issues_server_certs() {
        let ca = Ca::create("CA", 365).unwrap();
        let again = Ca::load(ca.cert_pem(), ca.key_pem()).unwrap();
        let server = again.issue_server("nats", &["nats".into(), "localhost".into()], 30).unwrap();
        let der = parse(&server.cert_pem);
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        assert!(cert.extended_key_usage().unwrap().unwrap().value.server_auth);
        assert!(cert.get_extension_unique(&oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER).unwrap().is_some(), "AKI present");
    }
}
