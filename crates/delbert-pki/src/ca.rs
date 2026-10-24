//! The certificate authority behind a trait (docs/ABSTRACT.md §4).
//!
//! The Core issues three kinds of certificates and needs nothing else from a CA: agent
//! certificates from a CSR, proxy certificates from a CSR, and (for the `delbert-pki` tool)
//! certificates of infrastructure components. Everything is Ed25519 and path length 0: the CA
//! never issues another CA.
//!
//! Backends:
//!
//! | Name | Implementation | State |
//! |------|----------------|-------|
//! | `rcgen` | [`crate::RcgenCa`], pure Rust (rcgen on ring) | the default, used everywhere |
//! | `openssl` | not written | would go through the `openssl` crate and add a system dependency; the trait and [`conformance`] are the whole contract |
//!
//! To add a backend: implement [`CertificateAuthority`], add an arm to [`load_backend`] and make
//! `conformance::check` pass in its tests (see `rcgen_ca.rs` for how).

use std::sync::Arc;

use crate::{Issued, PkiError, SignedCsr};

/// What the Core needs from a certificate authority.
pub trait CertificateAuthority: Send + Sync {
    /// The CA certificate (PEM) that clients are given to trust.
    fn cert_pem(&self) -> &str;

    /// Server certificate (TLS server authentication) for the given DNS names; the key is generated here.
    fn issue_server(&self, common_name: &str, dns_names: &[String], valid_days: i64) -> Result<Issued, PkiError>;

    /// Client certificate for a component that holds no CSR flow (the Core itself); the key is generated here.
    fn issue_client(&self, common_name: &str, uri: &str, valid_days: i64) -> Result<Issued, PkiError>;

    /// Sign an agent's CSR. Subject and URI are chosen by the caller: whatever the CSR asks for is
    /// ignored, only its public key (proven by the CSR signature) is used. Non-Ed25519 keys are
    /// refused with [`PkiError::UnsupportedKey`].
    fn sign_csr(&self, csr_pem: &str, common_name: &str, uri: &str, valid_days: i64) -> Result<SignedCsr, PkiError>;

    /// Sign a proxy's CSR. The certificate serves both ways: client authentication towards the Core
    /// (URI `urn:delbert:component:proxy:<site>`) and server authentication for the given DNS names.
    fn sign_proxy_csr(&self, csr_pem: &str, site: &str, dns_names: &[String], valid_days: i64) -> Result<SignedCsr, PkiError>;
}

/// Backends this build knows, for messages and configuration checks.
pub const BACKENDS: &[&str] = &["rcgen"];

/// Open the CA of the named backend from its certificate and key (PEM).
pub fn load_backend(name: &str, cert_pem: &str, key_pem: &str) -> Result<Arc<dyn CertificateAuthority>, PkiError> {
    match name {
        "rcgen" => Ok(Arc::new(crate::RcgenCa::load(cert_pem, key_pem)?)),
        other => Err(PkiError::Invalid(format!("unknown CA backend '{other}' (available: {})", BACKENDS.join(", ")))),
    }
}

/// The checklist a backend must pass: run [`check`] on a freshly created CA in the backend's tests.
pub mod conformance {
    use x509_parser::{oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER, prelude::*};

    use super::CertificateAuthority;
    use crate::{CertIdentity, PkiError, agent_uri, cert_validity, identity_from_pem, new_identity, sign, verify};

    fn der(pem: &str) -> Vec<u8> {
        x509_parser::pem::parse_x509_pem(pem.as_bytes()).expect("PEM").1.contents
    }

    /// Panics, naming the broken rule, when `ca` does not behave as the Core expects.
    pub fn check(ca: &dyn CertificateAuthority) {
        let ca_der = der(ca.cert_pem());
        let (_, ca_cert) = X509Certificate::from_der(&ca_der).expect("CA certificate");
        assert!(ca_cert.is_ca(), "the CA certificate must be a CA");
        let now = ::time::OffsetDateTime::now_utc().unix_timestamp();

        // --- agent certificate from a CSR ------------------------------------------------------
        let (key_pem, csr_pem) = new_identity("whatever-the-agent-says").unwrap();
        let signed = ca.sign_csr(&csr_pem, "agent-1", &agent_uri("acme", "agent-1"), 30).unwrap();
        let cert_der = der(&signed.cert_pem);
        let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();
        assert_eq!(cert.subject().to_string(), "CN=agent-1", "the caller decides the subject, not the CSR");
        let san = cert.subject_alternative_name().unwrap().unwrap();
        assert!(matches!(&san.value.general_names[0], GeneralName::URI(u) if *u == "urn:delbert:agent:acme:agent-1"), "identity URI");
        let eku = cert.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.client_auth && !eku.server_auth, "an agent certificate is for client authentication only");
        assert!(cert.get_extension_unique(&OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER).unwrap().is_some(), "authority key identifier (strict verifiers need it)");
        assert!(!cert.is_ca(), "a leaf certificate");
        cert.verify_signature(Some(ca_cert.public_key())).expect("signed by the CA");
        assert!(verify(&signed.public_key, b"hello", &sign(&key_pem, b"hello").unwrap()), "the certified key is the CSR's key");
        assert_eq!(identity_from_pem(&signed.cert_pem).unwrap(), CertIdentity::Agent { tenant: "acme".into(), agent: "agent-1".into(), public_key: signed.public_key.clone() });
        let (from, to) = cert_validity(&signed.cert_pem).unwrap();
        assert!(from <= now && (to - now - 30 * 86_400).abs() < 60, "valid for the requested days, backdated at most a few minutes");
        assert!(crate::bundle::issuer_of(&signed.cert_pem, ca.cert_pem()).is_some(), "the issuer is found in the CA bundle");

        // --- proxy certificate -----------------------------------------------------------------
        let (_, proxy_csr) = new_identity("branch").unwrap();
        let proxy = ca.sign_proxy_csr(&proxy_csr, "branch-a", &["proxy".into(), "nats-site".into()], 30).unwrap();
        assert_eq!(identity_from_pem(&proxy.cert_pem).unwrap(), CertIdentity::Component { name: "proxy:branch-a".into() });
        let proxy_der = der(&proxy.cert_pem);
        let (_, proxy_cert) = X509Certificate::from_der(&proxy_der).unwrap();
        let eku = proxy_cert.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.client_auth && eku.server_auth, "a proxy certificate serves both ways");
        let names: Vec<String> = proxy_cert.subject_alternative_name().unwrap().unwrap().value.general_names.iter().filter_map(|n| if let GeneralName::DNSName(d) = n { Some(d.to_string()) } else { None }).collect();
        assert_eq!(names, ["proxy", "nats-site"], "the DNS names the proxy will be reached by");
        proxy_cert.verify_signature(Some(ca_cert.public_key())).expect("proxy certificate signed by the CA");

        // --- certificates of components --------------------------------------------------------
        let core = ca.issue_client("core-nats", "urn:delbert:component:core-nats", 30).unwrap();
        assert_eq!(identity_from_pem(&core.cert_pem).unwrap(), CertIdentity::Component { name: "core-nats".into() });
        let server = ca.issue_server("nats", &["nats".into(), "localhost".into()], 30).unwrap();
        let server_der = der(&server.cert_pem);
        let (_, server_cert) = X509Certificate::from_der(&server_der).unwrap();
        assert!(server_cert.extended_key_usage().unwrap().unwrap().value.server_auth, "server authentication");
        assert!(server_cert.get_extension_unique(&OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER).unwrap().is_some(), "authority key identifier");
        assert!(identity_from_pem(&server.cert_pem).is_err() && identity_from_pem("garbage").is_err(), "a server certificate carries no Delbert identity; garbage is an error, not a panic");

        // --- what must be refused --------------------------------------------------------------
        let mut broken = csr_pem.clone().into_bytes();
        let i = broken.iter().position(|b| *b == b'\n').unwrap() + 20;
        broken[i] = if broken[i] == b'A' { b'B' } else { b'A' };
        assert!(ca.sign_csr(&String::from_utf8(broken).unwrap(), "x", "urn:x", 1).is_err(), "a CSR whose signature does not verify");
        assert!(ca.sign_csr("not a csr", "x", "urn:x", 1).is_err(), "garbage");
        let ecdsa = rcgen::KeyPair::generate().unwrap(); // ECDSA P-256
        let foreign = rcgen::CertificateParams::default().serialize_request(&ecdsa).unwrap().pem().unwrap();
        assert!(matches!(ca.sign_csr(&foreign, "x", "urn:x", 1), Err(PkiError::UnsupportedKey)), "only Ed25519 keys");
        assert!(matches!(ca.sign_proxy_csr(&foreign, "s", &[], 1), Err(PkiError::UnsupportedKey)), "only Ed25519 keys (proxy)");
    }
}
