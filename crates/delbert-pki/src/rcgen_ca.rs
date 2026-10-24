//! The `rcgen` backend of [`crate::CertificateAuthority`]: pure Rust (rcgen on ring), no OpenSSL.

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    PKCS_ED25519, PublicKeyData, SanType, string::Ia5String,
};
use time::{Duration, OffsetDateTime};

use crate::{CertificateAuthority, Issued, PkiError, SignedCsr};

/// A CA that only issues leaf certificates (path length 0), kept as PEM.
pub struct RcgenCa {
    cert_pem: String,
    key_pem: String,
}

fn validity(params: &mut CertificateParams, days: i64) {
    let now = OffsetDateTime::now_utc();
    // A little backdating tolerates small clock differences between hosts.
    params.not_before = now - Duration::minutes(5);
    params.not_after = now + Duration::days(days);
}

impl RcgenCa {
    pub fn create(common_name: &str, valid_days: i64) -> Result<Self, PkiError> {
        let key = KeyPair::generate_for(&PKCS_ED25519)?;
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        validity(&mut params, valid_days);
        let cert = params.self_signed(&key)?;
        Ok(RcgenCa { cert_pem: cert.pem(), key_pem: key.serialize_pem() })
    }

    /// Load an existing CA; fails if the certificate and key cannot be used as an issuer.
    pub fn load(cert_pem: &str, key_pem: &str) -> Result<Self, PkiError> {
        let ca = RcgenCa { cert_pem: cert_pem.to_owned(), key_pem: key_pem.to_owned() };
        ca.issuer()?;
        Ok(ca)
    }

    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }

    fn issuer(&self) -> Result<Issuer<'static, KeyPair>, PkiError> {
        let key = KeyPair::from_pem(&self.key_pem)?;
        Ok(Issuer::from_ca_cert_pem(&self.cert_pem, key)?)
    }
}

impl CertificateAuthority for RcgenCa {
    fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    fn issue_server(&self, common_name: &str, dns_names: &[String], valid_days: i64) -> Result<Issued, PkiError> {
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

    fn issue_client(&self, common_name: &str, uri: &str, valid_days: i64) -> Result<Issued, PkiError> {
        let key = KeyPair::generate_for(&PKCS_ED25519)?;
        let params = client_params(common_name, uri, valid_days)?;
        let cert = params.signed_by(&key, &self.issuer()?)?;
        Ok(Issued { cert_pem: cert.pem(), key_pem: key.serialize_pem() })
    }

    fn sign_csr(&self, csr_pem: &str, common_name: &str, uri: &str, valid_days: i64) -> Result<SignedCsr, PkiError> {
        let csr = CertificateSigningRequestParams::from_pem(csr_pem)?; // verifies the CSR signature
        if csr.public_key.algorithm() != &PKCS_ED25519 {
            return Err(PkiError::UnsupportedKey);
        }
        let params = client_params(common_name, uri, valid_days)?;
        let cert = params.signed_by(&csr.public_key, &self.issuer()?)?;
        Ok(SignedCsr { cert_pem: cert.pem(), public_key: csr.public_key.der_bytes().to_vec() })
    }

    fn sign_proxy_csr(&self, csr_pem: &str, site: &str, dns_names: &[String], valid_days: i64) -> Result<SignedCsr, PkiError> {
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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rcgen_backend_passes_the_conformance_suite() {
        crate::ca::conformance::check(&RcgenCa::create("Delbert test CA", 365).unwrap());
    }

    #[test]
    fn a_ca_can_be_reloaded_and_the_backend_is_chosen_by_name() {
        let ca = RcgenCa::create("CA", 365).unwrap();
        let again = crate::load_backend("rcgen", ca.cert_pem(), ca.key_pem()).unwrap();
        crate::ca::conformance::check(again.as_ref());
        let err = crate::load_backend("openssl", ca.cert_pem(), ca.key_pem()).err().expect("not built").to_string();
        assert!(err.contains("unknown CA backend 'openssl'") && err.contains("rcgen"), "{err}");
        assert!(crate::load_backend("rcgen", "junk", ca.key_pem()).is_err(), "not a certificate");
    }

    /// A backend that wrongly lets the CSR decide the identity: the suite must notice.
    struct Careless(RcgenCa);
    impl CertificateAuthority for Careless {
        fn cert_pem(&self) -> &str {
            self.0.cert_pem()
        }
        fn issue_server(&self, cn: &str, dns: &[String], days: i64) -> Result<Issued, PkiError> {
            self.0.issue_server(cn, dns, days)
        }
        fn issue_client(&self, cn: &str, uri: &str, days: i64) -> Result<Issued, PkiError> {
            self.0.issue_client(cn, uri, days)
        }
        fn sign_csr(&self, csr: &str, _cn: &str, _uri: &str, days: i64) -> Result<SignedCsr, PkiError> {
            self.0.sign_csr(csr, "someone-else", "urn:delbert:agent:other:other", days)
        }
        fn sign_proxy_csr(&self, csr: &str, site: &str, dns: &[String], days: i64) -> Result<SignedCsr, PkiError> {
            self.0.sign_proxy_csr(csr, site, dns, days)
        }
    }

    #[test]
    #[should_panic(expected = "the caller decides the subject")]
    fn the_conformance_suite_catches_a_backend_that_lets_the_csr_decide() {
        crate::ca::conformance::check(&Careless(RcgenCa::create("CA", 365).unwrap()));
    }
}
