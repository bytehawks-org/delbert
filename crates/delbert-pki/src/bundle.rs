//! CA bundles (several CA certificates in one PEM file) for rotating the internal CA with overlap
//! (docs/ROTATION.md). Components trust every CA in their bundle; the Core issues from one of them.

use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

/// DER of each certificate in a PEM bundle.
fn ders(bundle: &str) -> Vec<Vec<u8>> {
    x509_parser::pem::Pem::iter_from_buffer(bundle.as_bytes()).filter_map(Result::ok).filter(|p| p.label == "CERTIFICATE").map(|p| p.contents).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// SHA-256 fingerprints (hex) of the certificates in a bundle, in order.
pub fn fingerprints(bundle: &str) -> Vec<String> {
    ders(bundle).iter().map(|d| hex(&Sha256::digest(d))).collect()
}

/// The certificates of a bundle as separate PEM strings.
pub fn split(bundle: &str) -> Vec<String> {
    ders(bundle).iter().map(|d| pem(d)).collect()
}

/// Is this a single, self-signed CA certificate that is currently valid or about to be?
pub fn is_ca_certificate(pem: &str) -> bool {
    let all = ders(pem);
    let [der] = all.as_slice() else { return false };
    let Ok((_, cert)) = X509Certificate::from_der(der) else { return false };
    cert.is_ca() && cert.verify_signature(None).is_ok()
}

/// The fingerprint of the CA in `bundle` that signed `cert_pem`, if any.
pub fn issuer_of(cert_pem: &str, bundle: &str) -> Option<String> {
    let cert_der = ders(cert_pem).into_iter().next()?;
    let (_, cert) = X509Certificate::from_der(&cert_der).ok()?;
    ders(bundle).into_iter().find_map(|ca_der| {
        let (_, ca) = X509Certificate::from_der(&ca_der).ok()?;
        cert.verify_signature(Some(ca.public_key())).ok().map(|_| hex(&Sha256::digest(&ca_der)))
    })
}

/// Apply an announced change to a bundle: add CA certificates (PEM), remove by fingerprint.
/// Fail closed: every added certificate must be a CA certificate, and the bundle never ends up empty.
/// Returns the new bundle when something changed.
pub fn apply(bundle: &str, add: &[String], remove: &[String]) -> Result<Option<String>, String> {
    let mut certs: Vec<(String, String)> = x509_parser::pem::Pem::iter_from_buffer(bundle.as_bytes())
        .filter_map(Result::ok)
        .filter(|p| p.label == "CERTIFICATE")
        .map(|p| (hex(&Sha256::digest(&p.contents)), pem(&p.contents)))
        .collect();
    let mut changed = false;
    for ca in add {
        if !is_ca_certificate(ca) {
            return Err("an announced CA is not a valid self-signed CA certificate".into());
        }
        let fp = fingerprints(ca).remove(0);
        if !certs.iter().any(|(f, _)| *f == fp) {
            certs.push((fp, ca.trim().to_owned()));
            changed = true;
        }
    }
    let before = certs.len();
    certs.retain(|(f, _)| !remove.contains(f));
    changed |= certs.len() != before;
    if certs.is_empty() {
        return Err("an update would leave no trusted CA".into());
    }
    Ok(changed.then(|| certs.iter().map(|(_, p)| format!("{}\n", p.trim())).collect()))
}

fn pem(der: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let b64 = STANDARD.encode(der);
    let lines: Vec<&str> = b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).expect("base64 is ASCII")).collect();
    format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----", lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Ca;

    #[test]
    fn rotation_with_overlap() {
        let (ca1, ca2) = (Ca::create("CA one", 30).unwrap(), Ca::create("CA two", 30).unwrap());
        let (fp1, fp2) = (fingerprints(ca1.cert_pem()).remove(0), fingerprints(ca2.cert_pem()).remove(0));
        assert_ne!(fp1, fp2);
        let leaf1 = ca1.issue_server("core", &["core".into()], 30).unwrap().cert_pem;
        let leaf2 = ca2.issue_server("core", &["core".into()], 30).unwrap().cert_pem;

        let bundle = apply(ca1.cert_pem(), &[ca2.cert_pem().to_owned()], &[]).unwrap().unwrap();
        assert_eq!(fingerprints(&bundle), [fp1.clone(), fp2.clone()]);
        assert_eq!(apply(&bundle, &[ca2.cert_pem().to_owned()], &[]).unwrap(), None, "idempotent");
        assert_eq!((issuer_of(&leaf1, &bundle), issuer_of(&leaf2, &bundle)), (Some(fp1.clone()), Some(fp2.clone())));
        assert_eq!(issuer_of(&leaf2, ca1.cert_pem()), None);

        let only2 = apply(&bundle, &[], &[fp1.clone()]).unwrap().unwrap();
        assert_eq!(fingerprints(&only2), [fp2.clone()]);
        assert!(apply(&only2, &[], &[fp2]).unwrap_err().contains("no trusted CA"));
    }

    #[test]
    fn only_ca_certificates_are_accepted() {
        let ca = Ca::create("CA", 30).unwrap();
        let leaf = ca.issue_server("core", &["core".into()], 30).unwrap().cert_pem;
        assert!(is_ca_certificate(ca.cert_pem()));
        assert!(!is_ca_certificate(&leaf), "a leaf is not a CA");
        assert!(!is_ca_certificate("garbage"));
        assert!(!is_ca_certificate(&format!("{}{}", ca.cert_pem(), ca.cert_pem())), "one certificate at a time");
        assert!(apply(ca.cert_pem(), &[leaf], &[]).is_err());
    }
}
