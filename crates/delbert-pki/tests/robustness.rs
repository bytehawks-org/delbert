//! Certificates and CSRs arrive from the network (enrollment, renewal, the NATS callout): mutated
//! or garbage input must be refused, never panic, and a CSR must never obtain an identity of its
//! own choosing (docs/SECURITY-REVIEW.md F-10).

use delbert_pki::{CertificateAuthority, RcgenCa, identity_from_pem, new_identity, public_key_from_pem};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn mutate(rng: &mut Rng, text: &str) -> String {
    let mut bytes = text.as_bytes().to_vec();
    for _ in 0..=(rng.next() % 5) {
        if bytes.is_empty() {
            break;
        }
        let at = (rng.next() as usize) % bytes.len();
        match rng.next() % 4 {
            0 => bytes[at] = rng.next() as u8,
            1 => bytes.truncate(at.max(1)),
            2 => {
                bytes.remove(at);
            }
            _ => bytes.insert(at, b"A+/=\n- "[(rng.next() as usize) % 7]),
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

#[test]
fn mutated_csrs_and_certificates_never_panic() {
    let ca = RcgenCa::create("Test CA", 30).unwrap();
    let (_, csr) = new_identity("agent-1").unwrap();
    let signed = ca.sign_csr(&csr, "agent-1", &delbert_pki::agent_uri("acme", "agent-1"), 30).unwrap();
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let (mut csr_ok, mut cert_ok) = (0, 0);
    for _ in 0..2_000 {
        if ca.sign_csr(&mutate(&mut rng, &csr), "agent-1", &delbert_pki::agent_uri("acme", "agent-1"), 30).is_ok() {
            csr_ok += 1;
        }
        let cert = mutate(&mut rng, &signed.cert_pem);
        if identity_from_pem(&cert).is_ok() {
            cert_ok += 1;
        }
        let _ = public_key_from_pem(&cert);
        let _ = delbert_pki::cert_validity(&cert);
    }
    // A mutation can land in a PEM line ending or padding and leave the document valid; that is fine.
    eprintln!("mutated CSRs signed: {csr_ok}, certificates still parsed: {cert_ok}");
    for garbage in ["", "-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----", "\u{0}\u{0}", &"A".repeat(1_000_000)] {
        assert!(identity_from_pem(garbage).is_err(), "{garbage:.40}");
        assert!(ca.sign_csr(garbage, "a", "urn:x", 1).is_err());
    }
}

#[test]
fn a_csr_cannot_choose_its_own_identity() {
    let ca = RcgenCa::create("Test CA", 30).unwrap();
    // The agent names itself "core-nats" (a component with full bus permissions) in its CSR...
    let (_, csr) = new_identity("core-nats").unwrap();
    let signed = ca.sign_csr(&csr, "agent-1", &delbert_pki::agent_uri("acme", "agent-1"), 30).unwrap();
    // ...but the certificate carries the identity the Core chose, not the one in the CSR.
    match identity_from_pem(&signed.cert_pem).unwrap() {
        delbert_pki::CertIdentity::Agent { tenant, agent, .. } => assert_eq!((tenant.as_str(), agent.as_str()), ("acme", "agent-1")),
        other => panic!("unexpected identity {other:?}"),
    }
}
