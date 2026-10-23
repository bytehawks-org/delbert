//! TOTP (RFC 6238, HMAC-SHA1, 6 digits, 30 s) and recovery codes.
//!
//! SHA-1 is what authenticator apps universally support; it is safe inside HMAC.

use hmac::{Hmac, Mac};
use sha1::Sha1;

const STEP_SECS: i64 = 30;
const DIGITS: u32 = 1_000_000;

pub fn secret_to_base32(secret: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(secret)
}

pub fn uri(issuer: &str, account: &str, secret: &[u8]) -> String {
    format!("otpauth://totp/{issuer}:{account}?secret={}&issuer={issuer}&algorithm=SHA1&digits=6&period=30", secret_to_base32(secret))
}

fn code_at(secret: &[u8], step: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(&step.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let o = (h[19] & 0x0f) as usize;
    let n = u32::from_be_bytes([h[o] & 0x7f, h[o + 1], h[o + 2], h[o + 3]]);
    n % DIGITS
}

/// The current code (for tests and tooling).
pub fn generate(secret: &[u8], now: i64) -> String {
    format!("{:06}", code_at(secret, (now / STEP_SECS) as u64))
}

/// The 30-second step a code belongs to, accepting one step of clock drift either way, but only
/// steps after `last_step` (a code can be used once). `None` when the code does not match.
pub fn verify(secret: &[u8], code: &str, now: i64, last_step: i64) -> Option<i64> {
    let code = code.trim();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let want: u32 = code.parse().ok()?;
    let current = now / STEP_SECS;
    (current - 1..=current + 1).filter(|s| *s > last_step).find(|s| code_at(secret, *s as u64) == want)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 appendix B, SHA-1 secret "12345678901234567890" (8 digits there; we keep the last 6).
    #[test]
    fn rfc_6238_vectors() {
        let secret = b"12345678901234567890";
        assert_eq!(code_at(secret, 59 / 30), 287082);
        assert_eq!(code_at(secret, 1111111109 / 30), 81804);
        assert_eq!(code_at(secret, 2000000000 / 30), 279037);
    }

    #[test]
    fn drift_replay_and_garbage() {
        let secret = b"12345678901234567890";
        let now = 1111111109;
        let code = format!("{:06}", code_at(secret, (now / 30) as u64));
        assert_eq!(verify(secret, &code, now, 0), Some(now / 30));
        assert_eq!(verify(secret, &code, now + 30, 0), Some(now / 30)); // one step late
        assert_eq!(verify(secret, &code, now + 90, 0), None); // too old
        assert_eq!(verify(secret, &code, now, now / 30), None); // replay
        assert_eq!(verify(secret, "12345", now, 0), None);
        assert_eq!(verify(secret, "abcdef", now, 0), None);
    }
}
