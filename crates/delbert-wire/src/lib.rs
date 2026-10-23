//! Delbert wire format (docs/ABSTRACT.md §3).
//!
//! The Core compiles authoring YAML into a per-endpoint [`EffectivePolicy`],
//! serializes it with JCS (RFC 8785) and signs it as a JWS (EdDSA, RFC 7515/8037).
//! Agents call [`Verifier::verify`] before acting on anything.

pub mod canonical;
pub mod jws;
pub mod model;
pub mod trust;

pub use jws::{Expect, Signer, VerifyError, Verifier};
pub use trust::{TrustUpdate, TrustedKey};
pub use model::{ArtifactRef, EffectivePolicy, SCHEMA};
