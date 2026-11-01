//! Pure translation of a resolved [`Bundle`] into a `ConfigMap`, a `Secret` and a content hash.
//!
//! No I/O here, so the rules (key validity, no collisions, sensitive values never in the
//! `ConfigMap`, hash that does not leak secrets) are unit-tested without a cluster.

use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::{ConfigMap, Secret};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::crd::DelbertBindingSpec;

/// Annotation carrying the keyed content hash (also put on workloads' pod templates).
pub const HASH_ANNOTATION: &str = "delbert.bytehawks.io/content-hash";
/// Annotation carrying the Core bundle version.
pub const VERSION_ANNOTATION: &str = "delbert.bytehawks.io/version";
const MANAGED_BY: (&str, &str) = ("app.kubernetes.io/managed-by", "delbert-operator");
/// Kubernetes limit for ConfigMap/Secret keys.
const MAX_KEY_LEN: usize = 253;

/// What the Core resolved for one tenant/environment (layered variables already merged).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Bundle {
    /// Monotonic version assigned by the Core.
    pub version: i64,
    /// Plain variables, delivered as `ConfigMap` entries (usable with `envFrom`).
    #[serde(default)]
    pub variables: BTreeMap<String, String>,
    /// Non-sensitive files: key is the file name inside the volume.
    #[serde(default)]
    pub files: BTreeMap<String, String>,
    /// Sensitive values, delivered only through the `Secret`.
    #[serde(default)]
    pub sensitive: BTreeMap<String, String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RenderError {
    #[error("invalid key {0:?}: use 1-253 characters from [-._a-zA-Z0-9], not '.' or '..'")]
    InvalidKey(String),
    #[error("key {0:?} is defined more than once across variables, files and sensitive values")]
    DuplicateKey(String),
    #[error("the hash key must not be empty")]
    EmptyHashKey,
}

/// The objects to apply and the hash that tells whether anything changed.
#[derive(Clone, Debug)]
pub struct Rendered {
    pub config_map: ConfigMap,
    pub secret: Secret,
    /// Hex HMAC-SHA256 over the whole bundle content (version excluded).
    pub content_hash: String,
}

fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= MAX_KEY_LEN
        && key != "."
        && key != ".."
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Keyed hash: the value is published on workloads (readable by whoever can read a Deployment),
/// so a plain hash of low-entropy secrets could be brute-forced. The key stays in the Operator.
fn content_hash(bundle: &Bundle, hash_key: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(hash_key).expect("HMAC accepts any key length");
    // BTreeMap keeps the serialization deterministic; the version is excluded on purpose, so a
    // republished identical bundle does not restart workloads.
    let content = (&bundle.variables, &bundle.files, &bundle.sensitive);
    mac.update(&serde_json::to_vec(&content).expect("string maps always serialize"));
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Build the `ConfigMap` and `Secret` for `bundle`. Names come from `spec`; the caller sets the
/// namespace and the owner reference when applying.
pub fn render(
    spec: &DelbertBindingSpec,
    bundle: &Bundle,
    hash_key: &[u8],
) -> Result<Rendered, RenderError> {
    if hash_key.is_empty() {
        return Err(RenderError::EmptyHashKey);
    }
    let mut seen = std::collections::BTreeSet::new();
    for key in bundle
        .variables
        .keys()
        .chain(bundle.files.keys())
        .chain(bundle.sensitive.keys())
    {
        if !valid_key(key) {
            return Err(RenderError::InvalidKey(key.clone()));
        }
        if !seen.insert(key.as_str()) {
            return Err(RenderError::DuplicateKey(key.clone()));
        }
    }

    let hash = content_hash(bundle, hash_key);
    let meta = |name: &str| ObjectMeta {
        name: Some(name.to_owned()),
        labels: Some(BTreeMap::from([(
            MANAGED_BY.0.to_owned(),
            MANAGED_BY.1.to_owned(),
        )])),
        annotations: Some(BTreeMap::from([
            (HASH_ANNOTATION.to_owned(), hash.clone()),
            (VERSION_ANNOTATION.to_owned(), bundle.version.to_string()),
        ])),
        ..ObjectMeta::default()
    };

    let config_map = ConfigMap {
        metadata: meta(spec.config_map_name()),
        data: Some(
            bundle
                .variables
                .iter()
                .chain(&bundle.files)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        ),
        ..ConfigMap::default()
    };
    let secret = Secret {
        metadata: meta(spec.secret_name()),
        type_: Some("Opaque".to_owned()),
        data: Some(
            bundle
                .sensitive
                .iter()
                .map(|(k, v)| (k.clone(), ByteString(v.clone().into_bytes())))
                .collect(),
        ),
        ..Secret::default()
    };
    Ok(Rendered {
        config_map,
        secret,
        content_hash: hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> DelbertBindingSpec {
        DelbertBindingSpec {
            tenant: "acme".into(),
            environment: "prod".into(),
            config_map_name: None,
            secret_name: Some("app-secret".into()),
            restart_workloads: vec![],
        }
    }

    fn bundle() -> Bundle {
        Bundle {
            version: 3,
            variables: BTreeMap::from([("LOG_LEVEL".into(), "info".into())]),
            files: BTreeMap::from([("app.toml".into(), "port = 80".into())]),
            sensitive: BTreeMap::from([("DB_PASSWORD".into(), "hunter2".into())]),
        }
    }

    #[test]
    fn sensitive_values_only_in_secret() {
        let r = render(&spec(), &bundle(), b"k").unwrap();
        let cm = r.config_map.data.unwrap();
        assert_eq!(cm.len(), 2);
        assert!(!cm.contains_key("DB_PASSWORD"));
        assert!(!cm.values().any(|v| v.contains("hunter2")));
        assert_eq!(r.secret.data.unwrap()["DB_PASSWORD"].0, b"hunter2");
        assert_eq!(
            r.config_map.metadata.name.as_deref(),
            Some("delbert-config")
        );
        assert_eq!(r.secret.metadata.name.as_deref(), Some("app-secret"));
    }

    #[test]
    fn hash_follows_content_not_version() {
        let a = render(&spec(), &bundle(), b"k").unwrap().content_hash;
        let mut republished = bundle();
        republished.version = 4;
        assert_eq!(a, render(&spec(), &republished, b"k").unwrap().content_hash);
        let mut rotated = bundle();
        rotated
            .sensitive
            .insert("DB_PASSWORD".into(), "hunter3".into());
        assert_ne!(a, render(&spec(), &rotated, b"k").unwrap().content_hash);
    }

    #[test]
    fn hash_is_keyed() {
        let a = render(&spec(), &bundle(), b"k1").unwrap().content_hash;
        assert_ne!(a, render(&spec(), &bundle(), b"k2").unwrap().content_hash);
        assert_eq!(
            render(&spec(), &bundle(), b"").unwrap_err(),
            RenderError::EmptyHashKey
        );
    }

    #[test]
    fn rejects_bad_and_duplicate_keys() {
        let mut b = bundle();
        b.variables.insert("bad key".into(), "x".into());
        assert_eq!(
            render(&spec(), &b, b"k").unwrap_err(),
            RenderError::InvalidKey("bad key".into())
        );
        let mut b = bundle();
        b.sensitive.insert("LOG_LEVEL".into(), "x".into());
        assert_eq!(
            render(&spec(), &b, b"k").unwrap_err(),
            RenderError::DuplicateKey("LOG_LEVEL".into())
        );
        let mut b = bundle();
        b.files.insert("..".into(), "x".into());
        assert!(matches!(
            render(&spec(), &b, b"k"),
            Err(RenderError::InvalidKey(_))
        ));
    }
}
