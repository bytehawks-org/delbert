//! The signed payload: what one agent must enforce.

use std::collections::BTreeMap;

use delbert_policy::Resource;

use crate::trust::TrustUpdate;
use serde::{Deserialize, Serialize};

/// Value of [`EffectivePolicy::schema`].
pub const SCHEMA: &str = "delbert-effective/v1";

/// An artifact pinned by content: agents download it and refuse anything else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRef {
    /// Lowercase hex SHA-256.
    pub sha256: String,
    pub size: u64,
}

/// Output of the Core's compilation step for a single endpoint: variables,
/// artifacts and conflicts are already resolved. Agents never see YAML.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectivePolicy {
    pub schema: String,
    pub tenant: String,
    /// Identity of the only agent allowed to apply this policy.
    pub agent: String,
    pub name: String,
    /// Monotonic per (agent, name): agents refuse older versions (anti-rollback).
    pub version: u64,
    /// Unix seconds.
    pub issued_at: i64,
    /// Unix seconds; the agent refuses the policy afterwards.
    pub expires_at: i64,
    /// Variables available to templates (integers, strings, booleans, arrays, objects).
    #[serde(default)]
    pub vars: BTreeMap<String, serde_json::Value>,
    /// `artifact://<name>` references used by the resources, pinned by SHA-256.
    #[serde(default)]
    pub artifacts: BTreeMap<String, ArtifactRef>,
    /// Secret values encrypted (age) to this agent's key, base64 encoded.
    #[serde(default)]
    pub secrets: BTreeMap<String, String>,
    pub resources: Vec<Resource>,
    /// Signing-key rotation: keys to learn or forget (docs/ROTATION.md). Only honoured because the
    /// whole payload is signed by a key the agent already trusts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<TrustUpdate>,
}
