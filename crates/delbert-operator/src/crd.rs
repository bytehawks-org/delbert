//! The `DelbertBinding` custom resource: binds one namespace to a Core tenant/environment.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Default name of the generated `ConfigMap`.
pub const DEFAULT_CONFIG_MAP: &str = "delbert-config";
/// Default name of the generated `Secret`.
pub const DEFAULT_SECRET: &str = "delbert-secret";

/// A workload to roll out when the delivered content changes.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadRef {
    /// `Deployment`, `StatefulSet` or `DaemonSet`.
    pub kind: WorkloadKind,
    pub name: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum WorkloadKind {
    Deployment,
    StatefulSet,
    DaemonSet,
}

/// Desired delivery for the namespace the resource lives in.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "delbert.bytehawks.io",
    version = "v1alpha1",
    kind = "DelbertBinding",
    namespaced,
    status = "DelbertBindingStatus",
    shortname = "dbind"
)]
#[serde(rename_all = "camelCase")]
pub struct DelbertBindingSpec {
    /// Core tenant (slug) whose configuration is delivered.
    pub tenant: String,
    /// Environment (layer) inside the tenant, e.g. `prod`.
    pub environment: String,
    /// Name of the generated `ConfigMap` (default `delbert-config`).
    #[serde(default)]
    pub config_map_name: Option<String>,
    /// Name of the generated `Secret` (default `delbert-secret`).
    #[serde(default)]
    pub secret_name: Option<String>,
    /// Workloads to restart (pod-template annotation) when the content changes.
    #[serde(default)]
    pub restart_workloads: Vec<WorkloadRef>,
}

impl DelbertBindingSpec {
    pub fn config_map_name(&self) -> &str {
        self.config_map_name
            .as_deref()
            .unwrap_or(DEFAULT_CONFIG_MAP)
    }

    pub fn secret_name(&self) -> &str {
        self.secret_name.as_deref().unwrap_or(DEFAULT_SECRET)
    }
}

/// Last delivery outcome, written by the reconcile loop.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DelbertBindingStatus {
    /// Core bundle version last applied.
    pub observed_version: Option<i64>,
    /// Keyed content hash last applied (never a plain hash of secret values).
    pub content_hash: Option<String>,
    /// Human-readable result of the last reconcile.
    pub message: Option<String>,
}
