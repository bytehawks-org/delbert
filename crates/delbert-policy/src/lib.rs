//! Delbert policy model (draft v0.1, see `docs/POLICY.md`).
//!
//! A policy is declarative YAML. It is parsed into strongly typed structures
//! (unknown keys are errors) and then semantically validated before the Core
//! accepts or distributes it.

mod validate;

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use validate::{ValidationError, clash, validate, validate_resources};

/// Only supported value of `apiVersion`.
pub const API_VERSION: &str = "delbert/v1";

/// Errors returned by [`from_yaml`].
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid YAML: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
    #[error("YAML too complex: {0}")]
    TooComplex(String),
    #[error("invalid policy: {}", .0.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "))]
    Invalid(Vec<ValidationError>),
}

/// Instructions one template rendering or `when` evaluation may execute.
///
/// MiniJinja has no limit of its own: `{% for a in range(100000) %}{% for b in range(100000) %}`
/// ran for ever (measured), which would freeze the Core's render preview and, worse, an agent
/// applying the policy on a managed host (docs/SECURITY-REVIEW.md F-12). A real template uses a
/// few thousand instructions; this ceiling is hit in well under a second.
pub const TEMPLATE_FUEL: u64 = 5_000_000;

/// The one way templates and `when` expressions are evaluated everywhere (Core preview, agent):
/// undefined variables are errors and the work is bounded by [`TEMPLATE_FUEL`].
pub fn template_env() -> minijinja::Environment<'static> {
    let mut env = minijinja::Environment::new();
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Strict);
    env.set_fuel(Some(TEMPLATE_FUEL));
    env
}

/// Most `[` and `{` characters a YAML document may contain.
///
/// The YAML parser (libyaml) takes time **quadratic** in the nesting of flow collections: measured,
/// 80 KB of `[` kept a core busy for 15 s and 320 KB of `{a: ` for 37 s, so a request body of a few
/// MiB could stall a Core worker for minutes (docs/SECURITY-REVIEW.md F-10). Nesting needs one
/// bracket per level, so bounding their number bounds the work (about 10 ms at the limit). Real
/// policies, variables and tenant files have a handful; large inline text belongs in an artifact.
pub const MAX_FLOW_BRACKETS: usize = 2_000;

/// Refuse, before parsing, a document that could make the parser slow. Applied by [`from_yaml`] and
/// [`parse_yaml`]; call it yourself before any other `serde_yaml_ng` parse of untrusted text.
pub fn guard_yaml(input: &str) -> Result<(), PolicyError> {
    let brackets = input.bytes().filter(|b| matches!(b, b'[' | b'{')).count();
    if brackets > MAX_FLOW_BRACKETS {
        return Err(PolicyError::TooComplex(format!("{brackets} '[' or '{{' characters, at most {MAX_FLOW_BRACKETS} are accepted (move large inline text to an artifact)")));
    }
    Ok(())
}

/// Parse untrusted YAML into `T` after [`guard_yaml`].
pub fn parse_yaml<T: serde::de::DeserializeOwned>(input: &str) -> Result<T, PolicyError> {
    guard_yaml(input)?;
    Ok(serde_yaml_ng::from_str(input)?)
}

/// Parse and validate a policy. Nothing invalid is ever returned.
pub fn from_yaml(input: &str) -> Result<Policy, PolicyError> {
    let policy: Policy = parse_yaml(input)?;
    validate(&policy).map_err(PolicyError::Invalid)?;
    Ok(policy)
}

/// JSON Schema of the policy format (used by the UI editor and the API docs).
pub fn json_schema() -> schemars::schema::RootSchema {
    schemars::schema_for!(Policy)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Policy {
    pub api_version: String,
    pub kind: Kind,
    pub metadata: Metadata,
    pub spec: Spec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum Kind {
    Policy,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub name: String,
    pub tenant: String,
    /// Monotonic version, assigned (and signed) by the Core.
    #[serde(default)]
    pub version: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    #[serde(default)]
    pub target: Target,
    #[serde(default)]
    pub vars: BTreeMap<String, serde_json::Value>,
    /// Names of tenant secrets this policy needs on the agent. Values never appear in
    /// policies: they live in the Core's secret store and reach the agent encrypted.
    #[serde(default)]
    pub secrets: Vec<String>,
    /// Used by the `priority` conflict strategy; higher wins. Default 0.
    #[serde(default)]
    pub priority: Option<i64>,
    pub resources: Vec<Resource>,
}

/// Who receives the policy.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// Agents in any of these groups. With `agents` empty too: every agent of the tenant.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Agents with these names (a policy for one host).
    #[serde(default)]
    pub agents: Vec<String>,
    /// Restricted expression over `facts` and `vars`.
    #[serde(default)]
    pub when: Option<String>,
}

/// One desired-state item: common fields plus exactly one verb.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub id: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// Handlers triggered when this resource changes something.
    #[serde(default)]
    pub notify: Vec<String>,
    /// A handler runs only when notified.
    #[serde(default)]
    pub handler: bool,
    /// When a later policy version no longer declares this file, link or directory, the agent
    /// removes it (only what it applied itself, after a clean cycle). `true` keeps it. Only for
    /// `file` (file, link, directory), `copy` and `template`.
    #[serde(default)]
    pub keep_if_absent_in_policy: bool,
    /// What to do when this (service) resource fails or does not come up after a policy update
    /// (docs/REMEDIATION.md). Absent: nothing is verified and nothing is undone.
    #[serde(default)]
    pub remediation: Option<Remediation>,
    /// Condition evaluated by the agent on its own host: a MiniJinja expression over `facts` and
    /// `vars` (`facts.os_family == 'debian'`). False: the resource does not apply there. An
    /// expression that cannot be evaluated (undefined name) fails the resource: never applied by guess.
    #[serde(default)]
    pub when: Option<String>,

    // Verbs: exactly one must be set (checked by `validate`).
    #[serde(default)]
    pub file: Option<FileSpec>,
    #[serde(default)]
    pub copy: Option<CopySpec>,
    #[serde(default)]
    pub template: Option<TemplateSpec>,
    #[serde(default)]
    pub line_in_file: Option<LineInFileSpec>,
    #[serde(default)]
    pub package: Option<PackageSpec>,
    #[serde(default)]
    pub service: Option<ServiceSpec>,
    #[serde(default)]
    pub container: Option<ContainerSpec>,
}

impl Resource {
    /// Names of the verbs set on this resource.
    pub fn verbs(&self) -> Vec<&'static str> {
        [
            ("file", self.file.is_some()),
            ("copy", self.copy.is_some()),
            ("template", self.template.is_some()),
            ("line_in_file", self.line_in_file.is_some()),
            ("package", self.package.is_some()),
            ("service", self.service.is_some()),
            ("container", self.container.is_some()),
        ]
        .into_iter()
        .filter_map(|(name, set)| set.then_some(name))
        .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FileState {
    #[default]
    File,
    Directory,
    Link,
    Absent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileSpec {
    pub path: String,
    #[serde(default)]
    pub state: FileState,
    pub owner: Option<String>,
    pub group: Option<String>,
    /// Octal string, e.g. "0644".
    pub mode: Option<String>,
    /// Link target (state: link).
    pub target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CopySpec {
    /// `artifact://<name>`; the signed policy pins its SHA-256.
    pub src: Option<String>,
    /// Inline content (alternative to `src`).
    pub content: Option<String>,
    pub dest: String,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub mode: Option<String>,
}

/// File rendered on the agent from a MiniJinja template artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TemplateSpec {
    /// `artifact://<name>`.
    pub src: String,
    pub dest: String,
    /// Extra variables, overriding policy `vars`.
    #[serde(default)]
    pub vars: BTreeMap<String, serde_json::Value>,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub mode: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Presence {
    #[default]
    Present,
    Absent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LineInFileSpec {
    pub path: String,
    pub line: String,
    /// Replaces the first matching line instead of appending.
    pub regexp: Option<String>,
    #[serde(default)]
    pub state: Presence,
    pub insert_after: Option<String>,
    pub insert_before: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PackageState {
    #[default]
    Present,
    Absent,
    Latest,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackageSpec {
    pub name: String,
    #[serde(default)]
    pub state: PackageState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    Started,
    Stopped,
    Restarted,
    Reloaded,
}

/// How a service resource is judged after a change, and what the agent does when it fails.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Remediation {
    /// How to tell it came up. Without it only a failing `systemctl` counts as a failure.
    #[serde(default)]
    pub verify: Option<Verify>,
    #[serde(default)]
    pub on_failure: OnFailure,
    /// Clean stop before a rollback or a stop (defaults: 30 s, never kill).
    #[serde(default)]
    pub stop: StopSpec,
    /// Clean start after a rollback (default: 60 s).
    #[serde(default)]
    pub start: StartSpec,
}

/// Judged on this host only: the service is active, stays active for `settle_seconds`, and
/// optionally accepts TCP connections on `127.0.0.1:port`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Verify {
    /// It must remain active this long (default 10).
    #[serde(default = "Verify::default_settle")]
    pub settle_seconds: u32,
    /// Give up waiting for it to come up after this long (default 60).
    #[serde(default = "Verify::default_timeout")]
    pub timeout_seconds: u32,
    /// Local TCP port that must accept a connection.
    #[serde(default)]
    pub port: Option<u16>,
}

impl Verify {
    fn default_settle() -> u32 {
        10
    }
    fn default_timeout() -> u32 {
        60
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OnFailure {
    /// Report only (default): what is not declared is not automated.
    #[default]
    None,
    /// Stop the service cleanly and leave the host as it is; the agent becomes inconsistent.
    Stop,
    /// Stop cleanly, re-apply the last known good policy as a whole, start cleanly.
    Rollback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum KillMode {
    /// Wait for the service forever (systemd's own timeout still applies).
    #[default]
    Never,
    /// SIGKILL once `graceful_seconds` have passed.
    AfterTimeout,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StopSpec {
    #[serde(default = "StopSpec::default_graceful")]
    pub graceful_seconds: u32,
    #[serde(default)]
    pub kill: KillMode,
}

impl StopSpec {
    fn default_graceful() -> u32 {
        30
    }
}

impl Default for StopSpec {
    fn default() -> Self {
        StopSpec { graceful_seconds: Self::default_graceful(), kill: KillMode::Never }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StartSpec {
    #[serde(default = "StartSpec::default_timeout")]
    pub timeout_seconds: u32,
}

impl StartSpec {
    fn default_timeout() -> u32 {
        60
    }
}

impl Default for StartSpec {
    fn default() -> Self {
        StartSpec { timeout_seconds: Self::default_timeout() }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceSpec {
    pub name: String,
    pub state: Option<ServiceState>,
    pub enabled: Option<bool>,
}

// --- container -------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContainerState {
    /// Created and running (default).
    #[default]
    Running,
    /// Created, not running.
    Stopped,
    /// Removed, with its secret files.
    Absent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum RestartPolicy {
    #[serde(rename = "no")]
    No,
    #[serde(rename = "on-failure")]
    OnFailure,
    #[serde(rename = "always")]
    Always,
    #[serde(rename = "unless-stopped")]
    UnlessStopped,
}

impl RestartPolicy {
    pub fn as_arg(self) -> &'static str {
        match self {
            RestartPolicy::No => "no",
            RestartPolicy::OnFailure => "on-failure",
            RestartPolicy::Always => "always",
            RestartPolicy::UnlessStopped => "unless-stopped",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContainerEngine {
    Podman,
    Docker,
}

/// A secret delivered to the container as a read-only file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretMount {
    /// Name of a secret listed in `spec.secrets`.
    pub secret: String,
    /// Absolute path inside the container.
    pub path: String,
    /// Octal mode of the file on the host (default "0400": the container user must be able to read it).
    #[serde(default)]
    pub mode: Option<String>,
}

/// A Podman or Docker container, managed through the engine's command line (an argv, no shell).
/// Nothing privileged can be declared: no `--privileged`, capabilities, devices or host networking.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContainerSpec {
    pub name: String,
    /// Fully qualified image, a digest is recommended (`registry.example.com/app@sha256:...`).
    /// Required unless `state: absent`. The image is pulled only when the container is created.
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub state: ContainerState,
    /// `[ip:]host_port:container_port[/tcp|udp]`.
    #[serde(default)]
    pub ports: Vec<String>,
    /// `/host/path:/container/path[:ro|rw]`.
    #[serde(default)]
    pub volumes: Vec<String>,
    /// Literal environment variables.
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,
    /// Names of policy variables (`vars`, shared, tenant, group and agent layers) passed as
    /// environment variables of the same name. Variables are not secrets.
    #[serde(default)]
    pub env_from: Vec<String>,
    /// Secrets as read-only files: never environment variables (those show in `inspect`).
    #[serde(default)]
    pub secret_from: Vec<SecretMount>,
    #[serde(default)]
    pub restart: Option<RestartPolicy>,
    /// Arguments after the image: replaces the image's default command (an argv inside the container, no shell).
    #[serde(default)]
    pub command: Vec<String>,
    /// Default: Podman if present, else Docker.
    #[serde(default)]
    pub engine: Option<ContainerEngine>,
}
