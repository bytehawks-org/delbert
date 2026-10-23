//! Configuration file (TOML) for the Core, layered under the environment.
//!
//! Precedence: environment variable, then the file, then the built-in default. Every setting
//! keeps its environment name (docs/API.md); the file only gives it a structured home:
//! `[server] bind = "..."` is `DELBERT_BIND`. Unknown keys and wrong types are errors, so a typo
//! cannot silently leave a security setting at its default. Settings holding secrets are masked
//! when the effective configuration is printed (`--check-config`); prefer the `*_file` variants.

use std::{collections::HashMap, fmt::Write as _, path::Path};

/// (`section.key`, environment variable, secret?)
pub const KEYS: &[(&str, &str, bool)] = &[
    ("server.bind", "DELBERT_BIND", false),
    ("server.tls_cert_file", "DELBERT_TLS_CERT_FILE", false),
    ("server.tls_key_file", "DELBERT_TLS_KEY_FILE", false),
    ("server.api_docs", "DELBERT_API_DOCS", false),
    ("server.trust_forwarded", "DELBERT_TRUST_FORWARDED", false),
    ("server.cookie_insecure", "DELBERT_COOKIE_INSECURE", false),
    ("server.public_url", "DELBERT_PUBLIC_URL", false),
    ("server.ui_url", "DELBERT_UI_URL", false),
    ("database.url", "DATABASE_URL", true),
    ("database.migrate_url", "DATABASE_MIGRATE_URL", true),
    ("bootstrap.admin_password", "DELBERT_BOOTSTRAP_ADMIN_PASSWORD", true),
    ("nats.url", "NATS_URL", false),
    ("nats.user", "NATS_USER", false),
    ("nats.password", "NATS_PASSWORD", true),
    ("nats.ca_file", "NATS_CA_FILE", false),
    ("nats.client_cert_file", "NATS_CLIENT_CERT_FILE", false),
    ("nats.client_key_file", "NATS_CLIENT_KEY_FILE", false),
    ("nats.auth_user", "NATS_AUTH_USER", false),
    ("nats.auth_password", "NATS_AUTH_PASSWORD", true),
    ("nats.issuer_seed_file", "DELBERT_NATS_ISSUER_SEED_FILE", false),
    ("nats.account", "DELBERT_NATS_ACCOUNT", false),
    ("nats.session_secs", "DELBERT_NATS_SESSION_SECS", false),
    ("nats.public_url", "DELBERT_PUBLIC_NATS_URL", false),
    ("pki.ca_cert_file", "DELBERT_CA_CERT_FILE", false),
    ("pki.ca_key_file", "DELBERT_CA_KEY_FILE", false),
    ("pki.agent_cert_days", "DELBERT_AGENT_CERT_DAYS", false),
    ("pki.secrets_key_file", "DELBERT_SECRETS_KEY_FILE", false),
    ("policy.signing_key_file", "DELBERT_SIGNING_KEY_FILE", false),
    ("policy.signing_kid", "DELBERT_SIGNING_KID", false),
    ("policy.publish_keys", "DELBERT_SIGNING_PUBLISH_KEYS", false),
    ("policy.retire_keys", "DELBERT_SIGNING_RETIRE_KEYS", false),
    ("policy.ttl_secs", "DELBERT_POLICY_TTL_SECS", false),
    ("policy.conflict_strategy", "DELBERT_CONFLICT_STRATEGY", false),
    ("policy.approval_default", "DELBERT_APPROVAL_DEFAULT", false),
    ("auth.mfa_required", "DELBERT_MFA_REQUIRED", false),
    ("auth.local_login", "DELBERT_LOCAL_LOGIN", false),
    ("content.dir", "DELBERT_CONTENT_DIR", false),
    ("content.allow_tenant_git", "DELBERT_CONTENT_ALLOW_TENANT_GIT", false),
    ("content.allow_file_protocol", "DELBERT_CONTENT_ALLOW_FILE", false),
    ("content.poll", "DELBERT_CONTENT_POLL", false),
    ("artifacts.store", "DELBERT_ARTIFACT_STORE", false),
    ("artifacts.dir", "DELBERT_ARTIFACT_DIR", false),
    ("artifacts.s3_endpoint", "DELBERT_S3_ENDPOINT", false),
    ("artifacts.s3_bucket", "DELBERT_S3_BUCKET", false),
    ("artifacts.s3_region", "DELBERT_S3_REGION", false),
    ("artifacts.s3_access_key", "DELBERT_S3_ACCESS_KEY", false),
    ("artifacts.s3_secret_key", "DELBERT_S3_SECRET_KEY", true),
    ("artifacts.s3_secret_key_file", "DELBERT_S3_SECRET_KEY_FILE", false),
];

#[derive(Debug, Default)]
pub struct Config {
    /// Values from the file, by environment name.
    file: HashMap<&'static str, String>,
}

impl Config {
    /// Parse and validate a TOML file.
    pub fn from_toml(text: &str) -> Result<Self, String> {
        let root: toml::Table = text.parse().map_err(|e| format!("invalid TOML: {e}"))?;
        let mut file = HashMap::new();
        for (section, value) in &root {
            let toml::Value::Table(table) = value else { return Err(format!("'{section}' must be a section such as [{section}]")) };
            for (key, value) in table {
                let path = format!("{section}.{key}");
                let (_, env, _) = KEYS.iter().find(|(k, _, _)| *k == path).ok_or_else(|| format!("unknown setting '{path}'"))?;
                let text = match value {
                    toml::Value::String(s) => s.clone(),
                    toml::Value::Integer(i) => i.to_string(),
                    toml::Value::Boolean(b) => b.to_string(),
                    _ => return Err(format!("'{path}' must be a string, number or boolean")),
                };
                file.insert(*env, text);
            }
        }
        Ok(Config { file })
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
        Self::from_toml(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Environment first, then the file; empty values count as unset.
    pub fn get(&self, name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.is_empty()).or_else(|| self.file.get(name).cloned().filter(|v| !v.is_empty()))
    }

    /// Problems that would only show at runtime: files that do not exist, numbers that do not parse,
    /// values outside their set.
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (path, env, _) in KEYS {
            let Some(v) = self.get(env) else { continue };
            if path.ends_with("_file") && !Path::new(&v).is_file() {
                out.push(format!("{path} ({env}): file '{v}' not found"));
            }
            if (path.ends_with("_secs") || path.ends_with("_days")) && v.parse::<u64>().is_err() {
                out.push(format!("{path} ({env}): '{v}' is not a number"));
            }
        }
        let one_of = |env: &str, allowed: &[&str], out: &mut Vec<String>| {
            if let Some(v) = self.get(env).filter(|v| !allowed.contains(&v.as_str())) {
                out.push(format!("{env}: '{v}' is not one of {}", allowed.join(", ")));
            }
        };
        one_of("DELBERT_MFA_REQUIRED", &["none", "admins", "all"], &mut out);
        one_of("DELBERT_ARTIFACT_STORE", &["local", "s3"], &mut out);
        one_of("DELBERT_LOCAL_LOGIN", &["all", "admins"], &mut out);
        if self.get("DATABASE_URL").is_none() {
            out.push("database.url (DATABASE_URL) is required".into());
        }
        if self.get("DELBERT_ARTIFACT_STORE").as_deref() == Some("s3") {
            for env in ["DELBERT_S3_ENDPOINT", "DELBERT_S3_BUCKET", "DELBERT_S3_ACCESS_KEY"] {
                if self.get(env).is_none() {
                    out.push(format!("{env} is required with the s3 artifact store"));
                }
            }
            if self.get("DELBERT_S3_SECRET_KEY").is_none() && self.get("DELBERT_S3_SECRET_KEY_FILE").is_none() {
                out.push("DELBERT_S3_SECRET_KEY or DELBERT_S3_SECRET_KEY_FILE is required with the s3 artifact store".into());
            }
        }
        out
    }

    /// The effective configuration, one `section.key = value` per line, secrets masked.
    pub fn effective(&self) -> String {
        let mut out = String::new();
        for (path, env, secret) in KEYS {
            if let Some(v) = self.get(env) {
                let origin = if std::env::var(env).is_ok_and(|e| !e.is_empty()) { "env" } else { "file" };
                let _ = writeln!(out, "{path} = {} ({origin})", if *secret { "********" } else { &v });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_values_are_read_and_typos_are_errors() {
        let c = Config::from_toml("[server]\nbind = \"127.0.0.1:9000\"\n[pki]\nagent_cert_days = 90\n[policy]\napproval_default = true\n").unwrap();
        assert_eq!(c.get("DELBERT_BIND").as_deref(), Some("127.0.0.1:9000"));
        assert_eq!(c.get("DELBERT_AGENT_CERT_DAYS").as_deref(), Some("90"));
        assert_eq!(c.get("DELBERT_APPROVAL_DEFAULT").as_deref(), Some("true"));
        assert!(Config::from_toml("[server]\nbnid = \"x\"\n").unwrap_err().contains("unknown setting 'server.bnid'"));
        assert!(Config::from_toml("bind = \"x\"\n").unwrap_err().contains("must be a section"));
        assert!(Config::from_toml("[server]\nbind = [1]\n").unwrap_err().contains("string, number or boolean"));
    }

    #[test]
    fn problems_and_masking() {
        let c = Config::from_toml("[database]\nurl = \"postgres://u:pw@h/d\"\n[auth]\nmfa_required = \"sometimes\"\n[artifacts]\nstore = \"s3\"\n[policy]\nttl_secs = \"x\"\n[pki]\nca_cert_file = \"/nope\"\n").unwrap();
        let p = c.problems().join("\n");
        for needle in ["DELBERT_MFA_REQUIRED", "S3_ENDPOINT", "S3_SECRET_KEY", "not a number", "file '/nope' not found"] {
            assert!(p.contains(needle), "{needle} in {p}");
        }
        let shown = c.effective();
        assert!(shown.contains("database.url = ********") && !shown.contains("pw@h"));
    }
}
