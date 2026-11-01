//! Host facts reported by agents (docs/POLICY.md "Facts").
//!
//! A deliberately small, informational subset: the Core is not a CMDB. It is overwritten by each
//! report that carries it, never audited, and never used for a decision (RBAC, scoping, conflicts):
//! an agent says it about itself and may be wrong or compromised. It disappears with the agent
//! (`agent_reports` is deleted by cascade).

use std::net::IpAddr;

use serde_json::{Map, Value};

const STRING_KEYS: &[&str] = &["os_family", "distribution", "os_version", "kernel", "hostname", "domain"];
const MAX_LEN: usize = 128;
const MAX_IPS: usize = 16;

/// The known keys only, bounded and cleaned; `None` if `raw` is not an object.
pub fn sanitize(raw: &Value) -> Option<Value> {
    let raw = raw.as_object()?;
    let mut out = Map::new();
    for key in STRING_KEYS {
        let text: String = raw.get(*key).and_then(Value::as_str).unwrap_or_default().chars().filter(|c| !c.is_control()).take(MAX_LEN).collect();
        out.insert((*key).into(), Value::String(text));
    }
    let mut ips: Vec<String> = raw
        .get("ips")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .map(|ip| ip.to_string())
        .take(MAX_IPS)
        .collect();
    ips.sort();
    ips.dedup();
    out.insert("ips".into(), Value::from(ips));
    Some(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_known_bounded_clean_values_are_kept() {
        let long = "x".repeat(500);
        let f = sanitize(&json!({
            "os_family": "debian", "hostname": long, "kernel": "6.8\n0", "machine_id": "secret-ish",
            "ips": ["10.0.0.2", "not an ip", "10.0.0.2", "fd00::1"]
        }))
        .unwrap();
        assert_eq!(f["os_family"], "debian");
        assert_eq!(f["hostname"].as_str().unwrap().len(), MAX_LEN);
        assert_eq!(f["kernel"], "6.80");
        assert_eq!(f["distribution"], "");
        assert!(f.get("machine_id").is_none());
        assert_eq!(f["ips"], json!(["10.0.0.2", "fd00::1"]));
        assert!(sanitize(&json!("text")).is_none());
    }
}
