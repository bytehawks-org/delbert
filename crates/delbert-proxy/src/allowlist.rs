//! The agents this proxy serves and their public keys, synchronized from the Core and kept on
//! disk so that the site can authorize its agents while the Core is unreachable.

use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use delbert_natsauth::{DENIED, Decision, agent_permissions, proxy_site_permissions};
use delbert_pki::{CertIdentity, authn::{self, Proof}};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub public_key: Vec<u8>,
    pub previous_public_key: Option<Vec<u8>>,
}

#[derive(Clone)]
pub struct AllowList {
    inner: Arc<RwLock<HashMap<String, Entry>>>,
    file: PathBuf,
    /// This proxy's own certificate key: lets the proxy's relay connection to the site's NATS in.
    own_key: Vec<u8>,
    site: String,
}

fn id(tenant: &str, agent: &str) -> String {
    format!("{tenant}/{agent}")
}

impl AllowList {
    /// Load the persisted list (empty if there is none yet).
    pub fn load(file: PathBuf, site: &str, own_key: Vec<u8>) -> Self {
        let map = fs::read_to_string(&file).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        AllowList { inner: Arc::new(RwLock::new(map)), file, own_key, site: site.to_owned() }
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains(&self, tenant: &str, agent: &str) -> bool {
        self.inner.read().unwrap().contains_key(&id(tenant, agent))
    }

    /// Replace the list with the Core's answer (`{"agents": [{tenant, agent, public_key, previous_public_key}]}`).
    pub fn replace_from(&self, reply: &Value) -> Result<usize, String> {
        let agents = reply["agents"].as_array().ok_or_else(|| reply["error"].as_str().unwrap_or("malformed reply").to_owned())?;
        let mut map = HashMap::new();
        for a in agents {
            let (Some(t), Some(n), Some(k)) = (a["tenant"].as_str(), a["agent"].as_str(), a["public_key"].as_str()) else { continue };
            let public_key = B64.decode(k).map_err(|e| e.to_string())?;
            let previous_public_key = a["previous_public_key"].as_str().and_then(|k| B64.decode(k).ok());
            map.insert(id(t, n), Entry { public_key, previous_public_key });
        }
        let count = map.len();
        let tmp = self.file.with_extension("tmp");
        fs::write(&tmp, serde_json::to_vec(&map).map_err(|e| e.to_string())?).and_then(|()| fs::rename(&tmp, &self.file)).map_err(|e| e.to_string())?;
        *self.inner.write().unwrap() = map;
        Ok(count)
    }

    /// Does `proof` show that this agent made `body`? (current key, or the previous one while a renewal settles)
    pub fn verify(&self, kind: &str, tenant: &str, agent: &str, body: &Value, proof: &Proof) -> bool {
        let Some(entry) = self.inner.read().unwrap().get(&id(tenant, agent)).cloned() else { return false };
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
        authn::check(&entry.public_key, kind, tenant, agent, body, proof, now).is_ok()
            || entry.previous_public_key.is_some_and(|old| authn::check(&old, kind, tenant, agent, body, proof, now).is_ok())
    }

    /// The site's NATS callout: who may connect, and to which subjects.
    pub fn decide(&self, cert_pem: &str) -> Decision {
        match delbert_pki::identity_from_pem(cert_pem).map_err(|_| DENIED)? {
            CertIdentity::Agent { tenant, agent, public_key } => {
                let entry = self.inner.read().unwrap().get(&id(&tenant, &agent)).cloned().ok_or(DENIED)?;
                if entry.public_key == public_key || entry.previous_public_key.as_deref() == Some(public_key.as_slice()) {
                    Ok((format!("agent:{tenant}/{agent}"), agent_permissions(&tenant, &agent)))
                } else {
                    Err(DENIED)
                }
            }
            // Only this very proxy (certificate of its own key) may relay on the site's NATS.
            CertIdentity::Component { name } if name == format!("proxy:{}", self.site) && delbert_pki::public_key_from_pem(cert_pem).as_deref() == Some(self.own_key.as_slice()) => {
                Ok((name, proxy_site_permissions()))
            }
            CertIdentity::Component { .. } => Err(DENIED),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn setup() -> (AllowList, String, Vec<u8>, delbert_pki::Ca, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let ca = delbert_pki::Ca::create("CA", 30).unwrap();
        let (_, proxy_csr) = delbert_pki::new_identity("branch").unwrap();
        let own = ca.sign_proxy_csr(&proxy_csr, "branch", &["x".into()], 30).unwrap();
        let list = AllowList::load(dir.path().join("agents.json"), "branch", own.public_key.clone());
        (list, own.cert_pem, own.public_key, ca, dir)
    }

    #[test]
    fn decisions_follow_the_synced_list_and_survive_a_restart() {
        let (list, own_cert, own_key, ca, dir) = setup();
        let (key_pem, csr) = delbert_pki::new_identity("a1").unwrap();
        let agent = ca.sign_csr(&csr, "a1", &delbert_pki::agent_uri("acme", "a1"), 30).unwrap();

        assert!(list.decide(&agent.cert_pem).is_err(), "unknown before the first sync");
        let reply = json!({ "agents": [{ "tenant": "acme", "agent": "a1", "public_key": B64.encode(&agent.public_key), "previous_public_key": null }] });
        assert_eq!(list.replace_from(&reply), Ok(1));
        let (name, perms) = list.decide(&agent.cert_pem).unwrap();
        assert_eq!((name.as_str(), perms), ("agent:acme/a1", agent_permissions("acme", "a1")));

        // Proofs are verified against the same keys.
        let proof = authn::prove(&key_pem, "req", "acme", "a1", &Value::Null, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64).unwrap();
        assert!(list.verify("req", "acme", "a1", &Value::Null, &proof));
        assert!(!list.verify("req", "acme", "a2", &Value::Null, &proof) && !list.verify("report", "acme", "a1", &Value::Null, &proof));

        // The proxy's own certificate gets the relay permissions; another proxy's, and unknown components, do not.
        let (_, perms) = list.decide(&own_cert).unwrap();
        assert_eq!(perms, proxy_site_permissions());
        let (_, other_csr) = delbert_pki::new_identity("branch").unwrap();
        assert!(list.decide(&ca.sign_proxy_csr(&other_csr, "branch", &["x".into()], 30).unwrap().cert_pem).is_err(), "same name, other key");
        assert!(list.decide(&ca.sign_proxy_csr(&other_csr, "elsewhere", &["x".into()], 30).unwrap().cert_pem).is_err());
        assert!(list.decide(&ca.issue_client("core-nats", "urn:delbert:component:core-nats", 1).unwrap().cert_pem).is_err());

        // Restart: the list comes back from disk. A sync that drops the agent revokes it at once.
        let again = AllowList::load(dir.path().join("agents.json"), "branch", own_key);
        assert!(again.decide(&agent.cert_pem).is_ok());
        assert_eq!(again.replace_from(&json!({ "agents": [] })), Ok(0));
        assert!(again.decide(&agent.cert_pem).is_err() && !again.contains("acme", "a1"));
        assert!(again.replace_from(&json!({ "error": "unauthorized" })).is_err(), "an error reply never empties the list");
        assert!(list.contains("acme", "a1"), "other handles are separate until they sync");
    }
}
