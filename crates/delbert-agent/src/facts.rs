//! Facts: what the agent knows about its own host (docs/POLICY.md "Facts").
//!
//! Two sets, deliberately separate:
//! - the **shared subset** ([`shared`]): OS family, distribution, version, kernel, hostname, domain
//!   and IP addresses. It is reported to the Core (informational, overwritten, never audited, gone
//!   with the agent) and is also available to policies;
//! - the **local facts** ([`local`]): the machine id and the custom facts of `facts.d`. They never
//!   leave the host; policies use them in `when` and templates.
//!
//! Collection only reads files (no command is run). `root` is the sandbox root of the agent, so
//! tests and `--root` runs read a fake tree; the IP addresses are those of the real host and are
//! left out when `root` is not `/`.

use std::{fs, path::Path};

use serde_json::{Map, Value, json};

/// Interfaces that belong to containers or virtual bridges: their addresses say nothing about the host.
const VIRTUAL_PREFIXES: &[&str] = &["docker", "veth", "cni", "flannel", "cali", "br-", "virbr", "podman", "lo"];
/// Custom facts files are small declarative documents.
const MAX_CUSTOM_BYTES: u64 = 64 * 1024;

fn read(root: &Path, absolute: &str) -> String {
    fs::read_to_string(root.join(absolute.trim_start_matches('/'))).unwrap_or_default()
}

fn os_release_field(os_release: &str, key: &str) -> String {
    os_release
        .lines()
        .find_map(|l| l.strip_prefix(key).and_then(|v| v.strip_prefix('=')))
        .map(|v| v.trim().trim_matches('"').to_string())
        .unwrap_or_default()
}

/// `debian`, `rhel`, `suse`, `arch`, `alpine`, otherwise `linux`; `windows` elsewhere.
fn os_family(id: &str, id_like: &str) -> &'static str {
    if cfg!(windows) {
        return "windows";
    }
    let ids = format!("{id} {id_like}");
    let has = |names: &[&str]| ids.split_whitespace().any(|i| names.contains(&i));
    if has(&["debian", "ubuntu"]) {
        "debian"
    } else if has(&["rhel", "fedora", "centos"]) {
        "rhel"
    } else if has(&["suse", "opensuse"]) {
        "suse"
    } else if has(&["arch"]) {
        "arch"
    } else if has(&["alpine"]) {
        "alpine"
    } else {
        "linux"
    }
}

fn is_virtual(name: &str) -> bool {
    VIRTUAL_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Addresses of the host, without loopback, link-local and container interfaces; sorted, unique.
fn addresses() -> Vec<String> {
    let mut ips: Vec<String> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.is_loopback() && !is_virtual(&i.name))
        .map(|i| i.ip())
        .filter(|ip| match ip {
            std::net::IpAddr::V4(v4) => !v4.is_link_local(),
            std::net::IpAddr::V6(v6) => !v6.is_loopback() && (v6.segments()[0] & 0xffc0) != 0xfe80,
        })
        .map(|ip| ip.to_string())
        .collect();
    ips.sort();
    ips.dedup();
    ips
}

/// The subset the Core stores. Keys are stable: they are an API (`GET .../agents`) and policy input.
pub fn shared(root: &Path) -> Value {
    let os_release = read(root, "/etc/os-release");
    let id = os_release_field(&os_release, "ID");
    let hostname = read(root, "/etc/hostname").trim().to_string();
    // The domain: the part of a fully qualified hostname, else the kernel's NIS domain.
    let domain = match hostname.split_once('.') {
        Some((_, d)) => d.to_string(),
        None => match read(root, "/proc/sys/kernel/domainname").trim() {
            "(none)" => String::new(),
            d => d.to_string(),
        },
    };
    let ips = if root == Path::new("/") { addresses() } else { vec![] };
    json!({
        "os_family": os_family(&id, &os_release_field(&os_release, "ID_LIKE")),
        "distribution": id,
        "os_version": os_release_field(&os_release, "VERSION_ID"),
        "kernel": read(root, "/proc/sys/kernel/osrelease").trim(),
        "hostname": hostname.split('.').next().unwrap_or_default(),
        "domain": domain,
        "ips": ips,
    })
}

/// Facts that stay on the host: machine id and the documents of `<state_dir>/facts.d` (`*.yaml`,
/// `*.yml`, `*.json`; the file name without extension becomes the key under `custom`).
/// A broken or oversized file is skipped.
pub fn local(root: &Path, facts_dir: &Path) -> Value {
    let mut custom = Map::new();
    let mut files: Vec<_> = fs::read_dir(facts_dir).into_iter().flatten().flatten().map(|e| e.path()).collect();
    files.sort();
    for path in files {
        let (Some(stem), Some(ext)) = (path.file_stem().and_then(|s| s.to_str()), path.extension().and_then(|e| e.to_str())) else { continue };
        if !matches!(ext, "yaml" | "yml" | "json") || fs::metadata(&path).map_or(true, |m| !m.is_file() || m.len() > MAX_CUSTOM_BYTES) {
            continue;
        }
        match fs::read_to_string(&path).map_err(|e| e.to_string()).and_then(|t| serde_yaml_ng::from_str::<Value>(&t).map_err(|e| e.to_string())) {
            Ok(v) => {
                custom.insert(stem.to_string(), v);
            }
            Err(e) => tracing::warn!("custom facts file {} ignored: {e}", path.display()),
        }
    }
    json!({ "machine_id": read(root, "/etc/machine-id").trim(), "custom": custom })
}

/// What policies see as `facts`: the shared subset, the local facts, and the names the first
/// version used (`os_id`, `os_version_id`).
pub fn all(root: &Path, facts_dir: &Path) -> Value {
    let mut facts = shared(root);
    let object = facts.as_object_mut().expect("an object");
    object.insert("os_id".into(), object["distribution"].clone());
    object.insert("os_version_id".into(), object["os_version"].clone());
    if let Value::Object(local) = local(root, facts_dir) {
        object.extend(local);
    }
    facts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        for (p, c) in [
            ("etc/os-release", "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n"),
            ("etc/hostname", "web01.example.com\n"),
            ("etc/machine-id", "abc123\n"),
            ("proc/sys/kernel/osrelease", "6.8.0-1\n"),
        ] {
            let path = t.path().join(p);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, c).unwrap();
        }
        t
    }

    #[test]
    fn the_shared_subset_is_read_from_the_root() {
        let t = tree();
        let f = shared(t.path());
        assert_eq!(f["os_family"], "debian");
        assert_eq!(f["distribution"], "ubuntu");
        assert_eq!(f["os_version"], "24.04");
        assert_eq!(f["kernel"], "6.8.0-1");
        assert_eq!(f["hostname"], "web01");
        assert_eq!(f["domain"], "example.com");
        assert_eq!(f["ips"], json!([])); // sandbox root: no addresses
    }

    #[test]
    fn families_follow_id_and_id_like() {
        assert_eq!(os_family("rocky", "rhel centos fedora"), "rhel");
        assert_eq!(os_family("fedora", ""), "rhel");
        assert_eq!(os_family("alpine", ""), "alpine");
        assert_eq!(os_family("nixos", ""), "linux");
    }

    #[test]
    fn containers_and_loopback_are_not_the_host() {
        assert!(is_virtual("docker0") && is_virtual("veth12ab") && is_virtual("cni0") && is_virtual("lo"));
        assert!(!is_virtual("eth0") && !is_virtual("ens3"));
    }

    #[test]
    fn local_facts_stay_local_and_custom_files_are_read() {
        let t = tree();
        let dir = t.path().join("facts.d");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("rack.yaml"), "row: 4\nzone: a\n").unwrap();
        fs::write(dir.join("broken.json"), "{ not json").unwrap();
        fs::write(dir.join("notes.txt"), "ignored").unwrap();
        let all = all(t.path(), &dir);
        assert_eq!(all["machine_id"], "abc123");
        assert_eq!(all["custom"]["rack"]["zone"], "a");
        assert!(all["custom"].get("notes").is_none() && all["custom"].get("broken").is_none());
        assert_eq!(all["os_id"], "ubuntu"); // names of the first version
        // The part sent to the Core has neither.
        let sent = shared(t.path());
        assert!(sent.get("machine_id").is_none() && sent.get("custom").is_none());
    }
}
