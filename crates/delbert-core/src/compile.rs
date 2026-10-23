//! Policy compiler: merges the policies that target one endpoint into a single
//! resource list and resolves conflicts (docs/ABSTRACT.md §3 "Conflitti").
//!
//! Resolution is deterministic and fail-closed: a conflict that no strategy
//! resolves leaves the conflicting resources out (the rest is still applied),
//! together with everything that depends on them.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use delbert_policy::{Resource, clash};
use delbert_wire::ArtifactRef;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Neither side is applied. Always the implicit last resort.
    Error,
    /// The policy with the higher `spec.priority` wins; ties fall through.
    Priority,
}

/// Parse a comma-separated chain such as `priority,error`.
pub fn parse_chain(text: &str) -> Result<Vec<Strategy>, String> {
    text.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| match s {
            "error" => Ok(Strategy::Error),
            "priority" => Ok(Strategy::Priority),
            other => Err(format!("unknown conflict strategy '{other}' (supported: priority, error)")),
        })
        .collect()
}

pub struct PolicyInput {
    pub name: String,
    pub priority: i64,
    /// Secret names the policy asks for.
    pub secrets: Vec<String>,
    pub vars: BTreeMap<String, Value>,
    pub resources: Vec<Resource>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct Conflict {
    pub what: String,
    pub resources: Vec<String>,
    pub resolution: String,
}

#[derive(Debug)]
pub struct Compiled {
    pub resources: Vec<Resource>,
    pub vars: BTreeMap<String, Value>,
    pub conflicts: Vec<Conflict>,
    /// Artifacts referenced by the remaining resources, pinned by hash.
    pub artifacts: BTreeMap<String, ArtifactRef>,
    /// Union of the secret names requested by the targeting policies.
    pub secrets: BTreeSet<String>,
}

/// Names of the artifacts a resource references (`artifact://<name>`).
fn artifact_names(r: &Resource) -> Vec<&str> {
    let srcs = [r.copy.as_ref().and_then(|c| c.src.as_deref()), r.template.as_ref().map(|t| t.src.as_str())];
    srcs.into_iter().flatten().filter_map(|s| s.strip_prefix("artifact://")).collect()
}

struct Entry {
    policy: usize,
    priority: i64,
    res: Resource,
    removed: bool,
}

fn qualify(policy: &str, id: &str) -> String {
    format!("{policy}/{id}")
}

/// Same desired state, ignoring identity and ordering metadata.
fn same_desired(a: &Resource, b: &Resource) -> bool {
    let strip = |r: &Resource| Resource { id: String::new(), depends_on: vec![], notify: vec![], handler: false, ..r.clone() };
    strip(a) == strip(b)
}

/// `catalog` holds the artifacts that exist (latest version of each name).
pub fn compile(inputs: &[PolicyInput], chain: &[Strategy], catalog: &BTreeMap<String, ArtifactRef>) -> Compiled {
    let mut inputs: Vec<&PolicyInput> = inputs.iter().collect();
    inputs.sort_by(|a, b| a.name.cmp(&b.name));

    // Ids become `<policy>/<id>` so they stay unique across policies.
    let mut entries: Vec<Entry> = Vec::new();
    for (pi, p) in inputs.iter().enumerate() {
        for r in &p.resources {
            let mut res = r.clone();
            res.id = qualify(&p.name, &r.id);
            res.depends_on = r.depends_on.iter().map(|d| qualify(&p.name, d)).collect();
            res.notify = r.notify.iter().map(|d| qualify(&p.name, d)).collect();
            entries.push(Entry { policy: pi, priority: p.priority, res, removed: false });
        }
    }

    // A resource that needs a missing artifact cannot work: leave it (and its dependents) out.
    let mut conflicts = Vec::new();
    for e in entries.iter_mut() {
        if let Some(name) = artifact_names(&e.res).into_iter().find(|n| !catalog.contains_key(*n)) {
            conflicts.push(Conflict { what: format!("artifact '{name}'"), resources: vec![e.res.id.clone()], resolution: "missing: not applied".into() });
            e.removed = true;
        }
    }

    let mut alias: HashMap<String, String> = HashMap::new(); // merged duplicate -> kept resource

    for i in 0..entries.len() {
        for j in i + 1..entries.len() {
            if entries[i].removed {
                break;
            }
            let (a, b) = (&entries[i], &entries[j]);
            // Handlers are exempt: reloading the same service from two policies is fine.
            if b.removed || a.policy == b.policy || a.res.handler || b.res.handler {
                continue;
            }
            let Some(what) = clash(&a.res, &b.res) else { continue };
            let (ids, ids_pair) = ((a.res.id.clone(), b.res.id.clone()), [a.res.id.clone(), b.res.id.clone()]);

            if same_desired(&a.res, &b.res) {
                alias.insert(ids.1.clone(), ids.0.clone());
                entries[j].removed = true;
                continue;
            }

            let mut resolution = None;
            for strategy in chain {
                match strategy {
                    Strategy::Priority if a.priority != b.priority => {
                        let (winner, loser) = if a.priority > b.priority { (i, j) } else { (j, i) };
                        resolution = Some(format!("priority: kept {}", entries[winner].res.id));
                        entries[loser].removed = true;
                        break;
                    }
                    Strategy::Priority => {}
                    Strategy::Error => break,
                }
            }
            let resolution = resolution.unwrap_or_else(|| {
                entries[i].removed = true;
                entries[j].removed = true;
                "error: neither applied".to_string()
            });
            conflicts.push(Conflict { what, resources: ids_pair.to_vec(), resolution });
        }
    }

    // Resources kept alias targets stay; ones removed by a conflict take their dependents with them.
    let mut dead: HashSet<String> = entries.iter().filter(|e| e.removed && !alias.contains_key(&e.res.id)).map(|e| e.res.id.clone()).collect();
    loop {
        let mut changed = false;
        for e in entries.iter_mut().filter(|e| !e.removed) {
            e.res.depends_on = e.res.depends_on.iter().map(|d| alias.get(d).cloned().unwrap_or_else(|| d.clone())).collect();
            e.res.notify = e.res.notify.iter().map(|d| alias.get(d).cloned().unwrap_or_else(|| d.clone())).collect();
            if let Some(d) = e.res.depends_on.iter().find(|d| dead.contains(*d)) {
                conflicts.push(Conflict {
                    what: "dependency".into(),
                    resources: vec![e.res.id.clone()],
                    resolution: format!("blocked: depends on unresolved {d}"),
                });
                dead.insert(e.res.id.clone());
                e.removed = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut resources: Vec<Resource> = entries.into_iter().filter(|e| !e.removed).map(|e| e.res).collect();
    for r in &mut resources {
        r.notify.retain(|n| !dead.contains(n));
    }

    // Variables: same key with different values is a conflict too.
    let mut vars = BTreeMap::new();
    let mut by_key: BTreeMap<&String, Vec<(i64, &String, &Value)>> = BTreeMap::new();
    for p in &inputs {
        for (k, v) in &p.vars {
            by_key.entry(k).or_default().push((p.priority, &p.name, v));
        }
    }
    for (key, mut defs) in by_key {
        if defs.iter().all(|(_, _, v)| *v == defs[0].2) {
            vars.insert(key.clone(), defs[0].2.clone());
            continue;
        }
        defs.sort_by(|a, b| b.0.cmp(&a.0));
        let by_priority = chain.contains(&Strategy::Priority) && defs[0].0 != defs[1].0;
        let (resolution, kept) = if by_priority {
            (format!("priority: kept value from {}", defs[0].1), Some(defs[0].2))
        } else {
            ("error: variable not set".to_string(), None)
        };
        if let Some(v) = kept {
            vars.insert(key.clone(), v.clone());
        }
        conflicts.push(Conflict {
            what: format!("variable '{key}'"),
            resources: defs.iter().map(|d| d.1.clone()).collect(),
            resolution,
        });
    }

    let artifacts = resources
        .iter()
        .flat_map(artifact_names)
        .filter_map(|n| catalog.get(n).map(|a| (n.to_owned(), a.clone())))
        .collect();
    let secrets = inputs.iter().flat_map(|p| p.secrets.iter().cloned()).collect();

    Compiled { resources, vars, conflicts, artifacts, secrets }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile(inputs: &[PolicyInput], chain: &[Strategy]) -> Compiled {
        super::compile(inputs, chain, &BTreeMap::new())
    }

    fn input(name: &str, priority: i64, yaml_resources: &str) -> PolicyInput {
        let yaml = format!(
            "apiVersion: delbert/v1\nkind: Policy\nmetadata: {{ name: {name}, tenant: t }}\nspec:\n  resources:\n{yaml_resources}"
        );
        let p = delbert_policy::from_yaml(&yaml).unwrap();
        PolicyInput { name: name.into(), priority, secrets: p.spec.secrets, vars: p.spec.vars, resources: p.spec.resources }
    }

    fn ids(c: &Compiled) -> Vec<&str> {
        c.resources.iter().map(|r| r.id.as_str()).collect()
    }

    const A: &str = "    - id: motd\n      copy: { content: \"hello\\n\", dest: /etc/motd }\n";
    const B_DIFF: &str = "    - id: motd2\n      copy: { content: \"other\\n\", dest: /etc/motd }\n";

    #[test]
    fn disjoint_policies_are_concatenated_with_qualified_ids() {
        let c = compile(&[input("b", 0, "    - id: x\n      file: { path: /etc/x }\n"), input("a", 0, A)], &[Strategy::Error]);
        assert_eq!(ids(&c), vec!["a/motd", "b/x"]);
        assert!(c.conflicts.is_empty());
        assert!(delbert_policy::validate_resources(&c.resources).is_ok());
    }

    #[test]
    fn identical_declarations_merge_and_references_are_remapped() {
        let b = format!("{A}    - id: after\n      file: {{ path: /etc/after }}\n      depends_on: [motd]\n");
        let c = compile(&[input("a", 0, A), input("b", 0, &b)], &[Strategy::Error]);
        assert_eq!(ids(&c), vec!["a/motd", "b/after"]);
        assert_eq!(c.resources[1].depends_on, vec!["a/motd"]);
        assert!(c.conflicts.is_empty());
        assert!(delbert_policy::validate_resources(&c.resources).is_ok());
    }

    #[test]
    fn error_strategy_drops_both_and_blocks_dependents() {
        let dependent = format!("{B_DIFF}    - id: later\n      file: {{ path: /etc/later }}\n      depends_on: [motd2]\n");
        let c = compile(&[input("a", 0, A), input("b", 0, &dependent)], &[Strategy::Error]);
        assert!(ids(&c).is_empty(), "{:?}", ids(&c));
        assert_eq!(c.conflicts.len(), 2);
        assert_eq!(c.conflicts[0].resolution, "error: neither applied");
        assert!(c.conflicts[1].resolution.starts_with("blocked"));
    }

    #[test]
    fn priority_strategy_keeps_the_higher_priority_and_falls_back_to_error_on_ties() {
        let chain = [Strategy::Priority, Strategy::Error];
        let c = compile(&[input("a", 1, A), input("b", 5, B_DIFF)], &chain);
        assert_eq!(ids(&c), vec!["b/motd2"]);
        assert_eq!(c.conflicts[0].resolution, "priority: kept b/motd2");

        let tie = compile(&[input("a", 5, A), input("b", 5, B_DIFF)], &chain);
        assert!(ids(&tie).is_empty());
        assert_eq!(tie.conflicts[0].resolution, "error: neither applied");
    }

    #[test]
    fn empty_chain_is_still_fail_closed() {
        let c = compile(&[input("a", 1, A), input("b", 5, B_DIFF)], &[]);
        assert!(ids(&c).is_empty());
    }

    #[test]
    fn variable_conflicts_follow_the_same_rules() {
        let mut a = input("a", 1, A);
        let mut b = input("b", 5, "    - id: x\n      file: { path: /etc/x }\n");
        a.vars.insert("port".into(), serde_json::json!(80));
        a.vars.insert("same".into(), serde_json::json!("v"));
        b.vars.insert("port".into(), serde_json::json!(8080));
        b.vars.insert("same".into(), serde_json::json!("v"));

        let c = compile(&[a, b], &[Strategy::Error]);
        assert!(!c.vars.contains_key("port") && c.vars["same"] == "v");

        let mut a = input("a", 1, A);
        let mut b = input("b", 5, "    - id: x\n      file: { path: /etc/x }\n");
        a.vars.insert("port".into(), serde_json::json!(80));
        b.vars.insert("port".into(), serde_json::json!(8080));
        let c = compile(&[a, b], &[Strategy::Priority, Strategy::Error]);
        assert_eq!(c.vars["port"], 8080);
    }

    #[test]
    fn artifacts_are_pinned_and_missing_ones_block_dependents() {
        let res = "    - id: conf\n      copy: { src: \"artifact://app.conf\", dest: /etc/app.conf }\n    - id: after\n      file: { path: /etc/after }\n      depends_on: [conf]\n    - id: free\n      file: { path: /etc/free }\n";
        let mut catalog = BTreeMap::new();
        let none = super::compile(&[input("a", 0, res)], &[Strategy::Error], &catalog);
        assert_eq!(ids(&none), vec!["a/free"]);
        assert_eq!(none.conflicts[0].what, "artifact 'app.conf'");
        assert!(none.conflicts[1].resolution.starts_with("blocked"));
        assert!(none.artifacts.is_empty());

        catalog.insert("app.conf".to_string(), ArtifactRef { sha256: "ab".repeat(32), size: 3 });
        catalog.insert("unused".to_string(), ArtifactRef { sha256: "cd".repeat(32), size: 1 });
        let ok = super::compile(&[input("a", 0, res)], &[Strategy::Error], &catalog);
        assert_eq!(ids(&ok), vec!["a/conf", "a/after", "a/free"]);
        assert_eq!(ok.artifacts.keys().collect::<Vec<_>>(), vec!["app.conf"]);
    }

    #[test]
    fn parse_chain_rejects_unknown_strategies() {
        assert_eq!(parse_chain("priority, error").unwrap(), vec![Strategy::Priority, Strategy::Error]);
        assert!(parse_chain("specificity").is_err());
    }
}
