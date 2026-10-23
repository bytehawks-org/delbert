//! Semantic validation: everything serde cannot express.

use std::collections::{HashMap, HashSet};

use crate::{API_VERSION, FileState, Policy, Resource, ServiceState};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("unsupported apiVersion '{0}' (expected '{API_VERSION}')")]
    ApiVersion(String),
    #[error("duplicate resource id '{0}'")]
    DuplicateId(String),
    #[error("resource '{id}' must set exactly one verb, found {found:?}")]
    VerbCount { id: String, found: Vec<&'static str> },
    #[error("resource '{id}' depends on unknown resource '{target}'")]
    UnknownDependency { id: String, target: String },
    #[error("resource '{id}' notifies '{target}', which is not a handler")]
    BadNotify { id: String, target: String },
    #[error("dependency cycle involving resource '{0}'")]
    Cycle(String),
    #[error("resources '{a}' and '{b}' both manage {what}")]
    Conflict { a: String, b: String, what: String },
    #[error("resource '{id}': {reason}")]
    Field { id: String, reason: String },
}

/// Validate a parsed policy; returns every problem found, not just the first.
pub fn validate(policy: &Policy) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();
    for name in &policy.spec.secrets {
        if !valid_name(name) {
            errors.push(ValidationError::Field { id: "spec.secrets".into(), reason: format!("invalid secret name '{name}'") });
        }
    }
    if policy.api_version != API_VERSION {
        errors.push(ValidationError::ApiVersion(policy.api_version.clone()));
    }
    if let Err(e) = validate_resources(&policy.spec.resources) {
        errors.extend(e);
    }
    if errors.is_empty() { Ok(()) } else { Err(errors) }
}

/// Validate a list of resources (also used by agents on signed effective policies).
pub fn validate_resources(resources: &[Resource]) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();
    let mut by_id: HashMap<&str, &Resource> = HashMap::new();
    for r in resources {
        if by_id.insert(r.id.as_str(), r).is_some() {
            errors.push(ValidationError::DuplicateId(r.id.clone()));
        }
    }

    for r in resources {
        let verbs = r.verbs();
        if verbs.len() != 1 {
            errors.push(ValidationError::VerbCount { id: r.id.clone(), found: verbs });
        }
        for dep in &r.depends_on {
            if !by_id.contains_key(dep.as_str()) {
                errors.push(ValidationError::UnknownDependency {
                    id: r.id.clone(),
                    target: dep.clone(),
                });
            }
        }
        for target in &r.notify {
            if !by_id.get(target.as_str()).is_some_and(|t| t.handler) {
                errors.push(ValidationError::BadNotify { id: r.id.clone(), target: target.clone() });
            }
        }
        check_fields(r, &mut errors);
    }

    for (i, a) in resources.iter().enumerate() {
        for b in &resources[i + 1..] {
            // A handler legitimately acts on what its notifier manages (e.g. reload a started service).
            if a.handler || b.handler {
                continue;
            }
            if let Some(what) = clash(a, b) {
                errors.push(ValidationError::Conflict { a: a.id.clone(), b: b.id.clone(), what });
            }
        }
    }

    if let Some(id) = find_cycle(resources) {
        errors.push(ValidationError::Cycle(id));
    }

    if errors.is_empty() { Ok(()) } else { Err(errors) }
}

/// How a resource touches a path.
enum Role<'a> {
    /// Existence and attributes (`file`).
    File,
    /// Whole content (`copy`).
    Copy,
    /// One line, identified by its `regexp` or its text (`line_in_file`).
    Line(&'a str),
}

fn path_role(r: &Resource) -> Option<(&str, Role<'_>)> {
    if let Some(f) = &r.file {
        Some((&f.path, Role::File))
    } else if let Some(c) = &r.copy {
        Some((&c.dest, Role::Copy))
    } else if let Some(t) = &r.template {
        Some((&t.dest, Role::Copy))
    } else {
        r.line_in_file.as_ref().map(|l| (l.path.as_str(), Role::Line(l.regexp.as_deref().unwrap_or(&l.line))))
    }
}

/// Two resources of the same policy governing the same thing (the "resource
/// key" of docs/POLICY.md). The Core reuses this idea across policies.
pub fn clash(a: &Resource, b: &Resource) -> Option<String> {
    if let (Some(x), Some(y)) = (&a.package, &b.package) {
        return (x.name == y.name).then(|| format!("package '{}'", x.name));
    }
    if let (Some(x), Some(y)) = (&a.service, &b.service) {
        return (x.name == y.name).then(|| format!("service '{}'", x.name));
    }
    let ((pa, ra), (pb, rb)) = (path_role(a)?, path_role(b)?);
    let conflict = pa == pb
        && match (ra, rb) {
            (Role::Line(x), Role::Line(y)) => x == y,
            (Role::File, Role::Line(_)) | (Role::Line(_), Role::File) => false,
            _ => true,
        };
    conflict.then(|| format!("path '{pa}'"))
}

fn field_err(r: &Resource, reason: impl Into<String>) -> ValidationError {
    ValidationError::Field { id: r.id.clone(), reason: reason.into() }
}

fn check_fields(r: &Resource, errors: &mut Vec<ValidationError>) {
    let mut absolute = |path: &str| {
        if !path.starts_with('/') || path.split('/').any(|c| c == "..") {
            errors.push(field_err(r, format!("path '{path}' must be absolute and without '..'")));
        }
    };
    if let Some(f) = &r.file {
        absolute(&f.path);
    }
    if let Some(c) = &r.copy {
        absolute(&c.dest);
    }
    if let Some(t) = &r.template {
        absolute(&t.dest);
    }
    if let Some(l) = &r.line_in_file {
        absolute(&l.path);
    }

    let modes = [
        r.file.as_ref().and_then(|f| f.mode.as_deref()),
        r.copy.as_ref().and_then(|c| c.mode.as_deref()),
        r.template.as_ref().and_then(|t| t.mode.as_deref()),
    ];
    for mode in modes.into_iter().flatten() {
        let ok = (3..=4).contains(&mode.len()) && mode.chars().all(|c| ('0'..='7').contains(&c));
        if !ok {
            errors.push(field_err(r, format!("mode '{mode}' must be an octal string like \"0644\"")));
        }
    }

    if let Some(f) = &r.file {
        if f.state == FileState::Link && f.target.is_none() {
            errors.push(field_err(r, "state 'link' requires 'target'"));
        }
    }
    if let Some(c) = &r.copy {
        if c.src.is_some() == c.content.is_some() {
            errors.push(field_err(r, "copy requires exactly one of 'src' or 'content'"));
        }
        if let Some(src) = &c.src {
            if !src.starts_with("artifact://") {
                errors.push(field_err(r, "copy 'src' must be an artifact:// reference"));
            }
        }
    }
    if let Some(t) = &r.template {
        if !t.src.starts_with("artifact://") {
            errors.push(field_err(r, "template 'src' must be an artifact:// reference"));
        }
    }
    if let Some(p) = &r.package {
        if !valid_name(&p.name) {
            errors.push(field_err(r, format!("invalid package name '{}'", p.name)));
        }
    }
    if let Some(s) = &r.service {
        if !valid_name(&s.name) {
            errors.push(field_err(r, format!("invalid service name '{}'", s.name)));
        }
        if s.state.is_none() && s.enabled.is_none() {
            errors.push(field_err(r, "service needs 'state' and/or 'enabled'"));
        }
        // restarted/reloaded are actions, not states: running them on every
        // check would never converge, so only notified handlers may use them.
        if matches!(s.state, Some(ServiceState::Restarted | ServiceState::Reloaded)) && !r.handler {
            errors.push(field_err(r, "'restarted'/'reloaded' are only allowed on handlers"));
        }
    }
    if let Some(l) = &r.line_in_file {
        if l.insert_after.is_some() && l.insert_before.is_some() {
            errors.push(field_err(r, "use only one of 'insert_after' or 'insert_before'"));
        }
    }
}

/// Names handed to package managers and `systemctl` as arguments: no leading
/// dash (option injection), only a conservative character set.
fn valid_name(name: &str) -> bool {
    name.len() <= 255
        && name.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "+._:@-".contains(c))
}

/// Depth-first search over `depends_on`; returns a resource on a cycle, if any.
fn find_cycle(resources: &[Resource]) -> Option<String> {
    let deps: HashMap<&str, &[String]> =
        resources.iter().map(|r| (r.id.as_str(), r.depends_on.as_slice())).collect();
    let mut done: HashSet<&str> = HashSet::new();

    fn visit<'a>(
        id: &'a str,
        deps: &HashMap<&'a str, &'a [String]>,
        stack: &mut Vec<&'a str>,
        done: &mut HashSet<&'a str>,
    ) -> Option<String> {
        if done.contains(id) {
            return None;
        }
        if stack.contains(&id) {
            return Some(id.to_string());
        }
        stack.push(id);
        for dep in deps.get(id).copied().unwrap_or(&[]) {
            if deps.contains_key(dep.as_str()) {
                if let Some(c) = visit(dep, deps, stack, done) {
                    return Some(c);
                }
            }
        }
        stack.pop();
        done.insert(id);
        None
    }

    for r in resources {
        if let Some(c) = visit(&r.id, &deps, &mut Vec::new(), &mut done) {
            return Some(c);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::{PolicyError, ValidationError, from_yaml};

    const VALID: &str = r#"
apiVersion: delbert/v1
kind: Policy
metadata: { name: web-baseline, tenant: example }
spec:
  target: { groups: [web] }
  vars: { app_port: 8080 }
  resources:
    - id: nginx-pkg
      package: { name: nginx, state: present }
    - id: nginx-conf
      copy: { src: "artifact://nginx.conf", dest: /etc/nginx/nginx.conf, mode: "0644" }
      depends_on: [nginx-pkg]
      notify: [nginx-reload]
    - id: nginx-svc
      service: { name: nginx, state: started, enabled: true }
      depends_on: [nginx-pkg]
    - id: nginx-reload
      handler: true
      service: { name: nginx, state: reloaded }
"#;

    fn errors(input: &str) -> Vec<ValidationError> {
        match from_yaml(input) {
            Err(PolicyError::Invalid(e)) => e,
            other => panic!("expected validation errors, got {other:?}"),
        }
    }

    #[test]
    fn valid_policy_is_accepted() {
        assert!(from_yaml(VALID).is_ok());
    }

    #[test]
    fn unknown_key_is_rejected() {
        let bad = VALID.replace("depends_on: [nginx-pkg]\n      notify", "depend_on: [nginx-pkg]\n      notify");
        assert!(matches!(from_yaml(&bad), Err(PolicyError::Yaml(_))));
    }

    #[test]
    fn two_verbs_are_rejected() {
        let bad = VALID.replace(
            "      package: { name: nginx, state: present }",
            "      package: { name: nginx }\n      service: { name: nginx }",
        );
        assert!(errors(&bad).iter().any(|e| matches!(e, ValidationError::VerbCount { .. })));
    }

    #[test]
    fn duplicate_id_and_bad_notify() {
        let bad = VALID.replace("id: nginx-svc", "id: nginx-pkg").replace("notify: [nginx-reload]", "notify: [nginx-pkg]");
        let e = errors(&bad);
        assert!(e.iter().any(|e| matches!(e, ValidationError::DuplicateId(_))));
        assert!(e.iter().any(|e| matches!(e, ValidationError::BadNotify { .. })));
    }

    #[test]
    fn cycle_is_rejected() {
        let bad = VALID.replace(
            "    - id: nginx-pkg\n      package",
            "    - id: nginx-pkg\n      depends_on: [nginx-svc]\n      package",
        );
        assert!(errors(&bad).iter().any(|e| matches!(e, ValidationError::Cycle(_))));
    }

    #[test]
    fn same_path_in_copy_and_line_in_file_is_a_conflict() {
        let bad = VALID.replace(
            "    - id: nginx-reload",
            "    - id: tweak\n      line_in_file: { path: /etc/nginx/nginx.conf, line: x }\n    - id: nginx-reload",
        );
        assert!(errors(&bad).iter().any(|e| matches!(e, ValidationError::Conflict { .. })));
    }

    #[test]
    fn file_and_line_in_file_on_same_path_are_compatible() {
        let ok = VALID.replace(
            "    - id: nginx-reload",
            "    - id: dir\n      file: { path: /etc/app.conf }\n    - id: l1\n      line_in_file: { path: /etc/app.conf, line: a }\n    - id: l2\n      line_in_file: { path: /etc/app.conf, line: b }\n    - id: nginx-reload",
        );
        assert!(from_yaml(&ok).is_ok());
    }

    #[test]
    fn service_and_package_rules() {
        let bad = VALID.replace("service: { name: nginx, state: started, enabled: true }", "service: { name: nginx, state: restarted }");
        assert!(errors(&bad).iter().any(|e| matches!(e, ValidationError::Field { .. })));
        let bad = VALID.replace("package: { name: nginx, state: present }", "package: { name: \"--force-yes\" }");
        assert!(errors(&bad).iter().any(|e| matches!(e, ValidationError::Field { .. })));
        let bad = VALID.replace("service: { name: nginx, state: started, enabled: true }", "service: { name: nginx }");
        assert!(errors(&bad).iter().any(|e| matches!(e, ValidationError::Field { .. })));
    }

    #[test]
    fn relative_path_and_bad_mode_are_rejected() {
        let bad = VALID.replace("/etc/nginx/nginx.conf", "etc/nginx.conf").replace("0644", "0999");
        let e = errors(&bad);
        assert_eq!(e.iter().filter(|e| matches!(e, ValidationError::Field { .. })).count(), 2);
    }
}
