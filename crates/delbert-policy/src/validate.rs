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
    // Secrets mounted into containers must be delivered: they have to be listed.
    for r in &policy.spec.resources {
        for m in r.container.iter().flat_map(|c| &c.secret_from) {
            if !policy.spec.secrets.contains(&m.secret) {
                errors.push(ValidationError::Field { id: r.id.clone(), reason: format!("secret '{}' is not listed in spec.secrets", m.secret) });
            }
        }
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
            // Two resources with different conditions can both name the same thing: the agent
            // refuses to apply them if both turn out to hold on one host.
            if a.when.is_some() && b.when.is_some() && a.when != b.when {
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
    /// One marked block, identified by its marker (`block_in_file`).
    Block(&'a str),
}

fn path_role(r: &Resource) -> Option<(&str, Role<'_>)> {
    if let Some(f) = &r.file {
        Some((&f.path, Role::File))
    } else if let Some(c) = &r.copy {
        Some((&c.dest, Role::Copy))
    } else if let Some(t) = &r.template {
        Some((&t.dest, Role::Copy))
    } else if let Some(g) = &r.get_url {
        Some((&g.dest, Role::Copy))
    } else if let Some(b) = &r.block_in_file {
        Some((&b.path, Role::Block(b.marker())))
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
    if let (Some(x), Some(y)) = (&a.container, &b.container) {
        return (x.name == y.name).then(|| format!("container '{}'", x.name));
    }
    if let (Some(x), Some(y)) = (&a.user, &b.user) {
        return (x.name == y.name).then(|| format!("user '{}'", x.name));
    }
    if let (Some(x), Some(y)) = (&a.group, &b.group) {
        return (x.name == y.name).then(|| format!("group '{}'", x.name));
    }
    if let (Some(x), Some(y)) = (&a.cron, &b.cron) {
        return (x.name == y.name).then(|| format!("cron job '{}'", x.name));
    }
    if let (Some(x), Some(y)) = (&a.sysctl, &b.sysctl) {
        return (x.key == y.key).then(|| format!("sysctl '{}'", x.key));
    }
    if let (Some(x), Some(y)) = (&a.mount, &b.mount) {
        return (x.path == y.path).then(|| format!("mount point '{}'", x.path));
    }
    let ((pa, ra), (pb, rb)) = (path_role(a)?, path_role(b)?);
    // Lines and blocks are parts of a file: they clash with each other only on the same line or
    // marker, never with the `file` that owns existence and attributes, always with a `copy`.
    let conflict = pa == pb
        && match (ra, rb) {
            (Role::Line(x), Role::Line(y)) | (Role::Block(x), Role::Block(y)) => x == y,
            (Role::Line(_), Role::Block(_)) | (Role::Block(_), Role::Line(_)) => false,
            (Role::File, Role::Line(_) | Role::Block(_)) | (Role::Line(_) | Role::Block(_), Role::File) => false,
            _ => true,
        };
    conflict.then(|| format!("path '{pa}'"))
}

fn field_err(r: &Resource, reason: impl Into<String>) -> ValidationError {
    ValidationError::Field { id: r.id.clone(), reason: reason.into() }
}

/// Longest `when` expression.
const MAX_WHEN: usize = 256;

fn check_container(r: &Resource, c: &crate::ContainerSpec, errors: &mut Vec<ValidationError>) {
    use regex::Regex;
    let ident = Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").expect("static");
    let name = Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$").expect("static");
    let port = Regex::new(r"^(([0-9]{1,3}(\.[0-9]{1,3}){3}|\[[0-9A-Fa-f:]+\]):)?([0-9]{1,5}):([0-9]{1,5})(/(tcp|udp))?$").expect("static");
    let in_range = |p: &str| p.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n));
    let absolute = |p: &str| p.starts_with('/') && !p.contains('\0') && !p.split('/').any(|s| s == "..");
    let mut bad = |reason: String| errors.push(field_err(r, reason));

    if !name.is_match(&c.name) {
        bad(format!("invalid container name '{}'", c.name));
    }
    match (&c.image, c.state) {
        (None, s) if s != crate::ContainerState::Absent => bad("'image' is required unless state is absent".into()),
        (Some(i), _) if i.is_empty() || i.len() > 255 || i.starts_with('-') || i.chars().any(|ch| ch.is_whitespace() || ch.is_control()) => bad(format!("invalid image '{i}'")),
        _ => {}
    }
    for p in &c.ports {
        match port.captures(p) {
            Some(m) if in_range(&m[4]) && in_range(&m[5]) => {}
            _ => bad(format!("invalid port mapping '{p}' (expected [ip:]host:container[/tcp|udp])")),
        }
    }
    for v in &c.volumes {
        let parts: Vec<&str> = v.split(':').collect();
        let ok = matches!(parts.len(), 2 | 3) && absolute(parts[0]) && absolute(parts[1]) && parts.get(2).is_none_or(|m| matches!(*m, "ro" | "rw"));
        if !ok {
            bad(format!("invalid volume '{v}' (expected /host:/container[:ro|rw], absolute paths without '..')"));
        }
    }
    for (k, v) in &c.env {
        if !ident.is_match(k) || v.contains(['\0', '\n']) {
            bad(format!("invalid environment variable '{k}'"));
        }
    }
    if c.command.iter().any(|a| a.contains('\0')) {
        bad("'command' arguments cannot contain NUL".into());
    }
    for k in &c.env_from {
        if !ident.is_match(k) {
            bad(format!("invalid variable name '{k}' in env_from"));
        } else if c.env.contains_key(k) {
            bad(format!("'{k}' is both in env and in env_from"));
        }
    }
    let mut paths = std::collections::HashSet::new();
    for m in &c.secret_from {
        if !valid_name(&m.secret) {
            bad(format!("invalid secret name '{}'", m.secret));
        }
        if !absolute(&m.path) || !paths.insert(m.path.as_str()) {
            bad(format!("secret path '{}' must be absolute, without '..', and unique", m.path));
        }
        if m.mode.as_deref().is_some_and(|mode| !((3..=4).contains(&mode.len()) && mode.chars().all(|ch| ('0'..='7').contains(&ch)))) {
            bad(format!("invalid mode for secret '{}'", m.secret));
        }
    }
}

fn check_fields(r: &Resource, errors: &mut Vec<ValidationError>) {
    if let Some(c) = &r.container {
        check_container(r, c, errors);
    }
    if let Some(rem) = &r.remediation {
        const MAX_SECONDS: u32 = 3600;
        if r.service.is_none() {
            errors.push(field_err(r, "'remediation' applies to service resources only"));
        }
        let mut seconds = vec![rem.stop.graceful_seconds, rem.start.timeout_seconds];
        if let Some(v) = &rem.verify {
            seconds.extend([v.settle_seconds, v.timeout_seconds]);
            if v.port == Some(0) {
                errors.push(field_err(r, "'remediation.verify.port' must be 1-65535"));
            }
        }
        if seconds.iter().any(|s| *s > MAX_SECONDS) {
            errors.push(field_err(r, format!("remediation times are at most {MAX_SECONDS} seconds")));
        }
    }
    if r.keep_if_absent_in_policy && r.file.is_none() && r.copy.is_none() && r.template.is_none() {
        errors.push(field_err(r, "'keep_if_absent_in_policy' applies to file, copy and template only"));
    }
    if let Some(when) = &r.when {
        if when.trim().is_empty() || when.len() > MAX_WHEN {
            errors.push(field_err(r, format!("'when' must be 1 to {MAX_WHEN} characters")));
        } else if let Err(e) = minijinja::Environment::new().compile_expression(when) {
            errors.push(field_err(r, format!("'when' is not a valid expression: {e}")));
        }
    }
    // POSIX (`/etc/app.conf`) or Windows with a drive (`C:/ProgramData/app.conf`, `C:\\...`).
    let mut absolute = |path: &str| {
        let rooted = path.starts_with('/') || split_drive(path).is_some();
        if !rooted || path.contains('\0') || path.split(['/', '\\']).any(|c| c == "..") {
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
    if let Some(b) = &r.block_in_file {
        absolute(&b.path);
    }
    if let Some(g) = &r.get_url {
        absolute(&g.dest);
    }

    let modes = [
        r.file.as_ref().and_then(|f| f.mode.as_deref()),
        r.copy.as_ref().and_then(|c| c.mode.as_deref()),
        r.template.as_ref().and_then(|t| t.mode.as_deref()),
        r.get_url.as_ref().and_then(|g| g.mode.as_deref()),
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
    check_more_verbs(r, errors);
}

/// `block_in_file`, `group`, `user`, `cron`, `sysctl`, `get_url`, `mount`, `command`.
fn check_more_verbs(r: &Resource, errors: &mut Vec<ValidationError>) {
    use crate::Presence;
    let mut bad = |reason: String| errors.push(field_err(r, reason));
    // One line of text for a passwd field, a cron line or a marker: nothing that could start a new line or field.
    let one_line = |s: &str| !s.chars().any(char::is_control);
    let account = |name: &str| {
        let mut chars = name.chars();
        (1..=32).contains(&name.len())
            && chars.next().is_some_and(|c| c.is_ascii_lowercase() || c == '_')
            && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    };
    let unix_path = |p: &str| p.starts_with('/') && one_line(p) && !p.contains(':') && !p.split('/').any(|c| c == "..");

    if let Some(b) = &r.block_in_file {
        let marker = b.marker();
        if !marker.contains("{mark}") || !one_line(marker) {
            bad("'marker' must be one line containing {mark}".into());
        }
        if b.state == Presence::Present && b.block.is_empty() {
            bad("block_in_file requires 'block'".into());
        }
        // The markers must stay recognisable: a block cannot contain them.
        if ["BEGIN", "END"].iter().any(|m| b.block.lines().any(|l| l == marker.replace("{mark}", m))) {
            bad("'block' must not contain its own marker lines".into());
        }
    }
    if let Some(g) = &r.group {
        if !account(&g.name) {
            bad(format!("invalid group name '{}'", g.name));
        }
        // The superuser's group is never managed from a policy.
        if g.name == "root" || g.gid == Some(0) {
            bad("the root group (gid 0) cannot be managed".into());
        }
    }
    if let Some(u) = &r.user {
        if !account(&u.name) {
            bad(format!("invalid user name '{}'", u.name));
        }
        // No policy may create a second superuser or change the first.
        if u.name == "root" || u.uid == Some(0) {
            bad("root (uid 0) cannot be managed".into());
        }
        for g in u.group.iter().chain(&u.groups) {
            if !account(g) {
                bad(format!("invalid group name '{g}'"));
            }
        }
        for p in u.shell.iter().chain(&u.home) {
            if !unix_path(p) {
                bad(format!("'{p}' must be an absolute path without ':' or '..'"));
            }
        }
        if u.comment.as_deref().is_some_and(|c| !one_line(c) || c.contains(':')) {
            bad("'comment' must be one line without ':'".into());
        }
    }
    if let Some(c) = &r.cron {
        let name_ok = (1..=64).contains(&c.name.len()) && c.name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-');
        if !name_ok {
            // cron ignores files whose name has a dot or other characters.
            bad(format!("invalid cron job name '{}' (letters, digits, '_' and '-')", c.name));
        }
        if c.user.as_deref().is_some_and(|u| !account(u)) {
            bad(format!("invalid user name '{}'", c.user.as_deref().unwrap_or_default()));
        }
        if c.state == Presence::Present {
            let field = |f: &str| !f.is_empty() && f.chars().all(|ch| ch.is_ascii_alphanumeric() || "*/,-".contains(ch));
            let schedule_ok = c.schedule.as_deref().is_some_and(|s| {
                matches!(s, "@reboot" | "@yearly" | "@annually" | "@monthly" | "@weekly" | "@daily" | "@midnight" | "@hourly")
                    || (s.split_whitespace().count() == 5 && s.split_whitespace().all(field))
            });
            if !schedule_ok {
                bad("'schedule' must be five cron fields (\"30 2 * * *\") or @hourly, @daily, @weekly, @monthly, @yearly, @reboot".into());
            }
            match c.command.first() {
                None => bad("cron requires 'command' (an argv: executable and arguments)".into()),
                Some(exe) if !unix_path(exe) => bad(format!("the executable '{exe}' must be an absolute path")),
                Some(_) => {}
            }
            if c.command.iter().any(|a| !one_line(a)) {
                bad("'command' arguments must not contain control characters".into());
            }
        }
        // A closed list: SHELL, PATH, BASH_ENV and the like would choose what really runs.
        for (k, v) in &c.env {
            if !matches!(k.as_str(), "MAILTO" | "MAILFROM" | "CRON_TZ" | "TZ" | "LANG" | "LC_ALL" | "RANDOM_DELAY") || !one_line(v) {
                bad(format!("cron variable '{k}' is not allowed (MAILTO, MAILFROM, CRON_TZ, TZ, LANG, LC_ALL, RANDOM_DELAY; one line)"));
            }
        }
    }
    if let Some(g) = &r.get_url {
        let rest = g.url.strip_prefix("https://").or_else(|| g.url.strip_prefix("http://"));
        // A host must follow; credentials in a URL would end up in reports and logs.
        let host_ok = rest.is_some_and(|r| r.chars().next().is_some_and(|c| c.is_ascii_alphanumeric() || c == '['));
        let authority = rest.unwrap_or_default().split(['/', '?', '#']).next().unwrap_or_default();
        if !host_ok || authority.contains('@') || g.url.chars().any(|c| c.is_control() || c.is_whitespace()) {
            bad(format!("'{}' must be an http(s) URL without credentials", g.url));
        }
        if g.sha256.len() != 64 || !g.sha256.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)) {
            bad("get_url requires 'sha256' (64 lowercase hexadecimal digits)".into());
        }
    }
    if let Some(m) = &r.mount {
        use crate::MountState;
        // fstab fields are separated by blanks: none of them may contain one (or a '#').
        let field = |s: &str| !s.is_empty() && !s.chars().any(|c| c.is_whitespace() || c.is_control() || c == '#' || c == '\\');
        // The root filesystem is never managed: a wrong line there stops the boot.
        if !unix_path(&m.path) || !field(&m.path) || m.path.trim_end_matches('/').is_empty() {
            bad(format!("mount point '{}' must be an absolute path without blanks, and not /", m.path));
        }
        for (name, value) in [("src", &m.src), ("fstype", &m.fstype), ("opts", &m.opts)] {
            if value.as_deref().is_some_and(|v| !field(v)) {
                bad(format!("'{name}' must not be empty or contain blanks"));
            }
        }
        if m.state != MountState::Absent && (m.src.is_none() || m.fstype.is_none()) {
            bad("mount requires 'src' and 'fstype'".into());
        }
    }
    if let Some(c) = &r.command {
        let arg = |a: &String| !a.contains('\0');
        for (name, argv, required) in [("argv", &c.argv, true), ("onlyif", &c.onlyif, false), ("unless", &c.unless, false)] {
            match argv.first() {
                None if required => bad("command requires 'argv'".into()),
                Some(exe) if !unix_path(exe) => bad(format!("'{name}': the executable '{exe}' must be an absolute path")),
                _ => {}
            }
            if !argv.iter().all(arg) {
                bad(format!("'{name}' must not contain NUL characters"));
            }
        }
        // Without a guard the command would run at every cycle: it could never converge.
        if c.creates.is_none() && c.onlyif.is_empty() && c.unless.is_empty() {
            bad("command requires a guard: 'creates', 'onlyif' or 'unless'".into());
        }
        for p in c.creates.iter().chain(&c.cwd) {
            if !unix_path(p) {
                bad(format!("'{p}' must be an absolute path without '..'"));
            }
        }
        if !account(&c.user) {
            bad(format!("invalid user name '{}'", c.user));
        }
        if !(1..=3600).contains(&c.timeout_seconds) {
            bad("'timeout_seconds' must be between 1 and 3600".into());
        }
        for (k, v) in &c.env {
            let key_ok = k.chars().next().is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_') && k.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_');
            // The loader's variables would change what the allowed executable really runs.
            if !key_ok || k.starts_with("LD_") || v.contains('\0') {
                bad(format!("invalid command variable '{k}'"));
            }
        }
    }
    if let Some(s) = &r.sysctl {
        let part = |p: &str| !p.is_empty() && p.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-');
        // Dotted name only: it becomes a path under /proc/sys, so no '/' and no empty or '..' parts.
        if s.key.len() > 128 || s.key.split('.').count() < 2 || !s.key.split('.').all(part) {
            bad(format!("invalid sysctl key '{}' (dotted name such as net.ipv4.ip_forward)", s.key));
        }
        if s.value.trim().is_empty() || !one_line(&s.value.replace('\t', " ")) {
            bad("'value' must be one non-empty line".into());
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

    /// A policy with only the given resources (YAML list items).
    fn with(resources: &str) -> String {
        format!("apiVersion: delbert/v1\nkind: Policy\nmetadata: {{ name: p, tenant: t1 }}\nspec:\n  resources:\n{resources}")
    }

    #[test]
    fn accounts_cron_sysctl_and_blocks_are_accepted() {
        from_yaml(&with(concat!(
            "    - id: g\n      group: { name: deploy, gid: 1800 }\n",
            "    - id: u\n      user: { name: deploy, group: deploy, groups: [www-data], shell: /bin/bash, home: /home/deploy, comment: \"Deploy user\", create_home: true }\n      depends_on: [g]\n",
            "    - id: old\n      user: { name: olduser, state: absent }\n",
            "    - id: job\n      cron: { name: backup, schedule: \"30 2 * * 1-5\", user: deploy, command: [/usr/local/bin/backup.sh, --all], env: { MAILTO: ops@example.com } }\n",
            "    - id: nojob\n      cron: { name: legacy, state: absent }\n",
            "    - id: fwd\n      sysctl: { key: net.ipv4.ip_forward, value: \"1\" }\n",
            "    - id: hosts\n      block_in_file: { path: /etc/hosts, block: \"10.0.0.1 db\\n\" }\n",
            "    - id: hosts2\n      block_in_file: { path: /etc/hosts, block: \"10.0.0.2 cache\", marker: \"# {mark} cache\" }\n",
            "    - id: line\n      line_in_file: { path: /etc/hosts, regexp: \"^10\\\\.9\\\\.\", line: \"\", state: absent }\n",
        )))
        .unwrap();
    }

    #[test]
    fn dangerous_or_malformed_accounts_jobs_and_parameters_are_rejected() {
        for bad in [
            "user: { name: root, shell: /bin/sh }",
            "user: { name: backdoor, uid: 0 }",
            "user: { name: \"-x\" }",
            "user: { name: alice, shell: bash }",
            "user: { name: alice, comment: \"a:b\" }",
            "user: { name: alice, groups: [\"a,b\"] }",
            "group: { name: wheel2, gid: 0 }",
            "group: { name: Root }",
            "cron: { name: backup, schedule: \"* * * * *\" }",
            "cron: { name: backup, schedule: \"* * * *\", command: [/bin/true] }",
            "cron: { name: backup, schedule: \"* * * * * root\", command: [/bin/true] }",
            "cron: { name: backup, schedule: \"@daily\", command: [backup.sh] }",
            "cron: { name: backup.sh, schedule: \"@daily\", command: [/bin/true] }",
            "cron: { name: backup, schedule: \"@daily\", command: [/bin/true, \"a\\nb\"] }",
            "cron: { name: backup, schedule: \"@daily\", command: [/bin/true], env: { SHELL: /tmp/x } }",
            "cron: { name: backup, schedule: \"@daily\", command: [/bin/true], env: { PATH: /tmp } }",
            "sysctl: { key: \"net/ipv4/ip_forward\", value: \"1\" }",
            "sysctl: { key: \"net..ip_forward\", value: \"1\" }",
            "sysctl: { key: kernel, value: \"1\" }",
            "sysctl: { key: net.ipv4.ip_forward, value: \"1\\n2\" }",
            "block_in_file: { path: /etc/hosts, block: x, marker: \"# managed\" }",
            "block_in_file: { path: /etc/hosts }",
            "block_in_file: { path: etc/hosts, block: x }",
            "block_in_file: { path: /etc/hosts, block: \"a\\n# END DELBERT MANAGED BLOCK\\nb\" }",
        ] {
            let e = errors(&with(&format!("    - id: r\n      {bad}\n")));
            assert!(e.iter().any(|e| matches!(e, ValidationError::Field { .. })), "accepted: {bad}");
        }
    }

    #[test]
    fn same_account_job_parameter_or_block_twice_is_a_conflict() {
        for (a, b) in [
            ("user: { name: app }", "user: { name: app, shell: /bin/sh }"),
            ("group: { name: app }", "group: { name: app, gid: 1500 }"),
            ("cron: { name: j, state: absent }", "cron: { name: j, schedule: \"@daily\", command: [/bin/true] }"),
            ("sysctl: { key: vm.swappiness, value: \"10\" }", "sysctl: { key: vm.swappiness, value: \"20\" }"),
            ("block_in_file: { path: /etc/hosts, block: a }", "block_in_file: { path: /etc/hosts, block: b }"),
            ("block_in_file: { path: /etc/hosts, block: a }", "copy: { content: x, dest: /etc/hosts }"),
        ] {
            let e = errors(&with(&format!("    - id: a\n      {a}\n    - id: b\n      {b}\n")));
            assert!(e.iter().any(|e| matches!(e, ValidationError::Conflict { .. })), "no conflict: {a} / {b}");
        }
        // A user and a group of the same name, a block and a line or the file itself: fine.
        from_yaml(&with(concat!(
            "    - id: g\n      group: { name: app }\n    - id: u\n      user: { name: app, group: app }\n",
            "    - id: f\n      file: { path: /etc/app.conf }\n    - id: b\n      block_in_file: { path: /etc/app.conf, block: x }\n    - id: l\n      line_in_file: { path: /etc/app.conf, line: y }\n",
        )))
        .unwrap();
    }

    #[test]
    fn downloads_mounts_and_commands_are_validated() {
        const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        from_yaml(&with(&format!(
            concat!(
                "    - id: tool\n      get_url: {{ url: \"https://downloads.example.com/tool-1.2.tar.gz\", dest: /opt/tool.tar.gz, sha256: {h}, mode: \"0644\" }}\n",
                "    - id: share\n      mount: {{ path: /srv/share, src: \"nas.example.com:/export\", fstype: nfs, opts: \"ro,noexec\" }}\n",
                "    - id: gone\n      mount: {{ path: /mnt/old, state: absent }}\n",
                "    - id: migrate\n      command: {{ argv: [/usr/local/bin/migrate, --apply], creates: /var/lib/app/.migrated, user: app, timeout_seconds: 120 }}\n",
                "    - id: reload\n      handler: true\n      command: {{ argv: [/usr/sbin/nginx, -s, reload], onlyif: [/usr/sbin/nginx, -t], user: root, timeout_seconds: 30 }}\n",
            ),
            h = HASH
        )))
        .unwrap();
        for bad in [
            format!("get_url: {{ url: \"https://example.com/x\", dest: /opt/x }}"),
            format!("get_url: {{ url: \"https://example.com/x\", dest: /opt/x, sha256: abc }}"),
            format!("get_url: {{ url: \"ftp://example.com/x\", dest: /opt/x, sha256: {HASH} }}"),
            format!("get_url: {{ url: \"file:///etc/shadow\", dest: /opt/x, sha256: {HASH} }}"),
            format!("get_url: {{ url: \"https://user:pw@example.com/x\", dest: /opt/x, sha256: {HASH} }}"),
            format!("get_url: {{ url: \"https://example.com/x\", dest: opt/x, sha256: {HASH} }}"),
            "mount: { path: /, src: /dev/sda1, fstype: ext4 }".to_string(),
            "mount: { path: /srv/share, fstype: nfs }".to_string(),
            "mount: { path: /srv/share, src: \"nas:/a b\", fstype: nfs }".to_string(),
            "mount: { path: /srv/share, src: nas:/a, fstype: nfs, opts: \"ro 0 0\\n/dev/sdb1 /etc ext4\" }".to_string(),
            "mount: { path: \"/srv/my share\", src: nas:/a, fstype: nfs }".to_string(),
            "command: { argv: [/bin/true], user: root, timeout_seconds: 10 }".to_string(),
            "command: { argv: [/bin/true], creates: /x, timeout_seconds: 10 }".to_string(),
            "command: { argv: [/bin/true], creates: /x, user: root }".to_string(),
            "command: { argv: [/bin/true], creates: /x, user: root, timeout_seconds: 0 }".to_string(),
            "command: { argv: [/bin/true], creates: /x, user: root, timeout_seconds: 99999 }".to_string(),
            "command: { argv: [\"true\"], creates: /x, user: root, timeout_seconds: 10 }".to_string(),
            "command: { argv: [], creates: /x, user: root, timeout_seconds: 10 }".to_string(),
            "command: { argv: [/bin/true], unless: [test, -f, /x], user: root, timeout_seconds: 10 }".to_string(),
            "command: { argv: [/bin/true], creates: /x, user: root, timeout_seconds: 10, env: { LD_PRELOAD: /tmp/x.so } }".to_string(),
            "command: { argv: [/bin/true], creates: /x, user: \"-u\", timeout_seconds: 10 }".to_string(),
            "command: { argv: \"/bin/sh -c x\", creates: /x, user: root, timeout_seconds: 10 }".to_string(),
        ] {
            match from_yaml(&with(&format!("    - id: r\n      {bad}\n"))) {
                Err(_) => {}
                Ok(_) => panic!("accepted: {bad}"),
            }
        }
        // Same destination or mount point twice.
        for (a, b) in [
            (format!("get_url: {{ url: \"https://example.com/x\", dest: /opt/x, sha256: {HASH} }}"), "copy: { content: x, dest: /opt/x }".to_string()),
            ("mount: { path: /srv/a, src: tmpfs, fstype: tmpfs }".to_string(), "mount: { path: /srv/a, state: absent }".to_string()),
        ] {
            let e = errors(&with(&format!("    - id: a\n      {a}\n    - id: b\n      {b}\n")));
            assert!(e.iter().any(|e| matches!(e, ValidationError::Conflict { .. })), "no conflict: {a} / {b}");
        }
    }

    fn container_policy(container: &str, secrets: &str) -> String {
        format!("apiVersion: delbert/v1\nkind: Policy\nmetadata: {{ name: c, tenant: example }}\nspec:\n  secrets: [{secrets}]\n  resources:\n    - id: app\n      container:\n{container}")
    }

    const GOOD: &str = "        name: app\n        image: registry.example.com/app@sha256:abc\n        ports: [\"8080:80\", \"127.0.0.1:9090:90/tcp\"]\n        volumes: [\"/srv/app:/data:ro\"]\n        env: { MODE: prod }\n        env_from: [LOG_LEVEL]\n        secret_from: [{ secret: db, path: /run/secrets/db, mode: \"0440\" }]\n        restart: unless-stopped\n";

    #[test]
    fn a_container_is_validated_and_nothing_privileged_can_be_declared() {
        assert!(from_yaml(&container_policy(GOOD, "db")).is_ok());
        let bad = |what: &str, with: &str| {
            let yaml = container_policy(&GOOD.replace(what, with), "db");
            assert!(errors(&yaml).iter().any(|e| matches!(e, ValidationError::Field { .. })), "accepted: {with}");
        };
        bad("name: app", "name: \"-rm\"");
        bad("image: registry.example.com/app@sha256:abc", "image: \"--privileged\"");
        bad("\"8080:80\"", "\"99999:80\"");
        bad("\"8080:80\"", "\"8080\"");
        bad("/srv/app:/data:ro", "../etc:/data");
        bad("/srv/app:/data:ro", "/srv/app:/data:suid");
        bad("MODE: prod", "\"BAD NAME\": x");
        bad("env_from: [LOG_LEVEL]", "env_from: [MODE]");
        bad("path: /run/secrets/db", "path: secrets/db");
        bad("\"0440\"", "\"0999\"");
        // Capabilities, devices, host networking do not exist in the schema.
        let yaml = container_policy(&format!("{GOOD}        privileged: true\n"), "db");
        assert!(from_yaml(&yaml).is_err());
        // A secret has to be listed to be delivered.
        let yaml = container_policy(GOOD, "");
        assert!(errors(&yaml).iter().any(|e| e.to_string().contains("not listed in spec.secrets")));
        // An image is needed, except to remove the container.
        let no_image = GOOD.replace("        image: registry.example.com/app@sha256:abc\n", "");
        assert!(errors(&container_policy(&no_image, "db")).iter().any(|e| matches!(e, ValidationError::Field { .. })));
        assert!(from_yaml(&container_policy("        name: app\n        state: absent\n", "")).is_ok());
    }
}

/// Split a Windows drive path (`C:/app`, `C:\\app`) into the drive letter and the rest (which
/// starts with the separator); `None` for anything else, POSIX paths included.
pub fn split_drive(path: &str) -> Option<(char, &str)> {
    let mut chars = path.chars();
    let drive = chars.next().filter(char::is_ascii_alphabetic)?;
    let rest = path.get(1..)?.strip_prefix(':')?;
    rest.starts_with(['/', '\\']).then_some((drive.to_ascii_uppercase(), rest))
}

/// The filesystem paths a resource manages (`file`, `copy`, `template`, `line_in_file`, `block_in_file`).
pub fn managed_paths(r: &Resource) -> Vec<&str> {
    [
        r.file.as_ref().map(|f| f.path.as_str()),
        r.copy.as_ref().map(|c| c.dest.as_str()),
        r.template.as_ref().map(|t| t.dest.as_str()),
        r.line_in_file.as_ref().map(|l| l.path.as_str()),
        r.block_in_file.as_ref().map(|b| b.path.as_str()),
        r.get_url.as_ref().map(|g| g.dest.as_str()),
    ]
        .into_iter()
        .flatten()
        .collect()
}

#[cfg(test)]
mod path_tests {
    use super::split_drive;

    #[test]
    fn drive_paths_are_recognised() {
        assert_eq!(split_drive("C:/app/x.conf"), Some(('C', "/app/x.conf")));
        assert_eq!(split_drive("d:\\app"), Some(('D', "\\app")));
        for p in ["/etc/app", "C:app", "C:", "1:/x", "", "é:/x", "CC:/x"] {
            assert_eq!(split_drive(p), None, "{p}");
        }
    }
}
