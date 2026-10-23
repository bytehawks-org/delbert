//! Filesystem helpers shared by the file-related verbs (Unix only for now).

use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

use anyhow::{Context, Result, bail};

use crate::engine::Ctx;

/// Ownership and permission attributes requested by a policy.
#[derive(Clone, Copy, Default)]
pub struct Attrs<'a> {
    pub owner: Option<&'a str>,
    pub group: Option<&'a str>,
    /// Octal string, e.g. "0644".
    pub mode: Option<&'a str>,
}

fn parse_mode(mode: &str) -> Result<u32> {
    u32::from_str_radix(mode, 8).with_context(|| format!("invalid mode '{mode}'"))
}

/// Resolve a user/group name to an id using the local `passwd`/`group` file
/// (numeric ids are accepted as-is). NSS sources such as LDAP are not consulted.
fn lookup_id(ctx: &Ctx, db: &str, name: &str) -> Result<u32> {
    if let Ok(id) = name.parse::<u32>() {
        return Ok(id);
    }
    let text = fs::read_to_string(ctx.path(db)).with_context(|| format!("reading {db}"))?;
    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.first() == Some(&name) {
            if let Some(id) = fields.get(2).and_then(|f| f.parse().ok()) {
                return Ok(id);
            }
        }
    }
    bail!("unknown name '{name}' in {db}")
}

/// Differences between the current metadata and the requested attributes.
pub fn attrs_drift(ctx: &Ctx, meta: &fs::Metadata, attrs: Attrs) -> Result<Vec<String>> {
    let mut drift = Vec::new();
    if let Some(mode) = attrs.mode {
        let (want, have) = (parse_mode(mode)?, meta.mode() & 0o7777);
        if want != have {
            drift.push(format!("mode {have:04o} -> {want:04o}"));
        }
    }
    if let Some(owner) = attrs.owner {
        if lookup_id(ctx, "/etc/passwd", owner)? != meta.uid() {
            drift.push(format!("owner {} -> {owner}", meta.uid()));
        }
    }
    if let Some(group) = attrs.group {
        if lookup_id(ctx, "/etc/group", group)? != meta.gid() {
            drift.push(format!("group {} -> {group}", meta.gid()));
        }
    }
    Ok(drift)
}

/// Make `path` match the requested attributes (only touching what differs).
pub fn apply_attrs(ctx: &Ctx, path: &Path, attrs: Attrs) -> Result<()> {
    let meta = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if let Some(mode) = attrs.mode {
        let want = parse_mode(mode)?;
        if want != meta.mode() & 0o7777 {
            fs::set_permissions(path, fs::Permissions::from_mode(want))
                .with_context(|| format!("chmod {}", path.display()))?;
        }
    }
    let uid = attrs.owner.map(|o| lookup_id(ctx, "/etc/passwd", o)).transpose()?;
    let gid = attrs.group.map(|g| lookup_id(ctx, "/etc/group", g)).transpose()?;
    if uid.is_some_and(|u| u != meta.uid()) || gid.is_some_and(|g| g != meta.gid()) {
        std::os::unix::fs::chown(path, uid, gid).with_context(|| format!("chown {}", path.display()))?;
    }
    Ok(())
}

/// Replace the content of a regular file atomically (see `replace_file`).
/// Mode and ownership of an existing file are preserved unless `attrs` says otherwise.
pub fn write_atomic(ctx: &Ctx, path: &Path, bytes: &[u8], attrs: Attrs) -> Result<()> {
    let parent = path.parent().context("path has no parent")?;
    if !parent.is_dir() {
        bail!("parent directory {} does not exist", parent.display());
    }
    let existing = match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() || !m.is_file() => {
            bail!("{} exists and is not a regular file", path.display())
        }
        Ok(m) => Some(m),
        Err(_) => None,
    };
    let mode = match attrs.mode {
        Some(m) => parse_mode(m)?,
        None => existing.as_ref().map_or(0o644, |m| m.mode() & 0o7777),
    };
    let uid = match attrs.owner {
        Some(o) => Some(lookup_id(ctx, "/etc/passwd", o)?),
        None => existing.as_ref().map(MetadataExt::uid),
    };
    let gid = match attrs.group {
        Some(g) => Some(lookup_id(ctx, "/etc/group", g)?),
        None => existing.as_ref().map(MetadataExt::gid),
    };
    delbert_fs::replace_file(path, bytes, mode, uid, gid).with_context(|| format!("writing {}", path.display()))
}
