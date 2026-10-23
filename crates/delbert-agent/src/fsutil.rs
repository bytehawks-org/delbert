//! Filesystem helpers shared by the file-related verbs (Unix only for now).

use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

use anyhow::{Context, Result, bail};
use rand_core::{OsRng, RngCore};

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

/// Replace `path` crash-safely: the content goes to a uniquely named temporary file in the same
/// directory (created exclusively, mode 0600, so nothing is readable before it is final), then
/// owner and mode are applied, the data is fsynced, the file is renamed over `path` (atomic on
/// POSIX) and the directory is fsynced. After a crash `path` holds the old or the new content,
/// never a mix; leftovers of a crashed run are swept on the next call.
pub fn replace_file(path: &Path, bytes: &[u8], mode: u32, uid: Option<u32>, gid: Option<u32>) -> Result<()> {
    let parent = path.parent().context("path has no parent")?;
    let name = path.file_name().context("path has no file name")?.to_string_lossy().into_owned();
    let prefix = format!(".{name}.delbert.tmp.");
    if let Ok(entries) = fs::read_dir(parent) {
        for e in entries.flatten().filter(|e| e.file_name().to_string_lossy().starts_with(&prefix)) {
            let _ = fs::remove_file(e.path());
        }
    }
    let mut suffix = [0u8; 6];
    OsRng.fill_bytes(&mut suffix);
    let tmp = parent.join(format!("{prefix}{}", suffix.iter().map(|b| format!("{b:02x}")).collect::<String>()));

    let result = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        file.write_all(bytes)?;
        // chown first: it may clear setuid/setgid, which the final chmod then sets again.
        if uid.is_some() || gid.is_some() {
            std::os::unix::fs::fchown(&file, uid, gid)?;
        }
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.with_context(|| format!("writing {}", path.display()))
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
    replace_file(path, bytes, mode, uid, gid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_is_atomic_private_until_final_and_leaves_no_debris() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.conf");
        fs::write(&path, "old").unwrap();
        // A leftover of a crashed run is swept.
        fs::write(dir.path().join(".app.conf.delbert.tmp.dead"), "half").unwrap();
        replace_file(&path, b"new", 0o640, None, None).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o640);
        let names: Vec<_> = fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names.len(), 1, "{names:?}");
        // A failure leaves the old content and no temporary file.
        let missing = dir.path().join("nope/x");
        assert!(replace_file(&missing, b"x", 0o644, None, None).is_err());
    }
}
