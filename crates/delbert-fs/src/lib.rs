//! Crash-safe file replacement, shared by the agent (managed files, state, identity) and the
//! proxy (queue, allow-list, caches). Unix only for now.

use std::{
    fs,
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

use rand_core::{OsRng, RngCore};

/// Replace `path` crash-safely: the content goes to a uniquely named temporary file in the same
/// directory (created exclusively, mode 0600, so nothing is readable before it is final), then
/// owner and mode are applied, the data is fsynced, the file is renamed over `path` (atomic on
/// POSIX) and the directory is fsynced. After a crash `path` holds the old or the new content,
/// never a mix; leftovers of a crashed run are swept on the next call.
pub fn replace_file(path: &Path, bytes: &[u8], mode: u32, uid: Option<u32>, gid: Option<u32>) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| io::Error::other("path has no parent"))?;
    let name = path.file_name().ok_or_else(|| io::Error::other("path has no file name"))?.to_string_lossy().into_owned();
    let prefix = format!(".{name}.delbert.tmp.");
    if let Ok(entries) = fs::read_dir(parent) {
        for e in entries.flatten().filter(|e| e.file_name().to_string_lossy().starts_with(&prefix)) {
            let _ = fs::remove_file(e.path());
        }
    }
    let mut suffix = [0u8; 6];
    OsRng.fill_bytes(&mut suffix);
    let tmp = parent.join(format!("{prefix}{}", suffix.iter().map(|b| format!("{b:02x}")).collect::<String>()));

    let result = (|| -> io::Result<()> {
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
    result
}


/// A file only its owner can read (keys, seeds, state).
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    replace_file(path, bytes, 0o600, None, None)
}

/// A file everybody may read (certificates, public keys, caches).
pub fn write_public(path: &Path, bytes: &[u8]) -> io::Result<()> {
    replace_file(path, bytes, 0o644, None, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

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
