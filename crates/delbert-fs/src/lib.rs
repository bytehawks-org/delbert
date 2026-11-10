//! Crash-safe file replacement, shared by the agent (managed files, state, identity) and the
//! proxy (queue, allow-list, caches).
//!
//! Windows: `mode`, `uid` and `gid` are ignored (a new file inherits the ACL of its directory, so a
//! private file is private when its directory is, which the installer arranges for the agent's
//! data directory). The rename replaces the destination atomically; the directory itself cannot be
//! flushed without FFI, so after a power loss the rename may not have reached the disk (the file
//! then holds the old content, never a mix).

use std::{
    fs,
    io::{self, Write},
    path::Path,
};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

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
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        #[cfg(unix)]
        {
            // chown first: it may clear setuid/setgid, which the final chmod then sets again.
            if uid.is_some() || gid.is_some() {
                std::os::unix::fs::fchown(&file, uid, gid)?;
            }
            file.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        #[cfg(not(unix))]
        let _ = (mode, uid, gid);
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        #[cfg(unix)]
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}


/// Create `dir` (and its parents) for private material: mode 0700 on Unix. On Windows its ACL is
/// replaced (inheritance from the parent removed) by full control for SYSTEM, Administrators and
/// the owner only, inherited by everything created inside; this uses the system's `icacls.exe`,
/// by full path and with well-known SIDs, so it does not depend on the display language.
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    #[cfg(windows)]
    {
        let icacls = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into())).join(r"System32\icacls.exe");
        let out = std::process::Command::new(icacls)
            .arg(dir)
            .args(["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/grant:r", "*S-1-3-4:(OI)(CI)F"])
            .stdin(std::process::Stdio::null())
            .output()?;
        if !out.status.success() {
            return Err(io::Error::other(format!("icacls failed on {}: {}", dir.display(), String::from_utf8_lossy(&out.stderr).trim())));
        }
    }
    Ok(())
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

    #[test]
    fn replace_is_atomic_private_until_final_and_leaves_no_debris() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.conf");
        fs::write(&path, "old").unwrap();
        // A leftover of a crashed run is swept.
        fs::write(dir.path().join(".app.conf.delbert.tmp.dead"), "half").unwrap();
        replace_file(&path, b"new", 0o640, None, None).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
        #[cfg(unix)]
        assert_eq!(std::os::unix::fs::MetadataExt::mode(&fs::metadata(&path).unwrap()) & 0o7777, 0o640);
        let names: Vec<_> = fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names.len(), 1, "{names:?}");
        // A failure leaves the old content and no temporary file.
        let missing = dir.path().join("nope/x");
        assert!(replace_file(&missing, b"x", 0o644, None, None).is_err());
    }
    #[test]
    fn private_dir_is_created_with_parents_and_holds_private_files() {
        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().join("a/identity");
        create_private_dir(&private).unwrap();
        create_private_dir(&private).unwrap(); // idempotent
        #[cfg(unix)]
        assert_eq!(std::os::unix::fs::MetadataExt::mode(&fs::metadata(&private).unwrap()) & 0o7777, 0o700);
        write_private(&private.join("key.pem"), b"secret").unwrap();
        assert_eq!(fs::read(private.join("key.pem")).unwrap(), b"secret");
    }
}
