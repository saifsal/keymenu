//! Open a KeePass database with password and optional keyfile.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use keepass::{Database, DatabaseKey};

use crate::secret::SecretString;

/// Unlock `path` with a master password and optional keyfile.
pub fn unlock(
    path: &Path,
    password: Option<&SecretString>,
    keyfile: Option<&Path>,
) -> Result<(Database, DatabaseKey), String> {
    let mut file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    unlock_reader(&mut file, password, keyfile)
}

/// Unlock from any reader (used by tests).
pub fn unlock_reader<R: Read>(
    reader: &mut R,
    password: Option<&SecretString>,
    keyfile: Option<&Path>,
) -> Result<(Database, DatabaseKey), String> {
    let mut key = DatabaseKey::new();
    if let Some(pw) = password {
        if !pw.is_empty() {
            key = key.with_password(pw.as_str());
        }
    }
    if let Some(kf) = keyfile {
        let mut f = File::open(kf).map_err(|e| format!("open keyfile {}: {e}", kf.display()))?;
        key = key
            .with_keyfile(&mut f)
            .map_err(|e| format!("keyfile {}: {e}", kf.display()))?;
    }
    if key.is_empty() {
        return Err("empty database key (need password and/or keyfile)".into());
    }
    let db = Database::open(reader, key.clone()).map_err(|e| format!("unlock failed: {e}"))?;
    Ok((db, key))
}

/// Convenience for password-only unlock (tests / simple call sites).
#[allow(dead_code)]
pub fn unlock_with_password(path: &Path, password: &SecretString) -> Result<Database, String> {
    unlock(path, Some(password), None).map(|(db, _)| db)
}
