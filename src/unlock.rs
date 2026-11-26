//! Open a KeePass database with a password (keyfile added in a later commit).

use std::fs::File;
use std::io::Read;
use std::path::Path;

use keepass::{Database, DatabaseKey};

use crate::secret::SecretString;

/// Unlock `path` with a master password.
pub fn unlock_with_password(path: &Path, password: &SecretString) -> Result<Database, String> {
    let mut file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    unlock_reader(&mut file, password)
}

/// Unlock from any reader (used by tests).
pub fn unlock_reader<R: Read>(reader: &mut R, password: &SecretString) -> Result<Database, String> {
    let key = DatabaseKey::new().with_password(password.as_str());
    Database::open(reader, key).map_err(|e| format!("unlock failed: {e}"))
}
