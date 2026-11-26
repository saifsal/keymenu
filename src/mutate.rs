//! Add / edit / delete entries and atomically save as KDBX4.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use keepass::config::DatabaseVersion;
use keepass::db::{fields, EntryId};
use keepass::{Database, DatabaseKey};

use crate::dmenu;
use crate::secret::SecretString;

const ADD_LABEL: &str = "+ Add entry";

pub fn add_label() -> &'static str {
    ADD_LABEL
}

/// Ensure the in-memory config can be written with `save_kdbx4` (upgrades KDBX3 → 4).
pub fn ensure_kdbx4(db: &mut Database) {
    if !matches!(db.config.version, DatabaseVersion::KDB4(_)) {
        db.config.version = DatabaseVersion::KDB4(1);
    }
}

/// Write `db` to `path` via temp file + rename.
pub fn save_atomic(db: &mut Database, path: &Path, key: DatabaseKey) -> Result<(), String> {
    ensure_kdbx4(db);

    let tmp = temp_path(path);
    {
        let mut file = File::create(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
        db.save(&mut file, key)
            .map_err(|e| format!("save failed: {e}"))?;
        file.flush().map_err(|e| format!("flush {}: {e}", tmp.display()))?;
    }

    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("rename {} → {}: {e}", tmp.display(), path.display())
    })?;
    Ok(())
}

fn temp_path(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".keymenu.tmp");
    PathBuf::from(tmp)
}

/// Interactive add: prompt title / username / password, append entry, save.
pub fn add_entry(
    db: &mut Database,
    dmenu_bin: &str,
    path: &Path,
    key: DatabaseKey,
) -> Result<(), String> {
    let title = prompt_text(dmenu_bin, "Title", None)?
        .ok_or_else(|| "add cancelled".to_string())?;
    let username = prompt_text(dmenu_bin, "Username", None)?.unwrap_or_default();
    let password = dmenu::prompt_password(dmenu_bin, "Password")?.unwrap_or_else(|| SecretString::new(String::new()));

    {
        let mut root = db.root_mut();
        root.add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, title);
            e.set_unprotected(fields::USERNAME, username);
            e.set_protected(fields::PASSWORD, password.as_str());
        });
    }

    save_atomic(db, path, key)
}

/// Interactive edit of title / username / password for an existing entry.
pub fn edit_entry(
    db: &mut Database,
    entry_id: EntryId,
    dmenu_bin: &str,
    path: &Path,
    key: DatabaseKey,
) -> Result<(), String> {
    let (cur_title, cur_user) = {
        let e = db
            .entry(entry_id)
            .ok_or_else(|| "entry not found".to_string())?;
        (
            e.get_title().unwrap_or("").to_string(),
            e.get_username().unwrap_or("").to_string(),
        )
    };

    let title = prompt_text(dmenu_bin, "Title", Some(&cur_title))?
        .ok_or_else(|| "edit cancelled".to_string())?;
    let username = prompt_text(dmenu_bin, "Username", Some(&cur_user))?
        .ok_or_else(|| "edit cancelled".to_string())?;

    let new_password = dmenu::prompt_password(dmenu_bin, "Password (empty=keep)")?;

    {
        let mut e = db
            .entry_mut(entry_id)
            .ok_or_else(|| "entry not found".to_string())?;
        e.set_unprotected(fields::TITLE, title);
        e.set_unprotected(fields::USERNAME, username);
        if let Some(pw) = new_password {
            if !pw.is_empty() {
                e.set_protected(fields::PASSWORD, pw.as_str());
            }
        }
    }

    save_atomic(db, path, key)
}

/// Delete with Yes/No confirm, then save.
pub fn delete_entry(
    db: &mut Database,
    entry_id: EntryId,
    dmenu_bin: &str,
    path: &Path,
    key: DatabaseKey,
) -> Result<(), String> {
    let title = db
        .entry(entry_id)
        .and_then(|e| e.get_title().map(|s| s.to_string()))
        .unwrap_or_else(|| "(untitled)".into());

    let choices = vec!["No".into(), "Yes".into()];
    let confirm = dmenu::select(dmenu_bin, &format!("Delete {title}?"), &choices)?
        .ok_or_else(|| "delete cancelled".to_string())?;
    if confirm != "Yes" {
        return Err("delete cancelled".into());
    }

    {
        let e = db
            .entry_mut(entry_id)
            .ok_or_else(|| "entry not found".to_string())?;
        e.remove();
    }

    save_atomic(db, path, key)
}

fn prompt_text(
    dmenu_bin: &str,
    prompt: &str,
    current: Option<&str>,
) -> Result<Option<String>, String> {
    let items = match current {
        Some(c) if !c.is_empty() => vec![c.to_string()],
        _ => Vec::new(),
    };
    // With an empty list, feed a blank line so dmenu still opens for free-typed input.
    let items = if items.is_empty() {
        vec![String::new()]
    } else {
        items
    };
    dmenu::select(dmenu_bin, prompt, &items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretString;
    use crate::unlock::unlock_with_password;
    use std::path::PathBuf;

    #[test]
    fn atomic_save_roundtrip_smoke() {
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/smoke.kdbx");
        let dir = std::env::temp_dir();
        let dst = dir.join(format!("keymenu-smoke-{}.kdbx", std::process::id()));

        fs::copy(&src, &dst).expect("copy fixture");
        let pw = SecretString::new("testpass".into());
        let mut db = unlock_with_password(&dst, &pw).expect("unlock");

        {
            let mut root = db.root_mut();
            root.add_entry().edit(|e| {
                e.set_unprotected(fields::TITLE, "AddedByTest");
                e.set_unprotected(fields::USERNAME, "t");
                e.set_protected(fields::PASSWORD, "p");
            });
        }

        let key = DatabaseKey::new().with_password(pw.as_str());
        save_atomic(&mut db, &dst, key.clone()).expect("save");

        let db2 = unlock_with_password(&dst, &pw).expect("reopen");
        let titles: Vec<_> = db2
            .iter_all_entries()
            .filter_map(|e| e.get_title().map(|s| s.to_string()))
            .collect();
        assert!(titles.iter().any(|t| t == "AddedByTest"));
        let _ = fs::remove_file(&dst);
    }
}
