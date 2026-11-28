//! Add / edit / delete entries and atomically save as KDBX4.

use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use keepass::config::DatabaseVersion;
use keepass::db::{fields, EntryId};
use keepass::{Database, DatabaseKey};

use crate::dmenu::{self, Outcome, PasswordMode};
use crate::secret::SecretString;

const ADD_LABEL: &str = "+ Add entry";
/// Sentinel typed into an edit prompt to clear a non-empty field.
const CLEAR_SENTINEL: &str = "-";

pub fn add_label() -> &'static str {
    ADD_LABEL
}

/// Snapshot of the vault file at unlock time (for lost-update detection + mode/owner).
#[derive(Debug, Clone)]
pub struct FileSnapshot {
    /// Path as given by the user (may be a symlink).
    #[allow(dead_code)]
    pub user_path: PathBuf,
    /// Canonical path of the regular file we will overwrite.
    pub resolved: PathBuf,
    pub mtime: SystemTime,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

impl FileSnapshot {
    pub fn capture(user_path: &Path) -> Result<Self, String> {
        let meta = fs::symlink_metadata(user_path)
            .map_err(|e| format!("stat {}: {e}", user_path.display()))?;
        let resolved = if meta.file_type().is_symlink() || user_path.exists() {
            fs::canonicalize(user_path)
                .map_err(|e| format!("canonicalize {}: {e}", user_path.display()))?
        } else {
            return Err(format!("database not found: {}", user_path.display()));
        };
        let meta =
            fs::metadata(&resolved).map_err(|e| format!("stat {}: {e}", resolved.display()))?;
        Ok(FileSnapshot {
            user_path: user_path.to_path_buf(),
            resolved,
            mtime: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            size: meta.len(),
            mode: meta.permissions().mode(),
            uid: meta.uid(),
            gid: meta.gid(),
        })
    }

    pub fn unchanged(&self) -> Result<bool, String> {
        let meta = fs::metadata(&self.resolved)
            .map_err(|e| format!("stat {}: {e}", self.resolved.display()))?;
        let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        Ok(mtime == self.mtime && meta.len() == self.size)
    }
}

/// Prompt before upgrading non-KDBX4 databases; refuse KDB/KDB2.
pub fn prepare_version_for_save(db: &mut Database, dmenu_bin: &str) -> Result<(), String> {
    match db.config.version {
        DatabaseVersion::KDB4(_) => Ok(()),
        DatabaseVersion::KDB3(_) => {
            let choices = vec!["No".into(), "Yes".into()];
            let confirm = dmenu::select(dmenu_bin, "Upgrade KDBX3 → KDBX4 on save?", &choices)?
                .ok_or_else(|| "upgrade cancelled".to_string())?;
            if confirm != "Yes" {
                return Err("refusing to save without KDBX4 upgrade".into());
            }
            db.config.version = DatabaseVersion::KDB4(1);
            Ok(())
        }
        DatabaseVersion::KDB(_) | DatabaseVersion::KDB2(_) => {
            Err("refusing to save KDB/KDB2 databases (only KDBX3/4 supported for write)".into())
        }
    }
}

/// Write `db` to the resolved vault path via create_new temp + sync + rename + dir fsync.
pub fn save_atomic(
    db: &mut Database,
    snapshot: &FileSnapshot,
    key: DatabaseKey,
    dmenu_bin: &str,
) -> Result<(), String> {
    if !snapshot.unchanged()? {
        return Err(format!(
            "database changed on disk since unlock ({}); refusing to overwrite",
            snapshot.resolved.display()
        ));
    }

    prepare_version_for_save(db, dmenu_bin)?;

    // Re-check after any dmenu prompt (e.g. KDBX3 upgrade) so a sync mid-prompt is caught.
    if !snapshot.unchanged()? {
        return Err(format!(
            "database changed on disk since unlock ({}); refusing to overwrite",
            snapshot.resolved.display()
        ));
    }

    write_atomic_bytes(db, snapshot, key)
}

fn write_atomic_bytes(
    db: &mut Database,
    snapshot: &FileSnapshot,
    key: DatabaseKey,
) -> Result<(), String> {
    let parent = snapshot
        .resolved
        .parent()
        .ok_or_else(|| "database path has no parent directory".to_string())?;

    let mode = if snapshot.mode & 0o777 == 0 {
        0o600
    } else {
        snapshot.mode & 0o777
    };

    let suffix = unique_suffix();
    let tmp = parent.join(format!(
        ".{}.keymenu.{}.tmp",
        snapshot
            .resolved
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("vault.kdbx"),
        suffix
    ));

    let write_result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
            .map_err(|e| format!("create {}: {e}", tmp.display()))?;

        // Apply exact mode (defeat umask) and restore owning group when possible.
        let mut perms = file
            .metadata()
            .map_err(|e| format!("meta {}: {e}", tmp.display()))?
            .permissions();
        perms.set_mode(mode);
        fs::set_permissions(&tmp, perms).map_err(|e| format!("chmod {}: {e}", tmp.display()))?;
        let rc = unsafe { libc::fchown(file.as_raw_fd(), snapshot.uid, snapshot.gid) };
        if rc != 0 {
            // Non-fatal if we lack privilege to chown (e.g. not owner of group).
            let err = io::Error::last_os_error();
            eprintln!("keymenu: warning: could not restore owner/group on temp file: {err}");
        }

        db.save(&mut file, key)
            .map_err(|e| format!("save failed: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("sync {}: {e}", tmp.display()))?;
        drop(file);

        fs::rename(&tmp, &snapshot.resolved).map_err(|e| {
            format!(
                "rename {} → {}: {e}",
                tmp.display(),
                snapshot.resolved.display()
            )
        })?;

        fsync_dir(parent)?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    write_result
}

fn unique_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}-{}", nanos, std::process::id())
}

fn fsync_dir(dir: &Path) -> Result<(), String> {
    let f = OpenOptions::new()
        .read(true)
        .open(dir)
        .map_err(|e| format!("open dir {}: {e}", dir.display()))?;
    let rc = unsafe { libc::fsync(f.as_raw_fd()) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        return Err(format!("fsync dir {}: {err}", dir.display()));
    }
    Ok(())
}

/// Interactive add: prompt title / username / password, append entry, save.
pub fn add_entry(
    db: &mut Database,
    dmenu_bin: &str,
    password_mode: &PasswordMode,
    snapshot: &FileSnapshot,
    key: DatabaseKey,
) -> Result<(), String> {
    let title = match dmenu::prompt_free(dmenu_bin, "Title")? {
        Outcome::Cancelled | Outcome::Empty => return Err("add cancelled".into()),
        Outcome::Value(v) => v,
    };
    let username = match dmenu::prompt_free(dmenu_bin, "Username")? {
        Outcome::Cancelled => return Err("add cancelled".into()),
        Outcome::Empty => String::new(),
        Outcome::Value(v) => v,
    };
    let password = match dmenu::prompt_password(dmenu_bin, password_mode, "Password")? {
        Outcome::Cancelled => return Err("add cancelled".into()),
        Outcome::Empty => SecretString::new(String::new()),
        Outcome::Value(v) => SecretString::new(v),
    };

    {
        let mut root = db.root_mut();
        root.add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, title);
            e.set_unprotected(fields::USERNAME, username);
            e.set_protected(fields::PASSWORD, password.as_str());
        });
    }

    save_atomic(db, snapshot, key, dmenu_bin)
}

/// Interactive edit of title / username / password for an existing entry.
///
/// Escape cancels; empty Enter keeps the current value (including empty fields).
/// Type `-` alone to clear a non-empty field.
pub fn edit_entry(
    db: &mut Database,
    entry_id: EntryId,
    dmenu_bin: &str,
    password_mode: &PasswordMode,
    snapshot: &FileSnapshot,
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

    let title = match edit_field(dmenu_bin, "Title", &cur_title)? {
        None => return Err("edit cancelled".into()),
        Some(v) => v,
    };
    let username = match edit_field(dmenu_bin, "Username", &cur_user)? {
        None => return Err("edit cancelled".into()),
        Some(v) => v,
    };

    let new_password =
        match dmenu::prompt_password(dmenu_bin, password_mode, "Password (empty=keep)")? {
            Outcome::Cancelled => return Err("edit cancelled".into()),
            Outcome::Empty => None,
            Outcome::Value(v) if v.is_empty() => None,
            Outcome::Value(v) => Some(SecretString::new(v)),
        };

    {
        let mut e = db
            .entry_mut(entry_id)
            .ok_or_else(|| "entry not found".to_string())?;
        e.edit_tracking(|t| {
            t.set_unprotected(fields::TITLE, title);
            t.set_unprotected(fields::USERNAME, username);
            if let Some(ref pw) = new_password {
                t.set_protected(fields::PASSWORD, pw.as_str());
            }
        });
    }

    save_atomic(db, snapshot, key, dmenu_bin)
}

/// Returns `None` on cancel; `Some(value)` with empty string allowed (keep or clear).
fn edit_field(dmenu_bin: &str, name: &str, current: &str) -> Result<Option<String>, String> {
    let prompt = if current.is_empty() {
        format!("{name} [empty]")
    } else {
        format!("{name} [{current}] (− clears)")
    };
    match dmenu::prompt_free(dmenu_bin, &prompt)? {
        Outcome::Cancelled => Ok(None),
        Outcome::Empty => Ok(Some(current.to_string())), // keep (including empty)
        Outcome::Value(v) if v == CLEAR_SENTINEL && !current.is_empty() => Ok(Some(String::new())),
        Outcome::Value(v) => Ok(Some(v)),
    }
}

/// Delete with Yes/No confirm: recycle bin when enabled, else track_changes().remove().
pub fn delete_entry(
    db: &mut Database,
    entry_id: EntryId,
    dmenu_bin: &str,
    snapshot: &FileSnapshot,
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

    let use_bin = db.meta.recyclebin_enabled.unwrap_or(false);
    if use_bin {
        if let Some(bin) = db.recycle_bin() {
            let bin_id = bin.id();
            let mut e = db
                .entry_mut(entry_id)
                .ok_or_else(|| "entry not found".to_string())?;
            e.track_changes()
                .move_to(bin_id)
                .map_err(|e| format!("move to recycle bin: {e}"))?;
        } else {
            let mut e = db
                .entry_mut(entry_id)
                .ok_or_else(|| "entry not found".to_string())?;
            e.track_changes().remove();
        }
    } else {
        let mut e = db
            .entry_mut(entry_id)
            .ok_or_else(|| "entry not found".to_string())?;
        e.track_changes().remove();
    }

    save_atomic(db, snapshot, key, dmenu_bin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretString;
    use crate::unlock::unlock_with_password;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::Command;

    fn fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/smoke.kdbx")
    }

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "keymenu-test-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    fn temp_copy(name: &str) -> PathBuf {
        let dir = temp_dir();
        let dst = dir.join(name);
        fs::copy(fixture(), &dst).expect("copy");
        let mut perms = fs::metadata(&dst).unwrap().permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&dst, perms).unwrap();
        dst
    }

    fn write_fake_dmenu(dir: &Path, answers: &str) -> PathBuf {
        let answers_path = dir.join("answers.txt");
        fs::write(&answers_path, answers).unwrap();
        let script = dir.join("fake-dmenu.sh");
        // Script: -h → vanilla usage; otherwise consume stdin, emit next answer line.
        // EMPTY → success with empty stdout; ESC → exit 1; otherwise print the line.
        let body = format!(
            r#"#!/bin/sh
ANSWERS="{answers}"
if [ "$1" = "-h" ]; then
  echo 'usage: dmenu [-bfiv]' >&2
  exit 1
fi
cat >/dev/null
if [ ! -s "$ANSWERS" ]; then
  exit 1
fi
line=$(sed -n '1p' "$ANSWERS")
tail -n +2 "$ANSWERS" > "$ANSWERS.tmp" && mv "$ANSWERS.tmp" "$ANSWERS"
case "$line" in
  ESC) exit 1 ;;
  EMPTY) exit 0 ;;
  *) printf '%s\n' "$line"; exit 0 ;;
esac
"#,
            answers = answers_path.display()
        );
        fs::write(&script, body).unwrap();
        let mut perms = fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).unwrap();
        script
    }

    fn visible_pw_mode() -> PasswordMode {
        PasswordMode {
            flag: Some(String::new()),
            allow_visible: true,
        }
    }

    #[test]
    fn atomic_save_preserves_mode_and_symlink() {
        let real = temp_copy("real.kdbx");
        let dir = real.parent().unwrap();
        let link = dir.join("link.kdbx");
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        let snap = FileSnapshot::capture(&link).expect("snap");
        assert_eq!(snap.resolved, fs::canonicalize(&real).unwrap());

        let pw = SecretString::new("testpass".into());
        let mut db = unlock_with_password(&link, &pw).expect("unlock");
        {
            let mut root = db.root_mut();
            root.add_entry().edit(|e| {
                e.set_unprotected(fields::TITLE, "ViaSymlink");
                e.set_protected(fields::PASSWORD, "x");
            });
        }
        let key = DatabaseKey::new().with_password(pw.as_str());
        save_atomic(&mut db, &snap, key, "true").expect("save");

        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        let mode = fs::metadata(&real).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let db2 = unlock_with_password(&link, &pw).expect("reopen");
        assert!(db2
            .iter_all_entries()
            .any(|e| e.get_title() == Some("ViaSymlink")));
    }

    #[test]
    fn edit_entry_and_delete_entry_via_fake_dmenu() {
        let path = temp_copy("crud.kdbx");
        let dir = path.parent().unwrap().to_path_buf();
        let snap = FileSnapshot::capture(&path).unwrap();
        let pw = SecretString::new("testpass".into());
        let mut db = unlock_with_password(&path, &pw).unwrap();
        let entry_id = db
            .iter_all_entries()
            .find(|e| e.get_title() == Some("Email"))
            .unwrap()
            .id();
        let hist_before = db
            .entry(entry_id)
            .unwrap()
            .history
            .as_ref()
            .map(|h| h.get_entries().len())
            .unwrap_or(0);

        // Title=Git, Username=keep empty-enter, Password=keep empty
        let fake = write_fake_dmenu(&dir, "Git\nEMPTY\nEMPTY\n");
        let key = DatabaseKey::new().with_password(pw.as_str());
        edit_entry(
            &mut db,
            entry_id,
            fake.to_str().unwrap(),
            &visible_pw_mode(),
            &snap,
            key.clone(),
        )
        .expect("edit_entry");

        {
            let entry = db.entry(entry_id).unwrap();
            assert_eq!(entry.get_title(), Some("Git"));
            assert_eq!(entry.get_username(), Some("user@example.com"));
            let hist_after = entry
                .history
                .as_ref()
                .map(|h| h.get_entries().len())
                .unwrap_or(0);
            assert_eq!(hist_after, hist_before + 1);
        }

        // Refresh snapshot after edit saved.
        let snap2 = FileSnapshot::capture(&path).unwrap();
        let fake_del = write_fake_dmenu(&dir, "Yes\n");
        let uuid = entry_id.uuid();
        delete_entry(&mut db, entry_id, fake_del.to_str().unwrap(), &snap2, key)
            .expect("delete_entry");
        assert!(db.deleted_objects.contains_key(&uuid));
        assert!(db.entry(entry_id).is_none());
    }

    #[test]
    fn edit_field_clear_sentinel() {
        let dir = temp_dir();
        let fake = write_fake_dmenu(&dir, "-\n");
        let got = edit_field(fake.to_str().unwrap(), "Username", "alice").unwrap();
        assert_eq!(got.as_deref(), Some(""));
    }

    #[test]
    fn save_cleans_temp_when_rename_fails() {
        let dir = temp_dir();
        let path = dir.join("vault.kdbx");
        fs::copy(fixture(), &path).unwrap();
        let mut snap = FileSnapshot::capture(&path).unwrap();
        let pw = SecretString::new("testpass".into());
        let mut db = unlock_with_password(&path, &pw).unwrap();

        // Replace the vault file with a directory so rename(tmp → path) fails with EISDIR,
        // after a temp file has been created. Refresh snapshot so unchanged() passes.
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let meta = fs::metadata(&path).unwrap();
        snap.mtime = meta.modified().unwrap();
        snap.size = meta.len();
        snap.mode = meta.permissions().mode();

        let key = DatabaseKey::new().with_password(pw.as_str());
        let err = save_atomic(&mut db, &snap, key, "true").unwrap_err();
        assert!(
            err.contains("rename") || err.contains("Is a directory") || err.contains("EISDIR"),
            "unexpected err: {err}"
        );
        for e in fs::read_dir(&dir).unwrap() {
            let n = e.unwrap().file_name().to_string_lossy().into_owned();
            assert!(
                !n.contains(".keymenu.") || !n.ends_with(".tmp"),
                "leftover temp: {n}"
            );
        }
    }

    #[test]
    fn fake_dmenu_script_is_executable() {
        let dir = temp_dir();
        let fake = write_fake_dmenu(&dir, "x\n");
        let status = Command::new(&fake).arg("-h").status().unwrap();
        assert!(!status.success());
    }
}
