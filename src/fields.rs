//! Custom fields, attachments, and TOTP helpers (dmenu-only UX).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use keepass::db::{fields as kp_fields, EntryRef};
use zeroize::Zeroize;

use crate::config::Config;
use crate::dmenu::{self, Outcome};
use crate::secret::{self, SecretString};

#[cfg(target_os = "linux")]
use crate::clipboard;

pub const ACTION_OTP: &str = "OTP";
pub const ACTION_ATTACHMENTS: &str = "Attachments…";

const STANDARD_SKIP: &[&str] = &[
    kp_fields::TITLE,
    kp_fields::USERNAME,
    kp_fields::PASSWORD,
    kp_fields::URL,
    kp_fields::NOTES,
    kp_fields::OTP,
];

/// Whether this entry has a parseable OTP field.
pub fn has_otp(entry: &EntryRef<'_>) -> bool {
    entry.get_raw_otp_value().is_some() && entry.get_otp().is_ok()
}

/// Current TOTP code as a zeroizing string.
pub fn otp_code(entry: &EntryRef<'_>) -> Result<SecretString, String> {
    let totp = entry.get_otp().map_err(|e| format!("OTP: {e}"))?;
    let code = totp
        .value_now()
        .map_err(|e| format!("OTP time: {e}"))?
        .code;
    Ok(SecretString::new(code))
}

/// Custom (non-standard) field names present on the entry, sorted.
pub fn custom_field_names(entry: &EntryRef<'_>) -> Vec<String> {
    let mut names: Vec<String> = entry
        .fields
        .keys()
        .filter(|k| !STANDARD_SKIP.iter().any(|s| s.eq_ignore_ascii_case(k)))
        .cloned()
        .collect();
    names.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()));
    names
}

/// Copy a named field value to the clipboard.
pub fn copy_field_value(entry: &EntryRef<'_>, name: &str) -> Result<SecretString, String> {
    let value = entry
        .get(name)
        .ok_or_else(|| format!("field {name} missing"))?;
    Ok(secret::owned(value))
}

pub fn has_attachments(entry: &EntryRef<'_>) -> bool {
    entry.attachments().next().is_some()
}

/// List attachment names only (no data clone until one is chosen).
pub fn attachment_names(entry: &EntryRef<'_>) -> Vec<String> {
    entry
        .attachments_named()
        .map(|(n, _)| n.to_string())
        .collect()
}

/// List attachments, pick one, prompt for destination path, write with 0600 / create_new.
pub fn save_attachment(entry: &EntryRef<'_>, dmenu_bin: &str) -> Result<(), String> {
    let names = attachment_names(entry);
    if names.is_empty() {
        return Err("entry has no attachments".into());
    }

    let idx = dmenu::select_index(dmenu_bin, "attachment", &names)?
        .ok_or_else(|| "no attachment selected".to_string())?;
    let name = names
        .get(idx)
        .ok_or_else(|| "invalid attachment index".to_string())?;

    let att = entry
        .attachment_by_name(name)
        .ok_or_else(|| format!("attachment missing: {name}"))?;
    let mut data = att.get().clone();

    let default = default_save_path(name);
    let dest = match dmenu::prompt_free(dmenu_bin, &format!("save path [{default}]"))? {
        Outcome::Cancelled => {
            data.zeroize();
            return Err("save cancelled".into());
        }
        Outcome::Empty => default,
        Outcome::Value(v) => v,
    };

    let path = PathBuf::from(&dest);
    let result = write_attachment_file(&path, &data, dmenu_bin);
    data.zeroize();
    result?;
    eprintln!("keymenu: wrote attachment to {}", path.display());
    Ok(())
}

/// Write attachment via temp `create_new` 0600 + rename (does not follow symlinks).
pub fn write_attachment_file(path: &Path, data: &[u8], dmenu_bin: &str) -> Result<(), String> {
    if path_exists_including_symlink(path) {
        let choices = vec!["No".into(), "Yes".into()];
        let confirm = dmenu::select(
            dmenu_bin,
            &format!("Overwrite {}?", path.display()),
            &choices,
        )?
        .ok_or_else(|| "overwrite cancelled".to_string())?;
        if confirm != "Yes" {
            return Err("overwrite cancelled".into());
        }
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }

    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = parent.join(format!(
        ".{}.keymenu-att.{}.tmp",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("attachment"),
        suffix
    ));

    let write_result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("create {}: {e}", tmp.display()))?;
        // Defeat umask narrowing.
        let mut perms = file.metadata().map_err(|e| format!("meta: {e}"))?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&tmp, perms).map_err(|e| format!("chmod {}: {e}", tmp.display()))?;

        file.write_all(data)
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        file.sync_all()
            .map_err(|e| format!("sync {}: {e}", tmp.display()))?;
        drop(file);

        // rename replaces a symlink at `path` rather than writing through it.
        fs::rename(&tmp, path).map_err(|e| {
            format!("rename {} → {}: {e}", tmp.display(), path.display())
        })?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    write_result
}

fn path_exists_including_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn default_save_path(name: &str) -> String {
    let base = Path::new(name)
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("attachment.bin");
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(base).to_string_lossy().into_owned()
}

pub fn copy_secret(secret: &SecretString, cfg: &Config) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        clipboard::copy_with_ttl(secret, cfg.clipboard_ttl)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (secret, cfg);
        Err("clipboard is only supported on Linux/X11".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unlock::unlock_with_password;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    #[test]
    fn smoke_entry_has_otp_custom_and_attachment() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/smoke.kdbx");
        let pw = SecretString::new("testpass".into());
        let db = unlock_with_password(&path, &pw).expect("unlock");
        let vpn = db
            .iter_all_entries()
            .find(|e| e.get_title() == Some("VPN"))
            .expect("VPN");
        assert!(has_otp(&vpn));
        let code = otp_code(&vpn).expect("otp");
        assert!(!code.is_empty());
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert!(custom_field_names(&vpn).iter().any(|n| n == "API Key"));
        assert!(has_attachments(&vpn));
    }

    #[test]
    fn default_path_uses_file_name_only() {
        let p = default_save_path("/home/u/.bashrc");
        assert!(p.ends_with(".bashrc") || p.ends_with("bashrc"));
        assert!(!p.contains("/home/u/.bashrc"));
        let p2 = default_save_path("../x");
        assert!(p2.ends_with("x"));
    }

    #[test]
    fn overwrite_uses_temp_rename_not_symlink_target() {
        let dir = std::env::temp_dir().join(format!("keymenu-att-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let real = dir.join("real.key");
        let link = dir.join("link.key");
        fs::write(&real, b"old-secret").unwrap();
        let mut perms = fs::metadata(&real).unwrap().permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&real, perms).unwrap();
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // Confirm overwrite via fake dmenu that always answers Yes.
        let fake = dir.join("yes-dmenu.sh");
        fs::write(
            &fake,
            "#!/bin/sh\nif [ \"$1\" = \"-h\" ]; then echo 'usage: dmenu [-bfiv]' >&2; exit 1; fi\ncat >/dev/null\necho Yes\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut p = fs::metadata(&fake).unwrap().permissions();
            p.set_mode(0o755);
            fs::set_permissions(&fake, p).unwrap();
        }

        write_attachment_file(&link, b"new-secret", fake.to_str().unwrap()).unwrap();

        // Symlink replaced by a regular 0600 file; target untouched.
        assert!(!link.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(fs::read(&link).unwrap(), b"new-secret");
        assert_eq!(fs::metadata(&link).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read(&real).unwrap(), b"old-secret");
    }
}
