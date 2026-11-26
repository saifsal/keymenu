//! Custom fields, attachments, and TOTP helpers (dmenu-only UX).

use std::fs;
use std::path::PathBuf;

use keepass::db::{fields as kp_fields, EntryRef};

use crate::dmenu;
use crate::secret::{self, SecretString};

#[cfg(target_os = "linux")]
use crate::clipboard;
use crate::config::Config;

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
pub fn copy_field(entry: &EntryRef<'_>, name: &str, cfg: &Config) -> Result<(), String> {
    let value = entry
        .get(name)
        .ok_or_else(|| format!("field {name} missing"))?;
    let secret = secret::owned(value);
    copy_secret(&secret, cfg)
}

pub fn has_attachments(entry: &EntryRef<'_>) -> bool {
    entry.attachments().next().is_some()
}

/// List attachments, pick one, prompt for destination path, write bytes.
pub fn save_attachment(entry: &EntryRef<'_>, dmenu_bin: &str) -> Result<(), String> {
    let named: Vec<(String, Vec<u8>)> = entry
        .attachments_named()
        .map(|(name, att)| {
            let data = att.get().clone();
            (name.to_string(), data)
        })
        .collect();

    if named.is_empty() {
        return Err("entry has no attachments".into());
    }

    let labels: Vec<String> = named.iter().map(|(n, _)| n.clone()).collect();
    let choice = dmenu::select(dmenu_bin, "attachment", &labels)?
        .ok_or_else(|| "no attachment selected".to_string())?;

    let (name, data) = named
        .into_iter()
        .find(|(n, _)| n == &choice)
        .ok_or_else(|| format!("unknown attachment: {choice}"))?;

    let default = default_save_path(&name);
    let dest = dmenu::select(dmenu_bin, "save path", &[default.clone()])?
        .ok_or_else(|| "save cancelled".to_string())?;
    let dest = if dest.is_empty() { default } else { dest };

    let path = PathBuf::from(&dest);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
    }
    fs::write(&path, &data).map_err(|e| format!("write {}: {e}", path.display()))?;
    eprintln!("keymenu: wrote attachment to {}", path.display());
    Ok(())
}

fn default_save_path(name: &str) -> String {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(name).to_string_lossy().into_owned()
}

fn copy_secret(secret: &SecretString, cfg: &Config) -> Result<(), String> {
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
}
