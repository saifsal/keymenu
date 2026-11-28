//! Post-select action menu (always shown).

use keepass::db::EntryId;
use keepass::{Database, DatabaseKey};

use crate::config::Config;
use crate::dmenu;
use crate::fields::{self, ACTION_ATTACHMENTS, ACTION_OTP};
use crate::mutate::{self, FileSnapshot};
use crate::secret::{self, SecretString};

#[cfg(target_os = "linux")]
use crate::autotype;

pub const ACTION_PASSWORD: &str = "Password";
pub const ACTION_USERNAME: &str = "Username";
pub const ACTION_AUTOTYPE: &str = "Autotype";
pub const ACTION_EDIT: &str = "Edit";
pub const ACTION_DELETE: &str = "Delete";

/// Outcome that lets the caller drop `db`/`key` before a long clipboard hold.
pub enum AfterAction {
    Done,
    Clipboard(SecretString),
    Autotype {
        username: SecretString,
        password: SecretString,
    },
}

/// Build the action list for an entry (OTP / custom fields / attachments when present).
pub fn actions_for_entry(entry: &keepass::db::EntryRef<'_>) -> Vec<String> {
    let mut actions = vec![
        ACTION_PASSWORD.into(),
        ACTION_USERNAME.into(),
        ACTION_AUTOTYPE.into(),
    ];
    if fields::has_otp(entry) {
        actions.push(ACTION_OTP.into());
    }
    for name in fields::custom_field_names(entry) {
        // Prefix so custom fields cannot collide with built-in action names in display;
        // selection is still index-based.
        actions.push(format!("Field: {name}"));
    }
    if fields::has_attachments(entry) {
        actions.push(ACTION_ATTACHMENTS.into());
    }
    actions.push(ACTION_EDIT.into());
    actions.push(ACTION_DELETE.into());
    actions
}

/// Run the always-on action menu for a selected entry.
pub fn run_for_entry(
    db: &mut Database,
    entry_id: EntryId,
    cfg: &Config,
    key: DatabaseKey,
    snapshot: &FileSnapshot,
) -> Result<AfterAction, String> {
    let actions = {
        let entry = db
            .entry(entry_id)
            .ok_or_else(|| "selected entry no longer exists".to_string())?;
        actions_for_entry(&entry)
    };

    let idx = dmenu::select_index(&cfg.dmenu_bin, "action", &actions)?
        .ok_or_else(|| "no action selected".to_string())?;
    let choice = actions
        .get(idx)
        .ok_or_else(|| "invalid action index".to_string())?;

    match choice.as_str() {
        ACTION_EDIT => {
            mutate::edit_entry(
                db,
                entry_id,
                &cfg.dmenu_bin,
                &cfg.password_mode,
                snapshot,
                key,
            )?;
            Ok(AfterAction::Done)
        }
        ACTION_DELETE => {
            mutate::delete_entry(db, entry_id, &cfg.dmenu_bin, snapshot, key)?;
            Ok(AfterAction::Done)
        }
        ACTION_ATTACHMENTS => {
            let entry = db
                .entry(entry_id)
                .ok_or_else(|| "selected entry no longer exists".to_string())?;
            fields::save_attachment(&entry, &cfg.dmenu_bin)?;
            Ok(AfterAction::Done)
        }
        ACTION_AUTOTYPE => {
            let entry = db
                .entry(entry_id)
                .ok_or_else(|| "selected entry no longer exists".to_string())?;
            let username = secret::owned(entry.get_username().unwrap_or(""));
            let password = secret::owned(entry.get_password().unwrap_or(""));
            Ok(AfterAction::Autotype { username, password })
        }
        ACTION_PASSWORD => {
            let entry = db
                .entry(entry_id)
                .ok_or_else(|| "selected entry no longer exists".to_string())?;
            let pw = entry
                .get_password()
                .ok_or_else(|| "entry has no password".to_string())?;
            Ok(AfterAction::Clipboard(secret::owned(pw)))
        }
        ACTION_USERNAME => {
            let entry = db
                .entry(entry_id)
                .ok_or_else(|| "selected entry no longer exists".to_string())?;
            let user = entry
                .get_username()
                .ok_or_else(|| "entry has no username".to_string())?;
            Ok(AfterAction::Clipboard(secret::owned(user)))
        }
        ACTION_OTP => {
            let entry = db
                .entry(entry_id)
                .ok_or_else(|| "selected entry no longer exists".to_string())?;
            Ok(AfterAction::Clipboard(fields::otp_code(&entry)?))
        }
        other if other.starts_with("Field: ") => {
            let name = &other["Field: ".len()..];
            let entry = db
                .entry(entry_id)
                .ok_or_else(|| "selected entry no longer exists".to_string())?;
            Ok(AfterAction::Clipboard(fields::copy_field_value(
                &entry, name,
            )?))
        }
        other => Err(format!("unknown action: {other}")),
    }
}

pub fn run_autotype(username: &SecretString, password: &SecretString) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        autotype::username_tab_password(username, password)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (username, password);
        Err("autotype is only supported on Linux/X11".into())
    }
}
