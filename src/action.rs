//! Post-select action menu (always shown).

use keepass::db::{EntryId, EntryRef};
use keepass::{Database, DatabaseKey};

use crate::config::Config;
use crate::dmenu;
use crate::mutate;
use crate::secret::{self, SecretString};

#[cfg(target_os = "linux")]
use crate::{autotype, clipboard};

pub const ACTION_PASSWORD: &str = "Password";
pub const ACTION_USERNAME: &str = "Username";
pub const ACTION_AUTOTYPE: &str = "Autotype";
pub const ACTION_EDIT: &str = "Edit";
pub const ACTION_DELETE: &str = "Delete";

/// Actions shown after selecting an entry.
pub fn entry_actions() -> Vec<String> {
    vec![
        ACTION_PASSWORD.into(),
        ACTION_USERNAME.into(),
        ACTION_AUTOTYPE.into(),
        ACTION_EDIT.into(),
        ACTION_DELETE.into(),
    ]
}

/// Run the always-on action menu for a selected entry.
pub fn run_for_entry(
    db: &mut Database,
    entry_id: EntryId,
    cfg: &Config,
    key: DatabaseKey,
) -> Result<(), String> {
    let actions = entry_actions();
    let choice = dmenu::select(&cfg.dmenu_bin, "action", &actions)?
        .ok_or_else(|| "no action selected".to_string())?;

    match choice.as_str() {
        ACTION_EDIT => mutate::edit_entry(db, entry_id, &cfg.dmenu_bin, &cfg.db_path, key),
        ACTION_DELETE => mutate::delete_entry(db, entry_id, &cfg.dmenu_bin, &cfg.db_path, key),
        other => {
            let entry = db
                .entry(entry_id)
                .ok_or_else(|| "selected entry no longer exists".to_string())?;
            dispatch_copy_or_type(&entry, other, cfg)
        }
    }
}

fn dispatch_copy_or_type(entry: &EntryRef<'_>, choice: &str, cfg: &Config) -> Result<(), String> {
    match choice {
        ACTION_PASSWORD => {
            let pw = entry
                .get_password()
                .ok_or_else(|| "entry has no password".to_string())?;
            let secret = secret::owned(pw);
            copy_secret(&secret, cfg)?;
        }
        ACTION_USERNAME => {
            let user = entry
                .get_username()
                .ok_or_else(|| "entry has no username".to_string())?;
            let secret = secret::owned(user);
            copy_secret(&secret, cfg)?;
        }
        ACTION_AUTOTYPE => {
            let user = secret::owned(entry.get_username().unwrap_or(""));
            let pw = secret::owned(entry.get_password().unwrap_or(""));
            autotype_user_pass(&user, &pw)?;
        }
        other => return Err(format!("unknown action: {other}")),
    }
    Ok(())
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

fn autotype_user_pass(user: &SecretString, pw: &SecretString) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        autotype::username_tab_password(user, pw)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (user, pw);
        Err("autotype is only supported on Linux/X11".into())
    }
}
