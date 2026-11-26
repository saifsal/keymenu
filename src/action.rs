//! Post-select action menu (always shown).

use keepass::db::EntryRef;
use keepass::Database;

use crate::config::Config;
use crate::dmenu;
use crate::secret::{self, SecretString};

#[cfg(target_os = "linux")]
use crate::{autotype, clipboard};

pub const ACTION_PASSWORD: &str = "Password";
pub const ACTION_USERNAME: &str = "Username";
pub const ACTION_AUTOTYPE: &str = "Autotype";

/// Base actions for commit 1.
pub fn base_actions() -> Vec<String> {
    vec![
        ACTION_PASSWORD.into(),
        ACTION_USERNAME.into(),
        ACTION_AUTOTYPE.into(),
    ]
}

/// Run the always-on action menu for a selected entry.
pub fn run_for_entry(db: &Database, entry_id: keepass::db::EntryId, cfg: &Config) -> Result<(), String> {
    let entry = db
        .entry(entry_id)
        .ok_or_else(|| "selected entry no longer exists".to_string())?;

    let actions = base_actions();
    let choice = dmenu::select(&cfg.dmenu_bin, "action", &actions)?
        .ok_or_else(|| "no action selected".to_string())?;

    dispatch(&entry, &choice, cfg)
}

fn dispatch(entry: &EntryRef<'_>, choice: &str, cfg: &Config) -> Result<(), String> {
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
