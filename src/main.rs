//! keymenu — dmenu KeePass/KDBX password menu.

mod action;
mod autotype;
mod clipboard;
mod config;
mod dbview;
mod dmenu;
mod fields;
mod mutate;
mod secret;
mod unlock;

use std::env;
use std::process;

use action::AfterAction;
use config::Config;
use dmenu::Outcome;
use mutate::FileSnapshot;

fn main() {
    harden_process();
    if let Err(e) = run() {
        eprintln!("keymenu: {e}");
        process::exit(1);
    }
}

/// Reduce crash-dump leakage of unlocked secrets.
fn harden_process() {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let _ = libc::setrlimit(libc::RLIMIT_CORE, &mut lim);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let cfg = match Config::from_args(&args)? {
        None => {
            print!("{}", config::usage());
            return Ok(());
        }
        Some(c) => c,
    };

    let snapshot = FileSnapshot::capture(&cfg.db_path)?;

    let password_outcome =
        dmenu::prompt_password(&cfg.dmenu_bin, &cfg.password_mode, "Master password")?;
    let password = match password_outcome {
        Outcome::Value(p) if !p.is_empty() => Some(secret::SecretString::new(p)),
        Outcome::Cancelled | Outcome::Empty | Outcome::Value(_) => {
            if cfg.keyfile.is_some() && cfg.allow_keyfile_only {
                None
            } else if cfg.keyfile.is_some() {
                return Err(
                    "password cancelled/empty; pass --allow-keyfile-only to unlock with keyfile alone"
                        .into(),
                );
            } else {
                return Err("password prompt cancelled".into());
            }
        }
    };

    let (mut db, key) = unlock::unlock(
        &snapshot.resolved,
        password.as_ref(),
        cfg.keyfile.as_deref(),
    )?;
    drop(password);

    let items = dbview::flat_entries(&db);
    let mut menu_labels = vec![mutate::add_label().to_string()];
    menu_labels.extend(dbview::labels(&items));

    let idx = dmenu::select_index(&cfg.dmenu_bin, "keymenu", &menu_labels)?
        .ok_or_else(|| "no entry selected".to_string())?;

    if idx == 0 {
        return mutate::add_entry(
            &mut db,
            &cfg.dmenu_bin,
            &cfg.password_mode,
            &snapshot,
            key,
        );
    }

    let item = items
        .get(idx - 1)
        .ok_or_else(|| "invalid entry index".to_string())?;
    let entry_id = item.id;

    let after = action::run_for_entry(&mut db, entry_id, &cfg, key, &snapshot)?;

    // Drop unlocked vault + master key before long clipboard/autotype work.
    drop(db);

    match after {
        AfterAction::Done => Ok(()),
        AfterAction::Clipboard(secret) => fields::copy_secret(&secret, &cfg),
        AfterAction::Autotype {
            username,
            password,
        } => action::run_autotype(&username, &password),
    }
}
