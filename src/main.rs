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

use config::Config;

fn main() {
    if let Err(e) = run() {
        eprintln!("keymenu: {e}");
        process::exit(1);
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

    let password = dmenu::prompt_password(&cfg.dmenu_bin, "Master password")?;
    // Allow keyfile-only unlock when password prompt is empty/cancelled but a keyfile is set.
    let password = match password {
        Some(p) if !p.is_empty() => Some(p),
        _ if cfg.keyfile.is_some() => None,
        _ => return Err("password prompt cancelled".into()),
    };

    let (mut db, key) = unlock::unlock(
        &cfg.db_path,
        password.as_ref(),
        cfg.keyfile.as_deref(),
    )?;

    let mut items = dbview::flat_entries(&db);
    let mut labels = vec![mutate::add_label().to_string()];
    labels.extend(dbview::labels(&items));

    let selection = dmenu::select(&cfg.dmenu_bin, "keymenu", &labels)?
        .ok_or_else(|| "no entry selected".to_string())?;

    if selection == mutate::add_label() {
        return mutate::add_entry(&mut db, &cfg.dmenu_bin, &cfg.db_path, key);
    }

    let item = dbview::find_by_label(&items, &selection)
        .ok_or_else(|| format!("unknown selection: {selection}"))?;
    let entry_id = item.id;
    // Drop borrow on items before mutating.
    items.clear();

    action::run_for_entry(&mut db, entry_id, &cfg, key)
}
