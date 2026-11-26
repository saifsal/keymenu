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

    let password = dmenu::prompt_password(&cfg.dmenu_bin, "Master password")?
        .ok_or_else(|| "password prompt cancelled".to_string())?;

    let db = unlock::unlock_with_password(&cfg.db_path, &password)?;
    // `password` is Zeroizing and drops here after unlock.

    let items = dbview::flat_entries(&db);
    if items.is_empty() {
        return Err("database has no entries".into());
    }

    let labels = dbview::labels(&items);
    let selection = dmenu::select(&cfg.dmenu_bin, "keymenu", &labels)?
        .ok_or_else(|| "no entry selected".to_string())?;

    let item = dbview::find_by_label(&items, &selection)
        .ok_or_else(|| format!("unknown selection: {selection}"))?;

    action::run_for_entry(&db, item.id, &cfg)
}
