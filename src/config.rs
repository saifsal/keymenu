//! Runtime configuration: database path, keyfile, clipboard TTL, dmenu argv.

use std::env;
use std::path::PathBuf;
use std::time::Duration;

use crate::dmenu::PasswordMode;

/// Default clipboard ownership lifetime.
pub const DEFAULT_CLIPBOARD_TTL_SECS: u64 = 45;
/// Maximum clipboard TTL (24h) — also avoids Instant overflow panics.
pub const MAX_CLIPBOARD_TTL_SECS: u64 = 86_400;

/// Env var for the KeePass database path.
pub const ENV_DB: &str = "KEYMENU_DB";
/// Env var for an optional keyfile path.
pub const ENV_KEYFILE: &str = "KEYMENU_KEYFILE";
/// Env var overriding the dmenu executable.
pub const ENV_DMENU: &str = "KEYMENU_DMENU";
/// Env var for clipboard TTL seconds.
pub const ENV_CLIPBOARD_TTL: &str = "KEYMENU_CLIPBOARD_TTL";
/// Env var for the dmenu password flag (e.g. `-P`). Empty disables auto-detect.
pub const ENV_DMENU_PASSWORD_FLAG: &str = "KEYMENU_DMENU_PASSWORD_FLAG";

#[derive(Debug, Clone)]
pub struct Config {
    pub db_path: PathBuf,
    pub keyfile: Option<PathBuf>,
    pub clipboard_ttl: Duration,
    pub dmenu_bin: String,
    pub password_mode: PasswordMode,
    pub allow_keyfile_only: bool,
}

fn clamp_ttl(secs: u64) -> u64 {
    secs.clamp(1, MAX_CLIPBOARD_TTL_SECS)
}

fn parse_ttl(raw: &str) -> Result<u64, String> {
    let v: u64 = raw
        .parse()
        .map_err(|_| format!("invalid TTL value: {raw}"))?;
    Ok(clamp_ttl(v))
}

impl Config {
    /// Parse argv after the program name. Returns `None` when `--help` / `-h` was requested.
    pub fn from_args(args: &[String]) -> Result<Option<Self>, String> {
        let mut db_path: Option<PathBuf> = None;
        let mut keyfile: Option<PathBuf> = env::var_os(ENV_KEYFILE).map(PathBuf::from);
        let mut ttl_secs = match env::var(ENV_CLIPBOARD_TTL) {
            Ok(s) => parse_ttl(&s)?,
            Err(_) => DEFAULT_CLIPBOARD_TTL_SECS,
        };
        let mut dmenu_bin = env::var(ENV_DMENU).unwrap_or_else(|_| "dmenu".to_string());
        let mut password_flag: Option<String> = env::var(ENV_DMENU_PASSWORD_FLAG).ok();
        let mut allow_visible = false;
        let mut allow_keyfile_only = false;

        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "-h" | "--help" => return Ok(None),
                "--db" => {
                    i += 1;
                    let p = args
                        .get(i)
                        .ok_or_else(|| "missing value for --db".to_string())?;
                    db_path = Some(PathBuf::from(p));
                }
                "--keyfile" => {
                    i += 1;
                    let p = args
                        .get(i)
                        .ok_or_else(|| "missing value for --keyfile".to_string())?;
                    keyfile = Some(PathBuf::from(p));
                }
                "--ttl" => {
                    i += 1;
                    let v = args
                        .get(i)
                        .ok_or_else(|| "missing value for --ttl".to_string())?;
                    ttl_secs = parse_ttl(v)?;
                }
                "--dmenu" => {
                    i += 1;
                    let v = args
                        .get(i)
                        .ok_or_else(|| "missing value for --dmenu".to_string())?;
                    dmenu_bin = v.clone();
                }
                "--password-flag" => {
                    i += 1;
                    let v = args
                        .get(i)
                        .ok_or_else(|| "missing value for --password-flag".to_string())?;
                    password_flag = Some(v.clone());
                }
                "--allow-visible-password" => {
                    allow_visible = true;
                }
                "--allow-keyfile-only" => {
                    allow_keyfile_only = true;
                }
                other if other.starts_with('-') => {
                    return Err(format!("unknown option: {other}"));
                }
                other => {
                    return Err(format!("unexpected argument: {other}"));
                }
            }
            i += 1;
        }

        let db_path = db_path
            .or_else(|| env::var_os(ENV_DB).map(PathBuf::from))
            .ok_or_else(|| format!("database path required via --db or {ENV_DB}"))?;

        Ok(Some(Config {
            db_path,
            keyfile,
            clipboard_ttl: Duration::from_secs(ttl_secs),
            dmenu_bin,
            password_mode: PasswordMode {
                flag: password_flag,
                allow_visible,
            },
            allow_keyfile_only,
        }))
    }
}

pub fn usage() -> &'static str {
    "\
keymenu — dmenu KeePass/KDBX password menu

USAGE:
  keymenu --db PATH [OPTIONS]
  KEYMENU_DB=PATH keymenu [OPTIONS]

OPTIONS:
  --db PATH                  Path to the .kdbx database (or KEYMENU_DB)
  --keyfile PATH             Optional keyfile (or KEYMENU_KEYFILE)
  --ttl SECS                 Clipboard TTL 1..86400 (default 45; KEYMENU_CLIPBOARD_TTL)
  --dmenu CMD                dmenu executable (default: dmenu; KEYMENU_DMENU)
  --password-flag FLAG       dmenu password flag (default: auto-detect -P;
                             KEYMENU_DMENU_PASSWORD_FLAG)
  --allow-visible-password   Allow unmasked password entry if no -P mode
  --allow-keyfile-only       Allow unlock with keyfile and empty/cancelled password
  -h, --help                 Show this help

ENTRY LIST:
  + Add entry       Create a new entry (title / user / password) and save
  <entry>           Select an entry, then choose an action (index-prefixed)

ACTIONS (after entry select):
  Password | Username | Autotype | OTP? | <custom fields> | Attachments…? | Edit | Delete
  Entry list uses Group/Title paths; recycle-bin entries are hidden.

NOTES:
  Master password requires dmenu -P (or --password-flag / --allow-visible-password).
  KDBX3 → KDBX4 upgrade asks for confirmation in dmenu before saving.
  Delete moves to the recycle bin when enabled; otherwise records deleted_objects.

WARNING — SAVING:
  Writes use keepass save_kdbx4 (experimental). Backup your vault before editing.
  Unparsed fields may be lost on rewrite.
"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_clamped_and_invalid_env_errors() {
        let cfg = Config::from_args(&[
            "--db".into(),
            "/tmp/x.kdbx".into(),
            "--ttl".into(),
            "999999999".into(),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(cfg.clipboard_ttl, Duration::from_secs(MAX_CLIPBOARD_TTL_SECS));

        let err = Config::from_args(&["--db".into(), "/tmp/x.kdbx".into(), "--ttl".into(), "abc".into()])
            .unwrap_err();
        assert!(err.contains("invalid TTL"));
    }

    #[test]
    fn flag_overrides_and_unknown() {
        let cfg = Config::from_args(&[
            "--db".into(),
            "/tmp/x.kdbx".into(),
            "--allow-visible-password".into(),
            "--allow-keyfile-only".into(),
            "--password-flag".into(),
            "-P".into(),
        ])
        .unwrap()
        .unwrap();
        assert!(cfg.password_mode.allow_visible);
        assert!(cfg.allow_keyfile_only);
        assert_eq!(cfg.password_mode.flag.as_deref(), Some("-P"));

        assert!(Config::from_args(&["--db".into(), "/tmp/x.kdbx".into(), "--nope".into()]).is_err());
    }
}
