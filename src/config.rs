//! Runtime configuration: database path, clipboard TTL, dmenu argv.

use std::env;
use std::path::PathBuf;
use std::time::Duration;

/// Default clipboard ownership lifetime.
pub const DEFAULT_CLIPBOARD_TTL_SECS: u64 = 45;

/// Env var for the KeePass database path.
pub const ENV_DB: &str = "KEYMENU_DB";

/// Env var overriding the dmenu executable.
pub const ENV_DMENU: &str = "KEYMENU_DMENU";

/// Env var for clipboard TTL seconds.
pub const ENV_CLIPBOARD_TTL: &str = "KEYMENU_CLIPBOARD_TTL";

#[derive(Debug, Clone)]
pub struct Config {
    pub db_path: PathBuf,
    pub clipboard_ttl: Duration,
    pub dmenu_bin: String,
}

impl Config {
    /// Parse argv after the program name. Returns `None` when `--help` / `-h` was requested.
    pub fn from_args(args: &[String]) -> Result<Option<Self>, String> {
        let mut db_path: Option<PathBuf> = None;
        let mut ttl_secs = env::var(ENV_CLIPBOARD_TTL)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_CLIPBOARD_TTL_SECS);
        let mut dmenu_bin = env::var(ENV_DMENU).unwrap_or_else(|_| "dmenu".to_string());

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
                "--ttl" => {
                    i += 1;
                    let v = args
                        .get(i)
                        .ok_or_else(|| "missing value for --ttl".to_string())?;
                    ttl_secs = v
                        .parse()
                        .map_err(|_| format!("invalid --ttl value: {v}"))?;
                }
                "--dmenu" => {
                    i += 1;
                    let v = args
                        .get(i)
                        .ok_or_else(|| "missing value for --dmenu".to_string())?;
                    dmenu_bin = v.clone();
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
            .ok_or_else(|| {
                format!("database path required via --db or {ENV_DB}")
            })?;

        Ok(Some(Config {
            db_path,
            clipboard_ttl: Duration::from_secs(ttl_secs),
            dmenu_bin,
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
  --db PATH       Path to the .kdbx database (or set KEYMENU_DB)
  --ttl SECS      Clipboard clear timeout (default: 45; env KEYMENU_CLIPBOARD_TTL)
  --dmenu CMD     dmenu executable (default: dmenu; env KEYMENU_DMENU)
  -h, --help      Show this help

ACTIONS (after entry select):
  Password | Username | Autotype

RUNTIME DEPENDENCIES:
  dmenu on PATH; libX11.so.6 and libXtst.so.6 (build: libx11-dev libxtst-dev).

NOTES:
  Master password is prompted via dmenu (-P when available).
  Interactive use needs a working X11 display and dmenu.
  Unlock/list unit tests use tests/fixtures/smoke.kdbx (password: testpass).
"
}
