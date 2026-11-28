# keymenu

Suckless-inspired Rust `passmenu` alternative: native KDBX unlock via dmenu, libX11 clipboard, libXtst autotype. No daemon, no async runtime, no GUI toolkit, no KeePassXC.

## Build

Rust is pinned with [mise](https://mise.jdx.dev/) (`mise.toml`). System libs: **libX11**, **libXtst**, **pkg-config**, and **dmenu** on `PATH`.

```bash
# Arch
pacman -S --needed libx11 libxtst pkgconf dmenu

# Debian/Ubuntu
sudo apt install libx11-dev libxtst-dev pkg-config dmenu

mise trust
mise install
mise run build   # → target/release/keymenu
```

`mise run test` / `mise run check` run tests (and fmt + clippy).

`mise run install` builds the release binary and installs it to `/usr/local/bin` plus `man/keymenu.1` to `/usr/local/share/man/man1` (dwm-style `PREFIX` / `MANPREFIX`; override with e.g. `PREFIX=/usr mise run install`). Run as root (or `sudo mise run install`); the task does not elevate. `mise run uninstall` removes both the same way.

The binary dynamically links **system** `libX11` and `libXtst` (via pkg-config). Rust `std` stays statically linked — do **not** pass `-C prefer-dynamic` for normal installs.

```bash
ldd target/release/keymenu | grep -E 'libX11|libXtst|libstd'
# expect: libX11.so.6, libXtst.so.6; no libstd-*.so
```

## Runtime dependencies

| Need | Notes |
|------|--------|
| `dmenu` on `PATH` | Selection + password prompt (prefer a build with `-P`) |
| `libX11.so.6` | Clipboard ownership |
| `libXtst.so.6` | Autotype (`XTestFakeKeyEvent`) |
| X11 display | Interactive unlock / copy / autotype |

## Usage

```text
keymenu --db PATH [OPTIONS]
KEYMENU_DB=PATH keymenu [OPTIONS]

Options:
  --db PATH                  Path to the .kdbx database (or KEYMENU_DB)
  --keyfile PATH             Optional keyfile (or KEYMENU_KEYFILE)
  --ttl SECS                 Clipboard TTL 1..86400 (default 45; KEYMENU_CLIPBOARD_TTL)
  --dmenu CMD                dmenu executable (default: dmenu; KEYMENU_DMENU)
  --password-flag FLAG       Password flag (default: auto-detect -P / [-bfiPv];
                             KEYMENU_DMENU_PASSWORD_FLAG)
  --allow-visible-password   Allow unmasked password entry if no -P mode
  --allow-keyfile-only       Allow unlock with keyfile after empty/cancelled password
  -h, --help                 Show help
```

Flow:

1. Prompt for master password via dmenu (`-P` when detected or configured). Without a password mode, keymenu **refuses** unless `--allow-visible-password`.
2. Show entry list with `+ Add entry` plus **group-aware** paths (`Work/VPN`); selections are index-based (`N\tlabel`). Duplicate titles append `(username)`. Recycle-bin entries are hidden.
3. **Add** → prompt title / username / password (Escape cancels), then save.
4. For an entry, **always** show an action menu (index-based):
   `Password` | `Username` | `Autotype` | `OTP` (if present) | `Field: …` | `Attachments…` | `Edit` | `Delete`.
5. Password/Username/OTP/custom field → extract secret, drop the unlocked DB, then own X11 `CLIPBOARD` until TTL (default 45s). If another client steals the selection, keymenu does **not** clear it.
6. Autotype → pre-resolve all keycodes (ASCII level 0/1 only); empty username skips Tab; reject AltGr-only chars.
7. Attachments → pick a file, then a save path (`file_name` only for the default); create 0600 / confirm overwrite.
8. Edit → prompt shows current value; Escape=cancel, empty Enter=keep; type `-` alone to clear a non-empty field. Uses KeePass history tracking.
9. Delete → recycle bin when enabled; otherwise `track_changes().remove()` with `deleted_objects`.

See also `man/keymenu.1`.

## Saving / backups

Writes use the `keepass` crate’s experimental **`save_kdbx4`**. **Backup your vault before editing.**

- Saves are atomic: `canonicalize` (write through symlinks), `create_new` temp with random suffix + preserved mode (else 0600), `sync_all`, rename, fsync parent dir.
- Refuses to save if the file’s mtime/size changed since unlock.
- KDBX3 → KDBX4 asks for confirmation in dmenu (not silent). KDB/KDB2 writes are refused.
- The XML is rebuilt on save; unparsed / exotic fields may be lost.

## Smoke fixture (no display)

`tests/fixtures/smoke.kdbx` is a small password-only vault (`testpass`) for unlock/list unit tests that do not need X11 or dmenu:

```bash
cargo test
```

Interactive copy/autotype still requires a display and dmenu.

## Threat notes (short)

- Unlocked secrets live in process memory until exit; `zeroize` reduces residue for owned buffers; `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0` at startup.
- Any X11 client can read `CLIPBOARD` while we own it; TTL limits the window. Clipboard managers may keep a copy past TTL.
- Autotype sends keys to whatever has focus (focus-stealing risk); ASCII/Shift only.
- Without dmenu `-P` (and without `--allow-visible-password`), unlock is refused.

## License

GPL-3.0-or-later (see `LICENSE`). Dependencies include MIT crates (`keepass`, `x11`, `zeroize`).
