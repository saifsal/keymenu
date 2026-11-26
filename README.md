# keymenu

Suckless-inspired Rust `passmenu` alternative: native KDBX unlock via dmenu, libX11 clipboard, libXtst autotype. No daemon, no async runtime, no GUI toolkit, no KeePassXC.

## Build

```bash
# Debian/Ubuntu
sudo apt install libx11-dev libxtst-dev pkg-config dmenu

cargo build --release
```

The binary dynamically links **system** `libX11` and `libXtst` (via pkg-config). Rust `std` stays statically linked — do **not** pass `-C prefer-dynamic` for normal installs.

```bash
ldd target/release/keymenu | grep -E 'libX11|libXtst|libstd'
# expect: libX11.so.6, libXtst.so.6; no libstd-*.so
```

## Runtime dependencies

| Need | Notes |
|------|--------|
| `dmenu` on `PATH` | Selection + password prompt |
| `libX11.so.6` | Clipboard ownership |
| `libXtst.so.6` | Autotype (`XTestFakeKeyEvent`) |
| X11 display | Interactive unlock / copy / autotype |

## Usage

```text
keymenu --db PATH [OPTIONS]
KEYMENU_DB=PATH keymenu [OPTIONS]

Options:
  --db PATH         Path to the .kdbx database (or KEYMENU_DB)
  --keyfile PATH    Optional keyfile (or KEYMENU_KEYFILE)
  --ttl SECS        Clipboard clear timeout (default: 45; KEYMENU_CLIPBOARD_TTL)
  --dmenu CMD       dmenu executable (default: dmenu; KEYMENU_DMENU)
  -h, --help        Show help
```

Flow:

1. Prompt for master password via dmenu (`-P` when the installed dmenu supports it); optional keyfile via `--keyfile`.
2. Show entry list with `+ Add entry` plus flat titles; select one.
3. **Add** → prompt title / username / password, then save.
4. For an entry, **always** show an action menu: `Password` | `Username` | `Autotype` | `Edit` | `Delete`.
5. Password/Username → own X11 `CLIPBOARD` as UTF8_STRING, clear after TTL (default 45s).
6. Autotype → type username, Tab, password into the focused window (ASCII printable).
7. Edit / Delete → dmenu prompts (Delete asks Yes/No), then atomic save.

Process exits after one action (clipboard clear may keep it alive until TTL).

See also `man/keymenu.1`.

## Saving / backups

Writes use the `keepass` crate’s experimental **`save_kdbx4`**. **Backup your vault before editing.**

- Saves are atomic (temp file + rename).
- Saving a KDBX 3.1 file **upgrades it to KDBX4** (aligned with KeePass 2.57+).
- The XML is rebuilt on save; unparsed / exotic fields may be lost.

## Smoke fixture (no display)

`tests/fixtures/smoke.kdbx` is a small password-only vault (`testpass`) for unlock/list unit tests that do not need X11 or dmenu:

```bash
cargo test
```

Interactive copy/autotype still requires a display and dmenu.

## Threat notes (short)

- Unlocked secrets live in process memory until exit; `zeroize` reduces residue for owned buffers only.
- Any X11 client can read `CLIPBOARD` while we own it; TTL limits the window.
- Autotype sends keys to whatever has focus (focus-stealing risk).
- Without dmenu `-P`, the password prompt is not masked — prefer a patched dmenu.

## License

GPL-3.0-or-later (see `LICENSE`). Dependencies include MIT crates (`keepass`, `x11`, `zeroize`).
