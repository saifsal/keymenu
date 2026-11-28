//! Autotype via libXtst (`XTestFakeKeyEvent`). ASCII + Shift only; pre-planned.

#![cfg(target_os = "linux")]

use std::ptr;
use std::thread;
use std::time::Duration;

use libc::{c_int, c_uint, c_ulong};
use x11::keysym::{XK_Shift_L, XK_Tab};
use x11::xlib::{self, Display};
use x11::xtest;

use crate::secret::SecretString;

const KEY_DELAY: Duration = Duration::from_millis(12);

/// Planned keystroke: keycode + whether Shift is required (level 0 vs 1 only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyStroke {
    pub keycode: u8,
    pub shift: bool,
}

/// Keysym → (keycode, shift) lookup. Allows testing the planner without a display.
pub trait Keymap {
    fn lookup(&self, keysym: u64) -> Result<KeyStroke, String>;
    /// Keycode for Left Shift, or 0 if unavailable.
    fn shift_keycode(&self) -> u8;
}

/// Live X11 keymap via `XKeysymToKeycode` / `XKeycodeToKeysym`.
pub struct XKeymap {
    display: *mut Display,
}

impl Keymap for XKeymap {
    fn lookup(&self, keysym: u64) -> Result<KeyStroke, String> {
        unsafe {
            let keycode = xlib::XKeysymToKeycode(self.display, keysym as c_ulong);
            if keycode == 0 {
                return Err("autotype: a character has no keycode on this keyboard layout".into());
            }
            let level0 = xlib::XKeycodeToKeysym(self.display, keycode, 0);
            let level1 = xlib::XKeycodeToKeysym(self.display, keycode, 1);
            if keysym as c_ulong == level0 {
                Ok(KeyStroke {
                    keycode,
                    shift: false,
                })
            } else if keysym as c_ulong == level1 {
                Ok(KeyStroke {
                    keycode,
                    shift: true,
                })
            } else {
                Err(
                    "autotype: a character requires modifiers keymenu cannot synthesize \
                     (e.g. AltGr); use clipboard copy instead"
                        .into(),
                )
            }
        }
    }

    fn shift_keycode(&self) -> u8 {
        unsafe { xlib::XKeysymToKeycode(self.display, XK_Shift_L as c_ulong) }
    }
}

/// Resolve ASCII text to keystrokes without sending events.
///
/// Rejects non-ASCII, unmappable keysyms, and anything that is not at
/// keyboard level 0 or 1 (e.g. AltGr). Error strings never include secret bytes.
pub fn plan_text_with(map: &dyn Keymap, text: &str) -> Result<Vec<KeyStroke>, String> {
    if text.bytes().any(|b| !(0x20..=0x7e).contains(&b)) {
        return Err("autotype supports ASCII printable characters only; \
             a character in the sequence is outside that range or unmappable"
            .into());
    }
    let mut out = Vec::with_capacity(text.len());
    for b in text.bytes() {
        out.push(map.lookup(b as u64)?);
    }
    finalize_shift(map, &out)?;
    Ok(out)
}

/// Plan username (+ Tab if non-empty) then password, before any XTest events.
pub fn plan_username_tab_password_with(
    map: &dyn Keymap,
    username: &str,
    password: &str,
) -> Result<Vec<KeyStroke>, String> {
    let mut plan = Vec::new();
    if !username.is_empty() {
        // Don't call finalize yet — compose then finalize once.
        if username.bytes().any(|b| !(0x20..=0x7e).contains(&b))
            || password.bytes().any(|b| !(0x20..=0x7e).contains(&b))
        {
            return Err("autotype supports ASCII printable characters only; \
                 a character in the sequence is outside that range or unmappable"
                .into());
        }
        for b in username.bytes() {
            plan.push(map.lookup(b as u64)?);
        }
        plan.push(map.lookup(XK_Tab as u64)?);
    } else if password.bytes().any(|b| !(0x20..=0x7e).contains(&b)) {
        return Err("autotype supports ASCII printable characters only; \
             a character in the sequence is outside that range or unmappable"
            .into());
    }
    for b in password.bytes() {
        plan.push(map.lookup(b as u64)?);
    }
    finalize_shift(map, &plan)?;
    Ok(plan)
}

fn finalize_shift(map: &dyn Keymap, plan: &[KeyStroke]) -> Result<(), String> {
    if plan.iter().any(|s| s.shift) && map.shift_keycode() == 0 {
        return Err(
            "autotype: Shift keycode unavailable but a shifted character is required".into(),
        );
    }
    Ok(())
}

/// Convenience wrappers that use a live display keymap.
#[allow(dead_code)]
pub fn plan_text(display: *mut Display, text: &str) -> Result<Vec<KeyStroke>, String> {
    plan_text_with(&XKeymap { display }, text)
}

#[allow(dead_code)]
pub fn plan_username_tab_password(
    display: *mut Display,
    username: &str,
    password: &str,
) -> Result<Vec<KeyStroke>, String> {
    plan_username_tab_password_with(&XKeymap { display }, username, password)
}

/// Refuse autotype while Caps Lock is on (would silently flip letter case).
unsafe fn ensure_caps_lock_off(display: *mut Display) -> Result<(), String> {
    let root = xlib::XDefaultRootWindow(display);
    let mut root_ret = 0;
    let mut child = 0;
    let mut root_x = 0;
    let mut root_y = 0;
    let mut win_x = 0;
    let mut win_y = 0;
    let mut mask: c_uint = 0;
    if xlib::XQueryPointer(
        display,
        root,
        &mut root_ret,
        &mut child,
        &mut root_x,
        &mut root_y,
        &mut win_x,
        &mut win_y,
        &mut mask,
    ) == 0
    {
        return Err("autotype: cannot query pointer/modifier state".into());
    }
    if mask & xlib::LockMask != 0 {
        return Err("autotype: Caps Lock is on; turn it off and try again".into());
    }
    let _ = c_int::default();
    Ok(())
}

/// Type username, Tab (if username non-empty), password into the focused window.
pub fn username_tab_password(
    username: &SecretString,
    password: &SecretString,
) -> Result<(), String> {
    unsafe {
        let display = xlib::XOpenDisplay(ptr::null());
        if display.is_null() {
            return Err("cannot open X display".into());
        }

        let mut event_base = 0;
        let mut error_base = 0;
        let mut major = 0;
        let mut minor = 0;
        if xtest::XTestQueryExtension(
            display,
            &mut event_base,
            &mut error_base,
            &mut major,
            &mut minor,
        ) == 0
        {
            xlib::XCloseDisplay(display);
            return Err("XTest extension not available".into());
        }

        if let Err(e) = ensure_caps_lock_off(display) {
            xlib::XCloseDisplay(display);
            return Err(e);
        }

        let map = XKeymap { display };
        let plan = match plan_username_tab_password_with(&map, username.as_str(), password.as_str())
        {
            Ok(p) => p,
            Err(e) => {
                xlib::XCloseDisplay(display);
                return Err(e);
            }
        };

        thread::sleep(Duration::from_millis(250));

        // Re-check Caps Lock immediately before typing.
        if let Err(e) = ensure_caps_lock_off(display) {
            xlib::XCloseDisplay(display);
            return Err(e);
        }

        let shift_code = map.shift_keycode();
        for stroke in plan {
            emit(display, stroke, shift_code);
        }

        xlib::XFlush(display);
        xlib::XCloseDisplay(display);
        Ok(())
    }
}

unsafe fn emit(display: *mut Display, stroke: KeyStroke, shift_code: u8) {
    if stroke.shift && shift_code != 0 {
        xtest::XTestFakeKeyEvent(display, shift_code as c_uint, xlib::True, 0);
    }
    xtest::XTestFakeKeyEvent(display, stroke.keycode as c_uint, xlib::True, 0);
    xtest::XTestFakeKeyEvent(display, stroke.keycode as c_uint, xlib::False, 0);
    if stroke.shift && shift_code != 0 {
        xtest::XTestFakeKeyEvent(display, shift_code as c_uint, xlib::False, 0);
    }
    xlib::XFlush(display);
    thread::sleep(KEY_DELAY);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fake US-ish keymap for display-free planner tests.
    struct FakeMap {
        shift: u8,
        /// Keysyms that should look like AltGr (level 2+).
        altgr: Vec<u64>,
    }

    impl Keymap for FakeMap {
        fn lookup(&self, keysym: u64) -> Result<KeyStroke, String> {
            if self.altgr.contains(&keysym) {
                return Err(
                    "autotype: a character requires modifiers keymenu cannot synthesize \
                     (e.g. AltGr); use clipboard copy instead"
                        .into(),
                );
            }
            if keysym == XK_Tab as u64 {
                return Ok(KeyStroke {
                    keycode: 23,
                    shift: false,
                });
            }
            // Printable ASCII: lowercase = unshifted, uppercase = shifted.
            if (b'a' as u64..=b'z' as u64).contains(&keysym) {
                return Ok(KeyStroke {
                    keycode: keysym as u8,
                    shift: false,
                });
            }
            if (b'A' as u64..=b'Z' as u64).contains(&keysym) {
                return Ok(KeyStroke {
                    keycode: (keysym as u8) + 32,
                    shift: true,
                });
            }
            if (0x20..=0x7e).contains(&keysym) {
                // Treat punctuation needing shift similarly to US: if it's an uppercase
                // ASCII letter already handled; for symbols mark shift when "shifted set".
                let shifted = b"!@#$%^&*()_+{}|:\"<>?".contains(&(keysym as u8));
                return Ok(KeyStroke {
                    keycode: keysym as u8,
                    shift: shifted,
                });
            }
            Err("autotype: a character has no keycode on this keyboard layout".into())
        }

        fn shift_keycode(&self) -> u8 {
            self.shift
        }
    }

    #[test]
    fn plan_rejects_non_ascii_without_leaking() {
        let map = FakeMap {
            shift: 50,
            altgr: vec![],
        };
        let err = plan_text_with(&map, "pässword").unwrap_err();
        assert!(err.contains("ASCII"));
        assert!(!err.contains('ä'));
        assert!(!err.contains("password"));
    }

    #[test]
    fn empty_username_plan_has_no_tab() {
        let map = FakeMap {
            shift: 50,
            altgr: vec![],
        };
        let plan = plan_username_tab_password_with(&map, "", "ab").unwrap();
        assert_eq!(plan.len(), 2);
        assert!(!plan.iter().any(|s| s.keycode == 23));
    }

    #[test]
    fn non_empty_username_includes_tab() {
        let map = FakeMap {
            shift: 50,
            altgr: vec![],
        };
        let plan = plan_username_tab_password_with(&map, "u", "p").unwrap();
        assert_eq!(plan.len(), 3);
        assert_eq!(plan[1].keycode, 23);
    }

    #[test]
    fn missing_shift_keycode_is_planning_error() {
        let map = FakeMap {
            shift: 0,
            altgr: vec![],
        };
        let err = plan_text_with(&map, "A").unwrap_err();
        assert!(err.contains("Shift"));
    }

    #[test]
    fn altgr_rejected() {
        let map = FakeMap {
            shift: 50,
            altgr: vec![b'@' as u64],
        };
        let err = plan_text_with(&map, "a@b").unwrap_err();
        assert!(err.contains("AltGr"));
        assert!(!err.contains('@'));
    }
}
