//! Autotype via libXtst (`XTestFakeKeyEvent`). ASCII + Shift only; pre-planned.

#![cfg(target_os = "linux")]

use std::ptr;
use std::thread;
use std::time::Duration;

use libc::{c_uint, c_ulong};
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

/// Resolve ASCII text to keystrokes without sending events.
///
/// Rejects non-ASCII, unmappable keysyms, and anything that is not at
/// keyboard level 0 or 1 (e.g. AltGr). Error strings never include secret bytes.
pub fn plan_text(display: *mut Display, text: &str) -> Result<Vec<KeyStroke>, String> {
    // Validate the entire string before any X11 lookup so we never partially resolve
    // (and so tests can exercise rejection without a display).
    if text.bytes().any(|b| !(0x20..=0x7e).contains(&b)) {
        return Err(
            "autotype supports ASCII printable characters only; \
             a character in the sequence is outside that range or unmappable"
                .into(),
        );
    }
    let mut out = Vec::with_capacity(text.len());
    for b in text.bytes() {
        out.push(plan_keysym(display, b as c_ulong)?);
    }
    Ok(out)
}

/// Plan username (+ Tab if non-empty) then password, before any XTest events.
pub fn plan_username_tab_password(
    display: *mut Display,
    username: &str,
    password: &str,
) -> Result<Vec<KeyStroke>, String> {
    let mut plan = Vec::new();
    if !username.is_empty() {
        plan.extend(plan_text(display, username)?);
        plan.push(plan_keysym(display, XK_Tab as c_ulong)?);
    }
    plan.extend(plan_text(display, password)?);
    Ok(plan)
}

fn plan_keysym(display: *mut Display, keysym: c_ulong) -> Result<KeyStroke, String> {
    unsafe {
        let keycode = xlib::XKeysymToKeycode(display, keysym);
        if keycode == 0 {
            return Err(
                "autotype: a character has no keycode on this keyboard layout".into(),
            );
        }
        let level0 = xlib::XKeycodeToKeysym(display, keycode, 0);
        let level1 = xlib::XKeycodeToKeysym(display, keycode, 1);
        if keysym == level0 {
            Ok(KeyStroke {
                keycode,
                shift: false,
            })
        } else if keysym == level1 {
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

/// Type username, Tab (if username non-empty), password into the focused window.
pub fn username_tab_password(username: &SecretString, password: &SecretString) -> Result<(), String> {
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

        // Plan everything first — no events yet on failure.
        let plan = match plan_username_tab_password(display, username.as_str(), password.as_str())
        {
            Ok(p) => p,
            Err(e) => {
                xlib::XCloseDisplay(display);
                return Err(e);
            }
        };

        thread::sleep(Duration::from_millis(250));

        let shift_code = xlib::XKeysymToKeycode(display, XK_Shift_L as c_ulong);
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

    #[test]
    fn plan_rejects_non_ascii_without_leaking() {
        // No display needed for the byte-range check path before X calls…
        // plan_text needs a display for keycode lookup of ASCII. For non-ASCII it
        // returns before XKeysymToKeycode.
        let err = plan_text(ptr::null_mut(), "pässword").unwrap_err();
        assert!(err.contains("ASCII"));
        assert!(!err.contains('ä'));
        assert!(!err.contains("0xc3"));
        assert!(!err.contains("0xäss"));
        // Ensure no raw password substring.
        assert!(!err.contains("päss"));
        assert!(!err.contains("password"));
    }

    #[test]
    fn empty_username_plan_has_no_tab_without_display() {
        // We can only assert the structural rule in the planner when display works.
        // Without X, plan_keysym will fail on null display — skip if no display.
        unsafe {
            let dpy = xlib::XOpenDisplay(ptr::null());
            if dpy.is_null() {
                return;
            }
            let plan = plan_username_tab_password(dpy, "", "ab").expect("plan");
            xlib::XCloseDisplay(dpy);
            // Two keystrokes for 'a','b' — no Tab.
            assert_eq!(plan.len(), 2);
        }
    }
}
