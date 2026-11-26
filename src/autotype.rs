//! Autotype via libXtst (`XTestFakeKeyEvent`). ASCII-first mapping.

#![cfg(target_os = "linux")]

use std::ptr;
use std::thread;
use std::time::Duration;

use libc::{c_int, c_uint, c_ulong};
use zeroize::Zeroize;
use x11::keysym::{XK_Shift_L, XK_Tab};
use x11::xlib::{self, Display};
use x11::xtest;

use crate::secret::SecretString;

const KEY_DELAY: Duration = Duration::from_millis(12);

/// Type username, Tab, password into the focused window.
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

        // Brief pause so the user can focus the target field after selecting Autotype.
        thread::sleep(Duration::from_millis(250));

        type_text(display, username.as_str())?;
        fake_keysym(display, XK_Tab as c_ulong, false)?;
        type_text(display, password.as_str())?;

        xlib::XFlush(display);
        xlib::XCloseDisplay(display);
        Ok(())
    }
}

unsafe fn type_text(display: *mut Display, text: &str) -> Result<(), String> {
    let mut owned = text.as_bytes().to_vec();
    for &b in owned.iter() {
        if b < 0x20 || b > 0x7e {
            owned.zeroize();
            return Err(format!(
                "autotype currently supports ASCII printable characters only (got 0x{b:02x})"
            ));
        }
        let keysym = b as c_ulong;
        let shift = needs_shift(display, keysym)?;
        fake_keysym(display, keysym, shift)?;
    }
    owned.zeroize();
    Ok(())
}

unsafe fn needs_shift(display: *mut Display, keysym: c_ulong) -> Result<bool, String> {
    let keycode = xlib::XKeysymToKeycode(display, keysym);
    if keycode == 0 {
        return Err(format!("no keycode for keysym 0x{keysym:x}"));
    }
    // Level 0 (unshifted) keysym for this keycode.
    let base = xlib::XKeycodeToKeysym(display, keycode, 0);
    Ok(base != keysym)
}

unsafe fn fake_keysym(display: *mut Display, keysym: c_ulong, shift: bool) -> Result<(), String> {
    let keycode = xlib::XKeysymToKeycode(display, keysym);
    if keycode == 0 {
        return Err(format!("no keycode for keysym 0x{keysym:x}"));
    }
    let shift_code = xlib::XKeysymToKeycode(display, XK_Shift_L as c_ulong);

    if shift && shift_code != 0 {
        xtest::XTestFakeKeyEvent(display, shift_code as c_uint, xlib::True, 0);
    }
    xtest::XTestFakeKeyEvent(display, keycode as c_uint, xlib::True, 0);
    xtest::XTestFakeKeyEvent(display, keycode as c_uint, xlib::False, 0);
    if shift && shift_code != 0 {
        xtest::XTestFakeKeyEvent(display, shift_code as c_uint, xlib::False, 0);
    }
    xlib::XFlush(display);
    thread::sleep(KEY_DELAY);

    let _ = c_int::default();
    Ok(())
}
