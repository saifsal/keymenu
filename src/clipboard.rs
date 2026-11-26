//! X11 CLIPBOARD ownership with timed clear (libX11).

#![cfg(target_os = "linux")]

use std::ptr;
use std::thread;
use std::time::{Duration, Instant};

use libc::{c_int, c_uchar};
use zeroize::Zeroize;
use x11::xlib::{
    self, Atom, Display, Time, Window, XA_ATOM, XEvent, XSelectionEvent, XSelectionRequestEvent,
};

use crate::secret::SecretString;

/// Own CLIPBOARD with `text` until `ttl` elapses or ownership is stolen.
pub fn copy_with_ttl(text: &SecretString, ttl: Duration) -> Result<(), String> {
    unsafe { copy_with_ttl_inner(text.as_bytes(), ttl) }
}

unsafe fn copy_with_ttl_inner(bytes: &[u8], ttl: Duration) -> Result<(), String> {
    let display = xlib::XOpenDisplay(ptr::null());
    if display.is_null() {
        return Err("cannot open X display".into());
    }

    let screen = xlib::XDefaultScreen(display);
    let root = xlib::XRootWindow(display, screen);
    let window = xlib::XCreateSimpleWindow(display, root, 0, 0, 1, 1, 0, 0, 0);
    if window == 0 {
        xlib::XCloseDisplay(display);
        return Err("XCreateSimpleWindow failed".into());
    }

    let clipboard = intern(display, "CLIPBOARD");
    let utf8 = intern(display, "UTF8_STRING");
    let targets = intern(display, "TARGETS");
    let xsel_data = intern(display, "XSEL_DATA");

    // Obtain a real server timestamp so a later release with that stamp cannot
    // clear a newer owner's selection (ICCCM).
    let owned_at = match server_time(display, window) {
        Ok(t) => t,
        Err(e) => {
            xlib::XDestroyWindow(display, window);
            xlib::XCloseDisplay(display);
            return Err(e);
        }
    };

    xlib::XSetSelectionOwner(display, clipboard, window, owned_at);
    xlib::XFlush(display);

    if xlib::XGetSelectionOwner(display, clipboard) != window {
        xlib::XDestroyWindow(display, window);
        xlib::XCloseDisplay(display);
        return Err("failed to acquire CLIPBOARD ownership".into());
    }

    let mut payload = bytes.to_vec();
    let deadline = Instant::now()
        .checked_add(ttl)
        .unwrap_or_else(|| Instant::now() + Duration::from_secs(45));
    let mut stolen = false;
    let mut event: XEvent = std::mem::zeroed();

    while Instant::now() < deadline {
        while xlib::XPending(display) > 0 {
            xlib::XNextEvent(display, &mut event);
            match event.get_type() {
                xlib::SelectionRequest => {
                    let req = event.selection_request;
                    handle_selection_request(display, &req, &payload, utf8, targets, xsel_data);
                }
                xlib::SelectionClear => {
                    stolen = true;
                    break;
                }
                _ => {}
            }
        }
        if stolen {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    // Only release ownership if we still own it, using our acquisition timestamp
    // (not CurrentTime) so a concurrent newer owner is not cleared.
    if !stolen && xlib::XGetSelectionOwner(display, clipboard) == window {
        xlib::XSetSelectionOwner(display, clipboard, 0, owned_at);
        xlib::XFlush(display);
    }
    payload.zeroize();

    xlib::XDestroyWindow(display, window);
    xlib::XCloseDisplay(display);

    if stolen {
        eprintln!("keymenu: clipboard ownership lost; cleared local buffer only");
    }
    Ok(())
}

/// ICCCM trick: PropertyNotify on a change gives a usable server Time.
unsafe fn server_time(display: *mut Display, window: Window) -> Result<Time, String> {
    xlib::XSelectInput(display, window, xlib::PropertyChangeMask);
    let atom = intern(display, "_KEYMENU_CLIPBOARD_TIME");
    let mut zero: u8 = 0;
    xlib::XChangeProperty(
        display,
        window,
        atom,
        atom,
        8,
        xlib::PropModeReplace,
        &mut zero,
        1,
    );
    xlib::XFlush(display);

    let mut event: XEvent = std::mem::zeroed();
    // Bound the wait so a broken X connection cannot hang forever.
    for _ in 0..1000 {
        if xlib::XPending(display) == 0 {
            thread::sleep(Duration::from_millis(1));
            continue;
        }
        xlib::XNextEvent(display, &mut event);
        if event.get_type() == xlib::PropertyNotify {
            return Ok(event.property.time);
        }
    }
    Err("timed out waiting for X server timestamp".into())
}

unsafe fn intern(display: *mut Display, name: &str) -> Atom {
    let c = std::ffi::CString::new(name).expect("atom name");
    xlib::XInternAtom(display, c.as_ptr(), xlib::False)
}

unsafe fn handle_selection_request(
    display: *mut Display,
    req: &XSelectionRequestEvent,
    payload: &[u8],
    utf8: Atom,
    targets: Atom,
    fallback_prop: Atom,
) {
    let property = if req.property != 0 {
        req.property
    } else {
        fallback_prop
    };

    let mut fulfilled = false;

    if req.target == targets {
        let mut atoms: [Atom; 2] = [utf8, targets];
        xlib::XChangeProperty(
            display,
            req.requestor,
            property,
            XA_ATOM,
            32,
            xlib::PropModeReplace,
            atoms.as_mut_ptr() as *mut c_uchar,
            2,
        );
        fulfilled = true;
    } else if req.target == utf8 {
        xlib::XChangeProperty(
            display,
            req.requestor,
            property,
            utf8,
            8,
            xlib::PropModeReplace,
            payload.as_ptr() as *const c_uchar,
            payload.len() as c_int,
        );
        fulfilled = true;
    }

    let notify = XSelectionEvent {
        type_: xlib::SelectionNotify,
        serial: 0,
        send_event: xlib::True,
        display: req.display,
        requestor: req.requestor,
        selection: req.selection,
        target: req.target,
        property: if fulfilled { property } else { 0 },
        time: req.time,
    };

    let mut ev: XEvent = std::mem::zeroed();
    ev.selection = notify;
    xlib::XSendEvent(display, req.requestor, xlib::False, 0, &mut ev);
    xlib::XFlush(display);

    let _ = Window::default();
}
