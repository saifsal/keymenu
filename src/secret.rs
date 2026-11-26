//! Zeroizing helpers for owned secret buffers.

use zeroize::{Zeroize, Zeroizing};

/// Owned UTF-8 secret that is wiped on drop.
pub type SecretString = Zeroizing<String>;

/// Copy a secret `&str` into a zeroizing buffer.
pub fn owned(s: &str) -> SecretString {
    Zeroizing::new(s.to_owned())
}

/// Overwrite a mutable byte slice with zeros.
#[allow(dead_code)]
pub fn wipe_bytes(buf: &mut [u8]) {
    buf.zeroize();
}
