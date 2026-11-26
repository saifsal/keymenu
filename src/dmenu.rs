//! Spawn dmenu for selection and password prompts.

use std::io::Write;
use std::process::{Command, Stdio};

use zeroize::Zeroize;

/// Result of a free-text / selection prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Escape or non-zero exit from dmenu.
    Cancelled,
    /// Successful exit with an empty string (Enter on blank).
    Empty,
    /// Successful exit with non-empty text.
    Value(String),
}

/// Detect `-P` in dmenu usage, including grouped forms like `[-bfiPv]`.
pub fn usage_supports_password_flag(usage: &str) -> bool {
    // Standalone tokens.
    for token in usage.split_whitespace() {
        if token == "-P" || token == "[-P]" {
            return true;
        }
        // Grouped flags: [-bfiPv] or [-P] etc.
        if let Some(inner) = token.strip_prefix("[-").and_then(|s| s.strip_suffix(']')) {
            if inner.contains('P') {
                return true;
            }
        }
    }
    // Also catch mid-line forms without relying on whitespace splits alone.
    for (i, _) in usage.match_indices("[-") {
        if let Some(end) = usage[i..].find(']') {
            let inner = &usage[i + 2..i + end];
            if inner.chars().all(|c| c.is_ascii_alphabetic()) && inner.contains('P') {
                return true;
            }
        }
    }
    false
}

/// Probe `dmenu -h` (no display required) for password-flag support.
pub fn detect_password_flag(dmenu_bin: &str) -> bool {
    let output = Command::new(dmenu_bin)
        .arg("-h")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    match output {
        Ok(out) => {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            usage_supports_password_flag(&text)
        }
        Err(_) => false,
    }
}

/// Settings for password prompts.
#[derive(Debug, Clone)]
pub struct PasswordMode {
    /// Explicit flag from config/env (e.g. `-P`). `None` means auto-detect.
    pub flag: Option<String>,
    /// Allow unmasked password entry when no password flag is available.
    pub allow_visible: bool,
}

impl PasswordMode {
    /// Resolve the argv flag to pass, or `None` if visible entry is allowed without a flag.
    pub fn resolve_flag(&self, dmenu_bin: &str) -> Result<Option<String>, String> {
        if let Some(ref f) = self.flag {
            if f.is_empty() {
                if self.allow_visible {
                    return Ok(None);
                }
                return Err(
                    "password flag disabled but visible passwords are not allowed \
                     (pass --allow-visible-password)"
                        .into(),
                );
            }
            return Ok(Some(f.clone()));
        }
        if detect_password_flag(dmenu_bin) {
            Ok(Some("-P".into()))
        } else if self.allow_visible {
            Ok(None)
        } else {
            Err(
                "dmenu has no password mode (-P); refuse cleartext password entry. \
                 Install a patched dmenu, set KEYMENU_DMENU_PASSWORD_FLAG, \
                 or pass --allow-visible-password"
                    .into(),
            )
        }
    }
}

/// Present newline-separated items; return rich outcome (Escape vs empty vs value).
pub fn prompt(dmenu_bin: &str, prompt_text: &str, items: &[String]) -> Result<Outcome, String> {
    let input = items.join("\n");
    let mut child = Command::new(dmenu_bin)
        .arg("-i")
        .arg("-p")
        .arg(prompt_text)
        .arg("-l")
        .arg("20")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("failed to spawn {dmenu_bin}: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(input.as_bytes())
            .map_err(|e| format!("failed writing to dmenu: {e}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("dmenu wait failed: {e}"))?;

    if !output.status.success() {
        return Ok(Outcome::Cancelled);
    }

    let selection = String::from_utf8_lossy(&output.stdout)
        .trim_end_matches(['\n', '\r'])
        .to_string();
    if selection.is_empty() {
        Ok(Outcome::Empty)
    } else {
        Ok(Outcome::Value(selection))
    }
}

/// Convenience: map Cancelled/Empty → None, Value → Some.
pub fn select(dmenu_bin: &str, prompt_text: &str, items: &[String]) -> Result<Option<String>, String> {
    match prompt(dmenu_bin, prompt_text, items)? {
        Outcome::Cancelled | Outcome::Empty => Ok(None),
        Outcome::Value(v) => Ok(Some(v)),
    }
}

/// Index-based selection: items shown as `N\tlabel`; returns the chosen index.
pub fn select_index(
    dmenu_bin: &str,
    prompt_text: &str,
    items: &[String],
) -> Result<Option<usize>, String> {
    let labeled: Vec<String> = items
        .iter()
        .enumerate()
        .map(|(i, s)| format!("{i}\t{s}"))
        .collect();
    match prompt(dmenu_bin, prompt_text, &labeled)? {
        Outcome::Cancelled | Outcome::Empty => Ok(None),
        Outcome::Value(v) => {
            let idx_str = v.split('\t').next().unwrap_or(&v);
            let idx: usize = idx_str
                .parse()
                .map_err(|_| format!("invalid selection index: {v}"))?;
            if idx >= items.len() {
                return Err(format!("selection index out of range: {idx}"));
            }
            // Prefer exact labeled match when present.
            if let Some(i) = labeled.iter().position(|l| l == &v) {
                return Ok(Some(i));
            }
            Ok(Some(idx))
        }
    }
}

/// Free-text prompt with no selectable items (typed text or empty Enter).
pub fn prompt_free(dmenu_bin: &str, prompt_text: &str) -> Result<Outcome, String> {
    prompt(dmenu_bin, prompt_text, &[])
}

/// Prompt for a password via dmenu (`-P` / configured flag when available).
pub fn prompt_password(
    dmenu_bin: &str,
    mode: &PasswordMode,
    prompt_text: &str,
) -> Result<Outcome, String> {
    let flag = mode.resolve_flag(dmenu_bin)?;
    let mut cmd = Command::new(dmenu_bin);
    if let Some(f) = flag {
        cmd.arg(f);
    }
    cmd.arg("-p").arg(prompt_text);

    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("failed to spawn {dmenu_bin}: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"\n");
    }

    let mut output = child
        .wait_with_output()
        .map_err(|e| format!("dmenu wait failed: {e}"))?;

    if !output.status.success() {
        output.stdout.zeroize();
        return Ok(Outcome::Cancelled);
    }

    let mut s = String::from_utf8_lossy(&output.stdout).into_owned();
    output.stdout.zeroize();
    while s.ends_with('\n') || s.ends_with('\r') {
        s.pop();
    }
    if s.is_empty() {
        Ok(Outcome::Empty)
    } else {
        Ok(Outcome::Value(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_grouped_password_flag() {
        assert!(usage_supports_password_flag("usage: dmenu [-bfiPv] [-l lines]"));
        assert!(usage_supports_password_flag("usage: dmenu [-P] [-l lines]"));
        assert!(usage_supports_password_flag("usage: dmenu [-bfiv] [-P] [-l lines]"));
        assert!(!usage_supports_password_flag("usage: dmenu [-bfiv] [-l lines]"));
        assert!(!usage_supports_password_flag("usage: dmenu [-bfiv]"));
    }
}
