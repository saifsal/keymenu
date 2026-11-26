//! Spawn dmenu for selection and password prompts.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use crate::secret::SecretString;

static SUPPORTS_P: OnceLock<bool> = OnceLock::new();

/// Detect whether `dmenu` accepts `-P` (password input patch) via its usage text.
fn supports_password_flag(dmenu_bin: &str) -> bool {
    *SUPPORTS_P.get_or_init(|| {
        // `dmenu -h` prints usage and does not need a display.
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
                text.split_whitespace().any(|t| t == "-P" || t.starts_with("[-P"))
                    || text.contains("[-P")
                    || text.contains(" -P ")
            }
            Err(_) => false,
        }
    })
}

/// Present newline-separated items; return the selected line (trimmed).
pub fn select(dmenu_bin: &str, prompt: &str, items: &[String]) -> Result<Option<String>, String> {
    let input = items.join("\n");
    let mut child = Command::new(dmenu_bin)
        .arg("-i")
        .arg("-p")
        .arg(prompt)
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
        // Escape / no selection
        return Ok(None);
    }

    let selection = String::from_utf8_lossy(&output.stdout)
        .trim_end_matches(['\n', '\r'])
        .to_string();
    if selection.is_empty() {
        Ok(None)
    } else {
        Ok(Some(selection))
    }
}

/// Prompt for the master password via dmenu (`-P` when available).
pub fn prompt_password(dmenu_bin: &str, prompt: &str) -> Result<Option<SecretString>, String> {
    let mut cmd = Command::new(dmenu_bin);
    if supports_password_flag(dmenu_bin) {
        cmd.arg("-P");
    }
    cmd.arg("-p").arg(prompt);

    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("failed to spawn {dmenu_bin}: {e}"))?;

    // Password mode still reads stdin for the menu; feed a blank line so it shows the prompt.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"\n");
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("dmenu wait failed: {e}"))?;

    if !output.status.success() {
        return Ok(None);
    }

    let mut s = String::from_utf8_lossy(&output.stdout).into_owned();
    while s.ends_with('\n') || s.ends_with('\r') {
        s.pop();
    }
    if s.is_empty() {
        Ok(None)
    } else {
        Ok(Some(SecretString::new(s)))
    }
}
