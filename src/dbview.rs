//! Flatten database entries for dmenu listing (group-aware paths).

use std::collections::HashMap;

use keepass::db::{EntryId, EntryRef, GroupId};
use keepass::Database;

/// A selectable entry row for dmenu.
#[derive(Debug, Clone)]
pub struct EntryItem {
    /// Display label, e.g. `Work/VPN` or `Gmail (alice@work)`.
    pub label: String,
    pub id: EntryId,
}

/// Strip newlines/control chars that would break the dmenu line protocol.
pub fn sanitize_label(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() || c == '\n' || c == '\r' {
                ' '
            } else {
                c
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Group-aware list of all entries as `Group/…/Title` paths.
/// Skips entries inside the recycle bin when one is configured.
/// When multiple entries share the same path label, append `(username)`.
pub fn flat_entries(db: &Database) -> Vec<EntryItem> {
    let bin_id = db.recycle_bin().map(|g| g.id());

    let mut raw: Vec<(EntryId, String, String)> = db
        .iter_all_entries()
        .filter(|e| !in_recycle_bin(db, e, bin_id))
        .map(|e| {
            let path = sanitize_label(&entry_path_label(&e));
            let user = e.get_username().unwrap_or("").to_string();
            (e.id(), path, user)
        })
        .collect();

    let mut counts: HashMap<String, usize> = HashMap::new();
    for (_, path, _) in &raw {
        *counts.entry(path.clone()).or_insert(0) += 1;
    }

    let mut items: Vec<EntryItem> = raw
        .drain(..)
        .map(|(id, path, user)| {
            let label = if counts.get(&path).copied().unwrap_or(0) > 1 {
                let u = sanitize_label(&user);
                if u.is_empty() {
                    format!("{path} (no user)")
                } else {
                    format!("{path} ({u})")
                }
            } else {
                path
            };
            EntryItem { label, id }
        })
        .collect();

    items.sort_by(|a, b| a.label.to_lowercase().cmp(&b.label.to_lowercase()));
    items
}

fn in_recycle_bin(db: &Database, entry: &EntryRef<'_>, bin_id: Option<GroupId>) -> bool {
    let Some(bin) = bin_id else {
        return false;
    };
    let mut current = Some(entry.parent().id());
    while let Some(id) = current {
        if id == bin {
            return true;
        }
        current = db.group(id).and_then(|g| g.parent().map(|p| p.id()));
    }
    false
}

/// Build `Group/Sub/Title` for an entry; skip a nameless or generic root.
fn entry_path_label(entry: &EntryRef<'_>) -> String {
    let title = entry.get_title().unwrap_or("(untitled)").to_string();
    let db = entry.database();
    let mut parts: Vec<String> = Vec::new();
    let mut current_id = entry.parent().id();

    loop {
        let Some(g) = db.group(current_id) else {
            break;
        };
        let name = g.name.clone();
        let parent_id = g.parent().map(|p| p.id());
        if parent_id.is_none() {
            let n = name.trim();
            if !n.is_empty() && !n.eq_ignore_ascii_case("root") {
                parts.push(n.to_string());
            }
            break;
        }
        let n = name.trim();
        if !n.is_empty() {
            parts.push(n.to_string());
        }
        match parent_id {
            Some(id) => current_id = id,
            None => break,
        }
    }

    parts.reverse();
    if parts.is_empty() {
        title
    } else {
        format!("{}/{}", parts.join("/"), title)
    }
}

/// Labels only, for feeding dmenu.
pub fn labels(items: &[EntryItem]) -> Vec<String> {
    items.iter().map(|i| i.label.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretString;
    use crate::unlock::unlock_with_password;
    use keepass::db::fields;
    use keepass::Database;
    use std::path::PathBuf;

    fn fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/smoke.kdbx")
    }

    #[test]
    fn lists_group_paths_from_smoke_db() {
        let pw = SecretString::new("testpass".into());
        let db = unlock_with_password(&fixture(), &pw).expect("unlock");
        let items = flat_entries(&db);
        let labels: Vec<_> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.contains(&"Example Site"));
        assert!(labels.contains(&"Email"));
        assert!(labels.contains(&"Work/VPN"));
    }

    #[test]
    fn sanitize_strips_newlines() {
        assert_eq!(sanitize_label("a\nb\rc"), "a b c");
    }

    #[test]
    fn duplicate_titles_show_username() {
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            root.add_entry().edit(|e| {
                e.set_unprotected(fields::TITLE, "Gmail");
                e.set_unprotected(fields::USERNAME, "alice@work");
            });
            root.add_entry().edit(|e| {
                e.set_unprotected(fields::TITLE, "Gmail");
                e.set_unprotected(fields::USERNAME, "bob@home");
            });
        }
        let items = flat_entries(&db);
        let labels: Vec<_> = items.iter().map(|i| i.label.clone()).collect();
        assert!(labels.iter().any(|l| l == "Gmail (alice@work)"));
        assert!(labels.iter().any(|l| l == "Gmail (bob@home)"));
    }
}
