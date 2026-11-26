//! Flatten database entries for dmenu listing (group-aware paths).

use keepass::db::{EntryId, EntryRef};
use keepass::Database;

/// A selectable entry row for dmenu.
#[derive(Debug, Clone)]
pub struct EntryItem {
    /// Display label, e.g. `Work/VPN` or `Example Site`.
    pub label: String,
    pub id: EntryId,
}

/// Group-aware list of all entries as `Group/…/Title` paths (root group name omitted when empty/"Root").
pub fn flat_entries(db: &Database) -> Vec<EntryItem> {
    let mut items: Vec<EntryItem> = db
        .iter_all_entries()
        .map(|e| EntryItem {
            label: entry_path_label(&e),
            id: e.id(),
        })
        .collect();

    // Disambiguate duplicate labels so dmenu selection is unique.
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for item in &mut items {
        let count = seen.entry(item.label.clone()).or_insert(0);
        if *count > 0 {
            item.label = format!("{} ({})", item.label, count);
        }
        *count += 1;
    }

    items.sort_by(|a, b| a.label.to_lowercase().cmp(&b.label.to_lowercase()));
    items
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
            // Database root: include name only if meaningful and not the common "Root".
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

/// Find an item by exact dmenu selection string.
pub fn find_by_label<'a>(items: &'a [EntryItem], label: &str) -> Option<&'a EntryItem> {
    items.iter().find(|i| i.label == label)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretString;
    use crate::unlock::unlock_with_password;
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
}
