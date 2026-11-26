//! Flatten database entries for dmenu listing.

use keepass::db::EntryId;
use keepass::Database;

/// A selectable entry row for dmenu.
#[derive(Debug, Clone)]
pub struct EntryItem {
    pub label: String,
    pub id: EntryId,
}

/// Flat list of all entries (title only; duplicates get a numeric suffix).
pub fn flat_entries(db: &Database) -> Vec<EntryItem> {
    let mut items: Vec<EntryItem> = db
        .iter_all_entries()
        .map(|e| {
            let title = e.get_title().unwrap_or("(untitled)").to_string();
            EntryItem {
                label: title,
                id: e.id(),
            }
        })
        .collect();

    // Disambiguate duplicate titles so dmenu selection is unique.
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
    fn lists_flat_titles_from_smoke_db() {
        let pw = SecretString::new("testpass".into());
        let db = unlock_with_password(&fixture(), &pw).expect("unlock");
        let items = flat_entries(&db);
        let labels: Vec<_> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.contains(&"Example Site"));
        assert!(labels.contains(&"Email"));
        assert!(labels.contains(&"VPN"));
    }
}
