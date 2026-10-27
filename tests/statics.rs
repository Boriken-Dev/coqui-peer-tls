//! A library keeps no process-wide state: no `static`, `OnceLock`, `LazyLock` or
//! `thread_local!` in `src/` except the items named in `ALLOWED`.

use std::fs;
use std::path::Path;

/// `(file under src/, the item)` pairs that may hold process-wide state.
const ALLOWED: &[(&str, &str)] = &[
    // The connection's addresses, scoped by `with_source` around the calls rustls makes into a
    // verifier on this thread.
    ("source.rs", "thread_local!"),
    ("source.rs", "static CURRENT"),
];

const MARKERS: &[&str] = &["static ", "OnceLock", "LazyLock", "thread_local!"];

fn scan(root: &Path, directory: &Path, found: &mut Vec<(String, String)>) {
    for entry in fs::read_dir(directory).expect("src/ is readable") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            scan(root, &path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let text = fs::read_to_string(&path).expect("a source file is UTF-8");
            let relative = path
                .strip_prefix(root)
                .expect("under src/")
                .to_string_lossy()
                .replace('\\', "/");
            for line in text.lines() {
                let code = line.split("//").next().unwrap_or_default();
                if MARKERS.iter().any(|marker| code.contains(marker)) && !code.contains("'static") {
                    found.push((relative.clone(), line.trim().to_owned()));
                }
            }
        }
    }
}

#[test]
fn the_source_holds_no_process_wide_state_but_the_allowed_items() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    scan(&root, &root, &mut found);
    let unexpected: Vec<_> = found
        .iter()
        .filter(|(file, line)| {
            !ALLOWED
                .iter()
                .any(|(allowed, item)| file == allowed && line.contains(item))
        })
        .collect();
    assert!(unexpected.is_empty(), "process-wide state: {unexpected:?}");
    for (allowed, item) in ALLOWED {
        assert!(
            found
                .iter()
                .any(|(file, line)| file == allowed && line.contains(item)),
            "{allowed}: {item} is allowed but absent"
        );
    }
}
