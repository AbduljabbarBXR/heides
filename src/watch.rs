// The watch loop.
//
// HEIDES is event driven. Watch mode polls the workspace for changes and
// reindexes on demand, keeping the spine fresh while the agent works.

use std::path::Path;
use std::time::Duration;

use crate::indexer;
use crate::spine::CodeGraph;

/// Watch the workspace for changes.
/// Runs for at most max_checks polls (None means forever).
/// Returns the number of reindex events observed.
pub fn watch(root: &Path, max_checks: Option<u64>, delay_secs: u64) -> u64 {
    let mut last = indexer::load_or_build(root).unwrap_or_else(|_| CodeGraph::new());
    println!("watch started on {}", root.display());
    let mut changes = 0u64;
    let mut checks = 0u64;
    loop {
        if let Some(max) = max_checks {
            if checks >= max {
                break;
            }
        }
        std::thread::sleep(Duration::from_secs(delay_secs));
        checks += 1;
        let fresh = indexer::build_graph(root);
        if snapshot_changed(&last, &fresh.0) {
            if let Err(e) = crate::spine::save(&fresh.0, &root.to_path_buf()) {
                eprintln!("could not persist index: {}", e);
            }
            changes += 1;
            println!("spine reindexed: {} parsed files, {} symbols", fresh.1, fresh.0.symbols.len());
            last = fresh.0;
        }
    }
    changes
}

fn snapshot_changed(a: &CodeGraph, b: &CodeGraph) -> bool {
    if a.files.len() != b.files.len() {
        return true;
    }
    for (fa, fb) in a.files.iter().zip(b.files.iter()) {
        if fa.path != fb.path || fa.mtime != fb.mtime {
            return true;
        }
    }
    a.symbols.len() != b.symbols.len()
}
