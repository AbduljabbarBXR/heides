// The watch loop.
//
// HEIDES is event driven. Watch mode polls the workspace, diffs the file
// table against disk and reparses only the changed files, keeping the spine
// fresh while the agent works without rebuilding the whole graph each poll.

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
        let mut current = last.clone();
        let touched = indexer::update_graph(root, &mut current);
        if touched > 0 {
            if let Err(e) = crate::spine::save(&current, &root.to_path_buf()) {
                eprintln!("could not persist index: {}", e);
            }
            changes += 1;
            println!(
                "spine reindexed: {} files touched, {} symbols",
                touched,
                current.symbols.len()
            );
            last = current;
        }
    }
    changes
}
