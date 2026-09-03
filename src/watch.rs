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
pub fn watch(root: &Path, max_checks: Option<u64>, delay_secs: u64, ui: &crate::ui::Ui) -> u64 {
    let mut last = indexer::load_or_build(root).unwrap_or_else(|_| CodeGraph::new());
    println!("watch started on {}", root.display());
    if ui.progress {
        eprintln!("watching, local guards run on every change");
    }
    let mut changes = 0u64;
    let mut checks = 0u64;
    loop {
        if let Some(max) = max_checks
            && checks >= max
        {
            break;
        }
        std::thread::sleep(Duration::from_secs(delay_secs));
        checks += 1;
        let mut current = last.clone();
        let touched = indexer::update_graph(root, &mut current);
        if touched > 0 {
            if let Err(e) = crate::spine::save(&current, root) {
                eprintln!("could not persist index: {}", e);
            }
            changes += 1;
            println!(
                "spine reindexed: {} files touched, {} symbols",
                touched,
                current.symbols.len()
            );
            if ui.progress {
                let reports = crate::harmony::check_workspace_local(&current);
                let b = reports.iter().filter(|r| r.severity == "blocker").count();
                let c = reports.iter().filter(|r| r.severity == "critical").count();
                let w = reports.iter().filter(|r| r.severity == "warning").count();
                let i = reports.iter().filter(|r| r.severity == "info").count();
                eprintln!(
                    "watch reindexed {} files, {} blocker(s), {} critical, {} warning(s), {} info",
                    touched,
                    ui.count("blocker", b),
                    ui.count("critical", c),
                    ui.count("warning", w),
                    ui.count("info", i)
                );
            }
            last = current;
        }
    }
    changes
}
