// Harmony is the judgment organ of HEIDES.
//
// It runs the guard modules against the spine graph and against proposed
// patches. Every guard is deterministic and explainable. A guard never
// guesses: it reports evidence from the graph or the file system.

use crate::spine::CodeGraph;

#[derive(Debug, serde::Serialize)]
pub struct GuardReport {
    pub guard: String,
    pub severity: String,
    pub message: String,
    pub file: Option<String>,
    pub line: Option<u64>,
}

/// Run every guard against the current graph.
///
/// Guards scheduled for implementation:
///   staged apply    compare current code against proposed code and block
///                   conflicts before anything is written to disk
///   edge cases      flag missing null, empty, error path and boundary
///                   handling on every changed function
///   security taint  trace user input into SQL, shell, filesystem and
///                   prompt sinks
///   dependency      detect upgrades that break the imports you actually use
///   practices       surface violations of project conventions
pub fn run_all(graph: &CodeGraph) -> Vec<GuardReport> {
    let mut reports = Vec::new();
    reports.push(GuardReport {
        guard: "spine.ready".to_string(),
        severity: "info".to_string(),
        message: format!(
            "spine is ready with {} files and {} symbols",
            graph.files.len(),
            graph.symbols.len()
        ),
        file: None,
        line: None,
    });
    reports
}
