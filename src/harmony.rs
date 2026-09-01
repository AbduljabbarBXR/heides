// Harmony is the judgment organ of HEIDES.
//
// It runs every guard against the spine graph and against the workspace,
// and normalizes the results into one report shape. Guards are deterministic
// and explainable. A guard never guesses: it reports evidence.

use std::path::Path;

use crate::spine::CodeGraph;

#[derive(Debug, Clone, serde::Serialize)]
pub struct GuardReport {
    pub guard: String,
    pub severity: String,
    pub message: String,
    pub file: String,
    pub line: u64,
}

/// Run the full workspace check: taint, edge cases, practices, dependencies.
pub fn check_workspace(root: &Path, graph: &CodeGraph) -> Vec<GuardReport> {
    let mut reports = Vec::new();

    for f in &graph.files {
        let path = Path::new(&f.path);
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        for r in crate::taint::scan_file(path, &content) {
            reports.push(GuardReport {
                guard: "security.taint".to_string(),
                severity: r.severity,
                message: r.message,
                file: r.file,
                line: r.line,
            });
        }
        for r in crate::edge::scan_file(path, &content) {
            reports.push(GuardReport {
                guard: "edge.cases".to_string(),
                severity: r.severity,
                message: r.message,
                file: r.file,
                line: r.line,
            });
        }
        for r in crate::practice::scan_file(path, &content, &f.lang) {
            reports.push(GuardReport {
                guard: "best.practice".to_string(),
                severity: r.severity,
                message: r.message,
                file: r.file,
                line: r.line,
            });
        }
    }

    for r in crate::practice::long_functions(graph) {
        reports.push(GuardReport {
            guard: "best.practice".to_string(),
            severity: r.severity,
            message: r.message,
            file: r.file,
            line: r.line,
        });
    }

    let (dep_reports, network_ok) = crate::deps::check(root);
    for r in dep_reports {
        reports.push(GuardReport {
            guard: "dependency".to_string(),
            severity: r.severity,
            message: r.message,
            file: r.file,
            line: r.line,
        });
    }
    if !network_ok {
        reports.push(GuardReport {
            guard: "dependency".to_string(),
            severity: "info".to_string(),
            message: "network was unavailable for the dependency check. results are partial.".to_string(),
            file: String::new(),
            line: 0,
        });
    }

    reports
}

/// Check a proposed patch against the workspace before it is applied.
pub fn check_staged(root: &Path, graph: &CodeGraph, patch_text: &str) -> Result<Vec<GuardReport>, String> {
    let parsed = crate::staged::parse_patch(patch_text)?;
    let findings = crate::staged::check_patch(graph, root, &parsed);
    let reports = findings
        .into_iter()
        .map(|r| GuardReport {
            guard: "staged.apply".to_string(),
            severity: r.severity,
            message: r.message,
            file: r.file,
            line: r.line,
        })
        .collect();
    Ok(reports)
}

/// Summarize reports by severity for a quick overview line.
pub fn summarize(reports: &[GuardReport]) -> String {
    let blockers = reports.iter().filter(|r| r.severity == "blocker").count();
    let critical = reports.iter().filter(|r| r.severity == "critical").count();
    let warnings = reports.iter().filter(|r| r.severity == "warning").count();
    let infos = reports.iter().filter(|r| r.severity == "info").count();
    format!(
        "{} blocker(s), {} critical, {} warning(s), {} info",
        blockers, critical, warnings, infos
    )
}
