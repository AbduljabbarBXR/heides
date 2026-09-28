// Harmony is the judgment organ of HEIDES.
//
// It runs every guard against the spine graph and against the workspace,
// and normalizes the results into one report shape. Guards are deterministic
// and explainable. A guard never guesses: it reports evidence.

use std::collections::HashMap;
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
    let mut reports = check_workspace_without_deps(graph);

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
            message: "network was unavailable for the dependency check. results are partial."
                .to_string(),
            file: String::new(),
            line: 0,
        });
    }

    reports
}

/// The shared local guard body behind check_workspace and the report tool.
pub fn check_workspace_without_deps(graph: &CodeGraph) -> Vec<GuardReport> {
    let mut reports = Vec::new();
    // Read every indexed file once. The intra guards and the interprocedural
    // taint pass share the same contents so nothing is parsed twice. Stored
    // paths are keys relative to the recorded scan root, so a check returns
    // the same findings from any working directory.
    let mut contents: HashMap<String, String> = HashMap::new();
    for f in &graph.files {
        let path = graph.file_path_of(&f.path);
        if let Ok(content) = std::fs::read_to_string(path) {
            contents.insert(f.path.trim_start_matches("./").replace('\\', "/"), content);
        }
    }

    for f in &graph.files {
        let path = Path::new(&f.path);
        let key = f.path.trim_start_matches("./").replace('\\', "/");
        let Some(content) = contents.get(&key) else {
            continue;
        };
        for r in crate::taint::scan_file(path, content) {
            reports.push(GuardReport {
                guard: "security.taint".to_string(),
                severity: r.severity,
                message: r.message,
                file: r.file,
                line: r.line,
            });
        }
        for r in crate::edge::scan_file(path, content) {
            reports.push(GuardReport {
                guard: "edge.cases".to_string(),
                severity: r.severity,
                message: r.message,
                file: r.file,
                line: r.line,
            });
        }
        for r in crate::practice::scan_file(path, content, &f.lang) {
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

    for r in crate::interproc::run_workspace(graph, &contents) {
        reports.push(GuardReport {
            guard: "security.taint".to_string(),
            severity: r.severity,
            message: r.message,
            file: r.file,
            line: r.line,
        });
    }

    reports
}

/// The local guards only, no network, for live watch deltas.
pub fn check_workspace_local(graph: &CodeGraph) -> Vec<GuardReport> {
    check_workspace_without_deps(graph)
}

/// Check a proposed patch against the workspace before it is applied.
pub fn check_staged(
    root: &Path,
    graph: &CodeGraph,
    patch_text: &str,
) -> Result<Vec<GuardReport>, String> {
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

#[cfg(test)]
mod liveness {
    use super::*;
    use crate::{deps, indexer};
    use std::path::{Path, PathBuf};

    /// Every module that has a guard has a unit test for it, and every one of
    /// those unit tests calls `scan_file` with an inline string. None of them
    /// proved a guard can fire through this pipeline from a real file on disk,
    /// which is why 0.15.2 shipped a guard that reported nothing: the guard was
    /// correct and it was handed no content.
    ///
    /// A liveness test is two halves. Plant a known bad input and assert the
    /// guard fires, which catches a guard that has quietly stopped working.
    /// Plant a known good input and assert silence, which catches a guard that
    /// has started reporting everything. A guard is only trustworthy with both.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "heides_liveness_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let _ = tag;
        dir
    }

    /// Run the real pipeline: index files from disk, then check them.
    fn run(dir: &Path) -> Vec<GuardReport> {
        let (graph, _) = indexer::build_graph(dir);
        assert!(!graph.files.is_empty(), "scratch dir must hold a file");
        check_workspace_without_deps(&graph)
    }

    fn guards(reports: &[GuardReport]) -> Vec<&str> {
        let mut g: Vec<&str> = reports.iter().map(|r| r.guard.as_str()).collect();
        g.sort();
        g.dedup();
        g
    }

    fn fires(reports: &[GuardReport], guard: &str) -> bool {
        reports.iter().any(|r| r.guard == guard)
    }

    #[test]
    fn taint_guard_fires_from_a_file_on_disk() {
        let dir = scratch("taint");
        std::fs::write(
            dir.join("a.js"),
            "function load(req) {\n  const q = req.query.id;\n  return db.query(q);\n}\n",
        )
        .unwrap();
        let reports = run(&dir);
        assert!(
            fires(&reports, "security.taint"),
            "security.taint must fire end to end, got {:?}",
            guards(&reports)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn edge_guard_fires_from_a_file_on_disk() {
        let dir = scratch("edge");
        std::fs::write(
            dir.join("a.rs"),
            "fn f(o: Option<i32>) -> i32 {\n    o.unwrap()\n}\n",
        )
        .unwrap();
        let reports = run(&dir);
        assert!(
            fires(&reports, "edge.cases"),
            "edge.cases must fire end to end, got {:?}",
            guards(&reports)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn practice_guard_fires_from_a_file_on_disk() {
        let dir = scratch("practice");
        std::fs::write(
            dir.join("a.py"),
            "API_KEY = 'sk-abc123def456ghi789jkl012mno345pqr678'\n",
        )
        .unwrap();
        let reports = run(&dir);
        assert!(
            fires(&reports, "best.practice"),
            "best.practice must fire end to end, got {:?}",
            guards(&reports)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_dependency_guard_reports_when_it_cannot_see_a_manifest() {
        // The dependency guard is the one guard that does not read source, so
        // its liveness shape is different. A directory with no manifest must
        // still produce a report, the one that says so, rather than nothing.
        let dir = scratch("deps");
        std::fs::write(dir.join("a.js"), "export const x = 1;\n").unwrap();
        let (reports, _) = deps::check(&dir);
        assert!(
            reports
                .iter()
                .any(|r| r.message.contains("no dependency manifests")),
            "a manifest-less directory must be reported, not silently clean, got {reports:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_clean_workspace_stays_silent_on_every_guard() {
        // The other half. A guard that fires on idiomatic code is worse than
        // one that does not fire, because it is the guard people learn to skip.
        let dir = scratch("clean");
        std::fs::write(
            dir.join("a.js"),
            "export function add(a, b) {\n  return a + b;\n}\n",
        )
        .unwrap();
        std::fs::write(dir.join("b.py"), "def add(a, b):\n    return a + b\n").unwrap();
        let reports = run(&dir);
        assert!(
            reports.is_empty(),
            "idiomatic code must produce no findings, got {reports:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
