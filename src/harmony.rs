// Harmony is the judgment organ of HEIDES.
//
// It runs every guard against the spine graph and against the workspace,
// and normalizes the results into one report shape. Guards are deterministic
// and explainable. A guard never guesses: it reports evidence.

use std::collections::HashMap;
use std::path::Path;

use crate::spine::CodeGraph;
use crate::{parser, taint};

#[derive(Debug, Clone, serde::Serialize)]
pub struct GuardReport {
    pub guard: String,
    pub severity: String,
    pub message: String,
    pub file: String,
    pub line: u64,
}

/// What a check actually looked at, so a clean result cannot be mistaken for
/// an unanalysable one.
///
/// The failure this exists to prevent shipped in 0.15.2: a check on a
/// never-indexed workspace printed "0 blockers" because every guard received no
/// content. Zero findings and analysed nothing printed the same words. A
/// receipt always prints, clean runs included, because a receipt you only see
/// when something is wrong is a warning and not a receipt.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Coverage {
    /// Files in the index, and how many of them could actually be read back.
    pub files: usize,
    pub files_read: usize,
    /// Files the walker saw but could not read, with the reason.
    pub unreadable: Vec<String>,
    /// Languages present in the index, ascending.
    pub languages: Vec<String>,
    /// Languages present that no taint rule covers. A Rust-only workspace lands
    /// here, and the receipt says so instead of implying it was scanned.
    pub taint_untested: Vec<String>,
    /// Files indexed but contributing no symbols, which is what a language
    /// without a grammar looks like.
    pub no_grammar: Vec<String>,
    /// False when the dependency guard could not reach its registries.
    pub deps_online: bool,
}

impl Coverage {
    /// One line per fact, no prose, so it reads the same in a terminal and in
    /// the MCP tool output.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "analysed {} of {} indexed file(s)",
            self.files_read, self.files
        ));
        if !self.languages.is_empty() {
            out.push_str(&format!("\nlanguages: {}", self.languages.join(", ")));
        }
        if !self.taint_untested.is_empty() {
            out.push_str(&format!(
                "\nno taint rules for: {} (indexed, taint not scanned)",
                self.taint_untested.join(", ")
            ));
        }
        if !self.no_grammar.is_empty() {
            out.push_str(&format!(
                "\ntaint scanned, no grammar: {} (no symbols in the graph)",
                self.no_grammar.join(", ")
            ));
        }
        if !self.unreadable.is_empty() {
            out.push_str(&format!(
                "\nunreadable ({}): {}",
                self.unreadable.len(),
                self.unreadable.join(", ")
            ));
        }
        if !self.deps_online {
            out.push_str("\ndependency check was partial: registries unreachable");
        }
        out
    }
}

/// Build the receipt for a graph. Counts languages from the index and the
/// taint rules from the rule tables, so neither can drift from what the
/// guards actually do.
pub fn coverage_of(graph: &CodeGraph, deps_online: bool) -> Coverage {
    use std::collections::BTreeSet;
    let mut langs: BTreeSet<String> = BTreeSet::new();
    let mut untested: BTreeSet<String> = BTreeSet::new();
    let mut no_grammar: BTreeSet<String> = BTreeSet::new();
    let mut files_read = 0usize;
    for f in &graph.files {
        if f.lang.is_empty() {
            continue;
        }
        langs.insert(f.lang.clone());
        // A language with no taint rule row at all, in either the shared source
        // table or the strict sink tables, is indexed but not taint scanned.
        let has_rules = taint::SOURCES.iter().any(|(l, _)| *l == f.lang)
            || taint::strict_sinks(&f.lang).next().is_some();
        if !has_rules {
            untested.insert(f.lang.clone());
        }
        // Indexed with no grammar: a taint language the parser cannot extract
        // symbols from, so it contributes findings but nothing to the graph.
        if !parser::has_grammar(&f.lang) && taint::strict_sinks(&f.lang).next().is_some() {
            no_grammar.insert(f.lang.clone());
        }
    }
    let mut unreadable = Vec::new();
    for f in &graph.files {
        if std::fs::read_to_string(graph.file_path_of(&f.path)).is_ok() {
            files_read += 1;
        } else {
            unreadable.push(f.path.clone());
        }
    }
    unreadable.sort();
    unreadable.dedup();
    Coverage {
        files: graph.files.len(),
        files_read,
        unreadable,
        languages: langs.into_iter().collect(),
        taint_untested: untested.into_iter().collect(),
        no_grammar: no_grammar.into_iter().collect(),
        deps_online,
    }
}

/// Run the full workspace check and report the dependency guard's network
/// state, which the coverage receipt needs. Kept separate from
/// `check_workspace` so the receipt can be built from the same call rather than
/// re-querying the registries.
pub fn check_workspace_with_coverage(
    root: &Path,
    graph: &CodeGraph,
) -> (Vec<GuardReport>, Coverage) {
    let (reports, network_ok) = check_workspace_and_online(root, graph);
    let cov = coverage_of(graph, network_ok);
    (reports, cov)
}

/// Run the full workspace check: taint, edge cases, practices, dependencies.
pub fn check_workspace(root: &Path, graph: &CodeGraph) -> Vec<GuardReport> {
    check_workspace_and_online(root, graph).0
}

fn check_workspace_and_online(root: &Path, graph: &CodeGraph) -> (Vec<GuardReport>, bool) {
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

    (reports, network_ok)
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
    fn the_receipt_reports_what_was_analysed() {
        let dir = scratch("receipt");
        std::fs::write(dir.join("a.js"), "export const x = 1;\n").unwrap();
        std::fs::write(dir.join("b.py"), "y = 1\n").unwrap();
        let (graph, _) = indexer::build_graph(&dir);
        let cov = coverage_of(&graph, true);
        let text = cov.render();
        assert_eq!(cov.files, 2, "{text}");
        assert_eq!(cov.files_read, 2, "both files must be readable: {text}");
        assert!(cov.languages.iter().any(|l| l == "javascript"), "{text}");
        assert!(cov.languages.iter().any(|l| l == "python"), "{text}");
        assert!(
            cov.taint_untested.is_empty(),
            "js and py both have rules: {text}"
        );
        assert!(cov.unreadable.is_empty(), "{text}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_receipt_names_a_language_with_no_taint_rules() {
        // The case that matters. A Rust only workspace is indexed fully, finds
        // nothing, and would otherwise read as clean with no hint that taint
        // never ran on it.
        let dir = scratch("rustonly");
        std::fs::write(dir.join("a.rs"), "fn f() -> i32 { 1 }\n").unwrap();
        let (graph, _) = indexer::build_graph(&dir);
        let cov = coverage_of(&graph, true);
        let text = cov.render();
        assert!(
            cov.taint_untested.iter().any(|l| l == "rust"),
            "a language with no taint rule must be named: {text}"
        );
        assert!(
            text.contains("taint not scanned"),
            "the receipt must say why, not just list it: {text}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_receipt_separates_taint_scanned_from_indexed() {
        // Ruby is recognised so the taint guard can scan it, and has no
        // grammar, so it contributes nothing to the graph. The receipt has to
        // distinguish that from a language with no rules at all.
        let dir = scratch("rubyonly");
        std::fs::write(dir.join("a.rb"), "def f\n  1\nend\n").unwrap();
        let (graph, _) = indexer::build_graph(&dir);
        let cov = coverage_of(&graph, true);
        let text = cov.render();
        assert!(
            cov.taint_untested.is_empty(),
            "ruby has taint rules, so it is not in the untested list: {text}"
        );
        assert!(
            cov.no_grammar.iter().any(|l| l == "ruby"),
            "ruby has no grammar and must be reported as such: {text}"
        );
        assert!(text.contains("no grammar"), "{text}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_receipt_names_files_it_could_not_read() {
        // This is the 0.15.2 shape as a receipt rather than a crash. A file the
        // walker listed but the checker could not open must be named, not
        // silently dropped from the analysed count.
        let dir = scratch("unreadable");
        let file = dir.join("a.js");
        std::fs::write(&file, "export const x = 1;\n").unwrap();
        let (graph, _) = indexer::build_graph(&dir);
        let cov = coverage_of(&graph, true);
        assert_eq!(cov.files_read, cov.files, "everything readable for now");
        std::fs::remove_file(&file).unwrap();
        let cov2 = coverage_of(&graph, true);
        let text = cov2.render();
        assert!(
            cov2.files_read < cov2.files,
            "a deleted file must drop the analysed count: {text}"
        );
        assert!(
            cov2.unreadable.iter().any(|p| p.contains("a.js")),
            "the unreadable file must be named: {text}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_receipt_says_when_the_dependency_check_was_partial() {
        let dir = scratch("offline");
        std::fs::write(dir.join("a.js"), "export const x = 1;\n").unwrap();
        let (graph, _) = indexer::build_graph(&dir);
        let text = coverage_of(&graph, false).render();
        assert!(text.contains("registries unreachable"), "{text}");
        let online = coverage_of(&graph, true).render();
        assert!(!online.contains("registries unreachable"), "{online}");
        std::fs::remove_dir_all(&dir).ok();
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
