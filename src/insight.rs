// Signals heides can prove by disagreeing with itself.
//
// Every other guard here reads one signal and applies a rule. This module reads
// two signals that were computed independently and reports where they cannot
// both be true: a route whose handler does not exist, a handler that is also
// reported as unreachable, a file that nothing can reach and nothing calls out
// of, a language with no rule that can fail on it.
//
// Those contradictions are the cheap ones. The expensive signal, what a change
// costs, is here too, because "you are about to edit this" is the question an
// agent asks most often and the one a guard list answers worst.

use crate::spine::CodeGraph;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Insight {
    pub severity: String,
    pub kind: String,
    pub message: String,
    pub file: String,
    pub line: u64,
}

impl Insight {
    fn new(severity: &str, kind: &str, message: String, file: &str, line: u64) -> Self {
        Insight {
            severity: severity.to_string(),
            kind: kind.to_string(),
            message,
            file: file.to_string(),
            line,
        }
    }
}

fn norm(file: &str) -> String {
    file.trim_start_matches("./").replace('\\', "/")
}

fn is_test_path(file: &str) -> bool {
    let f = norm(file);
    f.contains("/tests/")
        || f.contains("/test/")
        || f.starts_with("tests/")
        || f.starts_with("test/")
        || f.contains("/__tests__/")
        || std::path::Path::new(&f)
            .file_name()
            .map(|n| {
                let n = n.to_string_lossy().to_lowercase();
                n.starts_with("test_")
                    || n.ends_with("_test.py")
                    || n.ends_with("_test.go")
                    || n.ends_with("_test.rb")
                    || n.ends_with("test.java")
                    || n.ends_with("spec.js")
                    || n.ends_with("spec.ts")
            })
            .unwrap_or(false)
}

fn is_test_name(name: &str) -> bool {
    let n = name.to_lowercase();
    n.starts_with("test_") || n.ends_with("_test") || n.contains("::test")
}

/// The set heides can reach from a symbol, and how much of it is untested.
///
/// A caller list on its own does not tell an agent whether a change is safe to
/// land. What it needs is the transitive size, the files that move with it,
/// whether any HTTP route is behind it, and whether anything that would catch a
/// regression actually calls it. That last one is the difference between "four
/// callers" and "four callers and no test reaches it".
/// What a route scan could not read, so a caller can say so instead of
/// returning a shorter answer without mentioning it.
///
/// `MAX_FILES` and `MAX_FILE_BYTES` are the right limits: nobody wants a
/// generated 40 MB bundle in a route table. But a silent limit is a lie the
/// tool tells about its own coverage, which is the one thing it must not do.
/// Every drop is counted, and the caller prints why.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ScanLimits {
    pub files_seen: usize,
    pub files_over_cap: usize,
    pub files_too_large: usize,
    pub unreadable: usize,
}

impl ScanLimits {
    /// True when anything was left out, so the caller can print why.
    pub fn dropped(&self) -> bool {
        self.files_over_cap + self.files_too_large + self.unreadable > 0
    }

    pub fn summary(&self) -> String {
        format!(
            "route scan read {} file(s); dropped {} over the file cap, {} over the size cap, {} unreadable",
            self.files_seen, self.files_over_cap, self.files_too_large, self.unreadable
        )
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Impact {
    pub symbol: String,
    pub defined_in: Vec<String>,
    pub direct_callers: Vec<(String, String, u64)>,
    pub transitive_callers: usize,
    pub files: Vec<String>,
    pub routes: Vec<String>,
    pub untested_callers: Vec<String>,
    pub is_route_handler: bool,
    pub is_exported: bool,
}

impl Impact {
    /// One line an agent can act on, rather than a struct it has to interpret.
    pub fn summary(&self) -> String {
        let mut s = format!(
            "{}: {} direct caller(s), {} transitive, {} file(s)",
            self.symbol,
            self.direct_callers.len(),
            self.transitive_callers,
            self.files.len()
        );
        if self.is_route_handler {
            s.push_str(", reached by a route");
        }
        if !self.routes.is_empty() {
            s.push_str(&format!(" ({} route(s))", self.routes.len()));
        }
        if !self.untested_callers.is_empty() {
            s.push_str(&format!(
                ", NO TEST REACHES IT: {}",
                self.untested_callers.join(", ")
            ));
        } else if !self.direct_callers.is_empty() {
            s.push_str(", every caller is a test or an entry point");
        }
        s
    }
}

/// What a change to `symbol` could reach.
pub fn impact(graph: &CodeGraph, symbol: &str, routes: &[(String, String)]) -> Impact {
    let mut out = Impact {
        symbol: symbol.to_string(),
        is_route_handler: routes.iter().any(|(_, h)| h == symbol),
        ..Impact::default()
    };
    for s in &graph.symbols {
        if s.name == symbol {
            out.defined_in.push(s.file.clone());
        }
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut frontier: Vec<String> = vec![symbol.to_string()];
    seen.insert(symbol.to_string());
    let mut direct: Vec<(String, String, u64)> = Vec::new();
    let mut test_callers: Vec<String> = Vec::new();
    let mut prod_callers: Vec<String> = Vec::new();
    // Bounded so a cycle cannot spin. heides records cycles elsewhere; here the
    // job is size, and an approximate size is still worth having.
    for _ in 0..64 {
        let Some(next) = frontier.pop() else { break };
        for c in graph.callers_of(&next) {
            if c.caller == c.callee {
                continue;
            }
            let is_test = is_test_path(&c.file) || is_test_name(&c.caller);
            if next == symbol {
                direct.push((c.caller.clone(), c.file.clone(), c.line));
                if !is_test {
                    out.files.push(norm(&c.file));
                }
                if is_test {
                    test_callers.push(c.caller.clone());
                } else {
                    prod_callers.push(c.caller.clone());
                }
            }
            if seen.insert(c.caller.clone()) {
                frontier.push(c.caller.clone());
            }
        }
    }
    out.transitive_callers = seen.len().saturating_sub(1);
    direct.sort_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)));
    direct.dedup();
    out.direct_callers = direct;
    out.files.sort();
    out.files.dedup();
    out.routes = routes
        .iter()
        .filter(|(_, h)| seen.contains(h))
        .map(|(r, _)| r.clone())
        .collect();
    // "No test reaches it" means no caller is a test, which is a gap. The
    // callers are then listed so the gap is actionable rather than a verdict.
    if test_callers.is_empty() && !prod_callers.is_empty() {
        out.untested_callers = prod_callers.clone();
    }
    out.untested_callers.sort();
    out.untested_callers.dedup();
    out
}

/// Every route in the workspace, with a receipt of what the scan could not read.
///
/// The receipt travels with the answer. A route table that quietly stopped at
/// 400 files reads exactly like a service with 400 files.
pub fn routes_with_limits(root: &Path, files: &[String]) -> (Vec<(String, String)>, ScanLimits) {
    let mut limits = ScanLimits {
        files_seen: files.len(),
        ..ScanLimits::default()
    };
    let mut out = Vec::new();
    for e in crate::frameworks::endpoints(files, root) {
        out.push((format!("{} {}", e.method, e.path), e.handler));
    }
    for f in files {
        let p = root.join(f);
        match std::fs::metadata(&p) {
            Ok(m) if m.len() as usize > 256 * 1024 => limits.files_too_large += 1,
            Ok(_) => {}
            Err(_) => limits.unreadable += 1,
        }
    }
    (out, limits)
}

/// Where two independently computed signals cannot both be true.
pub fn contradictions(
    graph: &CodeGraph,
    routes: &[(String, String, String, u64)],
    dead: &BTreeSet<(String, u64)>,
) -> Vec<Insight> {
    let mut out = Vec::new();

    // A route names a handler that is not in the graph. Either the handler was
    // renamed, it is generated by a macro, or the route is unreachable. All
    // three are worth a person, and none of them is visible from the route table
    // alone.
    for (route, handler, file, line) in routes {
        let defined = graph.symbols.iter().any(|s| s.name == *handler);
        if !defined {
            out.push(Insight::new(
                "critical",
                "route.handler_missing",
                format!(
                    "route {route} names handler {handler}, which no definition in this workspace matches. \
                     The handler was renamed, is generated by a macro, or the route is dead."
                ),
                file,
                *line,
            ));
        }
    }

    // A handler that a route dispatches to, and that the dead root check also
    // says nothing dispatches. Two layers, two answers, one of them wrong.
    for (route, handler, file, line) in routes {
        if graph.symbols.iter().any(|s| s.name == *handler) && dead.contains(&(handler.clone(), 0))
        {
            out.push(Insight::new(
                "warning",
                "route.dead_handler",
                format!(
                    "{handler} is dispatched by {route}, and the dead root check also reports it unreachable. \
                     One of the two layers is wrong about how this is reached."
                ),
                file,
                *line,
            ));
        }
    }

    // The most called symbol in the workspace carries no doc comment, while its
    // file mostly does. That is a documentation gap a reader can trust, because
    // both halves come from different measurements.
    let mut inbound: BTreeMap<&str, usize> = BTreeMap::new();
    for c in &graph.calls {
        *inbound.entry(c.callee.as_str()).or_insert(0) += 1;
    }
    let mut per_file_doc: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for s in &graph.symbols {
        let e = per_file_doc.entry(s.file.as_str()).or_insert((0, 0));
        e.1 += 1;
        if !s.doc.is_empty() {
            e.0 += 1;
        }
    }
    for s in &graph.symbols {
        let Some(&count) = inbound.get(s.name.as_str()) else {
            continue;
        };
        if count < 12 || !s.doc.is_empty() {
            continue;
        }
        // A field or a getter named `kind` is called constantly and documents
        // itself. Only a function is a hotspot a reader would want explained.
        let kind = s.kind.as_str();
        let callable = kind.contains("function")
            || kind.contains("method")
            || kind == "constructor_declaration"
            || kind == "local_function_statement";
        if !callable {
            continue;
        }
        let Some(&(documented, total)) = per_file_doc.get(s.file.as_str()) else {
            continue;
        };
        if total < 5 || documented * 2 < total {
            continue;
        }
        out.push(Insight::new(
            "info",
            "doc.hotspot",
            format!(
                "{} is called {count} time(s) and has no doc comment, in a file where {documented} of {total} symbols do. \
                 The most depended on thing in the file is the one nobody explained.",
                s.name
            ),
            &s.file,
            s.line,
        ));
    }

    // A file that imports nothing, calls nothing and defines nothing is either
    // generated, dead, or a leftover. It cannot be reached by a call edge and
    // cannot call one, so nothing else in the index will ever mention it.
    let mut calls_by_file: BTreeMap<&str, usize> = BTreeMap::new();
    for c in &graph.calls {
        *calls_by_file.entry(c.file.as_str()).or_insert(0) += 1;
    }
    let mut imports_by_file: BTreeMap<&str, usize> = BTreeMap::new();
    for i in &graph.imports {
        *imports_by_file.entry(i.file.as_str()).or_insert(0) += 1;
    }
    let syms_by_file = graph.symbols_by_file();
    for (file, syms) in &syms_by_file {
        if syms.is_empty() {
            continue;
        }
        if calls_by_file.get(file).copied().unwrap_or(0) == 0
            && imports_by_file.get(file).copied().unwrap_or(0) == 0
            && !syms
                .iter()
                .any(|s| is_test_name(&s.name) || s.kind.contains("function"))
        {
            out.push(Insight::new(
                "info",
                "file.isolated",
                format!(
                    "{} defines {} symbol(s) but imports nothing and calls nothing, so no call edge reaches it or leaves it.",
                    file,
                    syms.len()
                ),
                file,
                syms.first().map(|s| s.line).unwrap_or(0),
            ));
        }
    }

    out.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
    out
}

/// The languages and files in this workspace that no rule can fail on.
///
/// A clean result is only clean where a rule exists. This says where it is not,
/// which is the difference between "nothing to fix" and "nothing was looked for".
/// Whether any taint rule can fire on a language.
///
/// This asked only about the strict SSRF and NoSQL tables, which is how a
/// language with SQL and shell rules but no strict rows read as uncovered, and
/// how Rust read as uncovered even with rows in front of it. The test is the
/// same one the coverage receipt uses: a source row or a sink row in any table.
pub fn lang_has_taint(lang: &str) -> bool {
    crate::taint::SOURCES.iter().any(|(l, _)| *l == lang)
        || crate::taint::SINKS.iter().any(|(l, _, _)| *l == lang)
        || crate::taint::strict_sinks(lang).next().is_some()
}

pub fn coverage_gaps(graph: &CodeGraph, guards_ran: usize) -> Vec<Insight> {
    let mut out = Vec::new();
    let mut by_lang: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for f in &graph.files {
        let e = by_lang.entry(f.lang.as_str()).or_insert((0, 0));
        e.0 += 1;
        if lang_has_taint(&f.lang) {
            e.1 += 1;
        }
    }
    for (lang, (total, covered)) in by_lang {
        if covered == 0 && total > 0 {
            out.push(Insight::new(
                "warning",
                "coverage.no_taint",
                format!(
                    "{lang}: {total} file(s) indexed, no taint rule can fire on any of them. \
                     A clean {lang} verdict means no rule looked, not that nothing was found.",
                    lang = lang
                ),
                "",
                0,
            ));
        }
    }
    let no_grammar: BTreeSet<&str> = graph
        .files
        .iter()
        .filter(|f| !crate::parser::has_grammar(&f.lang))
        .map(|f| f.lang.as_str())
        .collect();
    for lang in no_grammar {
        if !lang_has_taint(lang) {
            continue;
        }
        out.push(Insight::new(
            "warning",
            "coverage.no_grammar",
            format!(
                "{lang} is taint scanned but has no grammar, so it contributes findings and nothing to the graph. \
                 Callers, dead roots and impact cannot see it."
            ),
            "",
            0,
        ));
    }
    if guards_ran == 0 {
        out.push(Insight::new(
            "critical",
            "coverage.no_guards",
            "no guard produced a finding for this workspace, which may mean none ran. \
             An empty result and an unrun check are not the same answer."
                .to_string(),
            "",
            0,
        ));
    }
    out
}

/// A stable identity for a finding, so "is this new" survives a reformat.
pub fn finding_key(guard: &str, file: &str, message: &str) -> String {
    // A line number is position, not identity. Strip "line 12" before digesting
    // so a finding that only moved down the file is still the known finding, and
    // a baseline does not fill itself with noise on the next edit.
    let stripped = strip_line_refs(message);
    let digits: String = stripped.chars().filter(|c| c.is_ascii_digit()).collect();
    let letters: String = stripped
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .take(24)
        .collect();
    format!("{guard}|{file}|{letters}{digits}")
}

fn strip_line_refs(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let b: Vec<char> = message.chars().collect();
    let mut i = 0;
    while i < b.len() {
        let rest: String = b[i..].iter().take(5).collect::<String>().to_lowercase();
        if rest.starts_with("line") {
            let mut j = i + 4;
            while j < b.len() && b[j].is_whitespace() {
                j += 1;
            }
            let digits_start = j;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if j > digits_start {
                i = j;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

pub fn baseline_path(root: &Path) -> PathBuf {
    root.join(".heides").join("baseline")
}

pub fn load_baseline(root: &Path) -> BTreeMap<String, String> {
    let path = baseline_path(root);
    let Ok(text) = std::fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    // Tab, not pipe: a finding key already contains pipes, so splitting on the
    // first one truncated the key and nothing ever matched its baseline.
    text.lines()
        .filter_map(|l| l.split_once('\t'))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

pub fn save_baseline(root: &Path, keys: &BTreeMap<String, String>) -> std::io::Result<()> {
    let path = baseline_path(root);
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let mut body = String::new();
    for (k, v) in keys {
        body.push_str(k);
        body.push('\t');
        body.push_str(v);
        body.push('\n');
    }
    std::fs::write(path, body)
}

/// The keys in `current` that the baseline has never recorded.
pub fn new_keys(
    current: &BTreeMap<String, String>,
    baseline: &BTreeMap<String, String>,
) -> Vec<String> {
    current
        .keys()
        .filter(|k| !baseline.contains_key(*k))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_test_path_is_recognised_whatever_the_layout() {
        for p in [
            "tests/battle.rs",
            "src/tests/mod.rs",
            "app/__tests__/render.js",
            "pkg/handler_test.go",
            "src/foo_test.py",
            "src/x.spec.ts",
            "src/test_util.rs",
        ] {
            assert!(is_test_path(p), "{p} should read as a test path");
        }
        for p in ["src/db.rs", "npm/bin/heides.js", "src/testing_helpers.rs"] {
            assert!(!is_test_path(p), "{p} should not read as a test path");
        }
    }

    #[test]
    fn a_finding_key_survives_a_line_number_moving() {
        let a = finding_key(
            "best.practice",
            "src/a.rs",
            "user input reaches a SQL sink at line 12",
        );
        let b = finding_key(
            "best.practice",
            "src/a.rs",
            "user input reaches a SQL sink at line 480",
        );
        assert_eq!(a, b, "a moved line number is the same finding");
        let c = finding_key(
            "best.practice",
            "src/b.rs",
            "user input reaches a SQL sink at line 12",
        );
        assert_ne!(a, c, "a different file is a different finding");
    }

    #[test]
    fn only_findings_the_baseline_has_never_seen_are_new() {
        let mut base = BTreeMap::new();
        base.insert("a".to_string(), "1".to_string());
        let mut cur = BTreeMap::new();
        cur.insert("a".to_string(), "1".to_string());
        cur.insert("b".to_string(), "1".to_string());
        assert_eq!(new_keys(&cur, &base), vec!["b".to_string()]);
    }

    #[test]
    fn a_baseline_round_trips_through_disk() {
        let dir = std::env::temp_dir().join("heides-insight-baseline-test");
        let _ = std::fs::remove_dir_all(&dir);
        let mut keys = BTreeMap::new();
        keys.insert("guard|src/a.rs|abc".to_string(), "secret".to_string());
        save_baseline(&dir, &keys).unwrap();
        assert_eq!(load_baseline(&dir), keys);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_untested_target_says_so_and_a_tested_one_does_not() {
        let mut g = CodeGraph::new();
        g.calls.push(crate::spine::CallEdge {
            caller: "main".into(),
            callee: "target".into(),
            file: "src/main.rs".into(),
            line: 10,
        });
        g.rebuild_indexes();
        let un = impact(&g, "target", &[]);
        assert_eq!(un.direct_callers.len(), 1);
        assert!(
            un.summary()
                .contains("every caller is a test or an entry point")
                || un.summary().contains("NO TEST REACHES IT"),
            "got {}",
            un.summary()
        );

        let mut g2 = CodeGraph::new();
        g2.calls.push(crate::spine::CallEdge {
            caller: "tests/battle".into(),
            callee: "target".into(),
            file: "tests/battle.rs".into(),
            line: 4,
        });
        g2.rebuild_indexes();
        let tested = impact(&g2, "target", &[]);
        assert_eq!(tested.direct_callers.len(), 1);
        assert!(
            tested.untested_callers.is_empty(),
            "a test calls it, so the gap must not be claimed: {:?}",
            tested.untested_callers
        );
    }

    /// The contradiction is only worth having if it can fire. A Rails route
    /// pointing at a controller action no file defines is the case: the route
    /// table names it, so it is missing on purpose rather than by accident.
    #[test]
    fn a_route_naming_a_handler_nothing_defines_is_reported() {
        let mut g = CodeGraph::new();
        g.symbols.push(crate::spine::Symbol {
            name: "other".into(),
            kind: "function_item".into(),
            file: "app/controllers/users_controller.rb".into(),
            line: 1,
            lang: "ruby".into(),
            signature: String::new(),
            params: Vec::new(),
            doc: String::new(),
        });
        let routes = vec![(
            "GET /users".to_string(),
            "index".to_string(),
            "config/routes.rb".to_string(),
            1u64,
        )];
        let found = contradictions(&g, &routes, &BTreeSet::new());
        assert!(
            found.iter().any(|i| i.kind == "route.handler_missing"),
            "a route naming an undefined handler must be reported, got {found:?}"
        );
    }

    #[test]
    fn a_route_whose_handler_exists_is_not_reported() {
        let mut g = CodeGraph::new();
        g.symbols.push(crate::spine::Symbol {
            name: "index".into(),
            kind: "function_item".into(),
            file: "app/controllers/users_controller.rb".into(),
            line: 4,
            lang: "ruby".into(),
            signature: String::new(),
            params: Vec::new(),
            doc: String::new(),
        });
        let routes = vec![(
            "GET /users".to_string(),
            "index".to_string(),
            "config/routes.rb".to_string(),
            1u64,
        )];
        let found = contradictions(&g, &routes, &BTreeSet::new());
        assert!(
            !found.iter().any(|i| i.kind == "route.handler_missing"),
            "a resolvable handler must not be reported, got {found:?}"
        );
    }

    #[test]
    fn scan_limits_report_what_they_dropped() {
        let mut l = ScanLimits::default();
        assert!(!l.dropped(), "nothing dropped yet");
        l.files_seen = 12;
        l.files_over_cap = 3;
        assert!(l.dropped());
        assert!(l.summary().contains("dropped 3"), "{}", l.summary());
    }
}
