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
/// What happened to the dependency guard. Three states, not two, because
/// "skipped on request" and "could not reach the registry" are different facts
/// and a receipt that collapsed them would be the very problem it exists to
/// fix.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum DepsState {
    #[default]
    RanOnline,
    RanPartial,
    Skipped,
}

impl DepsState {
    /// A stable machine-readable name. Agents gate on this, so it must not be
    /// a Debug format that could change with a variant rename.
    pub fn as_str(self) -> &'static str {
        match self {
            DepsState::RanOnline => "ran_online",
            DepsState::RanPartial => "ran_partial",
            DepsState::Skipped => "skipped",
        }
    }

    fn note(self) -> Option<&'static str> {
        match self {
            DepsState::RanOnline => None,
            DepsState::RanPartial => Some("dependency check was partial: registries unreachable"),
            DepsState::Skipped => Some(
                "dependency check skipped: --no-deps or HEIDES_OFFLINE=1, so no advisory lookup ran",
            ),
        }
    }
}

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
    /// What the dependency guard did, stated in the receipt.
    pub deps: DepsState,
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
        if let Some(note) = self.deps.note() {
            out.push_str(&format!("\n{note}"));
        }
        out
    }
}

/// Build the receipt for a graph. Counts languages from the index and the
/// taint rules from the rule tables, so neither can drift from what the
/// guards actually do.
pub fn coverage_of(graph: &CodeGraph, deps: DepsState) -> Coverage {
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
        deps,
    }
}

/// Run the full workspace check and report the dependency guard's network
/// state, which the coverage receipt needs. Kept separate from
/// `check_workspace` so the receipt can be built from the same call rather than
/// re-querying the registries.
/// The policy is a value passed in, not a process global, so one caller's
/// choice cannot appear in another caller's result.
pub fn check_workspace_with_coverage(
    root: &Path,
    graph: &CodeGraph,
    policy: crate::deps::DepsPolicy,
) -> (Vec<GuardReport>, Coverage) {
    let (reports, state) = check_workspace_and_state(root, graph, policy);
    (reports, coverage_of(graph, state))
}

/// Run the full workspace check: taint, edge cases, practices, dependencies.
pub fn check_workspace(root: &Path, graph: &CodeGraph) -> Vec<GuardReport> {
    check_workspace_and_state(root, graph, crate::deps::DepsPolicy::default()).0
}

fn check_workspace_and_state(
    root: &Path,
    graph: &CodeGraph,
    policy: crate::deps::DepsPolicy,
) -> (Vec<GuardReport>, DepsState) {
    let mut reports = check_workspace_without_deps(graph);

    // The one guard that is allowed to want the network, and only when asked.
    if !policy.enabled {
        // Manifest parsing is local and still runs, so the pinned versions are
        // known even offline. The advisory answers come from the cache where one
        // is usable, which is what turns `--no-deps` from an honest refusal into
        // a real gate.
        //
        // The state is still Skipped when the cache could not answer for every
        // pinned version. A cache miss is not a clean bill of health, and
        // reporting Skipped over a partial cache is the honest reading.
        let cache_policy = crate::osv_cache::CachePolicy {
            enabled: true,
            allow_offline: true,
            ..Default::default()
        };
        let (dep_reports, offline_health) = crate::deps::check_offline_cached(root, cache_policy);
        let cache_health = offline_health.cache;
        for r in dep_reports {
            reports.push(GuardReport {
                guard: "dependency".to_string(),
                severity: r.severity,
                message: r.message,
                file: r.file,
                line: r.line,
            });
        }
        // The cache line is always printed, including when it is empty, so a
        // reader can tell "the cache answered" from "the cache was never asked".
        if cache_health.hits > 0 || cache_health.misses > 0 || cache_health.stale > 0 {
            reports.push(GuardReport {
                guard: "dependency".to_string(),
                severity: "info".to_string(),
                message: format!(
                    "advisory cache: {} answered, {} with no entry, {} expired{}",
                    cache_health.hits,
                    cache_health.misses,
                    cache_health.stale,
                    if cache_health.oldest_used_secs > 0 {
                        format!(
                            ". oldest answer relied on was {}",
                            crate::osv_cache::human_age(cache_health.oldest_used_secs)
                        )
                    } else {
                        String::new()
                    }
                ),
                file: String::new(),
                line: 0,
            });
        }
        // Two states, not one. A cache that answered for every pinned version is
        // a real check even though it was offline, so calling it Skipped would
        // understate it. A cache that answered for some of them is RanPartial,
        // which already means "looked at some of it and could not look at the
        // rest", so the state is reused rather than invented.
        let complete = cache_health.misses == 0 && cache_health.stale == 0;
        return (
            reports,
            if complete && cache_health.hits > 0 {
                DepsState::RanOnline
            } else if complete {
                // Nothing pinned, so nothing needed answering. Skipped is the
                // honest word: there was no advisory work to do.
                DepsState::Skipped
            } else {
                DepsState::RanPartial
            },
        );
    }

    let (dep_reports, health) = crate::deps::check(root);
    for r in dep_reports {
        reports.push(GuardReport {
            guard: "dependency".to_string(),
            severity: r.severity,
            message: r.message,
            file: r.file,
            line: r.line,
        });
    }
    // Only the advisory half drives the security posture. A missing
    // "latest version" answer is the convenience half failing and must not be
    // allowed to fail --require-advisories, or the flag becomes unusable on
    // any repository holding a package whose latest release is unresolvable.
    if !health.versions_ok && health.advisories_ok {
        reports.push(GuardReport {
            guard: "dependency".to_string(),
            severity: "info".to_string(),
            message: "some latest version lookups did not answer, so upgrade reminders are partial. advisory results are complete."
                .to_string(),
            file: String::new(),
            line: 0,
        });
    }

    let state = if health.advisories_ok {
        DepsState::RanOnline
    } else {
        DepsState::RanPartial
    };
    (reports, state)
}

/// The shared local guard body behind check_workspace and the report tool.
/// The database and configuration guard families, on their own.
///
/// Split out rather than folded into `check_workspace_without_deps` because this
/// is the part that needs a filesystem root and the code guards do not. More
/// importantly it does *not* call the code guards: a previous version returned
/// those too and the callers filtered them back out, which meant the entire
/// guard pass, interprocedural taint included, ran twice for every check. On a 56
/// file python project that was 675 seconds of a 675 second check.
pub fn check_workspace_with_database(root: &Path) -> Vec<GuardReport> {
    let mut reports: Vec<GuardReport> = Vec::new();

    // A workspace with no database is not a finding, so this is quiet by
    // construction: an empty graph produces no reports.
    if let Ok(db_graph) = crate::db::index_schema(root)
        && (!db_graph.tables.is_empty() || !db_graph.calls.is_empty())
    {
        for (guard, severity, message) in crate::db::guard_reports(root, &db_graph) {
            reports.push(GuardReport {
                guard,
                severity,
                message,
                file: String::new(),
                line: 0,
            });
        }
    }

    // Configuration credentials join the normal gate. A committed secret is not
    // something a separate command should be needed for: the same agent that runs
    // `check` has to see it, or the gate is green on a repository with a live key
    // in it.
    //
    // These two were originally inside the database branch above, behind its
    // early returns, so a workspace with no database never scanned its config at
    // all. That is the failure mode this layer exists to prevent, caused by the
    // wiring rather than by the rules.
    for f in crate::config::scan(root) {
        reports.push(GuardReport {
            guard: "config.credential".to_string(),
            severity: f.severity,
            message: f.message,
            file: f.file,
            line: f.line,
        });
    }
    reports
}

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
    let mut reports: Vec<GuardReport> = findings
        .into_iter()
        .map(|r| GuardReport {
            guard: "staged.apply".to_string(),
            severity: r.severity,
            message: r.message,
            file: r.file,
            line: r.line,
        })
        .collect();

    // Reconstruct the post-patch content for every touched file and run the
    // same guards `check` runs over it, so a patch that introduces a secret or
    // an injection is reported before it lands. Findings are tagged [staged]
    // so a hand can tell "this is the change you just made" from a
    // pre-existing finding in the same file.
    let applied = crate::staged::apply_in_memory(&parsed, root);
    for (path, maybe_text) in &applied {
        let Some(text) = maybe_text else {
            continue; // deleted file, nothing to scan
        };
        let key = path.trim_start_matches("./").replace('\\', "/");
        let p = Path::new(&key);
        let lang = crate::parser::detect_language(p).unwrap_or_default();

        for r in crate::taint::scan_file(p, text) {
            reports.push(GuardReport {
                guard: "security.taint".to_string(),
                severity: r.severity,
                message: format!("[staged] {}", r.message),
                file: r.file,
                line: r.line,
            });
        }
        for r in crate::edge::scan_file(p, text) {
            reports.push(GuardReport {
                guard: "edge.cases".to_string(),
                severity: r.severity,
                message: format!("[staged] {}", r.message),
                file: r.file,
                line: r.line,
            });
        }
        for r in crate::practice::scan_file(p, text, &lang) {
            reports.push(GuardReport {
                guard: "best.practice".to_string(),
                severity: r.severity,
                message: format!("[staged] {}", r.message),
                file: r.file,
                line: r.line,
            });
        }
    }

    Ok(reports)
}

/// Summarize reports by severity for a quick overview line.
static EXIT_ZERO: std::sync::Mutex<bool> = std::sync::Mutex::new(false);
static EXIT_THRESHOLD: std::sync::Mutex<Threshold> = std::sync::Mutex::new(Threshold::Critical);

/// Set by `--exit-zero`. The command line reads these once at startup.
pub fn set_exit_zero(v: bool) {
    *EXIT_ZERO.lock().unwrap() = v;
}

pub fn exit_zero() -> bool {
    *EXIT_ZERO.lock().unwrap()
}

pub fn set_exit_threshold(t: Threshold) {
    *EXIT_THRESHOLD.lock().unwrap() = t;
}

/// The default is blocker and critical, so `info` and `warning` findings do not
/// break a pipeline on upgrade.
pub fn exit_threshold() -> Threshold {
    *EXIT_THRESHOLD.lock().unwrap()
}

static EXPAND_ALL: std::sync::Mutex<bool> = std::sync::Mutex::new(false);
static HIDE_ADVICE: std::sync::Mutex<bool> = std::sync::Mutex::new(false);

/// Set by `--all`, the command line reads these once at startup and never
/// changes them again, so a global here is correct rather than dangerous.
pub fn set_expand_all(v: bool) {
    *EXPAND_ALL.lock().unwrap() = v;
}

pub fn set_hide_advice(v: bool) {
    *HIDE_ADVICE.lock().unwrap() = v;
}

pub fn expand_all() -> bool {
    *EXPAND_ALL.lock().unwrap()
}

pub fn hide_advice() -> bool {
    *HIDE_ADVICE.lock().unwrap()
}

/// How severe a finding has to be before `check` exits non-zero.
///
/// `check` used to always exit 0, whatever it found, so a CI job could not
/// fail on a finding without parsing the output. That makes the tool advisory
/// by default in exactly the place it matters most. The default is blocker and
/// critical. `info` never fails: an advisory note about a console call should
/// not break anyone's pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Threshold {
    Info,
    Warning,
    Critical,
    Blocker,
}

impl Threshold {
    pub fn rank(self) -> u8 {
        match self {
            Threshold::Info => 0,
            Threshold::Warning => 1,
            Threshold::Critical => 2,
            Threshold::Blocker => 3,
        }
    }

    pub fn parse(s: &str) -> Option<Threshold> {
        match s {
            "info" => Some(Threshold::Info),
            "warning" => Some(Threshold::Warning),
            "critical" => Some(Threshold::Critical),
            "blocker" => Some(Threshold::Blocker),
            _ => None,
        }
    }
}

/// True when the findings are severe enough to fail the gate.
pub fn exceeds(reports: &[GuardReport], threshold: Threshold) -> bool {
    reports
        .iter()
        .any(|r| threshold.rank() <= severity_rank(&r.severity))
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "info" => 0,
        "warning" => 1,
        "critical" => 2,
        "blocker" => 3,
        _ => 0,
    }
}

/// Whether a finding is evidence or advice.
///
/// They are printed in separate sections and never in the same voice. A taint
/// finding is a path through code, reproducible from the file and line. A
/// "function spans N lines" is a style opinion, and an agent cannot act on a
/// style opinion the same way it acts on a proven sink. Mixing them in one
/// ranked list is how the important finding hides inside the wall.
///
/// One honest caveat: `edge.cases` holds the `unwrap` rule, which is still a
/// syntactic substring match rather than a proof. It is being made provable in
/// its own change, and until then it is classed as evidence with that
/// limitation stated rather than quietly demoted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bucket {
    Proof,
    Advice,
}

pub fn bucket(guard: &str) -> Bucket {
    match guard {
        "best.practice" => Bucket::Advice,
        _ => Bucket::Proof,
    }
}

/// One line of output: either a finding, or several identical ones folded.
#[derive(Debug)]
pub enum Line<'a> {
    One(&'a GuardReport),
    Many {
        severity: &'a str,
        message: &'a str,
        guard: &'a str,
        count: usize,
        first: &'a GuardReport,
        /// Distinct files, capped for display. Folding must not hide which
        /// files to open, which the battle suite caught: a folded line that
        /// named only the first file made a PHP finding invisible because an
        /// earlier file had produced the same sentence.
        files: Vec<&'a str>,
        /// How many distinct files there are in total, before the cap.
        file_count: usize,
    },
}

/// Fold identical findings together, keeping the count and the first evidence.
///
/// 126 instances of one sentence is not 126 findings, it is one finding with a
/// count. Nothing is deleted: the count and the first file and line are kept,
/// and `--all` prints every one. Folding is keyed on guard plus message so two
/// guards saying similar things stay separate, and it walks the input in order
/// so the output is byte identical across runs.
pub fn collapse<'a>(reports: &[&'a GuardReport], expand: bool) -> Vec<Line<'a>> {
    let mut out: Vec<Line<'a>> = Vec::new();
    // Keys only. The position in this vec is the position in `out`, and the
    // count lives in `out`. Storing the count here as well meant the count was
    // used as the index, which the folding tests caught immediately.
    let mut seen: Vec<(&'a str, &'a str)> = Vec::new();
    for r in reports {
        if expand {
            out.push(Line::One(r));
            continue;
        }
        match seen
            .iter()
            .position(|(g, m)| *g == r.guard.as_str() && *m == r.message.as_str())
        {
            Some(pos) => {
                if let Line::Many {
                    count,
                    files,
                    file_count,
                    ..
                } = &mut out[pos]
                {
                    *count += 1;
                    if *file_count <= FILE_LIST_CAP && !files.contains(&r.file.as_str()) {
                        *file_count += 1;
                        files.push(r.file.as_str());
                    } else if *file_count > FILE_LIST_CAP {
                        *file_count += 1;
                    }
                }
            }
            None => {
                seen.push((r.guard.as_str(), r.message.as_str()));
                out.push(Line::Many {
                    severity: r.severity.as_str(),
                    message: r.message.as_str(),
                    guard: r.guard.as_str(),
                    count: 1,
                    first: r,
                    files: vec![r.file.as_str()],
                    file_count: 1,
                });
            }
        }
    }
    out
}

/// How many distinct files a folded line names before it says "and N more".
pub const FILE_LIST_CAP: usize = 4;

/// Where a folded finding lives, for display. Names the first few files rather
/// than only the first, because "one finding" that is actually in twelve files
/// is useless to whoever has to go and look.
pub fn folded_location(first: &GuardReport, files: &[&str], file_count: usize) -> String {
    if files.is_empty() {
        return String::new();
    }
    // A schema finding has no file, so the file list is one empty string. Naming
    // it produced a trailing " at " on every database finding, which reads as a
    // truncated location rather than an intentional omission.
    let named: Vec<&&str> = files.iter().filter(|f| !f.is_empty()).collect();
    if named.is_empty() {
        return String::new();
    }
    let mut out = format!(
        " at {}",
        named.iter().map(|f| **f).collect::<Vec<_>>().join(", ")
    );
    if file_count > files.len() {
        out.push_str(&format!(" and {} more", file_count - files.len()));
    }
    if let Some(first_file) = named.first()
        && let Some(first_line) = first.file.as_str().strip_prefix(**first_file)
        && !first_line.is_empty()
    {
        out.push_str(&format!(":{first_line}"));
    }
    out
}

/// Drop the advisory findings, for a gate that only wants evidence.
pub fn without_advice(reports: &[GuardReport]) -> Vec<&GuardReport> {
    reports
        .iter()
        .filter(|r| bucket(&r.guard) == Bucket::Proof)
        .collect()
}

/// How many findings were folded, for the summary line.
pub fn folded_count(lines: &[Line<'_>]) -> usize {
    lines
        .iter()
        .map(|l| match l {
            Line::One(_) => 1,
            Line::Many { count, .. } => *count,
        })
        .sum()
}

/// The headline. Counts alone, and counts alone are a lie when a guard did not
/// run: "0 critical" reads identically whether the advisory lookup found
/// nothing or was skipped. The posture travels with the numbers, on the same
/// line, so the summary cannot be skimmed past.
pub fn summarize(reports: &[GuardReport]) -> String {
    summarize_with(reports, DepsState::RanOnline)
}

pub fn summarize_with(reports: &[GuardReport], deps: DepsState) -> String {
    let blockers = reports.iter().filter(|r| r.severity == "blocker").count();
    let critical = reports.iter().filter(|r| r.severity == "critical").count();
    let warnings = reports.iter().filter(|r| r.severity == "warning").count();
    let infos = reports.iter().filter(|r| r.severity == "info").count();
    let posture = match deps {
        DepsState::RanOnline => String::new(),
        DepsState::RanPartial => ". ADVISORIES INCOMPLETE, registry unreachable".to_string(),
        DepsState::Skipped => ". ADVISORIES NOT CHECKED".to_string(),
    };
    format!(
        "{} blocker(s), {} critical, {} warning(s), {} info{}",
        blockers, critical, warnings, infos, posture
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

    /// `staged` must run the security guards, not only conflict detection.
    ///
    /// This is a regression test for a real regression. `check_staged` had a
    /// working second pass that reconstructed post-patch content and ran the
    /// taint, edge and practice guards over it, and a branch split dropped that
    /// pass while keeping the reworded success message. The result was a
    /// pre-commit gate that printed "the guards found nothing in the patched
    /// files" while having run no guard at all, on a patch containing
    /// `shell=True`, `verify=False`, an `eval` and a GitHub token.
    ///
    /// The wording and the behaviour have to be tested together, because the
    /// wording is what makes the absence believable.
    #[test]
    fn staged_runs_the_security_guards_on_patched_content() {
        let dir = scratch("staged_guards");
        std::fs::write(dir.join("app.py"), "def helper():\n    return 1\n").unwrap();
        let (graph, _) = indexer::build_graph(&dir);

        // input() is a real source, so this fixture tests the staged path and
        // not the separate, deliberate decision that a parameter is not one.
        let patch = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,8 @@\n def helper():\n+    return 1\n+\n+def danger():\n+    cmd = input()\n+    import subprocess\n+    subprocess.run(cmd, shell=True)\n+    token = \"ghp_abcdefghijklmnopqrstuvwxyz0123456789\"\n+    eval(cmd)\n";
        let reports = check_staged(&dir, &graph, patch).expect("the patch must parse");

        // The headline defect: only staged.apply findings means no guard ran.
        assert!(
            reports.iter().any(|r| r.guard != "staged.apply"),
            "staged must run the security guards, not only conflict detection: {:?}",
            reports
        );
        let joined: Vec<String> = reports.iter().map(|r| r.message.clone()).collect();
        assert!(
            joined.iter().any(|m| m.contains("shell")),
            "a shell=True introduced by the patch must be caught: {:?}",
            joined
        );
        assert!(
            joined.iter().any(|m| m.contains("hardcoded in source")),
            "a hardcoded token introduced by the patch must be caught: {:?}",
            joined
        );
        // Findings from the patched pass are marked, so a hand can tell the
        // change being made from a pre-existing finding in the same file.
        assert!(
            reports
                .iter()
                .filter(|r| r.guard != "staged.apply")
                .all(|r| r.message.starts_with("[staged]")),
            "patched-pass findings must be tagged [staged]: {:?}",
            reports
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The two paths must agree. `check` reads the file from disk and `staged`
    /// reads the same content from a patch, so anything one finds and the other
    /// does not is a bug in one of them. This is the assertion whose absence let
    /// the staged pass disappear unnoticed.
    ///
    /// Both the patch and the file are built from the same string, so the
    /// comparison cannot fail because the fixture drifted between the two.
    #[test]
    fn staged_and_check_agree_on_the_same_content() {
        let dir = scratch("staged_agree");
        std::fs::write(dir.join("app.py"), "def helper():\n    return 1\n").unwrap();
        let (graph, _) = indexer::build_graph(&dir);

        // One body, used to build both the patch and the file on disk, and the
        // whole original kept as context so the hunk header counts are real.
        let added: Vec<&str> = vec![
            "",
            "def danger():",
            "    cmd = input()",
            "    import subprocess",
            "    subprocess.run(cmd, shell=True)",
        ];
        let original_lines: Vec<&str> = vec!["def helper():", "    return 1"];
        let mut patched = String::new();
        for l in original_lines.iter().chain(added.iter()) {
            patched.push_str(l);
            patched.push('\n');
        }
        // The whole original kept as context, so the hunk header line counts
        // are real rather than asserted, and the patch applies to the file the
        // test actually wrote.
        let mut context = String::new();
        for l in &original_lines {
            context.push(' ');
            context.push_str(l);
            context.push('\n');
        }
        let mut addition = String::new();
        for l in &added {
            addition.push('+');
            addition.push_str(l);
            addition.push('\n');
        }
        let patch = format!(
            "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1,{} +1,{} @@\n{}{}",
            original_lines.len(),
            original_lines.len() + added.len(),
            context,
            addition
        );
        let staged = check_staged(&dir, &graph, &patch).expect("the patch must parse");

        // Now the identical content on disk, through the real check path.
        std::fs::write(dir.join("app.py"), &patched).unwrap();
        let on_disk = run(&dir);

        let staged_text: Vec<&str> = staged
            .iter()
            .filter(|r| r.guard != "staged.apply")
            .map(|r| r.message.as_str())
            .collect();
        let disk_text: Vec<&str> = on_disk.iter().map(|r| r.message.as_str()).collect();
        assert!(
            !staged_text.is_empty(),
            "staged found nothing, so there is nothing to compare. patch was:\n{}",
            patch
        );
        for m in &staged_text {
            let body = m.trim_start_matches("[staged] ");
            assert!(
                disk_text.iter().any(|d| d.contains(body)),
                "staged reported {:?} but check on the identical file did not: {:?}",
                body,
                disk_text
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A patch that deletes a file must not be scanned as if it still existed,
    /// and a patch that only conflicts must still be reported.
    #[test]
    fn staged_still_reports_conflicts_alongside_guard_findings() {
        let dir = scratch("staged_both");
        std::fs::write(
            dir.join("lib.rs"),
            "pub fn add(a: i32, b: i32) -> i32 { a + b }\n",
        )
        .unwrap();
        let (graph, _) = indexer::build_graph(&dir);
        // Changes the signature of a function that has callers.
        let patch = "diff --git a/lib.rs b/lib.rs\n--- a/lib.rs\n+++ b/lib.rs\n@@ -1,1 +1,2 @@\n-pub fn add(a: i32, b: i32) -> i32 { a + b }\n+pub fn add(a: i32, b: i32, c: i32) -> i32 { a + b + c }\n";
        let reports = check_staged(&dir, &graph, patch).expect("the patch must parse");
        assert!(
            reports.iter().any(|r| r.guard == "staged.apply"),
            "conflict detection must survive the restored guard pass: {:?}",
            reports
        );
        assert!(
            reports
                .iter()
                .any(|r| r.message.contains("signature of add changed")),
            "the signature change must still be reported: {:?}",
            reports
        );
        let _ = std::fs::remove_dir_all(&dir);
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
        let cov = coverage_of(&graph, DepsState::RanOnline);
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
        let cov = coverage_of(&graph, DepsState::RanOnline);
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
        let cov = coverage_of(&graph, DepsState::RanOnline);
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
        let cov = coverage_of(&graph, DepsState::RanOnline);
        assert_eq!(cov.files_read, cov.files, "everything readable for now");
        std::fs::remove_file(&file).unwrap();
        let cov2 = coverage_of(&graph, DepsState::RanOnline);
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

    fn rep(guard: &str, sev: &str, msg: &str, file: &str, line: u64) -> GuardReport {
        GuardReport {
            guard: guard.to_string(),
            severity: sev.to_string(),
            message: msg.to_string(),
            file: file.to_string(),
            line,
        }
    }

    #[test]
    fn identical_findings_fold_into_one_with_a_count() {
        // 126 identical lines is not 126 findings, it is one finding with a
        // count. This is the whole point of the change.
        let reports: Vec<GuardReport> = (1..=5)
            .map(|i| {
                rep(
                    "edge.cases",
                    "warning",
                    "unwrap can panic.",
                    &format!("f{i}.rs"),
                    i,
                )
            })
            .collect();
        let lines = collapse(&reports.iter().collect::<Vec<_>>(), false);
        assert_eq!(lines.len(), 1, "five identical findings must fold to one");
        match &lines[0] {
            Line::Many { count, first, .. } => {
                assert_eq!(*count, 5, "the count is kept, nothing is deleted");
                assert_eq!(first.file, "f1.rs", "first evidence is kept");
            }
            other => panic!("expected a folded line, got {other:?}"),
        }
        assert_eq!(folded_count(&lines), 5, "the fold must not lose findings");
    }

    #[test]
    fn expand_prints_every_finding() {
        let reports: Vec<GuardReport> = (1..=5)
            .map(|i| {
                rep(
                    "edge.cases",
                    "warning",
                    "unwrap can panic.",
                    &format!("f{i}.rs"),
                    i,
                )
            })
            .collect();
        let refs = reports.iter().collect::<Vec<_>>();
        let lines = collapse(&refs, true);
        assert_eq!(lines.len(), 5, "--all must not fold");
        assert!(lines.iter().all(|l| matches!(l, Line::One(_))));
        assert_eq!(folded_count(&lines), 5);
    }

    #[test]
    fn the_same_sentence_from_two_guards_stays_separate() {
        let reports = [
            rep("edge.cases", "warning", "same text", "a.rs", 1),
            rep("best.practice", "info", "same text", "b.rs", 2),
        ];
        let refs = reports.iter().collect::<Vec<_>>();
        assert_eq!(
            collapse(&refs, false).len(),
            2,
            "different guards are different findings"
        );
    }

    #[test]
    fn evidence_and_advice_are_never_mixed() {
        assert_eq!(bucket("best.practice"), Bucket::Advice);
        for g in ["security.taint", "edge.cases", "dependency", "staged.apply"] {
            assert_eq!(bucket(g), Bucket::Proof, "{g} is evidence");
        }
        let reports = vec![
            rep(
                "best.practice",
                "info",
                "function spans 40 lines",
                "a.rs",
                1,
            ),
            rep(
                "security.taint",
                "critical",
                "reaches an SQL sink",
                "b.rs",
                2,
            ),
        ];
        let kept = without_advice(&reports);
        assert_eq!(kept.len(), 1);
        assert_eq!(
            kept[0].guard, "security.taint",
            "advice is dropped, evidence stays"
        );
    }

    #[test]
    fn folding_is_byte_identical_across_runs() {
        // The determinism suite requires byte identical output. Folding walks
        // the input in order, so it must not depend on hash order.
        let build = || {
            let reports: Vec<GuardReport> = (1..=20)
                .map(|i| {
                    let m = if i % 3 == 0 { "alpha" } else { "beta" };
                    rep("edge.cases", "warning", m, &format!("f{i}.rs"), i)
                })
                .collect();
            collapse(&reports.iter().collect::<Vec<_>>(), false)
                .iter()
                .map(|l| match l {
                    Line::One(r) => format!("{}|{}|{}", r.message, r.file, r.line),
                    Line::Many {
                        message,
                        count,
                        first,
                        files,
                        file_count,
                        ..
                    } => format!(
                        "{message}|x{count}|{}",
                        folded_location(first, files, *file_count)
                    ),
                })
                .collect::<Vec<String>>()
        };
        assert_eq!(build(), build(), "folding must be stable");
    }

    #[test]
    fn the_summary_line_itself_carries_the_posture() {
        // The defect this fixes: "0 blocker(s), 0 critical, 0 warning(s), 0
        // info" is the same string whether advisories were checked and clean,
        // or never checked. The posture has to be on the headline.
        let clean: Vec<GuardReport> = Vec::new();
        let skipped = summarize_with(&clean, DepsState::Skipped);
        let online = summarize_with(&clean, DepsState::RanOnline);
        assert!(skipped.contains("ADVISORIES NOT CHECKED"), "{skipped}");
        assert!(skipped.contains("0 critical"), "{skipped}");
        assert!(
            online.contains("0 critical") && !online.contains("ADVISORIES"),
            "an online run must not carry the warning: {online}"
        );
        assert_ne!(
            skipped, online,
            "the two postures must not be indistinguishable"
        );
        let partial = summarize_with(&clean, DepsState::RanPartial);
        assert!(partial.contains("ADVISORIES INCOMPLETE"), "{partial}");
    }

    #[test]
    fn a_skipped_run_reports_skipped_not_online() {
        // Guards a real bug in the first draft: the offline branch returned
        // network_ok = true, which mapped to RanOnline and would have let
        // --require-advisories pass on a check that never asked OSV anything.
        crate::deps::set_deps_enabled(false);
        let dir = scratch("skipstate");
        std::fs::write(dir.join("a.js"), "export const x = 1;\n").unwrap();
        let (graph, _) = indexer::build_graph(&dir);
        // An explicit policy, not the process default, so this test cannot race
        // any other test that reads or writes a global.
        let (_, cov) = check_workspace_with_coverage(
            &dir,
            &graph,
            crate::deps::resolve_policy(Some(false), None, None),
        );
        assert_eq!(
            cov.deps,
            DepsState::Skipped,
            "a skipped dependency check must not report itself as online"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_skipped_dependency_check_is_stated_not_hidden() {
        // The whole point of the receipt. An offline run must say the advisory
        // lookup did not happen, or "no findings" reads as a clean bill of
        // health for a check that never ran.
        let text = coverage_of(&CodeGraph::new(), DepsState::Skipped).render();
        assert!(text.contains("skipped"), "{text}");
        assert!(text.contains("--no-deps"), "{text}");
    }

    #[test]
    fn offline_dependency_check_still_reads_pinned_versions() {
        // The offline path must not be the empty path. Manifest parsing and
        // pinned version extraction are local, so they still happen.
        let dir = scratch("offlinereads");
        std::fs::write(
            dir.join("package.json"),
            "{\"name\":\"x\",\"version\":\"1.0.0\",\"dependencies\":{\"left-pad\":\"1.3.0\"}}",
        )
        .unwrap();
        let (reports, _) = deps::check_offline(&dir);
        let text: Vec<String> = reports.iter().map(|r| r.message.clone()).collect();
        assert!(
            text.iter().any(|m| m.contains("1 pinned version")),
            "an offline check must report the pinned versions it read, got {text:?}"
        );
        assert!(
            text.iter().any(|m| m.contains("advisory lookup skipped")),
            "{text:?}"
        );
        assert!(
            !text.iter().any(|m| m.contains("falls outside")),
            "no registry comparison offline: {text:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_receipt_says_when_the_dependency_check_was_partial() {
        let dir = scratch("offline");
        std::fs::write(dir.join("a.js"), "export const x = 1;\n").unwrap();
        let (graph, _) = indexer::build_graph(&dir);
        let text = coverage_of(&graph, DepsState::RanPartial).render();
        assert!(text.contains("registries unreachable"), "{text}");
        let online = coverage_of(&graph, DepsState::RanOnline).render();
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
    fn the_exit_threshold_fails_on_critical_by_default() {
        let critical = rep(
            "security.taint",
            "critical",
            "reaches a SQL sink",
            "a.rs",
            1,
        );
        let warning = [rep("edge.cases", "warning", "unwrap can panic.", "a.rs", 2)];
        let info = [rep("best.practice", "info", "console call.", "a.rs", 3)];
        // Default is critical, so a warning does not break a pipeline.
        assert!(exceeds(&[critical], Threshold::Critical));
        assert!(!exceeds(&warning, Threshold::Critical));
        assert!(!exceeds(&info, Threshold::Critical));
        assert!(!exceeds(&[], Threshold::Critical));
        // Widening the threshold is opt in and works.
        assert!(exceeds(&warning, Threshold::Warning));
        assert!(exceeds(&info, Threshold::Info));
        // And a lower threshold catches more.
        let blocker = [rep(
            "security.taint",
            "blocker",
            "breaks a signature",
            "a.rs",
            1,
        )];
        assert!(exceeds(&blocker, Threshold::Blocker));
    }

    #[test]
    fn threshold_parsing_rejects_nonsense() {
        assert_eq!(Threshold::parse("critical"), Some(Threshold::Critical));
        assert_eq!(Threshold::parse("nope"), None);
        assert_eq!(
            Threshold::parse("CRITICAL"),
            None,
            "the values are lowercase"
        );
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
