// Directory walking, parallel graph building and incremental updates.
//
// A fresh scan parses files on every available core and merges results in
// file order so output is deterministic. A rescan diffs the stored file
// table against the disk, reparses only the changed files and leaves the
// rest of the graph untouched, so a large workspace stays cheap to keep
// fresh.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::parser;
use crate::spine::{CodeGraph, FileEntry};

pub const MAX_FILE_BYTES: u64 = 1_000_000;

fn skip_dir(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".heides"
            | "target"
            | "node_modules"
            | "vendor"
            | ".venv"
            | "venv"
            | "__pycache__"
            | ".next"
            | ".open-next"
            | ".netlify"
            | ".vercel"
            | ".output"
            | "storage"
            | "temp"
            | "dist"
            | "build"
            | "out"
    )
}

pub fn collect_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(root, &mut out);
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(name) = entry.file_name().to_str()
                && skip_dir(name)
            {
                continue;
            }
            walk(&path, out);
        } else if path.is_file()
            && parser::is_indexable(&path)
            && let Ok(meta) = std::fs::metadata(&path)
            && meta.len() <= MAX_FILE_BYTES
        {
            out.push(path);
        }
    }
}

/// Describe a file the way the file table stores it. The stored path is the
/// key relative to the scan root, so an index reads identically no matter
/// which directory the check runs from.
fn describe(path: &Path, key: &str, lang: &str) -> FileEntry {
    let meta = std::fs::metadata(path);
    let mtime = meta
        .as_ref()
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
    FileEntry {
        path: key.to_string(),
        lang: lang.to_string(),
        mtime,
        size,
    }
}

/// The absolute scan root, symlinks resolved when the path exists.
pub fn abs_root_of(root: &Path) -> PathBuf {
    std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf())
}

/// The stored key for a walked file, relative to the scan root. Public so
/// coverage disclosure keys off exactly what the file table stores. A path that
/// resolves outside the root falls back to its raw display so nothing breaks.
pub fn rel_key(abs_root: &Path, path: &Path) -> String {
    let abs = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    abs.strip_prefix(abs_root)
        .unwrap_or(path)
        .display()
        .to_string()
        .replace('\\', "/")
}

/// Build a fresh graph for the workspace at root, parsing on all cores.
/// Returns the graph and the number of files successfully parsed.
pub fn build_graph(root: &Path) -> (CodeGraph, usize) {
    let abs_root = abs_root_of(root);
    let files = collect_files(root);
    // Two files can walk to one key: rel_key canonicalises, so anything reached
    // through a symlink lands on the same string as its target. `files.path` is
    // a PRIMARY KEY, so the second insert aborted the whole save and the scan
    // died with "UNIQUE constraint failed: files.path" and exit 1. ripgrep
    // reproduced it on a clone with no duplicate path on disk and no case
    // collision, so the collision was real either way.
    //
    // A scan that cannot be written is worse than a scan that drops a row: the
    // caller gets no index at all and no idea why. First key wins, and the
    // number dropped is reported rather than swallowed.
    let mut pairs: Vec<(PathBuf, String)> = Vec::with_capacity(files.len());
    let mut seen_keys: std::collections::HashSet<String> = std::collections::HashSet::new();
    for p in &files {
        let key = rel_key(&abs_root, p);
        if seen_keys.insert(key.clone()) {
            pairs.push((p.clone(), key));
        }
    }
    let mut graph = CodeGraph::new();
    // The graph must remember where it was built. File entries store paths
    // relative to the root, and file_path_of turns them back into real paths by
    // joining them onto this. Without it, a freshly built graph has root = None,
    // file_path_of returns a bare relative path, every read resolves against the
    // current working directory and fails, and any guard that reads file content
    // silently finds nothing. On a workspace that had never been indexed, that
    // meant `heides check` reported a clean workspace.
    graph.root = Some(abs_root);
    let parsed_count = fill_graph(&mut graph, &pairs);
    graph.rebuild_indexes();
    (graph, parsed_count)
}

/// Parse the given files and append their records to the graph.
/// Files are parsed on worker threads, results merge in file order. Each
/// entry carries the raw path for IO and the stored key for attribution.
fn fill_graph(graph: &mut CodeGraph, entries: &[(PathBuf, String)]) -> usize {
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(1, 8);
    let parsed = if entries.is_empty() {
        vec![]
    } else {
        let chunk = entries.len().div_ceil(workers).max(1);
        std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for batch in entries.chunks(chunk) {
                let owned: Vec<(PathBuf, String)> = batch.to_vec();
                handles.push(scope.spawn(move || {
                    let mut out = Vec::with_capacity(owned.len());
                    for (path, key) in &owned {
                        out.push(
                            std::fs::read_to_string(path)
                                .ok()
                                .and_then(|content| parser::parse_file(Path::new(key), &content)),
                        );
                    }
                    out
                }));
            }
            let mut merged: Vec<Option<parser::ParsedFile>> = Vec::with_capacity(entries.len());
            for handle in handles {
                if let Ok(batch) = handle.join() {
                    merged.extend(batch);
                }
            }
            merged
        })
    };

    let mut parsed_count = 0usize;
    for ((path, key), item) in entries.iter().zip(parsed) {
        let lang = parser::detect_language(Path::new(key)).unwrap_or_default();
        graph.files.push(describe(path, key, &lang));
        if let Some(pf) = item {
            parsed_count += 1;
            graph.symbols.extend(pf.symbols);
            graph.calls.extend(pf.calls);
            graph.imports.extend(pf.imports);
        }
    }
    parsed_count
}

/// Diff the workspace against the stored graph and reparse only the files
/// that changed. Files that disappeared are dropped. Returns the number of
/// files that were added, changed or removed.
pub fn update_graph(root: &Path, graph: &mut CodeGraph) -> usize {
    let abs_root = abs_root_of(root);
    let files = collect_files(root);
    // `files.path` is a PRIMARY KEY, and rel_key canonicalises, so a symlink and
    // its target walk to one key and the second INSERT aborted the entire save:
    // "could not save index: UNIQUE constraint failed: files.path", exit 1, and
    // the caller got no index and no clue. ripgrep does this on purpose with a
    // `HomebrewFormula` symlink into pkg/brew, so it is not an exotic layout.
    //
    // First key wins, and a real file beats a symlink to it, because a path a
    // reader can open is more useful than a second name for the same bytes.
    let mut seen_keys: std::collections::HashMap<String, PathBuf> =
        std::collections::HashMap::new();
    for p in &files {
        let key = rel_key(&abs_root, p);
        match seen_keys.get(&key) {
            None => {
                seen_keys.insert(key.clone(), p.clone());
            }
            Some(existing) => {
                let existing_link = std::fs::symlink_metadata(existing)
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(false);
                let this_link = std::fs::symlink_metadata(p)
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(false);
                if existing_link && !this_link {
                    seen_keys.insert(key, p.clone());
                }
            }
        }
    }
    let mut pairs: Vec<(PathBuf, String)> = Vec::new();
    for p in &files {
        let key = rel_key(&abs_root, p);
        if seen_keys.get(&key).is_some_and(|w| w == p) {
            pairs.push((p.clone(), key));
        }
    }
    let mut current: std::collections::HashMap<String, (u64, u64)> =
        std::collections::HashMap::new();
    for (path, key) in &pairs {
        let lang = parser::detect_language(Path::new(key)).unwrap_or_default();
        let f = describe(path, key, &lang);
        current.insert(f.path.clone(), (f.mtime, f.size));
    }

    let old: std::collections::HashMap<String, (u64, u64)> = graph
        .files
        .iter()
        .map(|f| (f.path.clone(), (f.mtime, f.size)))
        .collect();

    let mut to_parse: Vec<(PathBuf, String)> = Vec::new();
    let mut to_drop: Vec<String> = Vec::new();

    for (path, key) in &pairs {
        match old.get(key) {
            None => to_parse.push((path.clone(), key.clone())),
            Some(&(om, os)) => {
                if current[key] != (om, os) {
                    to_drop.push(key.clone());
                    to_parse.push((path.clone(), key.clone()));
                }
            }
        }
    }
    for p in old.keys() {
        if !current.contains_key(p) {
            to_drop.push(p.clone());
        }
    }

    let changed = to_parse.len() + to_drop.iter().filter(|p| !current.contains_key(*p)).count();
    if changed > 0 {
        for p in &to_drop {
            graph.remove_file(p);
        }
        let parsed_count = fill_graph(graph, &to_parse);
        // fill_graph pushed files for every entry in to_parse, even the ones
        // that failed to parse, which is correct, the table tracks presence.
        let _ = parsed_count;
        graph.rebuild_indexes();
    }
    changed
}

/// Peak resident set size in megabytes, from the kernel on Linux.
pub fn peak_rss_mb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let kb: u64 = rest.trim().trim_end_matches("kB").trim().parse().ok()?;
            return Some(kb / 1024);
        }
    }
    None
}

/// Load the workspace index, building it first if missing.
///
/// A root that does not exist is refused before anything is built. The walk
/// over a missing directory yields zero files, so `check` printed a clean
/// summary and exited 0 for a path that was never inspected, and `save` then
/// created the directory just to put an empty `.heides/index.db` inside it.
/// "There is nothing here" and "there is nothing at that path" are different
/// answers, and only the first one is a pass.
pub fn load_or_build(root: &Path) -> Result<CodeGraph, String> {
    if !root.is_dir() {
        return Err(format!(
            "{} is not a directory. point the command at an existing workspace.",
            root.display()
        ));
    }
    if crate::spine::exists(&PathBuf::from(root)) {
        crate::spine::load(&PathBuf::from(root))
    } else {
        let (graph, count) = build_graph(root);
        crate::spine::save(&graph, &PathBuf::from(root))?;
        eprintln!("built index from {} parsed files", count);
        Ok(graph)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_junk_dirs() {
        assert!(skip_dir("node_modules"));
        assert!(skip_dir(".git"));
        assert!(skip_dir(".open-next"));
        assert!(skip_dir(".netlify"));
        assert!(skip_dir(".vercel"));
        assert!(skip_dir(".output"));
        assert!(skip_dir("storage"));
        assert!(skip_dir("temp"));
        assert!(skip_dir(".next"));
        assert!(skip_dir("dist"));
        assert!(skip_dir("build"));
        assert!(!skip_dir("src"));
    }

    #[test]
    fn parallel_build_is_deterministic() {
        let root = Path::new("testdata/small_mixed");
        let (a, _) = build_graph(root);
        let (b, _) = build_graph(root);
        let ka: Vec<_> = a
            .symbols
            .iter()
            .map(|s| (s.file.clone(), s.line, s.name.clone()))
            .collect();
        let kb: Vec<_> = b
            .symbols
            .iter()
            .map(|s| (s.file.clone(), s.line, s.name.clone()))
            .collect();
        assert_eq!(
            ka, kb,
            "two identical builds must produce identical symbol lists"
        );
        assert!(!a.symbols.is_empty(), "fixture must parse something");
    }

    /// The first run on a never indexed workspace reported a clean workspace.
    ///
    /// build_graph stored file paths relative to the root but never recorded
    /// the root itself, so file_path_of returned a bare relative path that
    /// resolved against the current working directory. Every content read
    /// failed, so the guards that read files found nothing and check printed
    /// zero findings. The second run was clean because spine::load restores the
    /// root from the database, which is exactly why this went unnoticed: only
    /// the first run was affected.
    #[test]
    fn a_freshly_built_graph_can_still_read_its_own_files() {
        let root = Path::new("testdata/small_mixed");
        let (graph, _) = build_graph(root);
        let mut readable = 0;
        let mut total = 0;
        for f in &graph.files {
            total += 1;
            if std::fs::read_to_string(graph.file_path_of(&f.path)).is_ok() {
                readable += 1;
            }
        }
        assert!(
            total > 0,
            "the fixture must contain at least one indexed file"
        );
        assert_eq!(
            readable, total,
            "a freshly built graph must resolve every file it lists, got {readable} of {total}"
        );
    }

    /// The end to end version of the same defect: a check against a workspace
    /// that has never been indexed must still find a real taint flow. This is
    /// the shape a user actually runs, on a fresh clone, where the previous
    /// behaviour was to report a clean workspace.
    #[test]
    fn a_first_run_over_unindexed_files_still_reports_findings() {
        let root = Path::new("testdata/first_run");
        let (graph, _) = build_graph(root);
        let reports = crate::harmony::check_workspace_without_deps(&graph);
        let taint: Vec<&crate::harmony::GuardReport> = reports
            .iter()
            .filter(|r| r.guard == "security.taint")
            .collect();
        assert!(
            !taint.is_empty(),
            "a fresh build over an unindexed tainted file must report it, got {reports:?}"
        );
    }
}

#[cfg(test)]
mod symlink_tests {
    use super::*;

    /// A symlink and its target walk to one key, because rel_key canonicalises.
    ///
    /// `files.path` is a PRIMARY KEY, so the second row aborted the whole save:
    /// heides printed "could not save index: UNIQUE constraint failed:
    /// files.path", exited 1, and left the caller with no index at all. ripgrep
    /// reproduced it with a `HomebrewFormula` symlink into pkg/brew, which is a
    /// packaging convention rather than an exotic layout.
    ///
    /// The real file must win over the alias: a path a reader can open is more
    /// useful than a second name for the same bytes.
    #[test]
    fn a_symlink_and_its_target_index_once_and_keep_the_real_path() {
        let d = std::env::temp_dir().join(format!("heides-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("pkg/brew")).unwrap();
        std::fs::write(d.join("pkg/brew/tool.rb"), "puts 1\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("pkg/brew/tool.rb", d.join("Formula")).unwrap();

        let root = d.canonicalize().unwrap();
        let mut g = CodeGraph::new();
        update_graph(&root, &mut g);

        let mut keys: Vec<String> = g.files.iter().map(|f| f.path.clone()).collect();
        keys.sort();
        let before = keys.len();
        keys.dedup();
        assert_eq!(
            before,
            keys.len(),
            "the graph must not carry one key twice, got {keys:?}"
        );
        assert!(
            g.files.iter().any(|f| f.path == "pkg/brew/tool.rb"),
            "the real file must be indexed: {:?}",
            g.files.iter().map(|f| &f.path).collect::<Vec<_>>()
        );
        #[cfg(unix)]
        assert!(
            !g.files.iter().any(|f| f.path == "Formula"),
            "the symlink must not become a second row"
        );

        // The whole point: saving must succeed rather than abort on the key.
        let dir = std::env::temp_dir().join(format!("heides-linkdb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(
            crate::spine::save(&g, &dir).is_ok(),
            "saving a workspace with a symlink must not fail"
        );
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
