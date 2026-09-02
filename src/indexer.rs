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

/// Describe a file the way the file table stores it.
fn describe(path: &Path, lang: &str) -> FileEntry {
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
        path: path.display().to_string(),
        lang: lang.to_string(),
        mtime,
        size,
    }
}

/// Build a fresh graph for the workspace at root, parsing on all cores.
/// Returns the graph and the number of files successfully parsed.
pub fn build_graph(root: &Path) -> (CodeGraph, usize) {
    let files = collect_files(root);
    let mut graph = CodeGraph::new();
    let parsed_count = fill_graph(&mut graph, &files);
    graph.rebuild_indexes();
    (graph, parsed_count)
}

/// Parse the given files and append their records to the graph.
/// Files are parsed on worker threads, results merge in file order.
fn fill_graph(graph: &mut CodeGraph, files: &[PathBuf]) -> usize {
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(1, 8);
    let parsed = if files.is_empty() {
        vec![]
    } else {
        let chunk = files.len().div_ceil(workers).max(1);
        std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for batch in files.chunks(chunk) {
                let owned: Vec<PathBuf> = batch.to_vec();
                handles.push(scope.spawn(move || {
                    let mut out = Vec::with_capacity(owned.len());
                    for path in &owned {
                        out.push(
                            std::fs::read_to_string(path)
                                .ok()
                                .and_then(|content| parser::parse_file(path, &content)),
                        );
                    }
                    out
                }));
            }
            let mut merged: Vec<Option<parser::ParsedFile>> = Vec::with_capacity(files.len());
            for handle in handles {
                if let Ok(batch) = handle.join() {
                    merged.extend(batch);
                }
            }
            merged
        })
    };

    let mut parsed_count = 0usize;
    for (path, item) in files.iter().zip(parsed) {
        let lang = parser::detect_language(path).unwrap_or_default();
        graph.files.push(describe(path, &lang));
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
    let files = collect_files(root);
    let mut current: std::collections::HashMap<String, (u64, u64)> =
        std::collections::HashMap::new();
    for path in &files {
        let lang = parser::detect_language(path).unwrap_or_default();
        let f = describe(path, &lang);
        current.insert(f.path.clone(), (f.mtime, f.size));
    }

    let old: std::collections::HashMap<String, (u64, u64)> = graph
        .files
        .iter()
        .map(|f| (f.path.clone(), (f.mtime, f.size)))
        .collect();

    let mut to_parse: Vec<PathBuf> = Vec::new();
    let mut to_drop: Vec<String> = Vec::new();

    for path in &files {
        let pstr = path.display().to_string();
        match old.get(&pstr) {
            None => to_parse.push(path.clone()),
            Some(&(om, os)) => {
                if current[&pstr] != (om, os) {
                    to_drop.push(pstr.clone());
                    to_parse.push(path.clone());
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
        // fill_graph pushed files for every path in to_parse, even the ones
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
pub fn load_or_build(root: &Path) -> Result<CodeGraph, String> {
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
}
