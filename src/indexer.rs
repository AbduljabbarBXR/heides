// Directory walking and graph building for the Spine.

use std::path::{Path, PathBuf};

use crate::parser;
use crate::spine::{CodeGraph, FileEntry};

pub const MAX_FILE_BYTES: u64 = 1_000_000;

fn skip_dir(name: &str) -> bool {
    matches!(
        name,
        ".git" | ".heides" | "target" | "node_modules" | "vendor" | ".venv" | "venv" | "__pycache__" | ".next" | "dist" | "build"
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
            if let Some(name) = entry.file_name().to_str() {
                if skip_dir(name) {
                    continue;
                }
            }
            walk(&path, out);
        } else if path.is_file() && parser::is_indexable(&path) {
            if let Ok(meta) = std::fs::metadata(&path) {
                if meta.len() <= MAX_FILE_BYTES {
                    out.push(path);
                }
            }
        }
    }
}

/// Build a fresh graph for the workspace at root.
/// Returns the graph and the number of files successfully parsed.
pub fn build_graph(root: &Path) -> (CodeGraph, usize) {
    let mut graph = CodeGraph::new();
    let mut parsed_count = 0usize;
    for path in collect_files(root) {
        let lang = parser::detect_language(&path).unwrap_or_default();
        let mtime = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        graph.files.push(FileEntry {
            path: path.display().to_string(),
            lang,
            mtime,
        });
        if let Some(parsed) = parser::parse_file(&path, &content) {
            parsed_count += 1;
            graph.symbols.extend(parsed.symbols);
            graph.calls.extend(parsed.calls);
            graph.imports.extend(parsed.imports);
        }
    }
    (graph, parsed_count)
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
        assert!(!skip_dir("src"));
    }
}
