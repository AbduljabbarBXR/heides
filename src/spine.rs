// The Spine is the perception and memory organ of HEIDES.
//
// It walks a codebase, builds a persistent graph of symbols, files, callers,
// imports and dataflow, and stores the result in a compact on disk index so
// that every later query (Harmony guards, Grounding plans, agents) sees one
// consistent map of the code. No model is involved. This layer is pure
// deterministic analysis.

use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Symbol {
    pub name: String,
    pub kind: String,
    pub file: PathBuf,
    pub line: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CallEdge {
    pub caller: String,
    pub callee: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CodeGraph {
    pub symbols: Vec<Symbol>,
    pub calls: Vec<CallEdge>,
    pub files: Vec<PathBuf>,
}

/// Scan the current directory and build the spine index.
/// The index is written to .heides/index.json inside the workspace.
pub fn scan(args: &[String]) -> ExitCode {
    let root = args.get(2).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    let graph = match index(&root) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("scan failed: {}", e);
            return ExitCode::FAILURE;
        }
    };
    println!(
        "spine indexed {} files, {} symbols, {} call edges",
        graph.files.len(),
        graph.symbols.len(),
        graph.calls.len()
    );
    let index_path = root.join(".heides").join("index.json");
    if let Some(parent) = index_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = persist(&graph, &index_path) {
        eprintln!("could not persist index: {}", e);
        return ExitCode::FAILURE;
    }
    println!("index saved to {}", index_path.display());
    ExitCode::SUCCESS
}

/// Report the current state of the spine index.
pub fn status() -> ExitCode {
    let root = PathBuf::from(".");
    let index_path = root.join(".heides").join("index.json");
    if !index_path.exists() {
        println!("no spine index found. run: heides scan");
        return ExitCode::FAILURE;
    }
    match std::fs::read_to_string(&index_path) {
        Ok(raw) => {
            let graph: CodeGraph = match serde_json::from_str(&raw) {
                Ok(g) => g,
                Err(e) => {
                    eprintln!("index is corrupt: {}", e);
                    return ExitCode::FAILURE;
                }
            };
            println!(
                "spine index present: {} files, {} symbols, {} call edges",
                graph.files.len(),
                graph.symbols.len(),
                graph.calls.len()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("could not read index: {}", e);
            ExitCode::FAILURE
        }
    }
}

/// Walk the workspace and build the code graph.
///
/// Milestone one: file inventory and shallow symbol extraction.
/// Milestone two: tree sitter parsing for the deep language set with call
/// graph and dataflow. Milestone three: incremental updates on file changes.
pub fn index(root: &PathBuf) -> Result<CodeGraph, String> {
    let mut files = Vec::new();
    collect_files(root, &mut files)?;
    let mut symbols = Vec::new();
    for f in &files {
        if let Some(name) = f.file_name().and_then(|n| n.to_str()) {
            if let Some(base) = name.strip_suffix(".rs") {
                symbols.push(Symbol {
                    name: base.to_string(),
                    kind: "module".to_string(),
                    file: f.clone(),
                    line: 1,
                });
            }
        }
    }
    Ok(CodeGraph {
        symbols,
        calls: Vec::new(),
        files,
    })
}

fn collect_files(dir: &PathBuf, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| e.to_string())?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy().to_string();
            if name == ".git" || name == ".heides" || name == "target" || name == "node_modules" {
                continue;
            }
            collect_files(&path, out)?;
        } else if path.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

fn persist(graph: &CodeGraph, path: &PathBuf) -> Result<(), String> {
    let raw = serde_json::to_string_pretty(graph).map_err(|e| e.to_string())?;
    std::fs::write(path, raw).map_err(|e| e.to_string())
}
