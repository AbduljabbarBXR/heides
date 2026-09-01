// The code graph model and persistence layer of HEIDES.
//
// Every organ reads and writes this one structure. The graph is stored as
// compact JSON in the workspace so it survives across sessions and updates
// incrementally as files change.

use std::collections::BTreeMap;
use std::path::PathBuf;

pub const INDEX_VERSION: u32 = 2;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Symbol {
    pub name: String,
    pub kind: String,
    pub file: String,
    pub line: u64,
    pub lang: String,
    pub signature: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CallEdge {
    pub caller: String,
    pub callee: String,
    pub file: String,
    pub line: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ImportEdge {
    pub file: String,
    pub imported: String,
    pub line: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub lang: String,
    pub mtime: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CodeGraph {
    pub version: u32,
    pub files: Vec<FileEntry>,
    pub symbols: Vec<Symbol>,
    pub calls: Vec<CallEdge>,
    pub imports: Vec<ImportEdge>,
}

impl CodeGraph {
    pub fn new() -> Self {
        CodeGraph {
            version: INDEX_VERSION,
            files: Vec::new(),
            symbols: Vec::new(),
            calls: Vec::new(),
            imports: Vec::new(),
        }
    }

    /// Look up every symbol with the given name.
    pub fn symbols_named(&self, name: &str) -> Vec<&Symbol> {
        self.symbols.iter().filter(|s| s.name == name).collect()
    }

    /// Every call site that targets the given callee name.
    pub fn callers_of(&self, callee: &str) -> Vec<&CallEdge> {
        self.calls.iter().filter(|c| c.callee == callee).collect()
    }

    /// Every file that imports the given module name.
    pub fn importers_of(&self, imported: &str) -> Vec<&ImportEdge> {
        self.imports.iter().filter(|i| i.imported == imported).collect()
    }

    /// Every distinct call that flows out of a caller.
    pub fn calls_from(&self, caller: &str) -> Vec<&CallEdge> {
        self.calls.iter().filter(|c| c.caller == caller).collect()
    }

    /// All symbols grouped by file, for fast lookups.
    pub fn symbols_by_file(&self) -> BTreeMap<&str, Vec<&Symbol>> {
        let mut map: BTreeMap<&str, Vec<&Symbol>> = BTreeMap::new();
        for s in &self.symbols {
            map.entry(s.file.as_str()).or_default().push(s);
        }
        map
    }
}

pub fn index_path(root: &PathBuf) -> PathBuf {
    root.join(".heides").join("index.json")
}

pub fn save(graph: &CodeGraph, root: &PathBuf) -> Result<(), String> {
    let path = index_path(root);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let raw = serde_json::to_string_pretty(graph).map_err(|e| e.to_string())?;
    std::fs::write(&path, raw).map_err(|e| e.to_string())
}

pub fn load(root: &PathBuf) -> Result<CodeGraph, String> {
    let path = index_path(root);
    let raw = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let graph: CodeGraph = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    if graph.version != INDEX_VERSION {
        return Err(format!(
            "index version {} does not match this build ({})",
            graph.version, INDEX_VERSION
        ));
    }
    Ok(graph)
}

pub fn exists(root: &PathBuf) -> bool {
    index_path(root).exists()
}
