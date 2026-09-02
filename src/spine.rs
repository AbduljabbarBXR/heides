// The code graph model and persistence layer of HEIDES.
//
// Every organ reads and writes this one structure. The graph is stored as a
// compact binary index in the workspace so it survives across sessions, loads
// fast and updates incrementally as files change. Lookup indexes over the
// symbol, callee and file names keep every query at constant time on any
// graph size.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

pub const INDEX_VERSION: u32 = 3;

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
    pub size: u64,
}

/// Lookup indexes over the flat vectors. Derived data, rebuilt after every
/// mutation and never persisted, so it can never drift from the vectors.
#[derive(Debug, Clone, Default)]
pub struct Indexes {
    pub symbols_by_name: HashMap<String, Vec<usize>>,
    pub calls_by_callee: HashMap<String, Vec<usize>>,
    pub calls_by_caller: HashMap<String, Vec<usize>>,
    pub imports_by_imported: HashMap<String, Vec<usize>>,
    pub symbols_by_file: HashMap<String, Vec<usize>>,
}

#[derive(Debug, Clone, Default)]
pub struct CodeGraph {
    pub version: u32,
    pub files: Vec<FileEntry>,
    pub symbols: Vec<Symbol>,
    pub calls: Vec<CallEdge>,
    pub imports: Vec<ImportEdge>,
    pub indexes: Indexes,
}

impl CodeGraph {
    pub fn new() -> Self {
        CodeGraph {
            version: INDEX_VERSION,
            ..Default::default()
        }
    }

    /// Rebuild every lookup index from the flat vectors.
    pub fn rebuild_indexes(&mut self) {
        let mut idx = Indexes::default();
        for (i, s) in self.symbols.iter().enumerate() {
            idx.symbols_by_name
                .entry(s.name.clone())
                .or_default()
                .push(i);
            idx.symbols_by_file
                .entry(s.file.clone())
                .or_default()
                .push(i);
        }
        for (i, c) in self.calls.iter().enumerate() {
            idx.calls_by_callee
                .entry(c.callee.clone())
                .or_default()
                .push(i);
            idx.calls_by_caller
                .entry(c.caller.clone())
                .or_default()
                .push(i);
        }
        for (i, im) in self.imports.iter().enumerate() {
            idx.imports_by_imported
                .entry(im.imported.clone())
                .or_default()
                .push(i);
        }
        self.indexes = idx;
    }

    /// Look up every symbol with the given name.
    pub fn symbols_named(&self, name: &str) -> Vec<&Symbol> {
        self.indexes
            .symbols_by_name
            .get(name)
            .map(|ids| ids.iter().map(|&i| &self.symbols[i]).collect())
            .unwrap_or_default()
    }

    /// Every call site that targets the given callee name.
    pub fn callers_of(&self, callee: &str) -> Vec<&CallEdge> {
        self.indexes
            .calls_by_callee
            .get(callee)
            .map(|ids| ids.iter().map(|&i| &self.calls[i]).collect())
            .unwrap_or_default()
    }

    /// Every file that imports the given module name.
    pub fn importers_of(&self, imported: &str) -> Vec<&ImportEdge> {
        self.indexes
            .imports_by_imported
            .get(imported)
            .map(|ids| ids.iter().map(|&i| &self.imports[i]).collect())
            .unwrap_or_default()
    }

    /// Every distinct call that flows out of a caller.
    pub fn calls_from(&self, caller: &str) -> Vec<&CallEdge> {
        self.indexes
            .calls_by_caller
            .get(caller)
            .map(|ids| ids.iter().map(|&i| &self.calls[i]).collect())
            .unwrap_or_default()
    }

    /// All symbols grouped by file, for fast lookups.
    pub fn symbols_by_file(&self) -> BTreeMap<&str, Vec<&Symbol>> {
        let mut map: BTreeMap<&str, Vec<&Symbol>> = BTreeMap::new();
        for (file, ids) in &self.indexes.symbols_by_file {
            map.insert(
                file.as_str(),
                ids.iter().map(|&i| &self.symbols[i]).collect(),
            );
        }
        map
    }

    /// Remove every record that belongs to the given file path.
    pub fn remove_file(&mut self, path: &str) {
        let keep_s = |p: &str| self.symbols.iter().any(|s| s.file == p);
        let keep_c = |p: &str| self.calls.iter().any(|c| c.file == p);
        let keep_i = |p: &str| self.imports.iter().any(|i| i.file == p);
        if !(keep_s(path) || keep_c(path) || keep_i(path)) {
            return;
        }
        self.symbols.retain(|s| s.file != path);
        self.calls.retain(|c| c.file != path);
        self.imports.retain(|i| i.file != path);
        self.files.retain(|f| f.path != path);
    }
}

pub fn index_path(root: &Path) -> PathBuf {
    root.join(".heides").join("index.bin")
}

/// Save the graph to a binary index with an atomic replace.
pub fn save(graph: &CodeGraph, root: &Path) -> Result<(), String> {
    let path = index_path(root);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let raw = bincode::serialize(&(
        graph.version,
        &graph.files,
        &graph.symbols,
        &graph.calls,
        &graph.imports,
    ))
    .map_err(|e| e.to_string())?;
    let tmp = path.with_extension("bin.tmp");
    std::fs::write(&tmp, &raw).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())
}

pub fn load(root: &Path) -> Result<CodeGraph, String> {
    let path = index_path(root);
    let raw = std::fs::read(&path).map_err(|e| e.to_string())?;
    let (version, files, symbols, calls, imports): (
        u32,
        Vec<FileEntry>,
        Vec<Symbol>,
        Vec<CallEdge>,
        Vec<ImportEdge>,
    ) = bincode::deserialize(&raw).map_err(|e| format!("index corrupt, rescan needed. {e}"))?;
    if version != INDEX_VERSION {
        return Err(format!(
            "index version {} does not match this build ({}), rescan needed",
            version, INDEX_VERSION
        ));
    }
    let mut graph = CodeGraph {
        version,
        files,
        symbols,
        calls,
        imports,
        indexes: Indexes::default(),
    };
    graph.rebuild_indexes();
    Ok(graph)
}

pub fn exists(root: &Path) -> bool {
    index_path(root).exists()
}
