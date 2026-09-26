// The code graph model and persistence layer of HEIDES.
//
// Every organ reads and writes this one structure. The graph is stored as a
// SQLite database in the workspace so it survives across sessions, loads
// fast, updates incrementally as files change, and stays directly readable
// by other tools and agents. Lookup indexes over the symbol, callee and
// file names keep every query at constant time on any graph size.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use rusqlite::{Connection, params};

pub const INDEX_VERSION: u32 = 8;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Symbol {
    pub name: String,
    pub kind: String,
    pub file: String,
    pub line: u64,
    pub lang: String,
    pub signature: String,
    /// Parameter names of a function symbol, in source order. Empty for
    /// every non function symbol kind. Feeds the interprocedural taint
    /// summaries, so a schema change on this field is a version bump.
    pub params: Vec<String>,
    /// Doc comment captured directly above the declaration, cleaned of
    /// comment markers and capped in length. Empty when no comment
    /// precedes the symbol. Carried into the SQLite index so agents can
    /// read what a symbol is for without opening the file.
    pub doc: String,
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
    /// The absolute scan root recorded at save time. Stored file paths are
    /// keys relative to this root, so every read resolves the same way no
    /// matter which directory the current command runs from.
    pub root: Option<PathBuf>,
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

    /// Resolve a stored file key to a readable path. Keys are relative to the
    /// recorded scan root; without a recorded root the key is used as given,
    /// so in memory graphs keep working.
    pub fn file_path_of(&self, key: &str) -> PathBuf {
        match &self.root {
            Some(root) => root.join(key.trim_start_matches("./")),
            None => PathBuf::from(key),
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
    root.join(".heides").join("index.db")
}

/// Open the SQLite store for the workspace, creating the schema when the
/// database does not exist yet. WAL mode keeps readers from blocking the
/// writer, so the watch loop, the MCP server and ad hoc queries can all
/// touch the same index.
fn open_db(root: &Path) -> Result<Connection, String> {
    let path = index_path(root);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let conn = Connection::open(&path).map_err(|e| e.to_string())?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         CREATE TABLE IF NOT EXISTS meta (
             key   TEXT PRIMARY KEY,
             value TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS files (
             path  TEXT PRIMARY KEY,
             lang  TEXT NOT NULL,
             mtime INTEGER NOT NULL,
             size  INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS symbols (
             id        INTEGER PRIMARY KEY,
             file      TEXT NOT NULL,
             name      TEXT NOT NULL,
             kind      TEXT NOT NULL,
             line      INTEGER NOT NULL,
             lang      TEXT NOT NULL,
             signature TEXT NOT NULL,
             params    TEXT NOT NULL,
             scope     TEXT NOT NULL DEFAULT '',
             doc       TEXT NOT NULL DEFAULT ''
         );
         CREATE TABLE IF NOT EXISTS calls (
             id     INTEGER PRIMARY KEY,
             caller TEXT NOT NULL,
             callee TEXT NOT NULL,
             file   TEXT NOT NULL,
             line   INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS imports (
             id       INTEGER PRIMARY KEY,
             file     TEXT NOT NULL,
             imported TEXT NOT NULL,
             line     INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);
         CREATE INDEX IF NOT EXISTS idx_symbols_file ON symbols(file);
         CREATE INDEX IF NOT EXISTS idx_calls_callee ON calls(callee);
         CREATE INDEX IF NOT EXISTS idx_calls_caller ON calls(caller);
         CREATE INDEX IF NOT EXISTS idx_imports_imported ON imports(imported);
         CREATE VIRTUAL TABLE IF NOT EXISTS search USING fts5(
             name, kind, signature, doc, file, line
         );
         CREATE VIRTUAL TABLE IF NOT EXISTS search_text USING fts5(
             path, kind, text, line
         );",
    )
    .map_err(|e| e.to_string())?;
    Ok(conn)
}

/// Save the graph to the SQLite index. The write replaces every row in one
/// transaction, so a crash never leaves a half written index, and the old
/// binary index from previous builds is cleaned up when present.
pub fn save(graph: &CodeGraph, root: &Path) -> Result<(), String> {
    let mut conn = open_db(root)?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute_batch(
        "DELETE FROM files; DELETE FROM symbols; DELETE FROM calls; DELETE FROM imports;\
         DELETE FROM search; DELETE FROM search_text;",
    )
    .map_err(|e| e.to_string())?;
    {
        let mut ins_file = tx
            .prepare("INSERT INTO files(path, lang, mtime, size) VALUES (?1, ?2, ?3, ?4)")
            .map_err(|e| e.to_string())?;
        for f in &graph.files {
            ins_file
                .execute(params![f.path, f.lang, f.mtime as i64, f.size as i64])
                .map_err(|e| e.to_string())?;
        }
    }
    {
        let mut ins_sym = tx
            .prepare(
                "INSERT INTO symbols(file, name, kind, line, lang, signature, params, doc) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )
            .map_err(|e| e.to_string())?;
        for s in &graph.symbols {
            let params = serde_json::to_string(&s.params).unwrap_or_default();
            ins_sym
                .execute(params![
                    s.file,
                    s.name,
                    s.kind,
                    s.line as i64,
                    s.lang,
                    s.signature,
                    params,
                    s.doc
                ])
                .map_err(|e| e.to_string())?;
        }
    }
    {
        // Literals and comments, so `query search` finds the string a caller
        // actually greps for and not only symbol names. One sequential read
        // per file, no parse, no AST retention, capped per file so the index
        // stays small. The audit showed `query search sql` returning nothing
        // for a file whose whole point was a SQL string.
        let mut ins_text = tx
            .prepare("INSERT INTO search_text(path, kind, text, line) VALUES (?1, ?2, ?3, ?4)")
            .map_err(|e| e.to_string())?;
        for f in &graph.files {
            let path = root.join(&f.path);
            let Ok(body) = std::fs::read_to_string(&path) else {
                continue;
            };
            for hit in extract_text(&body, &f.lang) {
                ins_text
                    .execute(params![f.path, hit.kind, hit.text, hit.line as i64])
                    .map_err(|e| e.to_string())?;
            }
        }
    }
    {
        let mut ins_call = tx
            .prepare("INSERT INTO calls(caller, callee, file, line) VALUES (?1, ?2, ?3, ?4)")
            .map_err(|e| e.to_string())?;
        for c in &graph.calls {
            ins_call
                .execute(params![c.caller, c.callee, c.file, c.line as i64])
                .map_err(|e| e.to_string())?;
        }
    }
    {
        let mut ins_import = tx
            .prepare("INSERT INTO imports(file, imported, line) VALUES (?1, ?2, ?3)")
            .map_err(|e| e.to_string())?;
        for im in &graph.imports {
            ins_import
                .execute(params![im.file, im.imported, im.line as i64])
                .map_err(|e| e.to_string())?;
        }
    }
    {
        let mut ins_search = tx
            .prepare(
                "INSERT INTO search(name, kind, signature, doc, file, line) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .map_err(|e| e.to_string())?;
        for s in &graph.symbols {
            ins_search
                .execute(params![
                    s.name,
                    s.kind,
                    s.signature,
                    s.doc,
                    s.file,
                    s.line as i64
                ])
                .map_err(|e| e.to_string())?;
        }
    }
    tx.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES ('version', ?1)",
        params![INDEX_VERSION.to_string()],
    )
    .map_err(|e| e.to_string())?;
    let root_abs = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    tx.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES ('root', ?1)",
        params![root_abs.display().to_string()],
    )
    .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;
    let legacy = root.join(".heides").join("index.bin");
    if legacy.exists() {
        let _ = std::fs::remove_file(&legacy);
    }
    Ok(())
}

pub fn load(root: &Path) -> Result<CodeGraph, String> {
    let path = index_path(root);
    if !path.exists() {
        return Err("no index found, run heides scan first".to_string());
    }
    let conn = open_db(root)?;
    let version: String = conn
        .query_row("SELECT value FROM meta WHERE key = 'version'", [], |r| {
            r.get(0)
        })
        .map_err(|_| "index has no version marker, rescan needed".to_string())?;
    if version != INDEX_VERSION.to_string() {
        return Err(format!(
            "index version {} does not match this build ({}), rescan needed",
            version, INDEX_VERSION
        ));
    }
    let mut graph = CodeGraph {
        version: INDEX_VERSION,
        root: conn
            .query_row("SELECT value FROM meta WHERE key = 'root'", [], |r| {
                r.get::<_, String>(0)
            })
            .ok()
            .map(PathBuf::from),
        ..Default::default()
    };
    {
        let mut stmt = conn
            .prepare("SELECT path, lang, mtime, size FROM files ORDER BY path")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                Ok(FileEntry {
                    path: r.get(0)?,
                    lang: r.get(1)?,
                    mtime: r.get::<_, i64>(2)? as u64,
                    size: r.get::<_, i64>(3)? as u64,
                })
            })
            .map_err(|e| e.to_string())?;
        for row in rows {
            graph.files.push(row.map_err(|e| e.to_string())?);
        }
    }
    {
        let mut stmt = conn
            .prepare(
                "SELECT file, name, kind, line, lang, signature, params, doc FROM symbols ORDER BY id",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                let params_raw: String = r.get(6)?;
                Ok(Symbol {
                    file: r.get(0)?,
                    name: r.get(1)?,
                    kind: r.get(2)?,
                    line: r.get::<_, i64>(3)? as u64,
                    lang: r.get(4)?,
                    signature: r.get(5)?,
                    params: serde_json::from_str(&params_raw).unwrap_or_default(),
                    doc: r.get(7)?,
                })
            })
            .map_err(|e| e.to_string())?;
        for row in rows {
            graph.symbols.push(row.map_err(|e| e.to_string())?);
        }
    }
    {
        let mut stmt = conn
            .prepare("SELECT caller, callee, file, line FROM calls ORDER BY id")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                Ok(CallEdge {
                    caller: r.get(0)?,
                    callee: r.get(1)?,
                    file: r.get(2)?,
                    line: r.get::<_, i64>(3)? as u64,
                })
            })
            .map_err(|e| e.to_string())?;
        for row in rows {
            graph.calls.push(row.map_err(|e| e.to_string())?);
        }
    }
    {
        let mut stmt = conn
            .prepare("SELECT file, imported, line FROM imports ORDER BY id")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                Ok(ImportEdge {
                    file: r.get(0)?,
                    imported: r.get(1)?,
                    line: r.get::<_, i64>(2)? as u64,
                })
            })
            .map_err(|e| e.to_string())?;
        for row in rows {
            graph.imports.push(row.map_err(|e| e.to_string())?);
        }
    }
    graph.rebuild_indexes();
    Ok(graph)
}

pub fn exists(root: &Path) -> bool {
    index_path(root).exists()
}

#[cfg(test)]
mod tests {

    use super::*;

    fn sample_graph() -> CodeGraph {
        let mut g = CodeGraph::new();
        g.files.push(FileEntry {
            path: "src/app.rs".into(),
            lang: "rust".into(),
            mtime: 1,
            size: 2,
        });
        g.symbols.push(Symbol {
            name: "run".into(),
            kind: "function_definition".into(),
            file: "src/app.rs".into(),
            line: 3,
            lang: "rust".into(),
            signature: "fn run()".into(),
            params: vec!["x".into()],
            doc: "Starts the worker".into(),
        });
        g.symbols.push(Symbol {
            name: "main".into(),
            kind: "function_definition".into(),
            file: "src/app.rs".into(),
            line: 1,
            lang: "rust".into(),
            signature: "fn main()".into(),
            params: vec![],
            doc: String::new(),
        });
        g.calls.push(CallEdge {
            caller: "main".into(),
            callee: "run".into(),
            file: "src/app.rs".into(),
            line: 2,
        });
        g.imports.push(ImportEdge {
            file: "src/app.rs".into(),
            imported: "std::env".into(),
            line: 1,
        });
        g
    }

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "heides_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn extract_text_finds_literals_and_comments() {
        let body = "// builds the user query\nconst q = \"SELECT * FROM users WHERE id = \";\nconst n = 5;\n";
        let hits = extract_text(body, "javascript");
        assert!(
            hits.iter().any(|h| h.kind == "comment" && h.line == 1),
            "comment: {:?}",
            hits
        );
        assert!(
            hits.iter()
                .any(|h| h.kind == "literal" && h.text.contains("SELECT") && h.line == 2),
            "literal: {:?}",
            hits
        );
        assert!(
            !hits.iter().any(|h| h.text == "5"),
            "numbers are not literals"
        );
        let py = "# note\nquery = 'SELECT 1'\n";
        let hits = extract_text(py, "python");
        assert!(hits.iter().any(|h| h.kind == "comment"));
        assert!(hits.iter().any(|h| h.kind == "literal"));
    }

    #[test]
    fn extract_text_is_capped_per_file() {
        let body: String = (0..200)
            .map(|i| format!("const v{i} = \"value {i}\";\n"))
            .collect();
        let hits = extract_text(&body, "javascript");
        assert!(hits.len() <= MAX_TEXT_PER_FILE, "{}", hits.len());
    }

    #[test]
    fn search_finds_a_literal_that_is_not_a_symbol() {
        // The audit found `query search sql` answering "no symbol matches"
        // for a file whose whole purpose was a SQL string.
        let dir = scratch_dir("searchtext");
        std::fs::write(
            dir.join("orders.js"),
            "function load(req) {\n  const sql = \"SELECT * FROM users WHERE id = \" + req.query.id;\n  return sql;\n}\n",
        )
        .unwrap();
        let mut graph = CodeGraph::new();
        graph.root = Some(dir.clone());
        graph.files.push(FileEntry {
            path: "orders.js".into(),
            lang: "javascript".into(),
            mtime: 0,
            size: 0,
        });
        save(&graph, &dir).unwrap();
        let hits = search(&dir, "users").expect("search runs");
        assert!(
            hits.iter()
                .any(|h| h.origin == "text" && h.file == "orders.js" && h.line == 2),
            "expected a text hit on line 2, got {:?}",
            hits
        );
    }

    #[test]
    fn search_still_finds_symbols_first() {
        let dir = scratch_dir("searchsym");
        let graph = sample_graph();
        save(&graph, &dir).unwrap();
        let hits = search(&dir, "run").expect("search runs");
        assert!(!hits.is_empty(), "symbol search must still work");
        assert_eq!(hits[0].origin, "symbol", "{:?}", hits[0]);
        assert_eq!(hits[0].name, "run");
    }

    #[test]
    fn sqlite_round_trip_preserves_the_graph() {
        let dir = std::env::temp_dir().join(format!(
            "heides_spine_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let graph = sample_graph();
        save(&graph, &dir).unwrap();
        assert!(index_path(&dir).exists(), "sqlite index must exist");
        assert!(!dir.join(".heides/index.bin").exists());

        let loaded = load(&dir).unwrap();
        assert_eq!(loaded.files.len(), graph.files.len());
        assert_eq!(loaded.symbols.len(), 2);
        assert_eq!(loaded.calls.len(), 1);
        assert_eq!(loaded.imports.len(), 1);
        let sym = &loaded.symbols[0];
        assert_eq!(sym.name, "run");
        assert_eq!(sym.params, vec!["x"]);
        assert_eq!(sym.doc, "Starts the worker");
        assert_eq!(loaded.callers_of("run").len(), 1);
        assert_eq!(loaded.importers_of("std::env").len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_version_demands_a_rescan() {
        let dir = std::env::temp_dir().join(format!(
            "heides_spine_v_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        save(&sample_graph(), &dir).unwrap();
        let conn = open_db(&dir).unwrap();
        conn.execute("UPDATE meta SET value = '99' WHERE key = 'version'", [])
            .unwrap();
        drop(conn);
        let err = load(&dir).unwrap_err();
        assert!(err.contains("rescan needed"), "unexpected error: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A literal or comment pulled out of a file body so text search can find it.
#[derive(Debug, Clone, PartialEq)]
pub struct TextHit {
    pub kind: &'static str,
    pub text: String,
    pub line: u64,
}

const MAX_TEXT_PER_FILE: usize = 24;
const MAX_TEXT_LEN: usize = 200;

/// Extract string literals and comments from one file body. Deliberately a
/// cheap scan rather than a parse: the point is that an agent can grep for a
/// query string and find the file, not that we understand the file.
pub fn extract_text(body: &str, lang: &str) -> Vec<TextHit> {
    let hash = lang == "python" || lang == "yaml" || lang == "toml" || lang == "dockerfile";
    let mut out: Vec<TextHit> = Vec::new();
    for (i, line) in body.lines().enumerate() {
        if out.len() >= MAX_TEXT_PER_FILE {
            break;
        }
        let trimmed = line.trim_start();
        if hash && trimmed.starts_with('#') {
            push_text(&mut out, "comment", trimmed, i);
            continue;
        }
        if !hash && (trimmed.starts_with("//") || trimmed.starts_with("/*")) {
            push_text(&mut out, "comment", trimmed, i);
        }
        for (quote, closer) in [('"', '"'), ('\'', '\''), ('`', '`')] {
            let mut rest = line;
            while let Some(start) = rest.find(quote) {
                let after = &rest[start + 1..];
                let Some(len) = after.find(closer) else {
                    break;
                };
                let literal = &after[..len];
                if !literal.trim().is_empty() && !literal.contains(quote) {
                    push_text(&mut out, "literal", literal, i);
                }
                rest = &after[len + 1..];
            }
        }
    }
    out
}

fn push_text(out: &mut Vec<TextHit>, kind: &'static str, raw: &str, line: usize) {
    if out.len() >= MAX_TEXT_PER_FILE {
        return;
    }
    let text: String = raw.trim().chars().take(MAX_TEXT_LEN).collect();
    if text.is_empty() {
        return;
    }
    out.push(TextHit {
        kind,
        text,
        line: line as u64 + 1,
    });
}

/// One text search hit, a symbol row whose name, kind, signature or doc
/// matched the query.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SearchHit {
    pub name: String,
    pub kind: String,
    pub file: String,
    pub line: u64,
    pub doc: String,
    /// "symbol" or "text", so the caller can say where the hit came from.
    pub origin: String,
}

/// Free text search over names, kinds, signatures and docs. Every word
/// becomes its own quoted phrase, so user input can never smuggle FTS5
/// query syntax in or out, and words match anywhere in any column.
pub fn search(root: &Path, query: &str) -> Result<Vec<SearchHit>, String> {
    let conn = open_db(root)?;
    let phrase: Vec<String> = query
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|w| !w.is_empty())
        .map(|w| format!("\"{}\"", w.to_ascii_lowercase()))
        .collect();
    if phrase.is_empty() {
        return Err("empty search query".to_string());
    }
    let match_q = phrase.join(" ");
    let mut stmt = conn
        .prepare(
            "SELECT name, kind, file, line, doc FROM search \
             WHERE search MATCH ?1 ORDER BY rank LIMIT 25",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params![match_q], |r| {
            Ok(SearchHit {
                name: r.get(0)?,
                kind: r.get(1)?,
                file: r.get(2)?,
                line: r.get::<_, i64>(3)? as u64,
                doc: r.get(4)?,
                origin: String::new(),
            })
        })
        .map_err(|e| e.to_string())?;
    let mut hits = Vec::new();
    for row in rows {
        let mut hit = row.map_err(|e| e.to_string())?;
        hit.origin = "symbol".to_string();
        hits.push(hit);
    }
    // Literals and comments, so a string in a file body is findable.
    let mut text_stmt = conn
        .prepare(
            "SELECT path, kind, text, line FROM search_text \
             WHERE search_text MATCH ?1 ORDER BY rank LIMIT 25",
        )
        .map_err(|e| e.to_string())?;
    let text_rows = text_stmt
        .query_map(params![match_q], |r| {
            Ok(SearchHit {
                name: r.get::<_, String>(2)?,
                kind: r.get::<_, String>(1)?,
                file: r.get::<_, String>(0)?,
                line: r.get::<_, i64>(3)? as u64,
                doc: String::new(),
                origin: "text".to_string(),
            })
        })
        .map_err(|e| e.to_string());
    if let Ok(text_rows) = text_rows {
        for row in text_rows.flatten() {
            if hits
                .iter()
                .any(|h| h.file == row.file && h.line == row.line && h.name == row.name)
            {
                continue;
            }
            hits.push(row);
        }
    }
    hits.truncate(25);
    Ok(hits)
}
