// Tier 1: the database layer.
//
// Databases show up in a code harness in two places, and until now heides
// understood neither. A SQL string was a taint sink regex, and a database
// driver was a dependency name. That means `check` could tell you a query was
// dangerous and nothing at all about which tables the code touches, which
// questions are what an agent actually asks when it is changing a codebase.
//
// This module is the answer to "what does this code read and write". It is
// three separate capabilities that share one output:
//
//   * a schema graph, parsed from `.sql` and from migration directories
//     (alembic, goose, flyway, prisma, plain numbered sql)
//   * call-site resolution, mapping ORM and raw SQL usage onto table names
//   * a syntactic sink for concatenated query construction, which needs no
//     taint flow at all and is therefore the only rule here that catches
//     injection that a source/sink matcher cannot see
//
// Two design commitments run through all of it.
//
// First, the parser never panics and never invents. A malformed migration
// yields fewer tables, not a crash and not a guess. `hostile.rs` exercises this.
//
// Second, the resolvers are gated hard. A method chain that merely mentions a
// word called `users` must not resolve to the `users` table, because a wrong
// table is worse than no answer: an agent acting on it will read the wrong
// schema. Every resolver therefore requires a recognised ORM receiver, and the
// negative half of that is in `tests/db.rs`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------- data shapes

/// One column of a table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    pub ty: String,
    pub pk: bool,
    pub nullable: bool,
    /// Set when this column references another table.
    pub fk_table: Option<String>,
    pub fk_col: Option<String>,
    /// True when the foreign key carries `ON DELETE CASCADE`. A cascade inside a
    /// cycle is the shape that can recurse into itself on delete, so it is
    /// recorded rather than inferred later.
    pub on_delete_cascade: bool,
}

/// One index declared on a table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Index {
    pub name: String,
    pub columns: Vec<String>,
    pub unique: bool,
}

/// One table, with its columns and indexes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub name: String,
    pub schema: Option<String>,
    pub kind: String,
    pub columns: Vec<Column>,
    pub indexes: Vec<Index>,
    /// The file this came from, for grounded output.
    pub source: String,
}

/// One table access resolved from a code call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub table: String,
    /// `read` or `write`. Nothing else; the pair is what agents branch on.
    pub op: Op,
    /// The source text that produced this, so a finding can be grounded.
    pub via: String,
    pub file: String,
    pub line: u64,
}

/// Whether a call reads or writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Read,
    Write,
}

impl Op {
    pub fn as_str(self) -> &'static str {
        match self {
            Op::Read => "read",
            Op::Write => "write",
        }
    }
}

/// A migration file, identified and fingerprinted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Migration {
    pub file: String,
    pub version: String,
    pub dialect: &'static str,
    pub sha: String,
}

/// The whole database picture for a workspace.
#[derive(Debug, Clone, Default)]
pub struct DbGraph {
    pub tables: Vec<Table>,
    pub calls: Vec<Call>,
    pub migrations: Vec<Migration>,
}

// ------------------------------------------------------------ SQL schema parse

/// Split a SQL file into statements, respecting quotes and comments.
///
/// This is a splitter, not a parser. It exists so that a `;` inside a string
/// literal or a comment does not cut a statement in half, which is the failure
/// that makes hand rolled SQL splitters produce phantom tables.
fn split_statements(sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = sql.chars().peekable();

    while let Some(c) = chars.next() {
        // Line comment.
        if quote.is_none() && c == '-' && chars.peek() == Some(&'-') {
            for c2 in chars.by_ref() {
                if c2 == '\n' {
                    break;
                }
            }
            cur.push(' ');
            continue;
        }
        // Block comment.
        if quote.is_none() && c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            let mut prev = '\0';
            for c2 in chars.by_ref() {
                if prev == '*' && c2 == '/' {
                    break;
                }
                prev = c2;
            }
            cur.push(' ');
            continue;
        }
        // Quoted identifier or string literal.
        if let Some(q) = quote {
            cur.push(c);
            if c == q {
                quote = None;
            }
            continue;
        }
        if c == '\'' || c == '"' || c == '`' {
            quote = Some(c);
            cur.push(c);
            continue;
        }
        if c == ';' {
            if !cur.trim().is_empty() {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
            continue;
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// Strip one layer of quoting from an identifier.
///
/// `"User"` is `User`. A quoted identifier is the one case where case is
/// significant, and prisma emits quoted PascalCase names, so this must not
/// lowercase anything. It only removes the delimiters.
fn unquote(s: &str) -> String {
    let t = s.trim();
    let t = if t.len() >= 2 {
        let b = t.as_bytes();
        let (f, l) = (b[0], b[t.len() - 1]);
        if (f == b'"' && l == b'"')
            || (f == b'`' && l == b'`')
            || (f == b'[' && l == b']')
            || (f == b'\'' && l == b'\'')
        {
            &t[1..t.len() - 1]
        } else {
            t
        }
    } else {
        t
    };
    t.trim().to_string()
}

/// Split `a.b.c` into its parts, ignoring dots inside quotes.
fn split_qualified(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for c in s.chars() {
        if let Some(q) = quote {
            cur.push(c);
            if c == q {
                quote = None;
            }
            continue;
        }
        if c == '"' || c == '`' {
            quote = Some(c);
            cur.push(c);
            continue;
        }
        if c == '.' {
            parts.push(std::mem::take(&mut cur));
            continue;
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        parts.push(cur);
    }
    parts
}

/// True when this statement creates a table rather than a view or index.
fn is_create_table(stmt: &str) -> bool {
    let head = stmt.trim_start();
    let upper = head.to_ascii_uppercase();
    if !upper.starts_with("CREATE") {
        return false;
    }
    // `CREATE TEMP TABLE`, `CREATE TABLE IF NOT EXISTS`, `CREATE UNLOGGED TABLE`.
    let rest = &upper["CREATE".len()..];
    let rest = rest.trim_start();
    for filler in [
        "TEMP ", "TEMPORARY ", "UNLOGGED ", "GLOBAL ", "LOCAL ", "IF NOT EXISTS ",
    ] {
        if let Some(r) = rest.strip_prefix(filler) {
            return r.trim_start().starts_with("TABLE");
        }
    }
    rest.trim_start().starts_with("TABLE")
}

/// Parse one SQL body into tables.
///
/// Handles inline `PRIMARY KEY`, table level `PRIMARY KEY (...)`, inline and
/// table level `REFERENCES`, `CREATE INDEX` and `CREATE UNIQUE INDEX` attached to
/// the table they name, and skips `DROP`, `ALTER`, `VIEW` and `TRIGGER`.
pub fn parse_sql(path: &Path, body: &str) -> Vec<Table> {
    let src = path.to_string_lossy().to_string();
    let mut tables: Vec<Table> = Vec::new();
    // Table level constraints collected per statement, applied after the
    // columns are known.
    let mut pending_pk: BTreeSet<String> = BTreeSet::new();
    let mut pending_fk: Vec<(String, String, Option<String>)> = Vec::new();
    let mut deferred_indexes: Vec<String> = Vec::new();

    for stmt in split_statements(body) {
        let t = stmt.trim();
        if t.is_empty() {
            continue;
        }

        // CREATE INDEX, standalone. Attached to the table it names.
        let upper = t.to_ascii_uppercase();
        // Index statements are recognised by the ON clause, not by the word
        // INDEX: `CREATE UNIQUE INDEX ..` and `CREATE INDEX ..` both qualify, and
        // a table named `indexes` must not qualify.
        if upper.starts_with("CREATE")
            && upper.contains(" INDEX ")
            && upper.contains(" ON ")
        {
            // Deferred: an index can precede its table in a migration file, so
            // attaching it here would silently drop it.
            deferred_indexes.push(t.to_string());
            continue;
        }

        if !is_create_table(t) && !t.contains("create_table") {
            continue;
        }
        if !is_create_table(t) {
            // Alembic and knex emit `create_table('users', Column('id', ...))`.
            // Handled here so parse_sql and parse_alembic agree, rather than one
            // path being able to answer a question the other cannot.
            for tb in parse_alembic_stmt(t) {
                match tables.iter().position(|x| x.name == tb.name) {
                    Some(i) => tables[i] = tb,
                    None => tables.push(tb),
                }
            }
            continue;
        }

        let open = match t.find('(') {
            Some(i) => i,
            None => continue,
        };
        let close = match matching_paren(t, open) {
            Some(i) => i,
            None => continue,
        };
        let head = &t[..open];
        let body = &t[open + 1..close];

        // Table name is the last qualified part after TABLE.
        let after = &head[head.to_ascii_uppercase().find("TABLE").map(|i| i + 5).unwrap_or(0)..];
        let name_part = after
            .split_whitespace()
            .filter(|w| *w != "IF")
            .filter(|w| *w != "NOT")
            .filter(|w| *w != "EXISTS")
            .filter(|w| *w != "IF NOT EXISTS")
            .next()
            .unwrap_or("");
        if name_part.is_empty() {
            continue;
        }
        let qualified = split_qualified(name_part);
        if qualified.is_empty() {
            continue;
        }
        let name = unquote(qualified.last().unwrap());
        if name.is_empty() {
            continue;
        }
        let schema = if qualified.len() > 1 {
            Some(unquote(&qualified[qualified.len() - 2]))
        } else {
            None
        };

        let mut table = Table {
            name,
            schema,
            kind: "table".into(),
            columns: Vec::new(),
            indexes: Vec::new(),
            source: src.clone(),
        };

        for part in split_top_level(body, ',') {
            let p = part.trim();
            if p.is_empty() {
                continue;
            }
            let up = p.to_ascii_uppercase();

            // Table level PRIMARY KEY (a, b, c)
            if up.starts_with("PRIMARY KEY") {
                let inner = paren_inner(p);
                for c in split_top_level(inner.as_deref().unwrap_or(""), ',') {
                    let cn = unquote(c.trim());
                    if !cn.is_empty() {
                        pending_pk.insert(cn);
                    }
                }
                continue;
            }
            // Table level FOREIGN KEY (col) REFERENCES t(c)
            if up.starts_with("FOREIGN KEY") {
                let inner = paren_inner(p).unwrap_or_default();
                let col = split_top_level(&inner, ',')
                    .first()
                    .map(|c| unquote(c.trim()))
                    .unwrap_or_default();
                if let Some((Some(tbl), col2)) = parse_references(p) {
                    if !col.is_empty() {
                        pending_fk.push((col, tbl, col2));
                    }
                }
                continue;
            }
            // Table level UNIQUE / CHECK / CONSTRAINT: no column information.
            if up.starts_with("UNIQUE")
                || up.starts_with("CHECK")
                || up.starts_with("CONSTRAINT")
                || up.starts_with("KEY ")
                || up.starts_with("INDEX ")
            {
                continue;
            }

            let Some(column) = parse_column(p) else {
                continue;
            };
            table.columns.push(column);
        }

        // Apply the table level constraints now that columns exist.
        for c in table.columns.iter_mut() {
            if pending_pk.contains(&c.name) {
                c.pk = true;
            }
        }
        for (col, tbl, col2) in std::mem::take(&mut pending_fk) {
            if let Some(c) = table.columns.iter_mut().find(|c| c.name == col) {
                c.fk_table = Some(tbl);
                c.fk_col = col2;
            }
        }
        pending_pk.clear();

        // A duplicate CREATE TABLE in the same file is a migration artifact. Last
        // one wins rather than appending a second table with the same name,
        // which would make every downstream count wrong.
        match tables.iter().position(|x| x.name == table.name) {
            Some(i) => tables[i] = table,
            None => tables.push(table),
        }
    }

    // Second pass, so index order inside the file does not matter.
    for stmt in &deferred_indexes {
        if let Some((target, idx)) = parse_create_index(stmt) {
            if let Some(tbl) = tables.iter_mut().find(|x| x.name == target) {
                if !tbl.indexes.iter().any(|e| e.name == idx.name) {
                    tbl.indexes.push(idx);
                }
            }
        }
    }

    tables
}
fn parse_create_index(t: &str) -> Option<(String, Index)> {
    let upper = t.to_ascii_uppercase();
    let unique = upper.contains("UNIQUE INDEX");
    let on_at = upper.find(" ON ")?;
    let after_on = t[on_at + 4..].trim_start();
    // `ON events(a, b)` and `ON events (a, b)` are both legal, so the table name
    // must stop at the first space OR the first paren. Splitting on whitespace
    // alone yielded `events(a,` as the table name and silently dropped the index.
    let name_part = after_on
        .split(|c: char| c.is_whitespace() || c == '(')
        .next()
        .unwrap_or_default();
    let table = split_qualified(name_part).last().map(|s| unquote(s))?;
    if table.is_empty() {
        return None;
    }
    let inner = paren_inner(after_on)?;
    let cols: Vec<String> = split_top_level(&inner, ',')
        .iter()
        .map(|c| unquote(c.trim()))
        .filter(|c| !c.is_empty())
        .collect();
    if cols.is_empty() {
        return None;
    }
    let name = if let Some(i) = upper.find("INDEX") {
        t[i + 5..on_at]
            .split_whitespace()
            .find(|w| *w != "IF" && *w != "NOT" && *w != "EXISTS" && *w != "UNIQUE")
            .map(unquote)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("idx_{}_{}", table, cols.join("_")))
    } else {
        format!("idx_{}_{}", table, cols.join("_"))
    };
    Some((
        table,
        Index {
            name,
            columns: cols,
            unique,
        },
    ))
}
fn parse_column(p: &str) -> Option<Column> {
    let mut parts = p.split_whitespace();
    let raw_name = parts.next()?;
    let name = unquote(raw_name);
    if name.is_empty() || name.eq_ignore_ascii_case("constraint") {
        return None;
    }
    let rest = p[raw_name.len()..].trim();

    // Type runs until the first constraint keyword. `NUMERIC(12,2)` and
    // `VARCHAR(255)` keep their parenthesised part.
    let upper = rest.to_ascii_uppercase();
    let mut ty_end = rest.len();
    for kw in [
        "NOT NULL", "PRIMARY KEY", "UNIQUE", "REFERENCES", "DEFAULT", "CHECK",
        "GENERATED", "AUTO_INCREMENT", "COLLATE", "COMMENT",
    ] {
        if let Some(i) = upper.find(kw) {
            ty_end = ty_end.min(i);
        }
    }
    let ty = rest[..ty_end].trim().trim_end_matches(',').trim().to_string();
    let ty = if ty.is_empty() { "UNKNOWN".into() } else { ty };

    let nullable = !upper.contains("NOT NULL");
    let mut primary_key = upper.contains("PRIMARY KEY");
    if upper.contains("AUTO_INCREMENT") {
        primary_key = true;
    }

    let (fk_table, fk_col) = parse_references(p).unwrap_or((None, None));

    Some(Column {
        name,
        ty,
        pk: primary_key,
        nullable,
        fk_table,
        fk_col,
        on_delete_cascade: upper.contains("ON DELETE CASCADE"),
    })
}

/// `REFERENCES table(column)` anywhere in the column definition.
fn parse_references(p: &str) -> Option<(Option<String>, Option<String>)> {
    let upper = p.to_ascii_uppercase();
    let at = upper.find("REFERENCES")?;
    let rest = p[at + "REFERENCES".len()..].trim_start();
    // `users(id)` is one token, so the table name has to be cut at the paren
    // before the qualified split, or the column comes along with it.
    let name_part = rest
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .split('(')
        .next()
        .unwrap_or_default();
    let table = split_qualified(name_part).last().map(|s| unquote(s))?;
    if table.is_empty() {
        return None;
    }
    let col = paren_inner(rest).map(|i| unquote(i.trim())).unwrap_or_default();
    Some((Some(table), if col.is_empty() { None } else { Some(col) }))
}

/// The contents of the first balanced paren group starting anywhere in `s`.
fn paren_inner(s: &str) -> Option<String> {
    let open = s.find('(')?;
    let close = matching_paren(s, open)?;
    Some(s[open + 1..close].to_string())
}

/// Index of the paren that closes the one at `open`, or None.
fn matching_paren(s: &str, open: usize) -> Option<usize> {
    let b = s.as_bytes();
    let mut depth = 0i32;
    let mut quote: Option<u8> = None;
    for (i, &c) in b.iter().enumerate().skip(open) {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            b'\'' | b'"' | b'`' => quote = Some(c),
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Split on `sep` at paren depth zero, respecting quotes.
fn split_top_level(s: &str, sep: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    for c in s.chars() {
        if let Some(q) = quote {
            cur.push(c);
            if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' | '`' => {
                quote = Some(c);
                cur.push(c);
            }
            '(' => {
                depth += 1;
                cur.push(c);
            }
            ')' => {
                depth -= 1;
                cur.push(c);
            }
            c if c == sep && depth == 0 => out.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

// ---------------------------------------------------------- migration handling

/// Identify a migration file and its dialect, from its path alone.
///
/// Deliberately conservative: a file that is not recognisably a migration
/// returns None rather than being parsed as one. A model file called `0001.py`
/// being treated as an alembic revision would add phantom tables.
pub fn classify_migration(path: &str) -> Option<&'static str> {
    let p = path.replace('\\', "/");
    let name = p.rsplit('/').next().unwrap_or(&p);
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());

    // Path based dialects first, they are the strongest signal.
    if p.contains("/prisma/migrations/") || p.contains("prisma/migrations/") {
        return Some("prisma");
    }
    if p.contains("/db/migrate/") || p.contains("db/migrate/") {
        return Some(match ext.as_deref() {
            Some("go") => "goose",
            _ => "sql",
        });
    }
    if p.contains("/migrations/") || p.contains("migrations/") {
        // A migrations dir containing .go files is goose; .sql is plain.
        return Some(match ext.as_deref() {
            Some("go") => "goose",
            Some("py") => "alembic",
            _ => "sql",
        });
    }

    // Flyway: V1__init.sql
    if name.starts_with('V') && name.contains("__") {
        return Some("flyway");
    }
    // Liquibase changelog
    if name.starts_with("changelog") || name.starts_with("db.changelog") {
        return Some("liquibase");
    }

    // Timestamped or numbered, with a known extension.
    let stem = name.split('.').next().unwrap_or(name);
    let numeric_prefix: String = stem
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let looks_numbered = numeric_prefix.len() >= 4 || {
        // 0001 is four digits; V1 handled above; a bare "1_" is too weak.
        numeric_prefix.len() == 1 && stem.contains('_')
    };
    if !looks_numbered {
        return None;
    }
    match ext.as_deref() {
        Some("sql") => Some("sql"),
        Some("py") => Some("alembic"),
        Some("go") => Some("goose"),
        Some("js") | Some("ts") => Some("knex"),
        _ => None,
    }
}

/// Extract a migration version from its filename.
pub fn migration_version(path: &str) -> String {
    let name = path.replace('\\', "/");
    let base = name.rsplit('/').next().unwrap_or(&name);
    let stem = base.split('.').next().unwrap_or(base);
    stem.to_string()
}

/// The migration directories heides recognises, as path suffixes to match.
pub const MIGRATION_DIRS: [&str; 6] = [
    "prisma/migrations",
    "db/migrate",
    "migrations",
    "db/migrations",
    "alembic/versions",
    "sql",
];

/// Any recognised migration directory under `root`, relative and sorted.
pub fn migration_dirs(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_dirs(root, root, 0, &mut out);
    out.sort();
    out.dedup();
    out
}

fn collect_dirs(root: &Path, dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > 6 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if !p.is_dir() {
            continue;
        }
        let name = e.file_name().to_string_lossy().to_string();
        if matches!(
            name.as_str(),
            "node_modules" | "target" | ".git" | "venv" | ".venv" | "__pycache__" | "dist" | "build"
        ) {
            continue;
        }
        if MIGRATION_DIRS.iter().any(|d| name == *d || p.ends_with(d)) {
            out.push(p.clone());
        }
        collect_dirs(root, &p, depth + 1, out);
    }
}

/// A short stable digest of a migration body, so drift is detectable without
/// storing the file. Not a security hash; only a change detector.
pub fn body_digest(body: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in body.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", h)
}

// ------------------------------------------------------- ORM call-site resolution

/// Method names that only read.
const READ_METHODS: &[&str] = &[
    "find", "findone", "findmany", "findfirst", "findunique", "findbyid", "first",
    "firstor", "last", "take", "all", "get", "filter", "where", "count",
    "exists", "any", "scalar", "one", "oneornone", "list", "select", "fetch",
    "fetchall", "fetchone", "fetchmany", "read", "load", "includes", "query",
    "selectone", "joins", "orderby", "groupby", "aggregate", "sum", "avg",
    "pluck", "values", "distinct", "with",
];

/// Method names that only write.
const WRITE_METHODS: &[&str] = &[
    "create", "createasync", "createmany", "insert", "insertmany", "add",
    "addasync", "save", "update", "updateasync", "updatemany", "upsert",
    "delete", "deleteasync", "deleteall", "deletemany", "destroy", "remove",
    "removerange", "destroyall", "increment", "decrement", "truncate",
    "updateorcreate", "savepoint", "rollbackto", "bulkcreate", "bulkupdate",
];

fn op_for(method: &str) -> Option<Op> {
    // Normalise the spellings an ORM actually uses. `create!` is ActiveRecord,
    // `delete_all` is ActiveRecord's bulk form, `deleteAll` is EF Core, and
    // `findMany` is prisma. Trimming a trailing `s` or `!` instead mangled
    // `delete_all` into `delete_al`, which matched nothing at all.
    let mut m = method
        .trim_matches(|c: char| c == '!' || c == '?')
        .to_ascii_lowercase();
    // camelCase to snake_case, so `findMany` and `deleteAll` reduce properly.
    let mut snake = String::with_capacity(m.len() + 4);
    for (i, c) in m.chars().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            snake.push('_');
        }
        snake.push(c);
    }
    m = snake;
    // A plural suffix on a bulk operation is still the operation.
    let trimmed = m
        .strip_suffix("_all")
        .or_else(|| m.strip_suffix("_many"))
        .or_else(|| m.strip_suffix("_list"))
        .map(|s| s.to_string())
        .unwrap_or_else(|| m.clone());

    // Writes are checked first: `deleteAll` must not be read as a read because it
    // ends in something that looks like a fetch.
    for candidate in [m.as_str(), trimmed.as_str()] {
        if WRITE_METHODS.contains(&candidate) {
            return Some(Op::Write);
        }
    }
    for candidate in [m.as_str(), trimmed.as_str()] {
        if READ_METHODS.contains(&candidate) {
            return Some(Op::Read);
        }
    }
    None
}

/// `prisma.user.findMany()` -> table `user`, read.
fn resolve_prisma(body: &str, file: &str) -> Vec<Call> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(at) = rest.find("prisma") {
        let after = &rest[at + 6..];
        let Some(open) = after.find('.') else {
            rest = after;
            continue;
        };
        let model_part = &after[open + 1..];
        let model: String = model_part
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
            .collect();
        let after_model = &model_part[model.len()..];
        if model.is_empty() || !after_model.starts_with('.') {
            rest = after;
            continue;
        }
        let method: String = after_model[1..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        // prisma.$queryRaw / $executeRaw are raw, not model calls.
        if !model.starts_with('$') {
            if let Some(op) = op_for(&method) {
                out.push(Call {
                    table: model.to_ascii_lowercase(),
                    op,
                    via: format!("prisma.{}.{}()", model, method),
                    file: file.to_string(),
                    line: 1,
                });
            }
        }
        rest = after_model;
    }
    out
}

/// `User.objects.filter()`, `session.query(User).add()`, `User.create!()`.
fn resolve_model_calls(body: &str, file: &str) -> Vec<Call> {
    let mut out = Vec::new();
    let b = body.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if !(b[i].is_ascii_alphabetic() || b[i] == b'_') {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
            i += 1;
        }
        let word = &body[start..i];
        // A capitalised or plural identifier directly followed by a known
        // method is a model. Requiring the method name is the whole gate.
        if i >= b.len() || b[i] != b'.' {
            continue;
        }
        let after = &body[i + 1..];
        let mlen = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .count();
        if mlen == 0 {
            continue;
        }
        let method_raw = &after[..mlen];
        // Django's manager and SQLAlchemy's query are accessors, not
        // operations. They mean "about to operate", so the scan continues past
        // them to the method that does the work. `User.objects.create(name=n)`
        // is a write on User; stopping at `objects` recorded only a read.
        // `query` is deliberately not an accessor here: it is a handle name
        // (`session.query(User)`), and treating it as an accessor let the chain
        // walk record a table called `query`.
        let is_accessor = matches!(method_raw, "objects" | "manager");
        let op: Option<Op> = if is_accessor {
            None
        } else {
            op_for(method_raw)
        };
        // A receiver that is a known handle or accessor is never a table. The
        // check has to happen before anything is recorded, because the chain walk
        // on `session.query(User).all()` otherwise emits tables called `query`
        // and `session`, which is worse than emitting nothing.
        const HANDLES: &[&str] = &[
            "session", "conn", "connection", "cursor", "cur", "db", "tx", "ctx",
            "context", "repo", "repository", "query", "objects", "manager",
            "client", "store", "em", "entitymanager", "unitofwork",
        ];
        let lower = word.to_ascii_lowercase();
        if HANDLES.contains(&lower.as_str()) {
            // Still resolve the model argument, e.g. `session.query(User)`.
            // `after` begins at the dot, so the argument search must start there
            // too. Slicing past the method name chopped the leading `.` and the
            // first character of the callee, so `add(User(..))` read as `dd(..)`
            // and matched nothing.
            out.extend(models_in_call_args(after, file));
            i += 1;
            continue;
        }
        let Some(op) = op else {
            if is_accessor {
                // `User.objects.create(..)` is a write on User. The accessor is
                // not an operation, so the chain past it decides.
                if let Some(tail) = find_operation_in_chain(after, file, word) {
                    out.push(tail);
                }
                i += 1;
            }
            continue;
        };
        // Skip obvious non models. A lowercase receiver is a local variable, and
        // a capitalised one can still be a method name: GORM chains read
        // `db.Where(..).Find(..)`, so `Where` looks exactly like a model class
        // and used to resolve a table named `Where`.
        const NOT_A_MODEL: &[&str] = &[
            "where", "query", "session", "conn", "connection", "cursor", "cur",
            "db", "database", "tx", "ctx", "context", "repo", "repository",
            "create", "delete", "update", "find", "first", "last", "save", "get",
            "exec", "execute", "run", "select", "insert", "count", "filter",
            "table", "column", "row", "result", "value", "name", "id", "self",
            "this", "super", "new",
        ];
        let lower = word.to_ascii_lowercase();
        if NOT_A_MODEL.contains(&lower.as_str()) {
            // Still pick the model out of `query(User)` before giving up.
            out.extend(models_in_call_args(after, file));
            continue;
        }
        if !word
            .chars()
            .next()
            .map(|c| c.is_ascii_uppercase())
            .unwrap_or(false)
            && !is_accessor
        {
            continue;
        }
        out.push(Call {
            table: word.to_string(),
            op,
            via: format!("{}.{}()", word, method_raw),
            file: file.to_string(),
            line: 1,
        });
    }
    out
}

/// Raw SQL: name the table out of the statement text.
fn tables_in_sql(stmt: &str) -> Vec<(String, Op)> {
    let up = stmt.to_ascii_uppercase();
    let mut out = Vec::new();
    let ops: &[(&str, Op)] = &[
        ("INSERT INTO", Op::Write),
        ("INSERT IGNORE INTO", Op::Write),
        ("REPLACE INTO", Op::Write),
        ("UPDATE", Op::Write),
        ("DELETE FROM", Op::Write),
        ("MERGE INTO", Op::Write),
        ("TRUNCATE", Op::Write),
        ("DROP TABLE", Op::Write),
        ("ALTER TABLE", Op::Write),
        ("SELECT", Op::Read),
        ("FROM", Op::Read),
        ("JOIN", Op::Read),
        ("INTO", Op::Read),
    ];
    for (kw, op) in ops {
        let mut from = 0usize;
        while let Some(at) = up[from..].find(kw) {
            let abs = from + at + kw.len();
            let rest = stmt[abs..].trim_start();
            // `SELECT ... INTO tmp` is a write, so INTO only counts as a read
            // when it follows a FROM clause rather than creating a table.
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.' || *c == '"')
                .collect();
            let name = unquote(&name);
            let name = name.rsplit('.').next().unwrap_or("").to_string();
            if !name.is_empty()
                && !matches!(
                    name.to_ascii_lowercase().as_str(),
                    "if" | "not" | "exists" | "set" | "values" | "where" | "only"
                )
            {
                out.push((name, *op));
            }
            from = abs;
        }
    }
    out
}


/// Model names passed as arguments inside a call, with the operation the call
/// implies.
///
/// `session.query(User).all()` puts the model in an argument of a handle call,
/// and `session.add(User(name=n))` puts it in a constructor argument. Neither has
/// the model as a receiver, so a receiver-only scanner sees nothing at all.
fn models_in_call_args(rest: &str, file: &str) -> Vec<Call> {
    // Only the near part of the expression is inspected; this is a lookup for a
    // model name, not a parse of the whole chain.
    // The window spans statements on purpose: a handle appears once but its
    // model arguments do not, so `session.add(User(..))` is a different line
    // from `session.query(User)`.
    let window = &rest[..rest.len().min(2000)];
    let mut out = Vec::new();
    const CALLS: &[(&str, Op)] = &[
        ("query(", Op::Read),
        ("select(", Op::Read),
        ("filter_by(", Op::Read),
        ("add(", Op::Write),
        ("create(", Op::Write),
        ("get(", Op::Read),
        ("merge(", Op::Write),
        ("save(", Op::Write),
    ];
    for (marker, op) in CALLS {
        let mut from = 0usize;
        while let Some(at) = window[from..].find(marker) {
            let after = &window[from + at + marker.len()..];
            let name: String = after
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let tail = &after[name.len()..];
            // A capitalised name is a model class. A lowercase single-word
            // argument to a write is an entity instance: `save(user)`,
            // `create(order)`. Anything with a dot, a call or a keyword shape is
            // not an entity name.
            const NOT_ENTITY: &[&str] = &[
                "true", "false", "null", "none", "undefined", "data", "options",
                "opts", "params", "args", "values", "result", "response", "req",
                "res", "ctx", "context", "config", "payload", "body", "id",
            ];
            let name_lower = name.to_ascii_lowercase();
            // A lowercase identifier is an entity only when it fills the whole
            // argument: `save(user)` yes, `create(name=n)` no. The `=` marks it a
            // keyword argument, and reading `name=n` as a table called `name` is
            // exactly the kind of invented answer that makes this untrustworthy.
            let lowercase_is_entity = *op == Op::Write
                && !name.is_empty()
                && name.chars().all(|c| c.is_alphanumeric() || c == '_')
                && (tail.starts_with(')') || tail.starts_with(','));
            let entity_like = !name.is_empty()
                && !NOT_ENTITY.contains(&name_lower.as_str())
                && !name.contains('.')
                && (name
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_uppercase())
                    .unwrap_or(false)
                    || lowercase_is_entity);
            if entity_like
                // Language builtins and sentinels, not model names. `User` was
                // wrongly in this list once, which silently filtered out the most
                // common model name in every Django and SQLAlchemy codebase.
                && !matches!(
                    name.as_str(),
                    "None" | "True" | "False" | "String" | "Int" | "List"
                        | "Dict" | "Optional" | "Bytes" | "Object" | "New"
                )
            {
                let _ = tail;
                out.push(Call {
                    table: name,
                    op: *op,
                    via: format!("orm.{}", marker.trim_end_matches('(')),
                    file: file.to_string(),
                    line: 1,
                });
            }
            from = from + at + marker.len();
        }
    }
    out
}


/// Case-insensitive substring search returning a byte offset into `haystack`.
///
/// TypeORM and EF spell methods in camelCase (`findOne`, `deleteAll`) while the
/// method table is lowercase, so a plain `find` missed every camelCase call. That
/// is exactly why `userRepo.save` resolved and `userRepo.findOne` did not.
fn find_ci(haystack: &str, needle: &str) -> Option<usize> {
    haystack.to_ascii_lowercase().find(needle)
}

/// TypeORM and Nest repositories are named after their entity: `userRepo`,
/// `orderRepository`. The entity is the prefix, so the table can be named without
/// reading a single query.
fn entity_from_repository_name(name: &str) -> Option<String> {
    for suffix in ["Repository", "repository", "Repo", "repo", "Model", "model"] {
        if let Some(prefix) = name.strip_suffix(suffix) {
            if !prefix.is_empty() {
                return Some(prefix.to_string());
            }
        }
    }
    None
}

/// The offset of the first character that cannot be part of the current
/// statement's method chain: a newline, a semicolon, or a comma at depth zero.
fn statement_boundary(s: &str) -> usize {
    let b = s.as_bytes();
    let mut depth = 0i32;
    let mut quote: Option<u8> = None;
    for (i, &c) in b.iter().enumerate() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            b'\'' | b'"' | b'`' => quote = Some(c),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'\n' | b';' => return i,
            b',' if depth <= 0 => return i,
            _ => {}
        }
    }
    s.len()
}

/// Walk the rest of a method chain looking for the operation, given the receiver
/// name. `User.objects.create()` becomes a write on `User`.
///
/// Bounded to a short chain and a short lookahead so a long expression cannot
/// turn this into a scan of the rest of the file.
fn find_operation_in_chain(rest: &str, file: &str, receiver: &str) -> Option<Call> {
    let mut cur = rest;
    // The terminal method is the operation. `Order.objects.filter(..).delete()`
    // contains a read in `filter` and the write in `delete`, and only the last
    // one is what actually happens, so every candidate is recorded and the
    // final one wins.
    let mut last: Option<Call> = None;
    for _ in 0..6 {
        // Stop at a statement boundary. Without this the walk runs off the end of
        // the line and reports the operation from the *next* statement:
        // `User.objects.filter(x)` followed by `User.objects.create(y)` was
        // recorded as a write, because the chain reader had no line limit.
        // Newline and semicolon end a statement. A comma only ends one when it is
        // at paren depth zero: `User.objects.create(name=n, bio=b)` has commas
        // inside its argument list, and cutting there hid the operation.
        let stop = statement_boundary(cur);
        let head = &cur[..stop];
        let Some(at) = head.find('.') else {
            break;
        };
        let tail = &cur[at + 1..stop];
        let after = tail;
        let mlen = after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .count();
        if mlen == 0 {
            break;
        }
        let method_raw = &after[..mlen];
        cur = &after[mlen..];
        if matches!(method_raw, "objects" | "manager") {
            continue;
        }
        if let Some(op) = op_for(method_raw) {
            last = Some(Call {
                table: receiver.to_string(),
                op,
                via: format!("{}.{}()", receiver, method_raw),
                file: file.to_string(),
                line: 1,
            });
        }
    }
    last
}

/// Go and Entity Framework name the collection in a receiver, and gorm names the
/// model in a destination variable. `db.Where(..).Find(&users)` is a read on
/// `users`; `_db.Users.Where(..)` is on `Users`.
///
/// This is the one place a lowercase name is accepted, because Go and C# do not
/// capitalise models. It is gated on the receiver looking like a database handle
/// (`db`, `_db`, `conn`, `session`) so an arbitrary lowercase word cannot
/// resolve to a table.
fn receiver_table(body: &str, receiver: &str) -> Option<String> {
    const DB_HANDLES: &[&str] = &["db", "_db", "conn", "connection", "session", "ctx", "repo"];
    let last = receiver.rsplit('.').next().unwrap_or(receiver);
    if !DB_HANDLES.contains(&last.to_ascii_lowercase().as_str()) {
        return None;
    }
    // The next path segment after the handle is the collection.
    let after = &body[receiver.len()..];
    let trimmed = after.trim_start().strip_prefix('.').unwrap_or(after);
    let name: String = trimmed
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// `userRepo.findOne()`, `orderRepository.save()`: the entity is in the name.
fn resolve_named_repositories(body: &str, file: &str) -> Vec<Call> {
    const METHODS: &[(&str, Op)] = &[
        ("findone", Op::Read),
        ("find", Op::Read),
        ("findmany", Op::Read),
        ("findby", Op::Read),
        ("save", Op::Write),
        ("create", Op::Write),
        ("insert", Op::Write),
        ("update", Op::Write),
        ("delete", Op::Write),
        ("remove", Op::Write),
        ("softdelete", Op::Write),
        ("count", Op::Read),
        ("exists", Op::Read),
    ];
    let mut out = Vec::new();
    for (method, op) in METHODS {
        let mut from = 0usize;
        while let Some(at) = find_ci(&body[from..], method) {
            let after = &body[from + at + method.len()..];
            if !after.starts_with('(') {
                from = from + at + method.len();
                continue;
            }
            // The receiver is the identifier before the dot.
            let before = &body[from..from + at];
            // The receiver may be a chain: `this.userRepo.findOne(..)`. Reading
            // backwards over only word characters stopped at the dot and produced
            // an empty identifier, so nothing resolved at all.
            let ident: String = before
                .chars()
                .rev()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            // The backward scan stops on the dot but leaves it attached, so
            // `this.userRepo.findOne` yields "this.userRepo." and rsplit gives an
            // empty last segment. Trim first, then take the last segment.
            let ident = ident.trim_matches('.').to_string();
            let ident = ident
                .rsplit('.')
                .next()
                .unwrap_or(&ident)
                .to_string();
            if let Some(entity) = entity_from_repository_name(&ident) {
                out.push(Call {
                    table: entity.to_ascii_lowercase(),
                    op: *op,
                    via: format!("{}.{}()", ident, method),
                    file: file.to_string(),
                    line: 1,
                });
            }
            from = from + at + method.len();
        }
    }
    out
}

/// A table name inside `db.Table("orders")`, `Table('users')`, `table_name=...`.
fn resolve_quoted_table(body: &str, file: &str, op: Op, via_prefix: &str) -> Vec<Call> {
    let mut out = Vec::new();
    for marker in ["Table(", "table(", "table_name=", "tableName=", "from_table("] {
        let mut from = 0usize;
        while let Some(at) = body[from..].find(marker) {
            let rest = &body[from + at + marker.len()..];
            let quote = rest.chars().next();
            if quote == Some('"') || quote == Some('\'') {
                let q = quote.unwrap();
                if let Some(end) = rest[1..].find(q) {
                    let name = unquote(&rest[..end + 2]);
                    if !name.is_empty() {
                        out.push(Call {
                            table: name,
                            op,
                            via: format!("{}{}", via_prefix, marker),
                            file: file.to_string(),
                            line: 1,
                        });
                    }
                }
            }
            from = from + at + marker.len();
        }
    }
    out
}

/// Every table access in `body`, from every supported ORM and raw SQL.
pub fn scan_calls(path: &Path, body: &str) -> Vec<Call> {
    let file = path.to_string_lossy().to_string();
    let mut calls = resolve_prisma(body, &file);
    calls.extend(resolve_model_calls(body, &file));
    calls.extend(resolve_quoted_table(body, &file, Op::Write, "gorm."));
    calls.extend(resolve_quoted_table(body, &file, Op::Read, "gorm."));
    calls.extend(resolve_handle_receivers(body, &file));
    calls.extend(resolve_destinations(body, &file));
    calls.extend(resolve_orm_arguments(body, &file));
    calls.extend(resolve_named_repositories(body, &file));

    // Raw SQL inside a string literal that mentions a keyword. The literal only
    // counts when it sits in a query position: assigned to a query-shaped name, or
    // passed to a call whose name says execute or query. Without that gate,
    // `console.log("SELECT * FROM users")` resolves as a table access, which is
    // exactly the wrong answer that makes this feature untrustworthy.
    for (stmt, in_query_position) in string_literals_with_context(body) {
        if !in_query_position {
            continue;
        }
        let up = stmt.to_ascii_uppercase();
        if !(up.contains("SELECT ")
            || up.contains("INSERT INTO")
            || up.contains("UPDATE ")
            || up.contains("DELETE FROM")
            || up.contains("JOIN "))
        {
            continue;
        }
        for (table, op) in tables_in_sql(&stmt) {
            calls.push(Call {
                table,
                op,
                via: "raw sql".into(),
                file: file.clone(),
                line: 1,
            });
        }
    }

    calls.sort_by(|a, b| a.table.cmp(&b.table));
    calls.dedup_by(|a, b| a.table == b.table && a.op == b.op && a.via == b.via);
    calls
}

/// `_db.Users.Where(...)`, `session.Orders.Add(...)`: a database handle followed
/// by a collection name and then a method.
fn resolve_handle_receivers(body: &str, file: &str) -> Vec<Call> {
    let mut out = Vec::new();
    for handle in ["_db", "db", "conn", "connection", "session"] {
        let mut from = 0usize;
        while let Some(at) = body[from..].find(handle) {
            let after = &body[from + at + handle.len()..];
            // Must be a real receiver: preceded by a boundary, followed by `.`.
            let before_ok = at == 0
                || !body[from + at - 1..]
                    .chars()
                    .last()
                    .map(|c| c.is_alphanumeric() || c == '_')
                    .unwrap_or(false);
            if before_ok && after.starts_with('.') {
                if let Some(table) = receiver_table(&body[from + at..], handle) {
                    // Find the operation method after the collection.
                    let chain = &after[after[1..]
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .count()
                        + 1..];
                    if let Some(call) = find_operation_in_chain(chain, file, &table) {
                        out.push(call);
                    }
                }
            }
            from = from + at + handle.len();
        }
    }
    out
}

/// SQLAlchemy and EF name the model as an argument: `session.query(User)`,
/// `select(Order)`, `_db.Users` already handled by the receiver resolver.
///
/// The argument is only accepted after a recognised ORM entry point, so
/// `print(User)` and `config.get("User")` cannot resolve to a table.
fn resolve_orm_arguments(body: &str, file: &str) -> Vec<Call> {
    const ENTRY: &[(&str, Op)] = &[
        ("query(", Op::Read),
        ("select(", Op::Read),
        ("filter_by(", Op::Read),
        ("get(", Op::Read),
        ("add(", Op::Write),
        ("merge(", Op::Write),
        ("bulk_save_objects(", Op::Write),
        ("scalar(", Op::Read),
    ];
    let mut out = Vec::new();
    for (marker, op) in ENTRY {
        let mut from = 0usize;
        while let Some(at) = body[from..].find(marker) {
            let after = &body[from + at + marker.len()..];
            let rest = after.trim_start();
            // A bare identifier followed by `)` or `.` is the model argument.
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let tail = &rest[name.len()..];
            let model_like = !name.is_empty()
                && name.chars().next().map(|c| c.is_ascii_uppercase()).unwrap_or(false)
                && (tail.starts_with(')') || tail.starts_with('.') || tail.starts_with(','));
            if model_like {
                out.push(Call {
                    table: name,
                    op: *op,
                    via: format!("orm.{}", marker.trim_end_matches('(')),
                    file: file.to_string(),
                    line: 1,
                });
            }
            from = from + at + marker.len();
        }
    }
    out
}

/// GORM and ActiveRecord pass the model in a destination variable:
/// `db.Where(..).Find(&users)`, `db.Create(&user)`, `User.first(&user)`.
///
/// The address-of or `new` prefix is stripped, then the variable name becomes
/// the table. Only after a recognised operation method, so an arbitrary
/// `&value` cannot resolve to a table.
fn resolve_destinations(body: &str, file: &str) -> Vec<Call> {
    let mut out = Vec::new();
    for (method, op) in [
        ("Find(", Op::Read),
        ("First(", Op::Read),
        ("Take(", Op::Read),
        ("Last(", Op::Read),
        ("Create(", Op::Write),
        ("Save(", Op::Write),
        ("Delete(", Op::Write),
    ] {
        let mut from = 0usize;
        while let Some(at) = body[from..].find(method) {
            let after = &body[from + at + method.len()..];
            let trimmed = after.trim_start();
            let rest = trimmed
                .strip_prefix('&')
                .or_else(|| trimmed.strip_prefix("new "))
                .unwrap_or(trimmed);
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                out.push(Call {
                    table: name,
                    op,
                    via: format!("gorm.{}", method.trim_end_matches('(')),
                    file: file.to_string(),
                    line: 1,
                });
            }
            from = from + at + method.len();
        }
    }
    out
}

/// Names that indicate a string literal is being used as a query rather than
/// printed. Without this gate, `console.log("SELECT * FROM users")` resolves as a
/// table access, which is exactly the kind of wrong answer that makes a feature
/// untrustworthy.
const QUERY_NAMES: &[&str] = &[
    "query",
    "sql",
    "stmt",
    "statement",
    "execute",
    "exec",
    "raw",
    "execsql",
    "prepare",
    "where",
    "select",
    "insert",
    "update",
    "delete",
    "find",
    "aggregate",
    "runquery",
    "db",
    "database",
    "connection",
    "conn",
    "cursor",
    "session",
    "text",
    "table",
];

/// True when the identifier immediately before a string literal says the string
/// is a query.
///
/// Walks back from the opening quote to the nearest statement or argument
/// boundary, then reads the identifier that precedes it. A bare string with no
/// name in front of it, like an argument to `console.log`, is not a query.
fn is_query_position(body: &str, quote_at: usize) -> bool {
    let before = &body[..quote_at];
    // The boundary walk stops at a separator, and the text after the last one is
    // the identifier the literal is bound to. A call argument keeps the callee
    // name on the tail, which is exactly what `execute("...")` needs, so `(` is
    // deliberately not a boundary here: cutting at it would discard `execute`
    // and leave the tail empty.
    let tail: String = before
        .rsplit(|c| c == ';' || c == '\n' || c == ',' || c == '=')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    // The callee name is on the tail for a call argument, so read through the
    // opening paren: `cur.execute(` must yield `execute`, not an empty string.
    let tail = tail.trim_end_matches(|c: char| c == '(' || c == ' ');
    let ident: String = tail
        .chars()
        .rev()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    if ident.is_empty() {
        return false;
    }
    let last = ident
        .rsplit('.')
        .next()
        .unwrap_or(&ident)
        .to_ascii_lowercase();
    QUERY_NAMES.iter().any(|n| last == *n)
}

/// Every quoted string, paired with whether it sits in a query position.
fn string_literals_with_context(body: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    for (text, at) in string_literal_spans(body) {
        out.push((text, is_query_position(body, at)));
    }
    out
}

/// `(content, offset_of_opening_quote)` for every quoted string.
fn string_literal_spans(body: &str) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    let b = body.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        if c == b'"' || c == b'\'' || c == b'`' {
            let q = c;
            let start = i + 1;
            let mut j = start;
            while j < b.len() && b[j] != q {
                if b[j] == b'\\' {
                    j += 1;
                }
                j += 1;
            }
            if j <= b.len() {
                out.push((
                    String::from_utf8_lossy(&b[start..j.min(b.len())]).to_string(),
                    i,
                ));
            }
            i = j + 1;
            continue;
        }
        i += 1;
    }
    out
}
// ------------------------------------------- deliverable 4: concatenated queries

/// A query built by string concatenation, f-string, `.format` or a template
/// literal.
///
/// This is the only rule in heides that needs no source and no sink. The
/// defect is syntactic: a query built from pieces is injection regardless of
/// where the values came from, so waiting for a taint flow to prove it is
/// what lets `"SELECT ... " + id` through entirely. It is the class the roadmap
/// names as the one `check` misses.
///
/// The gate is what makes it usable. A parameterised query is correct code and
/// is the overwhelming majority of queries in a healthy codebase, so:
///   * the string must actually look like SQL, not just be concatenated
///   * a `%s` or `?` or `$1` placeholder on the line means the values are
///     parameterised, which is the safe spelling
///   * `+` between two string literals is constant folding, not injection
pub fn concatenated_queries(path: &Path, body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (n, line) in body.lines().enumerate() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with("//") {
            continue;
        }
        // Placeholder query: the safe spelling, always.
        // A parameter placeholder means the values are bound, not interpolated.
        // `?` and `%s` are positional, `:name` is named. `{name}` and `${name}`
        // are *not* placeholders: they are holes in a f-string or a template
        // literal, which is the defect this rule exists to catch, so they must
        // not be skipped here.
        if line.contains('?')
            || line.contains("%s")
            || line.contains("$1")
            || line.contains(":id")
            || line.contains(":uid")
            || line.contains(":user_id")
        {
            continue;
        }

        let sql_like = line.contains("SELECT")
            || line.contains("INSERT")
            || line.contains("UPDATE")
            || line.contains("DELETE")
            || line.contains("WHERE")
            || line.contains("FROM ");
        if !sql_like {
            continue;
        }

        // Constant folding: "SELECT" + "FROM" builds no injection surface.
        let plus_concat = looks_like_concat(l);
        if !plus_concat {
            continue;
        }
        // Every operand must be a literal for it to be folding. If any operand
        // is a bare identifier, a call, or an f-string hole, it is a real
        // concatenation.
        if is_constant_fold(l) {
            continue;
        }
        let table = line
            .split(" FROM ")
            .nth(1)
            .map(|r| {
                r.split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_matches(|c: char| !c.is_alphanumeric() && c != '_')
                    .to_string()
            })
            .filter(|t| !t.is_empty());
        let has_where = line.contains(" WHERE ") || line.contains(" WHERE\t");
        let where_kind = if has_where { "where clause" } else { "query" };
        out.push(format!(
            "{}:{}: query built by concatenation into a {} ({}); use a parameter placeholder instead",
            path.to_string_lossy(),
            n + 1,
            where_kind,
            table.unwrap_or_else(|| "unknown table".into())
        ));
    }
    out
}

/// True when the line joins two string literals with `+`.
fn is_constant_fold(l: &str) -> bool {
    let Some(at) = l.find(" + ") else {
        return false;
    };
    let (left, right) = (&l[..at], &l[at + 3..]);
    is_literal_only(left) && is_literal_only(right)
}

/// True when every operand on this side of a `+` is a quoted literal.
fn is_literal_only(s: &str) -> bool {
    let mut rest = s.trim();
    let mut any = false;
    let mut expect_literal = true;
    while !rest.is_empty() {
        if expect_literal {
            let Some(q) = rest.chars().next().filter(|c| *c == '"' || *c == '\'') else {
                return false;
            };
            let Some(end) = rest[1..].find(q) else {
                return false;
            };
            rest = rest[end + 2..].trim();
            any = true;
            expect_literal = false;
        } else {
            let Some(r) = rest.strip_prefix('+') else {
                return false;
            };
            rest = r.trim();
            expect_literal = true;
        }
    }
    any
}

/// True when a line builds a value from a hole: `+ ident`, `+ call()`, f-string,
/// `.format(`, or a `${}` template hole.
fn looks_like_concat(l: &str) -> bool {
    // f-string with a hole.
    if l.contains("f\"") || l.contains("f'") {
        if l.contains('{') {
            return true;
        }
    }
    // Template literal with a hole.
    if l.contains("${") {
        return true;
    }
    // .format( with an argument.
    if let Some(at) = l.find(".format(") {
        let after = &l[at + 8..];
        if after.contains(')') || after.chars().next().map(|c| c != ')').unwrap_or(true) {
            return true;
        }
    }
    // `+ identifier` or `+ call()`
    let b = l.as_bytes();
    for i in 0..b.len().saturating_sub(3) {
        if &b[i..i + 3] != b" + " {
            continue;
        }
        let rest = l[i + 3..].trim_start();
        let Some(first) = rest.chars().next() else {
            continue;
        };
        // A quoted literal after the plus is constant folding, handled above.
        if first == '"' || first == '\'' || first == '`' {
            continue;
        }
        if first.is_alphanumeric() || first == '_' || first == '$' {
            return true;
        }
    }
    // A bare `%s`-less percent format with a variable is handled by placeholder
    // skipping, so `%` alone does not count.
    false
}

// ---------------------------------------------------------------- indexing API

/// Build the database picture for a workspace: schema graph, migrations, and
/// every resolved call site.
///
/// A workspace with no database is not an error. It yields an empty graph.
pub fn index_schema(root: &Path) -> Result<DbGraph, String> {
    let mut g = DbGraph::default();

    // Schema and migrations.
    let mut files: Vec<PathBuf> = Vec::new();
    walk(root, root, 0, &mut files);
    files.sort();
    files.dedup();

    for p in &files {
        let rel = p
            .strip_prefix(root)
            .unwrap_or(p)
            .to_string_lossy()
            .replace('\\', "/");
        if p.extension().map(|e| e == "sql").unwrap_or(false) {
            if let Ok(body) = std::fs::read_to_string(p) {
                if let Some(dialect) = classify_migration(&rel) {
                    g.migrations.push(Migration {
                        file: rel.clone(),
                        version: migration_version(&rel),
                        dialect,
                        sha: body_digest(&body),
                    });
                }
                let mut parsed = parse_sql(p, &body);
                // Merge by name, later file wins, which matches migration order.
                for t in parsed.drain(..) {
                    match g.tables.iter().position(|x| x.name == t.name) {
                        Some(i) => g.tables[i] = t,
                        None => g.tables.push(t),
                    }
                }
            }
        }
        // Alembic emits python that contains create_table calls.
        if p.extension().map(|e| e == "py").unwrap_or(false) {
            if let Ok(body) = std::fs::read_to_string(p) {
                let parsed = parse_alembic(p, &body);
                for t in parsed {
                    match g.tables.iter().position(|x| x.name == t.name) {
                        Some(i) => g.tables[i] = t,
                        None => g.tables.push(t),
                    }
                }
            }
        }
        // Call sites from every code and query file.
        if matches!(
            p.extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_default().as_str(),
            "py" | "ts" | "tsx" | "js" | "jsx" | "go" | "rb" | "cs" | "php" | "java" | "kt" | "sql"
        ) {
            if let Ok(body) = std::fs::read_to_string(p) {
                let mut calls = scan_calls(p, &body);
                for c in calls.iter_mut() {
                    c.file = rel.clone();
                    c.line = 1;
                }
                g.calls.extend(calls);
            }
        }
    }

    Ok(g)
}

/// One `create_table(...)` call, as a Table. Used by both the whole-file
/// alembic parser and the single-statement path inside parse_sql.
fn parse_alembic_stmt(stmt: &str) -> Vec<Table> {
    parse_alembic(Path::new(""), stmt)
}

/// Parse `op.create_table('users', sa.Column(...))` and its knex equivalent.
fn parse_alembic(path: &Path, body: &str) -> Vec<Table> {
    let src = path.to_string_lossy().to_string();
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(at) = rest.find("create_table") {
        let after = &rest[at + "create_table".len()..];
        let Some(open) = after.find('(') else {
            rest = after;
            continue;
        };
        let Some(close) = matching_paren(after, open) else {
            rest = after;
            continue;
        };
        let inner = &after[open + 1..close];
        let name = split_top_level(&inner, ',')
            .first()
            .map(|c| {
                let t = c.trim();
                unquote(t.trim_matches(|ch: char| ch != '\'' && ch != '"'))
            })
            .unwrap_or_default();
        if name.is_empty() {
            rest = &after[close..];
            continue;
        }
        let mut table = Table {
            name,
            schema: None,
            kind: "table".into(),
            columns: Vec::new(),
            indexes: Vec::new(),
            source: src.clone(),
        };
        for part in split_top_level(&inner, ',') {
            let p = part.trim();
            let Some(ca) = p.find("Column(") else {
                continue;
            };
            let Some(close) = matching_paren(p, ca) else {
                continue;
            };
            let cinner = &p[ca + 7..close];
            let col_name = split_top_level(cinner, ',')
                .first()
                .map(|c| unquote(c.trim().trim_matches(|ch: char| ch != '\'' && ch != '"')))
                .unwrap_or_default();
            if col_name.is_empty() {
                continue;
            }
            let nullable = !cinner.contains("nullable=False");
            let pk = inner.contains("PrimaryKeyConstraint") && cinner.contains(&col_name);
            table.columns.push(Column {
                name: col_name,
                ty: "UNKNOWN".into(),
                pk,
                nullable,
                fk_table: None,
                fk_col: None,
                on_delete_cascade: false,
            });
        }
        match out.iter().position(|t: &Table| t.name == table.name) {
            Some(i) => out[i] = table,
            None => out.push(table),
        }
        rest = &after[close..];
    }
    out
}

fn walk(root: &Path, dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > 8 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        if p.is_dir() {
            if matches!(
                name.as_str(),
                "node_modules" | "target" | "venv" | ".venv" | "__pycache__" | "dist" | "build" | "vendor"
            ) {
                continue;
            }
            walk(root, &p, depth + 1, out);
        } else {
            out.push(p);
        }
    }
}

/// Reload a previously indexed graph. The database graph is derived, so this
/// rebuilds rather than storing a second copy of the schema on disk.
pub fn load_schema(root: &Path) -> Result<DbGraph, String> {
    index_schema(root)
}

// ------------------------------------------------------------------- questions

/// Tables and columns nothing in the code touches.
///
/// A table nothing reads and nothing writes is a candidate for deletion. This
/// is only ever advisory: a table may be written by a job, a migration or a
/// report that is not in the workspace, so the answer says "unreferenced in
/// this workspace" and not "unused".
pub fn orphans(g: &DbGraph) -> Vec<String> {
    let mut out = Vec::new();
    for t in &g.tables {
        let touched = g.calls.iter().any(|c| table_names_match(&c.table, &t.name));
        if touched {
            continue;
        }
        // A table referenced by a foreign key is part of the schema even if no
        // code names it directly.
        let referenced = g.tables.iter().any(|other| {
            other.name != t.name && other.columns.iter().any(|c| {
                c.fk_table.as_deref().map(|f| table_names_match(f, &t.name)).unwrap_or(false)
            })
        });
        if !referenced {
            out.push(t.name.clone());
        }
    }
    out
}

/// Tables written but never read, or read but never written.
pub fn reads_only(g: &DbGraph) -> Vec<String> {
    g.tables
        .iter()
        .filter(|t| {
            let r = g
                .calls
                .iter()
                .any(|c| c.op == Op::Read && table_names_match(&c.table, &t.name));
            let w = g
                .calls
                .iter()
                .any(|c| c.op == Op::Write && table_names_match(&c.table, &t.name));
            w && !r
        })
        .map(|t| t.name.clone())
        .collect()
}

pub fn writes_only(g: &DbGraph) -> Vec<String> {
    g.tables
        .iter()
        .filter(|t| {
            let r = g
                .calls
                .iter()
                .any(|c| c.op == Op::Read && table_names_match(&c.table, &t.name));
            let w = g
                .calls
                .iter()
                .any(|c| c.op == Op::Write && table_names_match(&c.table, &t.name));
            r && !w
        })
        .map(|t| t.name.clone())
        .collect()
}

/// Foreign keys with no index on the child column.
///
/// Every such column is a table scan on join and on cascade delete. It is a
/// performance finding, not a correctness one, so it never blocks.
pub fn missing_index(g: &DbGraph) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for t in &g.tables {
        for c in &t.columns {
            if c.fk_table.is_none() {
                continue;
            }
            let indexed = t.indexes.iter().any(|i| {
                i.columns
                    .iter()
                    .any(|ic| table_names_match(ic, &c.name) || ic == &c.name)
            });
            if !indexed {
                out.push((t.name.clone(), c.name.clone()));
            }
        }
    }
    out
}

/// Column names that carry PII or credentials.
///
/// A fixed name list, deliberately. A heuristic that scores any column called
/// `name` or `data` would flag most of a schema and train the reader to ignore
/// it. Free text columns are excluded because the tool cannot judge them.
pub fn sensitive_columns(g: &DbGraph) -> Vec<(String, String, &'static str)> {
    let mut out = Vec::new();
    for t in &g.tables {
        for c in &t.columns {
            let lower = c.name.to_ascii_lowercase();
            // `is_sensitive_name` carries the list, and it classifies by suffix so
            // `user_email` is caught. Two copies of this table would drift, and a
            // drift means the policy layer and the exposure layer disagree about
            // what is sensitive.
            if !is_sensitive_name(&c.name) {
                continue;
            }
            let kind = if CREDENTIAL_COLUMNS
                .iter()
                .any(|n| lower == *n || lower.ends_with(&format!("_{}", n)))
            {
                "credential"
            } else {
                "PII"
            };
            out.push((t.name.clone(), c.name.clone(), kind));
        }
    }
    out
}

/// The subset of sensitive names that are credentials rather than personal data.
const CREDENTIAL_COLUMNS: &[&str] = &[
    "password",
    "password_hash",
    "passwd",
    "secret",
    "token",
    "api_key",
    "private_key",
    "salt",
];

/// Sensitive columns that are read or written on a line, for taint into logs and
/// responses.
pub fn sensitive_column_calls(g: &DbGraph) -> Vec<(String, String, String)> {
    let sens = sensitive_columns(g);
    let mut out = Vec::new();
    for (table, column, _kind) in sens {
        for c in &g.calls {
            if table_names_match(&c.table, &table) {
                out.push((table.clone(), column.clone(), c.via.clone()));
            }
        }
    }
    out
}

/// All tables the code touches.
pub fn touched_tables(g: &DbGraph) -> Vec<String> {
    let mut s: BTreeSet<String> = BTreeSet::new();
    for c in &g.calls {
        s.insert(c.table.clone());
    }
    s.into_iter().collect()
}

/// Columns read or written for a table, from raw SQL and from `.limit(n)`.
pub fn columns_of(g: &DbGraph, table: &str) -> Vec<String> {
    g.tables
        .iter()
        .find(|t| table_names_match(&t.name, table))
        .map(|t| t.columns.iter().map(|c| c.name.clone()).collect())
        .unwrap_or_default()
}

/// Singular/plural and case tolerant table name comparison.
///
/// ORM model names and physical table names differ by convention more often
/// than not: `User` for `users`, `OrderItem` for `order_items`. Getting this
/// wrong is the difference between a useful answer and a wrong one, so it is a
/// single named function rather than an ad hoc comparison at each call site.
pub fn table_names_match(a: &str, b: &str) -> bool {
    if a.eq_ignore_ascii_case(b) {
        return true;
    }
    normalize(a) == normalize(b)
}

/// `OrderItem` and `order_items` both normalise to `orderitem`.
pub fn normalize(name: &str) -> String {
    let mut s = String::with_capacity(name.len());
    let mut prev_lower = false;
    for c in name.chars() {
        if c == '_' || c == '-' || c == '.' || c == ' ' {
            prev_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() {
            if prev_lower {
                s.push('_');
            }
            s.push(c.to_ascii_lowercase());
            prev_lower = false;
        } else {
            s.push(c.to_ascii_lowercase());
            prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        }
    }
    s
}

/// Tables grouped by how the code reaches them, for `query tables`.
pub fn tables_report(g: &DbGraph) -> BTreeMap<String, (usize, usize)> {
    let mut out: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for t in &g.tables {
        out.entry(t.name.clone()).or_insert((0, 0));
    }
    for c in &g.calls {
        // Map onto the physical table where one is known.
        let key = g
            .tables
            .iter()
            .find(|t| table_names_match(&t.name, &c.table))
            .map(|t| t.name.clone())
            .unwrap_or_else(|| c.table.clone());
        let e = out.entry(key).or_insert((0, 0));
        match c.op {
            Op::Read => e.0 += 1,
            Op::Write => e.1 += 1,
        }
    }
    out
}

// ------------------------------------------------------ foreign key cycles

/// One closed loop in the foreign key graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cycle {
    /// The table whose column starts the loop.
    pub table: String,
    /// The column that creates the edge.
    pub column: String,
    /// Table names from the start back to the start, inclusive. Length 2 for a
    /// self reference, longer for an indirect cycle. A reader needs this path:
    /// knowing that a cycle exists is not actionable, knowing which three tables
    /// close it is.
    pub path: Vec<String>,
    /// True when the table references itself.
    pub self_referential: bool,
    /// True when the edge carries `ON DELETE CASCADE`, which is what turns a
    /// loop into a delete that can walk into itself.
    pub cascading_delete: bool,
}

/// Every foreign key cycle in the schema.
///
/// A cycle is not a defect on its own. `users.parent_id` for a category tree and
/// `employees.manager_id` are both correct and common, so this reports rather
/// than judges, and lets the caller decide. What it must never do is loop
/// forever, so the walk carries a visited set per starting table and a hard
/// bound on path length.
pub fn fk_cycles(g: &DbGraph) -> Vec<Cycle> {
    let mut out = Vec::new();

    for start in &g.tables {
        let mut path: Vec<String> = vec![start.name.clone()];
        let mut visited: Vec<String> = vec![start.name.clone()];
        walk_for_cycles(g, start, start, &mut path, &mut visited, &mut out, 0);
    }

    // Deduplicate: a two table cycle is discovered once per starting table and
    // per direction, and a reader wants it once.
    out.sort_by(|a, b| {
        a.table
            .cmp(&b.table)
            .then(a.column.cmp(&b.column))
            .then(a.path.cmp(&b.path))
    });
    out.dedup_by(|a, b| a.table == b.table && a.column == b.column && a.path == b.path);
    out
}

const MAX_CYCLE_DEPTH: usize = 12;

fn walk_for_cycles(
    g: &DbGraph,
    start: &Table,
    at: &Table,
    path: &mut Vec<String>,
    visited: &mut Vec<String>,
    out: &mut Vec<Cycle>,
    depth: usize,
) {
    if depth > MAX_CYCLE_DEPTH || out.len() > 512 {
        return;
    }
    for col in &at.columns {
        let Some(target) = col.fk_table.as_deref() else {
            continue;
        };
        // Resolve by name, tolerating singular/plural differences.
        let Some(next) = g
            .tables
            .iter()
            .find(|t| table_names_match(&t.name, target))
        else {
            continue;
        };

        let self_ref = table_names_match(&next.name, &start.name);
        if self_ref && col.fk_table.is_some() {
            // Only a self reference, not every edge pointing at the start.
            out.push(Cycle {
                table: at.name.clone(),
                column: col.name.clone(),
                path: vec![at.name.clone(), next.name.clone()],
                self_referential: true,
                cascading_delete: col.on_delete_cascade,
            });
        }

        if visited.iter().any(|v| table_names_match(v, &next.name)) {
            // The walk has closed a loop. The cycle is recorded from the table
            // where the loop began, not from wherever the walk happened to start:
            // walking `employees -> companies -> companies` and only recording a
            // loop that returns to `employees` loses the cycle entirely, because
            // it closes at `companies`.
            //
            // A diamond also lands here, on the second visit to the shared
            // ancestor, and that is not a loop. The distinction is whether the
            // edge that closes it is an edge the walk already took: on a diamond
            // the closing node was reached by a different edge and the path
            // between them contains no repeat, so the slice below collapses to a
            // single node and nothing is recorded.
            let begin = path
                .iter()
                .position(|p| table_names_match(p, &next.name))
                .unwrap_or(0);
            let mut cycle_path: Vec<String> = path[begin..].to_vec();
            cycle_path.push(next.name.clone());
            // A real loop has at least two edges, so the path has at least two
            // nodes and its first and last match. A diamond produces a path of
            // one repeated node with a distinct entry point, which fails the
            // length test and is correctly not recorded.
            let closes = cycle_path.len() >= 2
                && table_names_match(&cycle_path[0], cycle_path.last().unwrap());
            if closes {
                out.push(Cycle {
                    table: cycle_path[0].clone(),
                    column: if table_names_match(&at.name, &cycle_path[0]) {
                        col.name.clone()
                    } else {
                        // The closing edge belongs to the last distinct table.
                        at.columns
                            .iter()
                            .find(|c| {
                                c.fk_table
                                    .as_deref()
                                    .map(|f| table_names_match(f, &next.name))
                                    .unwrap_or(false)
                            })
                            .map(|c| c.name.clone())
                            .unwrap_or_else(|| col.name.clone())
                    },
                    path: cycle_path,
                    self_referential: false,
                    cascading_delete: col.on_delete_cascade,
                });
            }
            continue;
        }

        path.push(next.name.clone());
        visited.push(next.name.clone());
        walk_for_cycles(g, start, next, path, visited, out, depth + 1);
        path.pop();
        visited.pop();
    }
}

/// Cycles whose edges cascade on delete. This is the dangerous subset: a
/// mutual `ON DELETE CASCADE` can recurse into itself, and a self reference with
/// `CASCADE` deletes the whole subtree in one statement.
pub fn cyclic_cascades(g: &DbGraph) -> Vec<Cycle> {
    fk_cycles(g)
        .into_iter()
        .filter(|c| c.cascading_delete)
        .collect()
}

// ------------------------------------------------------------------ policies

/// One policy finding against a schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyFinding {
    /// Stable machine-readable kind, so a caller can gate on it.
    pub kind: String,
    pub table: String,
    pub column: String,
    pub message: String,
    /// `critical`, `warning` or `info`. Nothing in the database layer blocks on
    /// its own; the caller decides, which is why `critical` here means "a human
    /// should look" rather than "fail the build".
    pub severity: String,
}

/// A sensitive column that a read path can reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exposure {
    pub table: String,
    pub column: String,
    pub kind: &'static str,
    pub via: String,
}

/// Sensitive columns that a read in the code can reach.
///
/// The direction matters and is the whole point: writing a credential into a
/// column is normal, reading one back out is the exposure. Only `Op::Read`
/// call sites count.
pub fn sensitive_exposure(g: &DbGraph) -> Vec<Exposure> {
    let mut out = Vec::new();
    for (table, column, kind) in sensitive_columns(g) {
        for c in &g.calls {
            if c.op != Op::Read || !table_names_match(&c.table, &table) {
                continue;
            }
            out.push(Exposure {
                table: table.clone(),
                column: column.clone(),
                kind,
                via: c.via.clone(),
            });
        }
    }
    out
}

/// Tables written but never read in this workspace.
///
/// Advisory only. A table may be written by a job or a report outside the
/// workspace, so the answer is "write-only here" and never "unused".
pub fn write_only(g: &DbGraph) -> Vec<String> {
    g.tables
        .iter()
        .filter(|t| {
            let reads = g
                .calls
                .iter()
                .any(|c| c.op == Op::Read && table_names_match(&c.table, &t.name));
            let writes = g
                .calls
                .iter()
                .any(|c| c.op == Op::Write && table_names_match(&c.table, &t.name));
            writes && !reads
        })
        .map(|t| t.name.clone())
        .collect()
}

/// Every policy finding, sorted so output is deterministic.
pub fn policy_findings(g: &DbGraph) -> Vec<PolicyFinding> {
    let mut out = Vec::new();

    for t in &g.tables {
        let has_pk = t.columns.iter().any(|c| c.pk);
        if !has_pk {
            out.push(PolicyFinding {
                kind: "no_primary_key".into(),
                table: t.name.clone(),
                column: String::new(),
                message: format!(
                    "{} has no primary key, so rows cannot be addressed or deduplicated",
                    t.name
                ),
                severity: "warning".into(),
            });
        }

        for c in &t.columns {
            // A nullable sensitive column has no required value, which in
            // practice means the field is often left empty and the column is
            // treated as optional when it should not be.
            if c.nullable && is_sensitive_name(&c.name) {
                out.push(PolicyFinding {
                    kind: "nullable_sensitive".into(),
                    table: t.name.clone(),
                    column: c.name.clone(),
                    message: format!(
                        "{}.{} holds sensitive data but is nullable",
                        t.name, c.name
                    ),
                    severity: "warning".into(),
                });
            }
            if let Some(target) = c.fk_table.as_deref() {
                let indexed = t.indexes.iter().any(|i| {
                    i.columns
                        .iter()
                        .any(|ic| table_names_match(ic, &c.name) || ic == &c.name)
                });
                if !indexed {
                    out.push(PolicyFinding {
                        kind: "unindexed_foreign_key".into(),
                        table: t.name.clone(),
                        column: c.name.clone(),
                        message: format!(
                            "{}.{} references {} with no index, so every join and cascade scans",
                            t.name, c.name, target
                        ),
                        severity: "warning".into(),
                    });
                }
            }
        }
    }

    // A self reference with no index is a full table scan on every level of the
    // tree walk, and it is the shape most often introduced by a self join.
    for c in fk_cycles(g) {
        if c.self_referential {
            let indexed = g
                .tables
                .iter()
                .find(|t| t.name == c.table)
                .map(|t| {
                    t.indexes.iter().any(|i| {
                        i.columns
                            .iter()
                            .any(|ic| table_names_match(ic, &c.column) || ic == &c.column)
                    })
                })
                .unwrap_or(false);
            if !indexed {
                out.push(PolicyFinding {
                    kind: "unindexed_self_reference".into(),
                    table: c.table.clone(),
                    column: c.column.clone(),
                    message: format!(
                        "{}.{} is a self reference with no index; every level of the tree is a table scan",
                        c.table, c.column
                    ),
                    severity: "critical".into(),
                });
            }
        }
    }

    out.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then(a.table.cmp(&b.table))
            .then(a.column.cmp(&b.column))
    });
    out.dedup();
    out
}

/// Whether a column name carries PII or credentials, using the same fixed table
/// `sensitive_columns` uses so the two can never disagree.
fn is_sensitive_name(name: &str) -> bool {
    const RULES: &[&str] = &[
        "email", "e_mail", "phone", "mobile", "ssn", "social_security",
        "national_id", "passport", "dob", "date_of_birth", "birthdate",
        "address", "street", "postcode", "zip", "latitude", "longitude",
        "ip_address", "credit_card", "card_number", "cvv", "pan", "password",
        "password_hash", "passwd", "secret", "token", "api_key",
        "private_key", "salt",
    ];
    let lower = name.to_ascii_lowercase();
    RULES
        .iter()
        .any(|r| lower == *r || lower.ends_with(&format!("_{}", r)))
}

/// Everything the database layer can say about a workspace, in one value.
///
/// This is the shape a CLI, an MCP tool or `verify` consumes, so the question
/// "is this schema sound" has one answer rather than five partial ones.
#[derive(Debug, Clone, Default)]
pub struct SchemaVerdict {
    pub tables: usize,
    pub cycles: Vec<Cycle>,
    /// True when a cycle is present that is not merely informational, meaning an
    /// unindexed self reference or a cascading delete.
    pub cycles_blocking: bool,
    pub policies: Vec<PolicyFinding>,
    pub sensitive_exposed: Vec<Exposure>,
    pub orphans: Vec<String>,
    pub missing_indexes: Vec<(String, String)>,
    pub write_only: Vec<String>,
}

impl SchemaVerdict {
    /// One boolean a caller can branch on.
    pub fn ok(&self) -> bool {
        !self.cycles_blocking && !self.policies.iter().any(|p| p.severity == "critical")
    }

    /// One line per fact, no prose, matching the house style.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("tables {}\n", self.tables));
        if self.cycles.is_empty() {
            out.push_str("foreign key cycles  none\n");
        } else {
            out.push_str(&format!("foreign key cycles {}\n", self.cycles.len()));
            for c in &self.cycles {
                out.push_str(&format!(
                    "  {}.{} -> {}{}\n",
                    c.table,
                    c.column,
                    c.path.join(" -> "),
                    if c.cascading_delete {
                        "  [ON DELETE CASCADE]"
                    } else {
                        ""
                    }
                ));
            }
        }
        if self.sensitive_exposed.is_empty() {
            out.push_str("sensitive reads  none\n");
        } else {
            for e in &self.sensitive_exposed {
                out.push_str(&format!(
                    "  {}.{} ({}) via {}\n",
                    e.table, e.column, e.kind, e.via
                ));
            }
        }
        if !self.missing_indexes.is_empty() {
            for (t, c) in &self.missing_indexes {
                out.push_str(&format!("  unindexed fk  {}.{}\n", t, c));
            }
        }
        for p in &self.policies {
            out.push_str(&format!("  [{}] {}\n", p.severity, p.message));
        }
        if !self.orphans.is_empty() {
            out.push_str(&format!("orphans {}\n", self.orphans.join(", ")));
        }
        if !self.write_only.is_empty() {
            out.push_str(&format!("write only {}\n", self.write_only.join(", ")));
        }
        if self.ok() {
            out.push_str("schema OK");
        } else {
            out.push_str("schema has findings");
        }
        out
    }
}

/// Build the whole verdict for a workspace.
pub fn verify_schema(g: &DbGraph) -> SchemaVerdict {
    let cycles = fk_cycles(g);
    let cascades = cyclic_cascades(g);
    let cycles_blocking = !cascades.is_empty()
        || policy_findings(g)
            .iter()
            .any(|p| p.kind == "unindexed_self_reference");
    SchemaVerdict {
        tables: g.tables.len(),
        cycles,
        cycles_blocking,
        policies: policy_findings(g),
        sensitive_exposed: sensitive_exposure(g),
        orphans: orphans(g),
        missing_indexes: missing_index(g),
        write_only: write_only(g),
    }
}

/// The workspace root, given a command line where flags and subcommands are
/// interleaved with the path.
///
/// A positional argument that is not a flag and not a known subcommand is the
/// root, which is what makes `heides db tables .` and `heides db tables` both
/// work.
pub fn root_from_args(args: &[String], skip: usize) -> PathBuf {
    for a in args.iter().skip(skip) {
        if a.starts_with('-') {
            continue;
        }
        if matches!(
            a.as_str(),
            "tables"
                | "columns"
                | "reads"
                | "writes"
                | "orphans"
                | "missingindex"
                | "policies"
                | "cycles"
                | "sensitive"
                | "schema"
        ) {
            continue;
        }
        return PathBuf::from(a);
    }
    PathBuf::from(".")
}

// ------------------------------------------------------------ N+1 candidates

/// A query that appears to run once per row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NPlusOne {
    pub table: String,
    pub file: String,
    pub line: u64,
    pub reason: String,
    pub suggestion: String,
}

/// Spellings that batch the query and therefore make the pattern correct.
const BATCH_MARKERS: &[&str] = &[
    "in_", "__in", "in(", " in (", " in(", "wherein", "where_in", "bulk_",
    "bulkcreate", "bulk_create", "insertmany", "insert_many", "batch",
    "fetchallatonce", "findmanyin", "in: ids", "in: [",
];

/// True when this line batches rather than querying per row.
///
/// Checked on the line and the one before it, because the batch spelling often
/// appears in the preceding call of a chained expression.
fn is_batched(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    BATCH_MARKERS.iter().any(|m| lower.contains(m))
}

/// True when this line contains a query call at all.
fn has_query_call(line: &str) -> bool {
    const CALLS: &[&str] = &[
        "query(",
        "objects.",
        "findone(",
        "findmany(",
        "findoneby",
        ".first(",
        ".last(",
        ".get(",
        ".count(",
        ".all(",
        ".exists(",
        ".one(",
        ".scalar(",
        "executemany",
        ".exec(",
        "prisma.",
        "_db.",
        ".where(",
        ".filter(",
        ".find(",
        ".select(",
    ];
    let lower = line.to_ascii_lowercase();
    CALLS.iter().any(|c| lower.contains(c))
}

/// Indentation width of a line, counting leading spaces and tabs alike.
fn indent_of(line: &str) -> usize {
    line.chars()
        .take_while(|c| *c == ' ' || *c == '\t')
        .count()
}

/// True when the line opens a loop: a `for`, `while`, `forEach`, `for..of`, or a
/// comprehension that iterates something.
fn is_loop_header(line: &str) -> bool {
    let t = line.trim_start();
    let lower = t.to_ascii_lowercase();
    if lower.starts_with("for ")
        || lower.starts_with("for(")
        || lower.starts_with("for[")
        // `for await (const x of xs)` and the parenless `for const x of xs {`,
        // which is what prettier emits and is valid JavaScript.
        || lower.starts_with("for await")
        || lower.starts_with("for const")
        || lower.starts_with("for let")
        || lower.starts_with("for var")
        || lower.starts_with("while ")
        || lower.starts_with("while(")
        || lower.starts_with(".for_each")
        || lower.contains(" for ")
        || lower.contains(".map(")
        || lower.contains("for (")
    {
        return true;
    }
    false
}

/// True when the line is a comprehension, where the query runs once per item
/// even though there is no block body.
fn is_comprehension(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("[session.query")
        || lower.contains("[self.repo.")
        || lower.contains("[prisma.")
        || (lower.contains(" for ") && lower.contains('[') && has_query_call(line))
}

/// N+1 candidates in one file.
///
/// Syntactic and approximate by construction: it reports the unambiguous shapes
/// and stays silent everywhere else. A tool that flags every loop in a codebase
/// is not usable, so the negative cases matter as much as the positive ones and
/// the batch spellings are named explicitly rather than left to inference.
pub fn n_plus_one_candidates(path: &Path, body: &str) -> Vec<NPlusOne> {
    let file = path.to_string_lossy().to_string();
    let lines: Vec<&str> = body.lines().collect();
    let mut out: Vec<NPlusOne> = Vec::new();

    // Indentation of every open loop header. The header is recorded before any
    // query test runs, because the earlier version pushed it at the end of the
    // body behind a `continue`, so the stack was never populated and every loop
    // in every file was invisible.
    let mut loop_stack: Vec<usize> = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        let n = idx + 1;
        let trimmed = line.trim();
        let ind = indent_of(line);

        // A dedent to or below a header's indentation closes it. A blank line
        // does not, because a loop body often contains one.
        while let Some(top) = loop_stack.last().copied() {
            if !trimmed.is_empty() && ind <= top {
                loop_stack.pop();
            } else {
                break;
            }
        }

        let mut in_loop = !loop_stack.is_empty();
        let comprehension = is_comprehension(line);
        let header = is_loop_header(trimmed);

        if header && !comprehension {
            loop_stack.push(ind);
            // A header is the outer fetch, never the defect.
            continue;
        }
        // A single line comprehension is its own header and its own body, so it
        // opens no scope: there is no indented block following it.
        if header && comprehension {
            in_loop = true;
        }

        if !in_loop && !comprehension {
            continue;
        }
        if !has_query_call(trimmed) {
            continue;
        }
        // The batch spellings are the correct answer to this exact question.
        if is_batched(trimmed) {
            continue;
        }
        if trimmed == "pass" || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }

        let calls = scan_calls(path, line);
        // A receiver name is not a table. `session.query(Order)` also produces a
        // call for the accessor itself, and reporting a table called `query`
        // alongside `Order` is noise that hides the real finding.
        const NOT_TABLES: &[&str] = &[
            "query", "session", "conn", "connection", "cursor", "cur", "db",
            "objects", "manager", "where", "table", "repo", "repository",
            "em", "client", "store", "context", "ctx", "tx",
        ];
        let mut tables: Vec<String> = calls
            .iter()
            .filter(|c| c.op == Op::Read || c.op == Op::Write)
            .filter(|c| !NOT_TABLES.contains(&c.table.to_ascii_lowercase().as_str()))
            .map(|c| c.table.clone())
            .collect();
        tables.sort();
        tables.dedup();

        let reason = if comprehension {
            "query inside a comprehension runs once per item"
        } else {
            "query inside a loop runs once per row"
        };
        let suggestion =
            "fetch the related rows in one query with an IN clause, or preload the relation"
                .to_string();

        if tables.is_empty() {
            out.push(NPlusOne {
                table: String::new(),
                file: file.clone(),
                line: n as u64,
                reason: reason.to_string(),
                suggestion: suggestion.clone(),
            });
        }
        for t in &tables {
            out.push(NPlusOne {
                table: t.clone(),
                file: file.clone(),
                line: n as u64,
                reason: reason.to_string(),
                suggestion: suggestion.clone(),
            });
        }
    }

    out
}

/// N+1 candidates across a workspace, from the code files the schema walk reads.
pub fn n_plus_one_in_workspace(root: &Path) -> Vec<NPlusOne> {
    let mut out = Vec::new();
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    collect_code_files(root, root, 0, &mut files);
    files.sort();
    for p in files {
        if let Ok(body) = std::fs::read_to_string(&p) {
            for mut c in n_plus_one_candidates(&p, &body) {
                c.file = p
                    .strip_prefix(root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push(c);
            }
        }
    }
    out
}

fn collect_code_files(root: &Path, dir: &Path, depth: usize, out: &mut Vec<std::path::PathBuf>) {
    if depth > 8 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        if p.is_dir() {
            if matches!(
                name.as_str(),
                "node_modules" | "target" | "venv" | ".venv" | "__pycache__" | "dist"
                    | "build" | "vendor"
            ) {
                continue;
            }
            collect_code_files(root, &p, depth + 1, out);
        } else if matches!(
            p.extension()
                .map(|e| e.to_string_lossy().to_string())
                .unwrap_or_default()
                .as_str(),
            "py" | "ts" | "tsx" | "js" | "jsx" | "go" | "rb" | "cs" | "php" | "java" | "kt"
        ) {
            out.push(p);
        }
    }
}
