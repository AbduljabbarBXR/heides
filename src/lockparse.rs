// JSON lockfile parsers: npm, yarn, pnpm, poetry.
//
// Four formats, one shape out. Each parser's job is to produce versions and
// edges, because everything downstream needs the same two facts regardless of
// which tool wrote the file.
//
// A lockfile that cannot be read returns an error. Returning an empty graph
// would be worse than useless: the caller cannot tell "no dependencies" from
// "could not parse", and the advisory check would report a clean result for a
// project it never inspected.

use serde_json::Value;

use super::lockgraph::{LockGraph, LockNode};

/// Parse `package-lock.json` or `yarn.lock`'s JSON sibling.
///
/// Both the nested form of lockfileVersion 2 and 3 and the flat form of version
/// 1 are handled, because both are in the wild and version 1 projects have not
/// gone away. In the flat form the edges live in a `requires` field, and reading
/// only the nesting would report every package as a direct dependency, which is
/// the exact false answer this exists to prevent.
pub fn parse_package_lock(text: &str) -> Result<LockGraph, String> {
    let v: Value =
        serde_json::from_str(text).map_err(|e| format!("package-lock is not valid json: {e}"))?;
    let mut nodes: Vec<LockNode> = Vec::new();
    let mut edges: Vec<(String, String)> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut deferred: Vec<(String, String)> = Vec::new();
    // The manifest's direct dependencies, used to seed the resolve walk. Without
    // them the walk falls back to in-degree, and a direct dependency that
    // nothing else requires looks like a leaf.
    let mut direct: Vec<String> = Vec::new();

    if let Some(map) = v.get("packages").and_then(|p| p.as_object()) {
        // lockfileVersion 2 and 3: keyed by path, root first, then nested.
        for (key, entry) in map {
            // "" is the project itself, and "node_modules/x" or
            // "node_modules/a/node_modules/x" is a path, not a name.
            if key.is_empty() {
                continue;
            }
            let Some(name) = npm_name_from_path(key) else {
                continue;
            };
            let version = entry
                .get("version")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let dev = entry.get("dev").and_then(|x| x.as_bool()).unwrap_or(false);
            if !seen.insert(name.clone()) {
                continue;
            }
            nodes.push(LockNode {
                name: name.clone(),
                version,
                ecosystem: "npm",
                depth: None,
                dev,
                path: Vec::new(),
            });
            // Deferred like the flat form below: `seen` is still being filled as
            // the packages map is walked, so a child listed after its parent is
            // not in it yet and the edge would be dropped.
            if let Some(deps) = entry.get("dependencies").and_then(|d| d.as_object()) {
                for (child, _) in deps {
                    deferred.push((name.clone(), child.clone()));
                }
            }
        }
        // The root entry, keyed "", declares the project's own direct
        // dependencies. Skipping it without recording them left every direct
        // dependency looking like an unreachable leaf, because nothing pointed
        // at it. The root is not a node; its dependencies become roots instead,
        // which is what the direct set is for.
        if let Some(root) = v.get("packages").and_then(|p| p.get(""))
            && let Some(deps) = root.get("dependencies").and_then(|d| d.as_object())
        {
            for (child, _) in deps {
                direct.push(child.clone());
            }
        }
    } else if let Some(map) = v.get("dependencies").and_then(|d| d.as_object()) {
        // Edges are collected separately and applied after the walk. A v1
        // lockfile lists packages in no particular order, so a `requires` naming
        // a package further down the file found nothing yet and the edge was
        // silently dropped. That made every package in a sibling-heavy lockfile
        // look direct, which is the false answer this whole feature exists to
        // avoid.
        let mut pending: Vec<(String, String)> = Vec::new();
        for (name, entry) in map {
            walk_npm_flat(name, entry, &mut nodes, &mut pending, &mut seen, 1);
        }
        for (from, to) in pending {
            if seen.contains(&to) {
                edges.push((from, to));
            }
        }
    } else if !v.is_object() {
        return Err("package-lock has no object at the top level".to_string());
    }

    for (from, to) in deferred {
        if seen.contains(&to) {
            edges.push((from, to));
        }
    }

    let mut graph = LockGraph {
        nodes,
        edges,
        source: "package-lock.json".to_string(),
        direct,
    };
    graph.resolve();
    Ok(graph)
}

/// `node_modules/a/node_modules/b` -> `b`. The last segment is the installed
/// name, which is what an advisory is keyed on.
fn npm_name_from_path(path: &str) -> Option<String> {
    let last = path.rsplit("node_modules/").next()?.trim();
    if last.is_empty() {
        None
    } else {
        Some(last.to_string())
    }
}

/// Walk a lockfileVersion 1 entry, taking its `requires` as edges.
///
/// A `requires` value may be a range or a resolved object, and only the name
/// matters here, so a string is required and an object is skipped rather than
/// guessed at.
fn walk_npm_flat(
    name: &str,
    entry: &Value,
    nodes: &mut Vec<LockNode>,
    edges: &mut Vec<(String, String)>,
    seen: &mut std::collections::HashSet<String>,
    depth: u64,
) {
    if !seen.insert(name.to_string()) {
        return;
    }
    let version = entry
        .get("version")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let dev = entry.get("dev").and_then(|x| x.as_bool()).unwrap_or(false);
    nodes.push(LockNode {
        name: name.to_string(),
        version,
        ecosystem: "npm",
        // Provisional: the real depth comes from the edge walk, and this only
        // matters for a graph with no edges at all.
        depth: Some(depth),
        dev,
        path: Vec::new(),
    });

    let nested = entry.get("dependencies").and_then(|d| d.as_object());
    let requires = entry.get("requires").and_then(|r| r.as_object());
    if let Some(n) = nested {
        for (child, sub) in n {
            // The parent-child edge is recorded here rather than being inferred
            // from the walk. Without it a nested child is a node with no
            // incoming edge, so the resolve walk treats it as a root and reports
            // depth 1 for the whole tree.
            edges.push((name.to_string(), child.to_string()));
            walk_npm_flat(child, sub, nodes, edges, seen, depth + 1);
        }
    }
    if let Some(r) = requires {
        for (child, _) in r {
            // Unconditionally recorded. The presence check belongs to the caller,
            // after the whole walk: checking here meant a requires naming a
            // package listed further down the file was dropped, which made every
            // package in a v1 lockfile look direct.
            edges.push((name.to_string(), child.clone()));
        }
    }
}

/// Parse `yarn.lock` v1.
///
/// The format is a custom line-oriented one: a block header of comma separated
/// `name@range` specs, then indented `version` and `dependencies`. A header may
/// list several specs for one package, so all of them name the same node.
pub fn parse_yarn_lock(text: &str) -> Result<LockGraph, String> {
    let mut out = YarnState::default();
    for raw in text.lines() {
        let line = raw.trim_end();
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let t = line.trim();

        if indent == 0 && t.ends_with(':') {
            out.flush();
            let header = t.trim_end_matches(':');
            for spec in header.split(',') {
                let spec = spec.trim().trim_matches('"');
                if let Some(name) = yarn_package_name(spec) {
                    out.current.push(name);
                }
            }
            continue;
        }
        if indent == 0 {
            continue;
        }
        if let Some(rest) = t.strip_prefix("version ") {
            out.version = rest.trim().trim_matches('"').to_string();
            out.in_deps = false;
            continue;
        }
        if t == "dependencies:" {
            out.in_deps = true;
            continue;
        }
        if out.in_deps {
            let raw_name = t.split_whitespace().next().unwrap_or("").trim_matches('"');
            let name = yarn_dep_name(raw_name);
            if let Some(n) = name {
                out.deps.push(n);
            }
        }
    }
    out.flush();
    let mut edges = out.edges;
    for (from, to) in out.pending {
        if out.seen.contains(&to) {
            edges.push((from, to));
        }
    }

    let mut graph = LockGraph {
        nodes: out.nodes,
        edges,
        source: "yarn.lock".to_string(),
        direct: Vec::new(),
    };
    // Resolved here like every other parser. Returning without it left every
    // depth at None, which reads as "nothing here is reachable" rather than as
    // "the walk never ran".
    graph.resolve();
    Ok(graph)
}

/// A yarn dependency name, with a range or version stripped.
///
/// A scoped name keeps its `@`, so the split is on the second separator for
/// those and the first for everything else.
fn yarn_dep_name(raw: &str) -> Option<String> {
    yarn_package_name(raw.trim().trim_matches('"'))
}

/// The package name in a yarn spec such as `lodash@^4.17.0` or
/// `@babel/core@^7.0.0`.
///
/// A scoped name keeps its leading `@`, so the range is separated at the LAST
/// `@` rather than the first. Splitting at the first turned `@babel/core` into
/// `babel/core`, which matches no package and no advisory.
fn yarn_package_name(spec: &str) -> Option<String> {
    let s = spec.trim().trim_matches('"');
    if s.is_empty() {
        return None;
    }
    // The first @ is the scope marker, so the separator is the one after it.
    let at = if let Some(rest) = s.strip_prefix('@') {
        rest.find('@').map(|i| i + 1)
    } else {
        s.find('@')
    };
    let name = match at {
        Some(i) => &s[..i],
        None => s,
    };
    let name = name.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// The yarn block being read.
///
/// A struct rather than a closure over five locals, because a closure that
/// mutates a captured flag cannot also be called where the flag is read, and the
/// borrow checker was right to object.
#[derive(Default)]
struct YarnState {
    current: Vec<String>,
    version: String,
    deps: Vec<String>,
    in_deps: bool,
    nodes: Vec<LockNode>,
    edges: Vec<(String, String)>,
    pending: Vec<(String, String)>,
    seen: std::collections::HashSet<String>,
}

impl YarnState {
    fn flush(&mut self) {
        if self.current.is_empty() {
            return;
        }
        let name = self.current[0].clone();
        if self.seen.insert(name.clone()) {
            self.nodes.push(LockNode {
                name: name.clone(),
                version: self.version.clone(),
                ecosystem: "npm",
                depth: None,
                dev: false,
                path: Vec::new(),
            });
        }
        // Deferred for the same reason as every other format: a yarn block
        // declares its dependencies before those packages are read, and an edge
        // to a package not yet seen was being dropped.
        for d in self.deps.drain(..) {
            self.pending.push((name.clone(), d));
        }
        self.current.clear();
        self.version.clear();
        self.in_deps = false;
    }
}

/// Parse `pnpm-lock.yaml`.
///
/// A YAML subset, read line by line rather than through a YAML library: pnpm
/// writes a fixed shape, and a dependency here is one the security surface
/// cares about, so a full parser would be a large new surface for a format we
/// read four fields from.
///
/// The `packages:` section is keyed `/name@version` or
/// `/@scope/name@version`, and the `dependencies:` block under each entry is
/// the edge set.
pub fn parse_pnpm_lock(text: &str) -> Result<LockGraph, String> {
    let mut nodes: Vec<LockNode> = Vec::new();
    let mut edges: Vec<(String, String)> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    let mut in_packages = false;
    let mut current: Option<String> = None;
    let mut in_deps = false;

    for raw in text.lines() {
        if raw.trim().is_empty() {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        let t = raw.trim();

        if indent == 0 {
            in_packages = t == "packages:";
            current = None;
            in_deps = false;
            continue;
        }
        if !in_packages {
            continue;
        }
        // A package key sits at two spaces: "  /cookie@0.5.0:"
        if indent == 2 && t.ends_with(':') && !t.starts_with("dependencies") {
            let key = t.trim_end_matches(':');
            if let Some((name, version)) = pnpm_key(key) {
                if seen.insert(name.clone()) {
                    nodes.push(LockNode {
                        name: name.clone(),
                        version,
                        ecosystem: "npm",
                        depth: None,
                        dev: t.contains("dev: true"),
                        path: Vec::new(),
                    });
                }
                current = Some(name);
            }
            in_deps = false;
            continue;
        }
        if t == "dependencies:" {
            in_deps = true;
            continue;
        }
        if in_deps && indent >= 4 {
            // "      cookie: 0.5.0" or "      '@babel/core': 7.23.0". A metadata
            // key such as dev or optional sits at the same indent and is not an
            // edge; it is filtered by checking the key resolved to a package we
            // actually saw, so a typo in a key does not invent a dependency.
            if let Some((k, _)) = t.split_once(':') {
                let key = k.trim().trim_matches('\'').trim_matches('"');
                if PPNPM_META_KEYS.contains(&key) {
                    continue;
                }
                let dep = pnpm_dep_name(key);
                if let (Some(from), Some(d)) = (current.as_ref(), dep) {
                    edges.push((from.clone(), d));
                }
            }
        }
    }

    let mut graph = LockGraph {
        nodes,
        edges,
        source: "pnpm-lock.yaml".to_string(),
        direct: Vec::new(),
    };
    graph.resolve();
    Ok(graph)
}

/// `/cookie@0.5.0` or `/@babel/core@7.23.0` to `("cookie", "0.5.0")`.
fn pnpm_key(key: &str) -> Option<(String, String)> {
    let k = key.trim_start_matches('/');
    if k.is_empty() {
        return None;
    }
    // The version is the last @, except for a scoped name whose leading @ is
    // not one.
    let at = k.rfind('@')?;
    if at == 0 {
        return None;
    }
    let name = k[..at].to_string();
    let version = k[at + 1..].split('(').next().unwrap_or("").to_string();
    Some((name, version))
}

/// A pnpm dependency value can be a bare version, `1.2.3(peer@x)`, or
/// `/name@1.2.3`. Only the name is needed.
fn pnpm_dep_name(raw: &str) -> Option<String> {
    let r = raw.trim().trim_matches('\'').trim_matches('"');
    if r.is_empty() {
        return None;
    }
    if let Some(rest) = r.strip_prefix('/') {
        return pnpm_key(rest).map(|(n, _)| n);
    }
    Some(r.to_string())
}

/// Parse `poetry.lock`.
///
/// The same TOML block format as pyproject, so it goes through the project TOML
/// reader rather than a second TOML implementation.
pub fn parse_poetry_lock(text: &str) -> Result<LockGraph, String> {
    let mut nodes: Vec<LockNode> = Vec::new();
    let mut edges: Vec<(String, String)> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Split into package blocks first, then read each block on its own.
    //
    // Two passes, because a `[package.dependencies]` table belongs to the
    // package block it sits inside, and that is not the same as "the package
    // named most recently": in a real poetry.lock the table comes after the
    // owning block but the following `[[package]]` header arrives before the
    // next table, so tracking a single current name attributes every edge to
    // the wrong package. A self edge is the visible symptom.
    let lines: Vec<&str> = text.lines().collect();
    let mut blocks: Vec<(String, usize, usize)> = Vec::new(); // name, start, end
    let mut starts: Vec<usize> = Vec::new();
    for (n, raw) in lines.iter().enumerate() {
        if raw.trim() == "[[package]]" {
            starts.push(n);
        }
    }
    for (i, start) in starts.iter().enumerate() {
        let end = starts.get(i + 1).copied().unwrap_or(lines.len());
        let name = lines[*start..end]
            .iter()
            .find_map(|l| l.trim().strip_prefix("name = "))
            .map(|v| v.trim().trim_matches('"').to_string())
            .unwrap_or_default();
        if !name.is_empty() {
            blocks.push((name, *start, end));
        }
    }

    for (name, start, end) in &blocks {
        if !seen.insert(name.clone()) {
            continue;
        }
        let version = lines[*start..*end]
            .iter()
            .find_map(|l| l.trim().strip_prefix("version = "))
            .map(|v| v.trim().trim_matches('"').to_string())
            .unwrap_or_default();
        let dev = lines[*start..*end]
            .iter()
            .any(|l| l.trim().starts_with("category = ") && l.contains("dev"));
        nodes.push(LockNode {
            name: name.clone(),
            version,
            ecosystem: "pypi",
            depth: None,
            dev,
            path: Vec::new(),
        });
    }

    // Every `key = value` inside a block's `[package.dependencies]` table is an
    // edge from that block's package. Deferred because a dependency may be
    // declared in a block that comes later in the file.
    let mut pending: Vec<(String, String)> = Vec::new();
    for (name, start, end) in &blocks {
        let mut in_table = false;
        for l in &lines[*start..*end] {
            let t = l.trim();
            if t == "[package.dependencies]" {
                in_table = true;
                continue;
            }
            if t.starts_with('[') {
                in_table = false;
                continue;
            }
            if !in_table {
                continue;
            }
            if let Some((k, _)) = t.split_once('=') {
                let dep = k.trim().trim_matches('"').to_string();
                if !dep.is_empty() && &dep != name {
                    pending.push((name.clone(), dep));
                }
            }
        }
    }
    for (from, to) in pending {
        if seen.contains(&to) {
            edges.push((from, to));
        }
    }

    let mut graph = LockGraph {
        nodes,
        edges,
        source: "poetry.lock".to_string(),
        direct: Vec::new(),
    };
    graph.resolve();
    Ok(graph)
}

/// Parse `go.sum`.
///
/// Every module appears twice, once with a source hash and once with a `/go.mod`
/// hash. Counting those as two versions would make a module look like it has two
/// versions installed, so the `/go.mod` lines are skipped rather than merged.
pub fn parse_go_sum(text: &str) -> Result<LockGraph, String> {
    let mut nodes: Vec<LockNode> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for raw in text.lines() {
        let t = raw.trim();
        if t.is_empty() {
            continue;
        }
        let mut parts = t.split_whitespace();
        let Some(name) = parts.next() else { continue };
        let Some(version) = parts.next() else {
            continue;
        };
        // The go.mod hash line describes the module's own manifest, not a
        // second build of the module.
        if version.ends_with("/go.mod") {
            continue;
        }
        if !seen.insert(name.to_string()) {
            continue;
        }
        nodes.push(LockNode {
            name: name.to_string(),
            version: version.to_string(),
            ecosystem: "go",
            depth: Some(1),
            dev: false,
            path: vec![name.to_string()],
        });
    }
    Ok(LockGraph {
        nodes,
        edges: Vec::new(),
        source: "go.sum".to_string(),
        direct: Vec::new(),
    })
}

/// Parse `Gemfile.lock`.
///
/// The `specs:` section is an indented tree where a child sits under its parent,
/// so depth is read from the indentation rather than from a declared field.
pub fn parse_gemfile_lock(text: &str) -> Result<LockGraph, String> {
    let mut nodes: Vec<LockNode> = Vec::new();
    let mut edges: Vec<(String, String)> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut pending: Vec<(String, String)> = Vec::new();

    // The specs block is an indented tree: a child sits under its parent and
    // the parent is the nearest entry at a shallower indent, so the depth comes
    // from the indentation rather than from any declared field.
    //
    // Section headers are at column zero and the gems are indented, so the block
    // is entered on a zero-indent `specs:` and left on the next zero-indent
    // header. An earlier version cleared the flag on any unindented line, which
    // meant the block was left immediately and no gem was ever read.
    let mut in_specs = false;
    let mut stack: Vec<(usize, String)> = Vec::new();

    for raw in text.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();

        // The section header is indented, not at column zero, so it is matched by
        // name at any indent. An earlier version tested `indent == 0` and so never
        // entered the block, which produced an empty graph rather than a wrong
        // one. A new top-level section leaves it.
        if trimmed == "specs:" {
            in_specs = true;
            stack.clear();
            continue;
        }
        if indent == 0 {
            in_specs = false;
            stack.clear();
            continue;
        }
        if !in_specs {
            continue;
        }
        // `remote:` and `source:` sit inside GEM at a shallower indent than the
        // gems and are not packages.
        if trimmed.ends_with(':') || indent <= 2 {
            continue;
        }
        let entry = trimmed.trim_end_matches('!');
        let (name, version) = match entry.split_once(" (") {
            Some((n, v)) => (
                n.trim().to_string(),
                v.trim_end_matches(')').trim().to_string(),
            ),
            None => (entry.trim().to_string(), String::new()),
        };
        if name.is_empty() {
            continue;
        }
        stack.retain(|(w, _)| *w < indent);
        if let Some((_, parent)) = stack.last() {
            pending.push((parent.clone(), name.clone()));
        }
        if seen.insert(name.clone()) {
            nodes.push(LockNode {
                name: name.clone(),
                version,
                ecosystem: "rubygems",
                depth: None,
                dev: false,
                path: Vec::new(),
            });
        }
        stack.push((indent, name));
    }

    for (from, to) in pending {
        if seen.contains(&to) {
            edges.push((from, to));
        }
    }

    let mut graph = LockGraph {
        nodes,
        edges,
        source: "Gemfile.lock".to_string(),
        direct: Vec::new(),
    };
    graph.resolve();
    Ok(graph)
}

/// Keys that appear inside a pnpm package block but are not dependencies.
const PPNPM_META_KEYS: &[&str] = &[
    "dev",
    "optional",
    "resolution",
    "engines",
    "peer",
    "hasBin",
    "deprecated",
    "cpu",
    "os",
];
