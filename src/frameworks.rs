// Framework route recognition.
//
// A function nobody calls inside the workspace looks like a dead root, but in a
// web app the router calls it. The audit found Express handlers listed as
// uncalled roots, which is a false claim about live code.
//
// The recognition is deliberately cheap: a scan of the files that already have
// module level code, looking for a route registration and the handler name in
// the argument list. It runs at describe time on purpose, so no index schema
// moves and reindexing stays exactly as cheap as before. The roadmap suggests
// storing this as a flag on the symbol; that is an optimisation to add if
// describe ever becomes hot, not a correctness requirement.

use std::collections::HashSet;
use std::path::Path;

/// A file is scanned only up to this size, and at most this many files, so a
/// describe on a huge tree stays bounded.
const MAX_FILE_BYTES: usize = 256 * 1024;
const MAX_FILES: usize = 400;

/// Receivers that mean "this call registers a route" in JavaScript land.
const JS_ROUTERS: &[&str] = &[
    "app", "router", "server", "api", "fastify", "route", "routes", "auth", "v1", "v2",
];
/// The method names that register a route.
const JS_VERBS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "del", "head", "options", "all", "use", "route",
];
/// Python decorators and Go handlers.
const PY_DECORATORS: &[&str] = &[
    "app.route",
    "blueprint.route",
    "bp.route",
    "router.route",
    "add_url_rule",
    "path",
    "re_path",
];
const GO_HANDLERS: &[&str] = &["http.HandleFunc", "mux.HandleFunc", "HandleFunc"];

/// Handler names registered as routes in the given files.
pub fn route_handlers(root: &Path, files: &[&str]) -> HashSet<String> {
    let mut out = HashSet::new();
    for f in files.iter().take(MAX_FILES) {
        let path = root.join(f);
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if meta.len() as usize > MAX_FILE_BYTES {
            continue;
        }
        let Ok(body) = std::fs::read_to_string(&path) else {
            continue;
        };
        let lang = crate::parser::detect_language(&path);
        match lang.as_deref().unwrap_or("") {
            "javascript" | "typescript" => scan_js(&body, &mut out),
            "python" => scan_python(&body, &mut out),
            "go" => scan_go(&body, &mut out),
            _ => {}
        }
    }
    out
}

fn scan_js(body: &str, out: &mut HashSet<String>) {
    for line in body.lines() {
        let trimmed = line.trim_start();
        // app.get("/users", listUsers) or app.get("/users", auth, listUsers)
        for router in JS_ROUTERS {
            for verb in JS_VERBS {
                for prefix in [format!("{router}.{verb}("), format!("{router}[{verb}](")] {
                    let Some(start) = trimmed.find(&prefix) else {
                        continue;
                    };
                    let args = &trimmed[start + prefix.len()..];
                    collect_handlers(args, out);
                }
            }
        }
    }
}

fn scan_python(body: &str, out: &mut HashSet<String>) {
    let lines: Vec<&str> = body.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        // urlpatterns entries: path("x/<int:id>", view), anywhere in the line
        for name in ["path(", "re_path("] {
            let mut from = 0usize;
            while let Some(found) = trimmed[from..].find(name) {
                let at = from + found;
                let boundary_ok = at == 0
                    || !trimmed[..at]
                        .chars()
                        .next_back()
                        .map(|c| c.is_alphanumeric() || c == '_')
                        .unwrap_or(false);
                if boundary_ok {
                    collect_handlers(&trimmed[at + name.len() - 1..], out);
                }
                from = at + name.len();
            }
        }
        if !trimmed.starts_with('@') {
            continue;
        }
        let routed = PY_DECORATORS
            .iter()
            .any(|deco| trimmed.starts_with(&format!("@{deco}")));
        if !routed {
            continue;
        }
        // The handler of a decorated view is the def below it, not an argument.
        for next in lines.iter().skip(i + 1) {
            let n = next.trim_start();
            if n.is_empty() || n.starts_with('@') {
                continue;
            }
            if let Some(name) = n
                .strip_prefix("async def ")
                .or_else(|| n.strip_prefix("def "))
            {
                let bare: String = name
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if !bare.is_empty() {
                    out.insert(bare);
                }
            }
            break;
        }
    }
}

fn scan_go(body: &str, out: &mut HashSet<String>) {
    for line in body.lines() {
        let trimmed = line.trim_start();
        for h in GO_HANDLERS {
            if let Some(start) = trimmed.find(h) {
                let args = &trimmed[start + h.len()..];
                collect_handlers(args, out);
            }
        }
    }
}

/// Pull the handler out of a route registration. Only the last bare
/// identifier argument counts, because in Express the handler comes after any
/// middleware, and a path or an inline closure is not a named handler.
fn collect_handlers(args: &str, out: &mut HashSet<String>) {
    let trimmed = args.trim_start();
    let inner = match trimmed.strip_prefix('(') {
        Some(rest) => rest,
        None => trimmed,
    };
    // The closing paren of the call, at depth zero from here.
    let mut depth = 0i32;
    let mut end = inner.len();
    for (i, ch) in inner.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                if depth == 0 {
                    end = i;
                    break;
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    let inner = &inner[..end];
    let mut parts: Vec<String> = vec![];
    let mut depth = 0i32;
    let mut current = String::new();
    for ch in inner.chars() {
        match ch {
            '(' | '[' | '{' => {
                depth += 1;
                current.push(ch);
            }
            ')' | ']' | '}' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => parts.push(std::mem::take(&mut current)),
            _ => current.push(ch),
        }
    }
    parts.push(current);
    for part in parts.iter().rev() {
        let candidate = part
            .trim()
            .trim_start_matches("async ")
            .split('=')
            .next()
            .unwrap_or("")
            .trim();
        if !is_identifier(candidate) || candidate.len() < 2 || candidate.len() > 64 {
            continue;
        }
        let bare = candidate.rsplit('.').next().unwrap_or(candidate);
        if is_identifier(bare) {
            out.insert(bare.to_string());
            return;
        }
    }
}

fn is_identifier(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
        && !text.chars().next().unwrap().is_ascii_digit()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(set: &HashSet<String>) -> Vec<&str> {
        let mut v: Vec<&str> = set.iter().map(|s| s.as_str()).collect();
        v.sort();
        v
    }

    #[test]
    fn express_routes_are_handlers() {
        let mut out = HashSet::new();
        scan_js(
            "app.get(\"/user/:id\", findUser);\nrouter.post(\"/orders\", auth, createOrder);\n",
            &mut out,
        );
        assert_eq!(names(&out), vec!["createOrder", "findUser"]);
    }

    #[test]
    fn inline_closures_and_paths_are_not_named_handlers() {
        let mut out = HashSet::new();
        scan_js(
            "app.get(\"/inline\", (req, res) => { res.send(1); });\napp.get(\"/x\", \"/y\");\n",
            &mut out,
        );
        assert!(out.is_empty(), "{:?}", out);
    }

    #[test]
    fn python_decorators_and_urlpatterns() {
        let mut out = HashSet::new();
        scan_python(
            "@app.route(\"/items\")\ndef list_items():\n    pass\n\nurlpatterns = [path(\"items/<int:id>\", item_detail)]\n",
            &mut out,
        );
        assert_eq!(names(&out), vec!["item_detail", "list_items"]);
        // A name that merely ends in path must not become a route.
        let mut noise = HashSet::new();
        scan_python("x = filepath_get(\"/a\")\n", &mut noise);
        assert!(noise.is_empty(), "{:?}", noise);
    }

    #[test]
    fn go_handlers() {
        let mut out = HashSet::new();
        scan_go("http.HandleFunc(\"/health\", healthHandler)\n", &mut out);
        assert_eq!(names(&out), vec!["healthHandler"]);
    }
}

// ------------------------------------------------- the API surface graph

/// One recognised route: method, path, handler, and where it was registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub method: String,
    pub path: String,
    pub handler: String,
    pub file: String,
    pub line: u64,
}

/// Recognise routes with their method and path, not just the handler name.
///
/// `route_handlers` answers "is this function a route", which is all the
/// dead-root check needs. The API surface needs more: which method reaches a
/// table is a different question from whether a table is written at all, so the
/// method and path travel with the handler rather than being discarded here.
pub fn endpoints(files: &[String], root: &Path) -> Vec<Endpoint> {
    let mut out: Vec<Endpoint> = Vec::new();
    let mut seen: std::collections::HashSet<(String, String, String)> =
        std::collections::HashSet::new();
    for f in files.iter().take(MAX_FILES) {
        let path = root.join(f);
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if meta.len() as usize > MAX_FILE_BYTES {
            continue;
        }
        let Ok(body) = std::fs::read_to_string(&path) else {
            continue;
        };
        let mut here: Vec<Endpoint> = Vec::new();
        let lang = crate::parser::detect_language(&path);
        match lang.as_deref().unwrap_or("") {
            "javascript" | "typescript" => scan_js_endpoints(&body, f, &mut here),
            "python" => scan_python_endpoints(&body, f, &mut here),
            "go" => scan_go_endpoints(&body, f, &mut here),
            _ => {}
        }
        for e in here {
            let key = (e.method.clone(), e.path.clone(), e.handler.clone());
            if seen.insert(key) {
                out.push(e);
            }
        }
    }
    out.sort_by(|a, b| {
        a.path.cmp(&b.path)
            .then(a.method.cmp(&b.method))
            .then(a.handler.cmp(&b.handler))
    });
    out
}

fn scan_js_endpoints(body: &str, file: &str, out: &mut Vec<Endpoint>) {
    for (i, line) in body.lines().enumerate() {
        let trimmed = line.trim_start();
        for router in JS_ROUTERS {
            for verb in JS_VERBS {
                for prefix in [format!("{router}.{verb}("), format!("{router}[{verb}](")] {
                    let Some(start) = trimmed.find(&prefix) else {
                        continue;
                    };
                    let args = &trimmed[start + prefix.len()..];
                    let Some((route_path, handler)) = split_route_args(args) else {
                        continue;
                    };
                    out.push(Endpoint {
                        method: verb.to_ascii_uppercase(),
                        path: normalize_route_path(&route_path),
                        handler,
                        file: file.to_string(),
                        line: (i + 1) as u64,
                    });
                }
            }
        }
    }
}

/// Split a route registration's arguments into the path and the handler.
///
/// The handler is the last bare identifier, because in Express it comes after
/// any middleware, while the path is the first string literal. Both are
/// required: a registration with no recognisable path is not something to
/// report, since inventing one would put a wrong answer in an agent's hands.
fn split_route_args(args: &str) -> Option<(String, String)> {
    let trimmed = args.trim_start();
    let inner = trimmed.strip_prefix('(').unwrap_or(trimmed);
    let (inner, _) = balanced_slice(inner);
    let parts = split_top_level(inner);

    let path = parts.iter().find_map(|p| {
        let t = p.trim();
        for quote in ['\'', '"', '`'] {
            if let Some(rest) = t.strip_prefix(quote) {
                if let Some(end) = rest.find(quote) {
                    return Some(rest[..end].to_string());
                }
            }
        }
        None
    })?;

    // Walk backwards for the handler, skipping a bare string and an inline
    // arrow or function expression.
    for part in parts.iter().rev() {
        let candidate = part
            .trim()
            .trim_start_matches("async ")
            .split('=')
            .next()
            .unwrap_or("")
            .trim();
        if candidate.contains("=>") || candidate.contains("function") {
            continue;
        }
        if candidate.starts_with('\'') || candidate.starts_with('"') {
            continue;
        }
        if !is_identifier(candidate) {
            continue;
        }
        let bare = candidate.rsplit('.').next().unwrap_or(candidate);
        if is_identifier(bare) {
            return Some((path, bare.to_string()));
        }
    }
    None
}

fn scan_python_endpoints(body: &str, file: &str, out: &mut Vec<Endpoint>) {
    let lines: Vec<&str> = body.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();

        // urlpatterns: path("x/<int:id>", view)
        for name in ["path(", "re_path("] {
            let mut from = 0usize;
            while let Some(found) = trimmed[from..].find(name) {
                let at = from + found;
                let boundary_ok = at == 0
                    || !trimmed[..at]
                        .chars()
                        .next_back()
                        .map(|c| c.is_ascii_alphanumeric() || c == '_')
                        .unwrap_or(false);
                if boundary_ok {
                    if let Some(args) = trimmed[at + name.len() - 1..].strip_prefix('(') {
                        if let Some((p, handler)) = split_route_args(args) {
                            out.push(Endpoint {
                                method: "ANY".to_string(),
                                path: normalize_django_path(&p),
                                handler,
                                file: file.to_string(),
                                line: (i + 1) as u64,
                            });
                        }
                    }
                }
                from = at + name.len();
            }
        }

        if !trimmed.starts_with('@') {
            continue;
        }
        let deco = PY_DECORATORS
            .iter()
            .find(|deco| trimmed.starts_with(&format!("@{deco}")));
        let Some(deco) = deco else { continue };

        // A decorator's own arguments carry the path and the method list.
        let open = match trimmed.find('(') {
            Some(at) => at,
            None => continue,
        };
        let (args, _) = balanced_slice(&trimmed[open + 1..]);
        let (path, method) = decorator_route(args, deco);
        let Some(path) = path else { continue };

        // The handler of a decorated view is the def below it, not an argument.
        let mut handler: Option<String> = None;
        for next in lines.iter().skip(i + 1) {
            let n = next.trim_start();
            if n.is_empty() || n.starts_with('@') {
                continue;
            }
            if let Some(name) = n
                .strip_prefix("async def ")
                .or_else(|| n.strip_prefix("def "))
            {
                let bare: String = name
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if !bare.is_empty() {
                    handler = Some(bare);
                }
            }
            break;
        }
        if let Some(handler) = handler {
            out.push(Endpoint {
                method,
                path: normalize_django_path(&path),
                handler,
                file: file.to_string(),
                line: (i + 1) as u64,
            });
        }
    }
}

/// The path and method a Python decorator declares.
fn decorator_route(args: &str, deco: &str) -> (Option<String>, String) {
    let parts = split_top_level(args);
    let mut path: Option<String> = None;
    let mut method = "ANY".to_string();

    // @app.route("/x") has no method list; @app.get("/x") names one.
    if let Some(last) = deco.rsplit('.').next() {
        let upper = last.to_ascii_uppercase();
        if matches!(upper.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE") {
            method = upper;
        }
    }

    for part in &parts {
        let t = part.trim();
        if t.contains("methods") {
            for candidate in ["POST", "PUT", "PATCH", "DELETE", "GET"] {
                if t.to_ascii_uppercase().contains(candidate) {
                    method = candidate.to_string();
                    break;
                }
            }
            continue;
        }
        if path.is_none() {
            if let Some(rest) = t.strip_prefix('\'') {
                if let Some(end) = rest.find('\'') {
                    path = Some(rest[..end].to_string());
                }
            } else if let Some(rest) = t.strip_prefix('"') {
                if let Some(end) = rest.find('"') {
                    path = Some(rest[..end].to_string());
                }
            }
        }
    }
    (path, method)
}

fn scan_go_endpoints(body: &str, file: &str, out: &mut Vec<Endpoint>) {
    for (i, line) in body.lines().enumerate() {
        let trimmed = line.trim_start();
        for h in GO_HANDLERS {
            let Some(start) = trimmed.find(h) else { continue };
            let args = &trimmed[start + h.len()..];
            let Some((path, handler)) = split_route_args(args) else {
                continue;
            };
            out.push(Endpoint {
                method: "ANY".to_string(),
                path: normalize_route_path(&path),
                handler,
                file: file.to_string(),
                line: (i + 1) as u64,
            });
        }
    }
}

/// The content of the first balanced bracket run at the start of `text`, and
/// the index just past its close. Shared by the route splitter and the
/// decorator reader so a nested call cannot truncate an argument list.
fn balanced_slice(text: &str) -> (&str, usize) {
    let mut depth = 0i32;
    for (i, ch) in text.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                if depth == 0 {
                    return (&text[..i], i);
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    (text, text.len())
}

/// Split on commas that are not nested inside brackets.
fn split_top_level(inner: &str) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for ch in inner.chars() {
        match ch {
            '(' | '[' | '{' => {
                depth += 1;
                current.push(ch);
            }
            ')' | ']' | '}' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => parts.push(std::mem::take(&mut current)),
            _ => current.push(ch),
        }
    }
    parts.push(current);
    parts
}

/// A route path with its prefix slash kept and its trailing slash dropped, so
/// `/users`, `/users/`, and `/users` from two files do not read as two routes.
fn normalize_route_path(raw: &str) -> String {
    let mut p = raw.trim().to_string();
    while p.len() > 1 && p.ends_with('/') {
        p.pop();
    }
    if p.is_empty() {
        "/".to_string()
    } else if p.starts_with('/') {
        p
    } else {
        format!("/{p}")
    }
}

/// Django's angle-bracket converters become Express-style `:name`, so the same
/// route reads the same way whichever framework declared it.
fn normalize_django_path(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let chars: Vec<char> = raw.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '<' {
            let mut j = i + 1;
            let mut name = String::new();
            while j < chars.len() && chars[j] != '>' {
                name.push(chars[j]);
                j += 1;
            }
            // "int:id" names the converter first, then the field.
            let field = name.rsplit(':').next().unwrap_or(&name).to_string();
            if !field.is_empty() {
                out.push(':');
                out.push_str(field.trim());
            }
            i = j + 1;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    normalize_route_path(&out)
}

/// The API surface: every endpoint, and the tables each one can reach.
#[derive(Debug, Clone, Default)]
pub struct ApiSurface {
    pub endpoints: Vec<Endpoint>,
    /// Tables each endpoint reads, keyed by `METHOD path`.
    pub reads: std::collections::HashMap<String, Vec<TableReach>>,
    /// Tables each endpoint writes, keyed by `METHOD path`.
    pub writes: std::collections::HashMap<String, Vec<TableReach>>,
    /// The declared table names from the schema graph, used to map a model name
    /// back to the table it refers to.
    pub declared: Vec<String>,
}

/// One table reached from an endpoint, with the hop that reached it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TableReach {
    pub table: String,
    pub op: crate::db::Op,
    /// The function the query was found in, so the finding is grounded.
    pub via: String,
    pub file: String,
    pub line: u64,
    /// How many call hops from the handler to the query. Zero when the handler
    /// itself issues the query.
    pub depth: u64,
}

impl TableReach {
    /// The reach as a phrase, so the CLI does not print a bare number.
    pub fn depth_hop(&self) -> String {
        if self.depth == 0 {
            "in the handler itself".to_string()
        } else {
            format!("{} call hop(s) from the handler", self.depth)
        }
    }
}

impl ApiSurface {
    /// The tables an endpoint writes, deduplicated and sorted.
    ///
    /// Names are resolved against the declared schema before being returned.
    /// An ORM names a model, not a table: `prisma.user.create` touches the table
    /// `users`, and answering "user" when the table is `users` is a name the
    /// agent cannot grep, join on, or check against a migration.
    pub fn reachable_tables(&self, method: &str, path: &str) -> Vec<String> {
        self.tables_for_side(true, method, path)
    }

    fn tables_for_side(&self, writes: bool, method: &str, path: &str) -> Vec<String> {
        let key = route_key(method, path);
        let side = if writes { &self.writes } else { &self.reads };
        let mut v: Vec<String> = side
            .get(&key)
            .map(|r| {
                r.iter()
                    .map(|x| self.resolve_table(&x.table))
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v.dedup();
        v
    }

    /// The tables an endpoint reads, deduplicated and sorted.
    pub fn readable_tables(&self, method: &str, path: &str) -> Vec<String> {
        self.tables_for_side(false, method, path)
    }

    /// The declared table names, so a reached name can be mapped back to the
    /// table it means. Empty when the workspace declares no schema.
    pub fn resolve_table(&self, name: &str) -> String {
        // A repository or DAO name is a handle, not a table. `OrderRepo.create`
        // reaches the table `orders`; reporting `OrderRepo` is noise that hides
        // the real answer.
        if is_repository_handle(name) {
            let stem = repository_stem(name);
            return self.resolve_table(&stem);
        }
        if let Some(t) = self
            .declared
            .iter()
            .find(|t| crate::db::table_names_match(t, name))
        {
            return t.clone();
        }
        // Plural fallback. An ORM names a model and a model is singular where the
        // table is plural, so `prisma.user.create` has to land on `users`.
        // `table_names_match` normalises case and separators but deliberately
        // does not guess number, because in a schema `order` and `orders` can
        // both exist and guessing there would be wrong. Here the guess is safe
        // because it is only applied when an exact match already failed, and a
        // schema with both spellings is not one this feature is for.
        if let Some(t) = self
            .declared
            .iter()
            .find(|t| singular_of(t).eq_ignore_ascii_case(name))
        {
            return t.clone();
        }
        if let Some(t) = self
            .declared
            .iter()
            .find(|t| plural_of(name).eq_ignore_ascii_case(t))
        {
            return t.clone();
        }
        name.to_string()
    }
}

fn route_key(method: &str, path: &str) -> String {
    format!("{} {}", method.to_ascii_uppercase(), path)
}

/// Walk the call graph out from every handler and collect the tables reached.
///
/// `max_depth` bounds the walk. A call graph in a real repository has cycles
/// and a route file can be large, so without a bound this is a hang rather than
/// a slow answer. Six hops is enough for handler to service to repository in
/// the layouts that actually ship, and a project needing more should say so.
pub fn api_surface(
    graph: &crate::spine::CodeGraph,
    db: &crate::db::DbGraph,
    endpoints: &[Endpoint],
    max_depth: u64,
) -> ApiSurface {
    let mut surface = ApiSurface {
        endpoints: endpoints.to_vec(),
        declared: db.tables.iter().map(|t| t.name.clone()).collect(),
        ..Default::default()
    };
    if endpoints.is_empty() {
        return surface;
    }

    // A call edge records a call by name, so the walk keys on names. An index by
    // name keeps it O(edges) per hop instead of O(edges) per node.
    let mut callees: std::collections::HashMap<&str, Vec<&str>> =
        std::collections::HashMap::new();
    for edge in &graph.calls {
        callees
            .entry(edge.caller.as_str())
            .or_default()
            .push(edge.callee.as_str());
    }

    // Queries per function, resolved once rather than per endpoint.
    let mut queries_by_function: std::collections::HashMap<String, Vec<QuerySite>> =
        std::collections::HashMap::new();
    for call in &db.calls {
        // Keyed on the resolved enclosing function. A call at file scope has an
        // empty name and is not attributable to any endpoint, so it is skipped
        // rather than guessed at.
        if call.fn_name.is_empty() {
            continue;
        }
        queries_by_function
            .entry(call.fn_name.clone())
            .or_default()
            .push(QuerySite {
                table: call.table.clone(),
                op: call.op.clone(),
                file: call.file.clone(),
                line: call.line,
            });
    }

    for ep in endpoints {
        let key = route_key(&ep.method, &ep.path);
        let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
        visited.insert(ep.handler.clone());
        let mut frontier: Vec<(String, u64)> = vec![(ep.handler.clone(), 0)];

        while let Some((name, depth)) = frontier.pop() {
            if depth > max_depth {
                continue;
            }
            // A function's own queries count, not just those of its callees. The
            // handler often queries directly, and checking only callees meant the
            // most common shape, a route that touches the database itself, was
            // reported as touching nothing.
            if let Some(queries) = queries_by_function.get(name.as_str()) {
                for q in queries {
                    let reach = TableReach {
                        table: q.table.clone(),
                        op: q.op.clone(),
                        via: name.clone(),
                        file: q.file.clone(),
                        line: q.line,
                        depth,
                    };
                    if q.op == crate::db::Op::Write {
                        surface.writes.entry(key.clone()).or_default().push(reach);
                    } else {
                        surface.reads.entry(key.clone()).or_default().push(reach);
                    }
                }
            }
            if depth >= max_depth {
                continue;
            }
            let Some(next) = callees.get(name.as_str()) else {
                continue;
            };
            for callee in next.iter() {
                if visited.insert((*callee).to_string()) {
                    frontier.push(((*callee).to_string(), depth + 1));
                }
            }
        }

        // Deduplicate: the same table can be reached by several paths, and an
        // agent asking "what does this write" wants the set, not the routes.
        if let Some(v) = surface.writes.get_mut(&key) {
            v.sort();
            v.dedup();
        }
        if let Some(v) = surface.reads.get_mut(&key) {
            v.sort();
            v.dedup();
        }
    }

    surface
}

/// A query found in a function body.
struct QuerySite {
    table: String,
    op: crate::db::Op,
    file: String,
    line: u64,
}

/// The singular of a declared table name, for matching a model name.
fn singular_of(table: &str) -> String {
    let lower = table.to_ascii_lowercase();
    for suffix in ["ies"] {
        if let Some(stem) = lower.strip_suffix(suffix) {
            return format!("{stem}y");
        }
    }
    for suffix in ["ses", "xes", "zes", "ches", "shes"] {
        if let Some(stem) = lower.strip_suffix(suffix) {
            return stem.to_string();
        }
    }
    lower
        .strip_suffix("s")
        .map(|s| s.to_string())
        .unwrap_or(lower)
}

/// The plural of a model name, for matching a declared table.
fn plural_of(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with('y')
        && !lower.ends_with("ay")
        && !lower.ends_with("ey")
        && !lower.ends_with("oy")
        && !lower.ends_with("uy")
    {
        return format!("{}ies", &lower[..lower.len() - 1]);
    }
    for suffix in ["s", "x", "z", "ch", "sh"] {
        if lower.ends_with(suffix) {
            return format!("{lower}es");
        }
    }
    format!("{lower}s")
}

/// Suffixes that mark a name as a repository, DAO, or context rather than a
/// table.
const HANDLE_SUFFIXES: &[&str] = &[
    "repo", "repository", "dao", "store", "model", "entity", "mapper", "service",
];

/// True when a name is a data-access handle rather than a table.
fn is_repository_handle(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    HANDLE_SUFFIXES.iter().any(|s| {
        lower == *s || lower.strip_suffix(s).map(|stem| !stem.is_empty()).unwrap_or(false)
    })
}

/// The table a repository handle most likely names: `OrderRepo` -> `Order`.
fn repository_stem(name: &str) -> String {
    let mut stem = name.to_string();
    for suffix in HANDLE_SUFFIXES {
        if stem.to_ascii_lowercase().ends_with(suffix) && stem.len() > suffix.len() {
            stem.truncate(stem.len() - suffix.len());
            break;
        }
    }
    stem
}
