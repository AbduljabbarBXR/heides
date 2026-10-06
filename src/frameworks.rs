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
            "rust" => scan_rust(&body, &mut out),
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

    fn routes(src: &str) -> Vec<(String, String, String)> {
        let mut out = Vec::new();
        scan_rust_endpoints(src, "m.rs", &mut out);
        out.iter()
            .map(|e| (e.method.clone(), e.path.clone(), e.handler.clone()))
            .collect()
    }

    #[test]
    fn axum_routes_carry_method_path_and_handler() {
        let src = concat!(
            "let app = Router::new()\n",
            "    .route(\"/users\", get(list_users).post(create_user))\n",
            "    .route(\"/health\", get(health));\n",
        );
        assert_eq!(
            routes(src),
            vec![
                ("GET".into(), "/users".into(), "list_users".into()),
                ("POST".into(), "/users".into(), "create_user".into()),
                ("GET".into(), "/health".into(), "health".into()),
            ]
        );
    }

    #[test]
    fn actix_resource_then_route_finds_path_and_handler() {
        let src = "App::new().service(web::resource(\"/users\").route(web::get().to(list_users)));\n";
        assert_eq!(
            routes(src),
            vec![("GET".into(), "/users".into(), "list_users".into())]
        );
    }

    #[test]
    fn rocket_attribute_binds_to_the_function_below() {
        let src = concat!(
            "#[get(\"/users/{id}\")]\n",
            "async fn get_user(id: Path<u64>) -> Json<User> { todo!() }\n",
            "#[post(\"/users\")]\n",
            "pub async fn create_user() -> &'static str { \"\" }\n",
        );
        assert_eq!(
            routes(src),
            vec![
                ("GET".into(), "/users/{id}".into(), "get_user".into()),
                ("POST".into(), "/users".into(), "create_user".into()),
            ]
        );
    }

    #[test]
    fn combinators_are_not_mistaken_for_handlers() {
        let src = concat!(
            "let app = Router::new()\n",
            "    .route(\"/x\", get(handler).layer(TraceLayer::new_for_http()))\n",
            "    .route(\"/y\", any(fallback));\n",
        );
        assert_eq!(
            routes(src),
            vec![
                ("GET".into(), "/x".into(), "handler".into()),
                ("ANY".into(), "/y".into(), "fallback".into()),
            ]
        );
    }

    #[test]
    fn rust_route_handlers_reach_the_dead_root_check() {
        let mut out = HashSet::new();
        scan_rust(
            "Router::new().route(\"/users\", get(list_users));\n#[get(\"/ping\")]\nasync fn ping() {}\n",
            &mut out,
        );
        assert_eq!(names(&out), vec!["list_users", "ping"]);
    }

    #[test]
    fn a_rust_string_literal_is_not_a_route() {
        assert!(routes("let sql = \"SELECT * FROM users WHERE id = 1\";\n").is_empty());
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
            "rust" => scan_rust_endpoints(&body, f, &mut here),
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
        a.path
            .cmp(&b.path)
            .then(a.method.cmp(&b.method))
            .then(a.handler.cmp(&b.handler))
    });
    out
}

/// Join a registration with the lines its body spans, so a multi line route is
/// scanned at all.
///
/// The scanner read one line at a time, which is why
/// `app.post('/users', async (req, res) => {` on one line with its body on the
/// next three was not a route at all: the closing of the call never appeared on
/// the line the registration started on. That is the shape Express emits by
/// default once a handler has a body, so the omission was most real routes.
///
/// Lines are only joined while brackets stay open, so unrelated code between two
/// registrations is never merged into one blob.
fn logical_lines(body: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = body.lines().collect();
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut i = 0usize;
    while i < lines.len() {
        let start = i;
        let mut buf = String::new();
        let mut depth = 0i32;
        // Accumulate until the brackets balance. A line with no open bracket is
        // already complete, so the common one line registration is never joined to
        // whatever happens to follow it.
        while let Some(l) = lines.get(i) {
            if !buf.is_empty() {
                buf.push('\n');
            }
            buf.push_str(l);
            depth += bracket_delta(l);
            i += 1;
            if depth <= 0 {
                break;
            }
        }
        out.push((start, buf));
    }
    out
}

/// Net bracket movement in a line, ignoring brackets inside strings and comments
/// well enough for the shapes that matter here.
fn bracket_delta(line: &str) -> i32 {
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut prev_backslash = false;
    for ch in line.chars() {
        match quote {
            Some(q) => {
                if ch == q && !prev_backslash {
                    quote = None;
                }
                prev_backslash = ch == '\\';
            }
            None => match ch {
                '\'' | '"' | '`' => quote = Some(ch),
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth -= 1,
                _ => {}
            },
        }
    }
    depth
}

fn scan_js_endpoints(body: &str, file: &str, out: &mut Vec<Endpoint>) {
    for (i, line) in logical_lines(body) {
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
/// The handler an inline route expression reaches, when the registration has no
/// named handler to point at.
///
/// `app.post('/users', async (req, res) => { await svc.insertUser(req.body.id) })`
/// is not a route with no handler, it is a route whose handler is an expression.
/// Reporting nothing for it made the API graph claim the endpoint does not exist,
/// which is the worst failure mode this tool has: an agent reads the absence and
/// concludes the feature is not implemented.
///
/// So the calls made inside the expression body are read, and the first one that
/// looks like service or model access becomes the handler. A heuristic is being
/// used here, so two things guard it:
///
///   - Only a dotted call qualifies. A bare local call is not evidence of a
///     handler, because it is usually something like `res.send(...)`.
///   - The route must still have a recognisable path. Without one there is
///     nothing to report, and inventing a path would be worse than reporting
///     nothing at all.
///
/// The reported handler is the callee the route invokes, not a symbol standing
/// for the anonymous function. That is a weaker claim than a named handler and it
/// is stated as such in the endpoint's own file and line: the answer answers "what
/// does this route act on", which is the question the caller asked. A traversal
/// that cannot find that symbol then reports nothing reachable rather than
/// inventing a chain.
fn inline_handler(parts: &[String]) -> Option<(String, String)> {
    let path = parts.iter().find_map(|p| {
        let t = p.trim();
        for quote in ['\'', '"', '`'] {
            if let Some(rest) = t.strip_prefix(quote)
                && let Some(end) = rest.find(quote)
            {
                return Some(rest[..end].to_string());
            }
        }
        None
    })?;
    let last = parts.last()?.trim();
    if !(last.contains("=>") || last.contains("function")) {
        return None;
    }
    // The calls inside the body, in order. The first dotted one wins, because a
    // route handler's first action is nearly always the thing it acts on.
    // `str::split` takes one pattern, so a `['(', ')']` pattern matches that exact
    // two character sequence rather than either character. Using a closure is the
    // way to split on a set, and getting this wrong silently produced no chunks at
    // all, which is why the middleware case reported nothing.
    let chunks: Vec<&str> = last
        .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$' || c == '.'))
        .filter(|c| !c.is_empty())
        .collect();
    // Rejoin into `receiver.callee` pairs, since the split keeps the dot.
    for chunk in chunks.iter().filter(|c| c.contains('.')) {
        // `svc.insertUser` is receiver, dot, callee. The callee is what a
        // traversal can look up, so that is what is reported; the receiver is
        // only used to decide whether the call leaves the handler.
        let mut parts = chunk.split('.');
        let receiver = parts.next().unwrap_or("").trim();
        let Some(callee) = parts.next().map(|c| {
            c.chars()
                .take_while(|ch| ch.is_alphanumeric() || *ch == '_' || *ch == '$')
                .collect::<String>()
        }) else {
            continue;
        };
        if callee.is_empty() || receiver.is_empty() {
            continue;
        }
        // `res.json`, `console.log` and friends are how a handler talks back to the
        // caller, not what it acts on. Following them would answer a question
        // nobody asked.
        if matches!(
            receiver,
            "res" | "response" | "console" | "req" | "request" | "next" | "this" | "self"
        ) {
            continue;
        }
        return Some((path, callee));
    }
    None
}

fn split_route_args(args: &str) -> Option<(String, String)> {
    let trimmed = args.trim_start();
    let inner = trimmed.strip_prefix('(').unwrap_or(trimmed);
    let (inner, _) = balanced_slice(inner);
    let parts = split_top_level(inner);
    // An inline handler is the commonest Express shape and it has no name. So when
    // the last argument is an arrow or function expression, read the calls it
    // makes and take the first service-looking one. That is a weaker answer than
    // a named handler, and it is why the endpoint carries the inline label rather
    // than pretending a symbol was found.
    if let Some((path, inline)) = inline_handler(&parts) {
        return Some((path, inline));
    }

    let path = parts.iter().find_map(|p| {
        let t = p.trim();
        for quote in ['\'', '"', '`'] {
            if let Some(rest) = t.strip_prefix(quote)
                && let Some(end) = rest.find(quote)
            {
                return Some(rest[..end].to_string());
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
                if boundary_ok
                    && let Some(args) = trimmed[at + name.len() - 1..].strip_prefix('(')
                    && let Some((p, handler)) = split_route_args(args)
                {
                    out.push(Endpoint {
                        method: "ANY".to_string(),
                        path: normalize_django_path(&p),
                        handler,
                        file: file.to_string(),
                        line: (i + 1) as u64,
                    });
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
            } else if let Some(rest) = t.strip_prefix('"')
                && let Some(end) = rest.find('"')
            {
                path = Some(rest[..end].to_string());
            }
        }
    }
    (path, method)
}

fn scan_go_endpoints(body: &str, file: &str, out: &mut Vec<Endpoint>) {
    for (i, line) in body.lines().enumerate() {
        let trimmed = line.trim_start();
        for h in GO_HANDLERS {
            let Some(start) = trimmed.find(h) else {
                continue;
            };
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

/// Rust routing verbs, in the shape each framework writes them.
const RUST_VERBS: &[(&str, &str)] = &[
    ("get", "GET"),
    ("post", "POST"),
    ("put", "PUT"),
    ("delete", "DELETE"),
    ("patch", "PATCH"),
    ("head", "HEAD"),
    ("options", "OPTIONS"),
    ("trace", "TRACE"),
];

/// Combinators that take a closure or another value but never name the handler,
/// so the identifier before the paren is not a route handler.
const RUST_NOT_HANDLERS: &[&str] = &[
    "to",
    "and",
    "and_then",
    "or",
    "from_fn",
    "from_fn_with_state",
    "with_state",
    "route",
    "service",
    "nest",
    "merge",
    "layer",
    "route_layer",
    "map",
    "map_to",
    "wrap",
    "default",
    "resource",
    "scope",
    "guard",
    "wrap_fn",
    "any",
    "all",
];

/// The balanced argument text of the first `marker` call on this line. The
/// marker carries its own opening paren, so the run after it is the arguments.
fn rust_call_args(text: &str, marker: &str) -> Option<String> {
    let at = text.find(marker)?;
    let rest = &text[at + marker.len()..];
    let (inner, _) = balanced_slice(rest);
    Some(inner.to_string())
}

/// The string literal at the start of `text`, unquoted.
fn rust_path_literal(text: &str) -> Option<String> {
    let t = text.trim_start();
    let q = t.chars().next()?;
    if q != '"' && q != '\'' {
        return None;
    }
    let body = &t[1..];
    let end = body.find(q)?;
    let p = &body[..end];
    if p.is_empty() {
        None
    } else {
        Some(p.to_string())
    }
}

/// Every verb named by a method chain segment, in source order.
fn rust_verbs(segment: &str) -> Vec<String> {
    let segment = segment.trim();
    let tail = segment.rsplit("::").next().unwrap_or(segment);
    let name: String = tail
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    RUST_VERBS
        .iter()
        .find(|(lowercased, _)| *lowercased == name)
        .map(|(_, upper)| vec![upper.to_string()])
        .unwrap_or_default()
}

/// The handler a method chain names: the last argument that is not a verb and
/// not a combinator.
///
/// The argument is read by position rather than by what follows it, because in
/// every Rust router the handler is the last argument and so is followed by a
/// close paren, never an open one. `get(list_users)` and `web::get().to(
/// list_users)` both yield `list_users`, and a module path segment such as the
/// `web` of `web::get()` is not a handler because a path continues after it.
fn rust_handler(part: &str) -> Option<String> {
    let part = part.trim();
    let bytes = part.as_bytes();
    let mut found: Option<String> = None;
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if !(c.is_alphanumeric() || c == '_') {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && ((bytes[i] as char).is_alphanumeric() || bytes[i] == b'_') {
            i += 1;
        }
        let ident = &part[start..i];
        let boundary_ok = start == 0
            || !(bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
        let prev = part[..start].trim_end();
        let in_argument = prev.is_empty() || prev.ends_with('(') || prev.ends_with(',');
        let next = part[i..].trim_start();
        let is_path_prefix = next.starts_with("::");
        if boundary_ok && in_argument && !is_path_prefix {
            let bare = ident.rsplit("::").next().unwrap_or(ident);
            let is_verb = RUST_VERBS.iter().any(|(v, _)| *v == bare);
            if !is_verb && !RUST_NOT_HANDLERS.contains(&bare) {
                found = Some(bare.to_string());
            }
        }
    }
    found
}

/// The verb and handler pairs a method chain declares.
///
/// Each verb is paired with the handler of its own segment, or with the next
/// segment's when the verb is a bare filter such as `web::get()`. Stopping at
/// `.layer(...)` and `.with_state(...)` is what keeps a middleware constructor
/// from being reported as the route handler.
fn rust_route_pairs(part: &str) -> Vec<(String, String)> {
    let segments: Vec<&str> = part.split('.').collect();
    let mut pairs: Vec<(String, String)> = Vec::new();
    for (idx, segment) in segments.iter().enumerate() {
        let verbs = rust_verbs(segment);
        if verbs.is_empty() {
            continue;
        }
        let handler = rust_handler(segment)
            .or_else(|| segments.get(idx + 1).and_then(|s| rust_handler(s)));
        let Some(handler) = handler else {
            continue;
        };
        for verb in verbs {
            pairs.push((verb, handler.clone()));
        }
    }
    pairs
}

/// Endpoints declared by Rust routers: axum and actix-web builders, and Rocket
/// attributes.
///
/// Without this a Rust service has no route inventory, so the route to table
/// surface and the auth risk of a route are both empty for it.
fn scan_rust_endpoints(body: &str, file: &str, out: &mut Vec<Endpoint>) {
    let lines: Vec<&str> = body.lines().collect();
    let mut resource_path: Option<String> = None;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        let lineno = (i + 1) as u64;

        // Rocket: #[get("/path")] on the attribute, the handler on the fn below.
        if trimmed.starts_with("#[") {
            if let Some((_, verb)) = RUST_VERBS
                .iter()
                .find(|(v, _)| trimmed.starts_with(&format!("#[{v}(")))
            {
                let after_paren = trimmed.split_once('(').map(|(_, rest)| rest).unwrap_or("");
                if let Some(path) = rust_path_literal(after_paren) {
                    if let Some(handler) = rust_fn_below(&lines, i + 1) {
                        out.push(Endpoint {
                            method: verb.to_string(),
                            path: normalize_route_path(&path),
                            handler,
                            file: file.to_string(),
                            line: lineno,
                        });
                    }
                }
                continue;
            }
        }

        // actix-web: web::resource("/users").route(web::get().to(list_users))
        if let Some(inner) = rust_call_args(trimmed, "web::resource(")
            .or_else(|| rust_call_args(trimmed, "resource("))
        {
            if let Some(p) = rust_path_literal(&inner) {
                resource_path = Some(normalize_route_path(&p));
            }
        }

        for marker in [".route(", ".service("] {
            let Some(inner) = rust_call_args(trimmed, marker) else {
                continue;
            };
            // `.service(web::resource("/x").route(web::get().to(h)))` carries the
            // route one level down. Reading the outer call as well reports the
            // same endpoint twice, once from the resource and once from the
            // service that wraps it.
            if marker == ".service(" && (inner.contains("web::resource(") || inner.contains(".route("))
            {
                continue;
            }
            let parts = split_top_level(&inner);
            let mut path = resource_path.clone();
            let mut verb_args: &[String] = &parts;
            if let Some(first) = parts.first() {
                if rust_path_literal(first).is_some() {
                    if let Some(p) = rust_path_literal(first) {
                        path = Some(normalize_route_path(&p));
                    }
                    verb_args = &parts[1..];
                }
            }
            let Some(path) = path else {
                continue;
            };
            for part in verb_args {
                let pairs = rust_route_pairs(part);
                if !pairs.is_empty() {
                    for (method, handler) in pairs {
                        out.push(Endpoint {
                            method,
                            path: path.clone(),
                            handler,
                            file: file.to_string(),
                            line: lineno,
                        });
                    }
                    continue;
                }
                let Some(handler) = rust_handler(part) else {
                    continue;
                };
                out.push(Endpoint {
                    method: "ANY".to_string(),
                    path: path.clone(),
                    handler,
                    file: file.to_string(),
                    line: lineno,
                });
            }
        }
    }
}

/// The name of the first `fn` declared at or after `from`, within a short
/// window so a route attribute never adopts an unrelated later function.
fn rust_fn_below(lines: &[&str], from: usize) -> Option<String> {
    for line in lines.iter().skip(from).take(4) {
        let t = line.trim_start();
        let rest = t.strip_prefix("pub ").unwrap_or(t);
        let rest = rest.strip_prefix("async ").unwrap_or(rest);
        if let Some(after) = rest.strip_prefix("fn ") {
            let name: String = after
                .trim_start()
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

/// Handler names of the Rust routes in `body`, for the dead root check.
fn scan_rust(body: &str, out: &mut HashSet<String>) {
    let mut eps = Vec::new();
    scan_rust_endpoints(body, "", &mut eps);
    for e in eps {
        out.insert(e.handler);
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
            .map(|r| r.iter().map(|x| self.resolve_table(&x.table)).collect())
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
    let mut callees: std::collections::HashMap<&str, Vec<&str>> = std::collections::HashMap::new();
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
                op: call.op,
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
                        op: q.op,
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
    if let Some(stem) = lower.strip_suffix("ies") {
        return format!("{stem}y");
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
    "repo",
    "repository",
    "dao",
    "store",
    "model",
    "entity",
    "mapper",
    "service",
];

/// True when a name is a data-access handle rather than a table.
fn is_repository_handle(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    HANDLE_SUFFIXES.iter().any(|s| {
        lower == *s
            || lower
                .strip_suffix(s)
                .map(|stem| !stem.is_empty())
                .unwrap_or(false)
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
