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
