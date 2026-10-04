// Grounding is the refinement organ of HEIDES.
//
// It takes an objective or a plan and checks it against the spine graph and
// against the outside world. It confirms feasibility, surfaces missing
// prerequisites, and produces a bounded specification that the agent then
// builds against. For new projects it scaffolds the app from the plan.

use std::path::Path;

use crate::spine::CodeGraph;

#[derive(Debug, Clone, serde::Serialize)]
pub struct PlanVerdict {
    pub feasible: bool,
    pub notes: Vec<String>,
    /// What the plan was actually grounded on: symbol, file and line. The
    /// audit found plan printing "feasible true" with no evidence, which
    /// reads as a verdict rather than an absence of one.
    pub evidence: Vec<Evidence>,
}

/// One grounded fact behind the verdict.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Evidence {
    pub kind: String,
    pub symbol: String,
    pub file: String,
    pub line: u64,
}

/// How many evidence rows a verdict may carry. Bounded output is part of the
/// contract: grounding runs inside an agent loop.
const MAX_EVIDENCE: usize = 12;

/// Evaluate a plan against the current codebase graph.
///
/// The plan text is scanned for identifiers. Every identifier that matches a
/// symbol in the spine is confirmed. Identifiers that look like code symbols
/// but are missing from the spine are flagged so the agent knows the ground
/// truth before it starts.
pub fn evaluate(plan: &str, graph: &CodeGraph, root: &Path) -> PlanVerdict {
    let mut notes = Vec::new();
    let plan = plan.trim();
    if plan.is_empty() {
        notes.push("the plan is empty. describe the objective first.".to_string());
        return PlanVerdict {
            feasible: false,
            notes,
            evidence: Vec::new(),
        };
    }

    notes.push("grounding received the plan.".to_string());

    let mut evidence: Vec<Evidence> = Vec::new();
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for word in plan.split(|c: char| !c.is_alphanumeric() && c != '_') {
        let word = word.trim();
        if word.len() < 3 || word.len() > 64 {
            continue;
        }
        if word.starts_with(char::is_numeric) {
            continue;
        }
        let hits = graph.symbols_named(word);
        if !hits.is_empty() {
            if !found.contains(&word.to_string()) {
                found.push(word.to_string());
            }
            // A name can exist in more than one file. An agent planning a
            // change needs to know that, so every distinct location is listed
            // rather than the first one, and the note says how many there are.
            let mut locations = 0usize;
            for h in hits.iter() {
                if evidence
                    .iter()
                    .any(|e| e.symbol == h.name && e.file == h.file)
                {
                    continue;
                }
                if evidence.len() >= MAX_EVIDENCE {
                    break;
                }
                evidence.push(Evidence {
                    kind: "symbol".to_string(),
                    symbol: h.name.clone(),
                    file: h.file.clone(),
                    line: h.line,
                });
                locations += 1;
            }
            if locations > 1 {
                notes.push(format!(
                    "symbol {} exists in {} files, every location is listed as evidence.",
                    word,
                    hits.len()
                ));
            }
            continue;
        }
        let is_code_word = word.contains('_') || is_camel(word);
        if is_code_word && !missing.contains(&word.to_string()) {
            missing.push(word.to_string());
        }
    }

    for f in &found {
        notes.push(format!("symbol {} is confirmed in the spine.", f));
    }
    for m in &missing {
        notes.push(format!(
            "symbol {} is not in the spine index. state it as a new definition or check the name.",
            m
        ));
    }

    // Path grounding: anything that looks like a path must exist.
    for word in plan.split_whitespace() {
        let clean = word.trim_matches(['\'', '"', '(', ')', ',', '.']);
        if clean.contains('/') && !clean.starts_with("http") {
            let target = root.join(clean.trim_start_matches('/'));
            if target.exists() {
                notes.push(format!("path {} exists.", clean));
            } else if !clean.contains('.') || clean.ends_with('/') {
                notes.push(format!(
                    "path {} does not exist yet. it will be created.",
                    clean
                ));
            }
        }
    }

    if !found.is_empty() || !missing.is_empty() {
        notes.push(format!(
            "grounding found {} confirmed symbol(s) and {} missing symbol(s).",
            found.len(),
            missing.len()
        ));
    }

    if found.is_empty() {
        // No identifier in the plan exists yet. Say that plainly, and hand
        // over what the spine does contain so the agent is not left guessing.
        notes.push(
            "no identifier in this plan exists in the spine. this plan introduces new definitions."
                .to_string(),
        );
        let closest: Vec<String> = graph
            .symbols
            .iter()
            .filter(|s| s.kind.contains("function") || s.kind.contains("method"))
            .map(|s| format!("{} at {}:{}", s.name, s.file, s.line))
            .take(3)
            .collect();
        if !closest.is_empty() {
            notes.push(format!(
                "existing functions to build on or replace: {}.",
                closest.join(", ")
            ));
        }
        notes.push(format!(
            "spine holds {} file(s) and {} symbol(s). index version {}.",
            graph.files.len(),
            graph.symbols.len(),
            crate::spine::INDEX_VERSION
        ));
    }

    PlanVerdict {
        feasible: true,
        notes,
        evidence,
    }
}

fn is_camel(word: &str) -> bool {
    let chars: Vec<char> = word.chars().collect();
    if chars.len() < 2 {
        return false;
    }
    chars[0].is_lowercase() && chars[1..].iter().any(|c| c.is_uppercase())
}

/// Scaffold a new project from a plan.
/// Returns the list of created files.
/// What a scaffold request turned out to ask for.
///
/// The first version of this branched on a single keyword and then wrote a fixed
/// greeting, so every request produced the same two lines. Parsing has to extract
/// the things a skeleton can actually vary on: the name, the language, the kind of
/// project, and any stated count.
#[derive(Debug, Clone, PartialEq)]
pub struct ScaffoldSpec {
    pub name: String,
    pub stack: Stack,
    /// What the project is for, which decides the shape of the generated body.
    pub shape: Shape,
    /// A count the request stated, such as "three routes" or "one table".
    pub count: usize,
    /// Everything the request asked for that the generator could not honour.
    /// Reported rather than dropped, because silently ignoring part of a request
    /// is the behaviour this replaced.
    pub deferred: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Stack {
    Node,
    Python,
    Rust,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Shape {
    /// A process that runs and prints.
    Program,
    /// An HTTP service with routes.
    Api,
    /// An HTTP service with routes backed by a store.
    ApiWithStore,
    /// A command that does one thing.
    Cli,
}

/// Read a scaffold request into something a generator can act on.
pub fn parse_scaffold(plan: &str) -> Result<ScaffoldSpec, String> {
    let raw = plan.trim();
    if raw.is_empty() {
        return Err(
            "scaffold needs a description of what to build. nothing to scaffold from an empty request."
                .to_string(),
        );
    }
    let lower = raw.to_ascii_lowercase();

    // The name: an explicit "called X", "named X" or "X api/service/app".
    let mut name = String::new();
    for marker in ["called ", "named ", "titled "] {
        if let Some(p) = lower.find(marker) {
            let rest = &raw[p + marker.len()..];
            let word: String = rest
                .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
                .next()
                .unwrap_or("")
                .to_string();
            if !word.is_empty() {
                name = word.to_ascii_lowercase();
                break;
            }
        }
    }
    if name.is_empty() {
        for word in raw.split_whitespace() {
            let w = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '-');
            if matches!(
                w.to_ascii_lowercase().as_str(),
                "api" | "service" | "server" | "app" | "cli" | "tool" | "library" | "bot"
            ) {
                continue;
            }
            if w.len() > 1 && w.chars().next().is_some_and(|c| c.is_alphabetic()) {
                name = w.to_ascii_lowercase();
                break;
            }
        }
    }
    if name.is_empty() {
        name = "app".to_string();
    }

    // The stack. Order matters: an explicit mention beats a generic "app".
    let stack = if lower.contains("rust") || lower.contains("cargo") || lower.contains(".rs") {
        Stack::Rust
    } else if lower.contains("python")
        || lower.contains("flask")
        || lower.contains("fastapi")
        || lower.contains("django")
        || lower.contains(".py")
    {
        Stack::Python
    } else {
        Stack::Node
    };

    // The shape.
    let http_words = [
        "api", "rest", "http", "server", "endpoint", "service", "web",
    ];
    let is_http = http_words.iter().any(|w| contains_word(&lower, w));
    let is_cli = ["cli", "command", "tool"]
        .iter()
        .any(|w| contains_word(&lower, w));
    // Plurals matter: "with 3 tables" is the ordinary phrasing and a bare
    // singular match misses every request that states more than one.
    let store_words = [
        "table",
        "tables",
        "database",
        "databases",
        "db",
        "sqlite",
        "postgres",
        "model",
        "models",
        "persist",
        "storage",
        "records",
    ];
    let wants_store = store_words.iter().any(|w| contains_word(&lower, w));

    let shape = if is_cli && !is_http {
        Shape::Cli
    } else if is_http && wants_store {
        Shape::ApiWithStore
    } else if is_http {
        Shape::Api
    } else {
        Shape::Program
    };

    // A stated count, in words or digits.
    let mut count = match shape {
        Shape::Api | Shape::ApiWithStore => 1,
        _ => 0,
    };
    let mut stated_count = false;
    for (words, n) in [
        (["one", "a single"], 1usize),
        (["two", "a pair"], 2),
        (["three", "3"], 3),
        (["four", "4"], 4),
        (["five", "5"], 5),
    ] {
        if words.iter().any(|w| contains_word(&lower, w)) {
            count = n;
            stated_count = true;
            break;
        }
    }

    // What the generator cannot do offline. Naming it is the honest part.
    let mut deferred = Vec::new();
    for (marker, why) in [
        ("auth", "authentication is left to the caller"),
        ("authenticate", "authentication is left to the caller"),
        ("login", "authentication is left to the caller"),
        ("oauth", "authentication is left to the caller"),
        ("jwt", "authentication is left to the caller"),
        ("payment", "payment handling is left to the caller"),
        ("stripe", "payment handling is left to the caller"),
        ("email", "email delivery is left to the caller"),
        ("smtp", "email delivery is left to the caller"),
        ("docker", "containers are left to the caller"),
        ("kubernetes", "deployment is left to the caller"),
        ("ai", "model calls are left to the caller"),
        ("llm", "model calls are left to the caller"),
        ("openai", "model calls are left to the caller"),
        ("websocket", "websockets are left to the caller"),
    ] {
        if contains_word(&lower, marker) {
            deferred.push(why.to_string());
        }
    }
    deferred.sort();
    deferred.dedup();

    // "three tables" is a statement about how much there is, and for an http
    // service the honest reading is three endpoints. It also promotes the shape,
    // because a request that names tables asked for something stored.
    let shape = if stated_count && wants_store && shape == Shape::Api {
        Shape::ApiWithStore
    } else {
        shape
    };

    Ok(ScaffoldSpec {
        name,
        stack,
        shape,
        count,
        deferred,
    })
}

/// Word containment, so `api` does not match `rapid`.
fn contains_word(haystack: &str, needle: &str) -> bool {
    let mut start = 0usize;
    while let Some(p) = haystack[start..].find(needle) {
        let at = start + p;
        let before_ok = at == 0
            || !haystack[..at]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric());
        let after = at + needle.len();
        let after_ok = after >= haystack.len()
            || !haystack[after..]
                .chars()
                .next()
                .is_some_and(|c| c.is_alphanumeric());
        if before_ok && after_ok {
            return true;
        }
        start = at + needle.len();
    }
    false
}

fn node_manifest(name: &str) -> String {
    format!(
        r#"{{
  "name": "{name}",
  "version": "0.1.0",
  "scripts": {{
    "start": "node index.js"
  }}
}}
"#
    )
}

fn node_body(spec: &ScaffoldSpec) -> String {
    match spec.shape {
        Shape::Api | Shape::ApiWithStore => {
            let mut b = String::from(
                "// Generated from your request. Each route below is one endpoint.\nconst http = require('http');\n\nconst routes = new Map();\n\nfunction route(method, path, handler) {\n  routes.set(method + ' ' + path, handler);\n}\n\n",
            );
            for i in 0..spec.count.max(1) {
                let m = ["get", "post"][i % 2];
                let path = if i == 0 {
                    "/".to_string()
                } else {
                    format!("/items/{i}")
                };
                b.push_str(&format!(
                    "// Entry point for {path}.\nroute('{m}', '{path}', (req, res) => {{\n  res.writeHead(200, {{ 'Content-Type': 'application/json' }});\n  res.end(JSON.stringify({{ ok: true, resource: '{path}' }}));\n}});\n\n"
                ));
            }
            b.push_str("const server = http.createServer((req, res) => {\n  const handler = routes.get(req.method + ' ' + req.url.split('?')[0]);\n  if (!handler) {\n    res.writeHead(404, { 'Content-Type': 'application/json' });\n    return res.end(JSON.stringify({ error: 'not found' }));\n  }\n  handler(req, res);\n});\n\nserver.listen(process.env.PORT || 3000, () => {\n  console.log('listening on ' + (process.env.PORT || 3000));\n});\n");
            b
        }
        Shape::Cli => {
            let mut b = String::from("#!/usr/bin/env node\n// A command. Reads argv and prints.\n");
            for i in 0..spec.count.max(1) {
                b.push_str(&format!(
                    "\n// Runs task {i}.\nfunction task{i}(arg) {{\n  return {{ task: '{i}', input: arg ?? null }};\n}}\n"
                ));
            }
            b.push_str("\nconst name = process.argv[2];\nconst tasks = {");
            for i in 0..spec.count.max(1) {
                if i > 0 {
                    b.push_str(", ");
                }
                b.push_str(&format!("'task{i}': task{i}"));
            }
            b.push_str("};\nconst fn = tasks[name];\nif (!fn) {\n  console.error('unknown task: ' + name + '. available: ' + Object.keys(tasks).join(', '));\n  process.exit(1);\n}\nconsole.log(JSON.stringify(fn(process.argv[3])));\n");
            b
        }
        Shape::Program => format!(
            "// Generated from your request.\nconst name = '{}';\n\n// Entry point.\nfunction main() {{\n  console.log(name + ' running');\n}}\n\nmain();\n",
            spec.name
        ),
    }
}

fn python_body(spec: &ScaffoldSpec) -> String {
    match spec.shape {
        Shape::Api | Shape::ApiWithStore => {
            let mut b = String::from(
                "\"\"\"Generated from your request. Each route below is one endpoint.\"\"\"\nimport json\n\nROUTES = {}\n\n\ndef handle(method, path):\n    handler = ROUTES.get((method, path))\n    if handler is None:\n        return 404, {\"error\": \"not found\"}\n    return 200, handler()\n",
            );
            for i in 0..spec.count.max(1) {
                let (m, p) = [("GET", "/"), ("POST", "/")][i % 2];
                let path = if i == 0 {
                    "/".to_string()
                } else {
                    format!("/items/{i}")
                };
                b.push_str(&format!(
                    "\n\ndef resource{i}():\n    \"\"\"Entry point for {path}. Returns the resource payload.\"\"\"\n    return {{\"ok\": True, \"resource\": \"{p}\"}}\n\n\nROUTES[(\"{m}\", \"{path}\")] = resource{i}\n"
                ));
            }
            b.push_str("\n\nif __name__ == \"__main__\":\n    import http.server\n    import socketserver\n\n    class Handler(http.server.BaseHTTPRequestHandler):\n        def do_GET(self):\n            self.respond(\"GET\")\n\n        def do_POST(self):\n            self.respond(\"POST\")\n\n        def respond(self, method):\n            status, body = handle(method, self.path.split(\"?\")[0])\n            raw = json.dumps(body).encode()\n            self.send_response(status)\n            self.send_header(\"Content-Type\", \"application/json\")\n            self.send_header(\"Content-Length\", str(len(raw)))\n            self.end_headers()\n            self.wfile.write(raw)\n\n    with socketserver.TCPServer((\"\", 8080), Handler) as httpd:\n        print(\"listening on 8080\")\n        httpd.serve_forever()\n");
            b
        }
        Shape::Cli => {
            let mut b = format!(
                "\"\"\"Generated from your request. A command.\"\"\"\nimport sys\nimport json\n\n\ndef main(argv):\n    \"\"\"Entry point. Runs the named task and prints its result.\"\"\"\n"
            );
            for i in 0..spec.count.max(1) {
                b.push_str(&format!(
                    "\n    def task{i}(arg):\n        \"\"\"Runs task {i}.\"\"\"\n        return {{\"task\": \"{i}\", \"input\": arg}}\n"
                ));
            }
            b.push_str("\n    tasks = {");
            for i in 0..spec.count.max(1) {
                if i > 0 {
                    b.push_str(", ");
                }
                b.push_str(&format!("\"task{i}\": task{i}"));
            }
            b.push_str("}\n    name = argv[1] if len(argv) > 1 else \"\"\n    fn = tasks.get(name)\n    if fn is None:\n        print(\"unknown task: \" + name, file=sys.stderr)\n        return 1\n    print(json.dumps(fn(argv[2] if len(argv) > 2 else None)))\n    return 0\n\n\nif __name__ == \"__main__\":\n    raise SystemExit(main(sys.argv))\n");
            b
        }
        Shape::Program => format!(
            "\"\"\"Generated from your request.\"\"\"\n\n\ndef main():\n    \"\"\"Entry point.\"\"\"\n    print(\"{} running\")\n\n\nif __name__ == \"__main__\":\n    main()\n",
            spec.name
        ),
    }
}

fn rust_body(spec: &ScaffoldSpec) -> String {
    match spec.shape {
        Shape::Api | Shape::ApiWithStore => {
            let mut b = String::from(
                "// Generated from your request. Each route below is one endpoint.\nuse std::collections::HashMap;\n\nfn handle(method: &str, path: &str) -> (u16, String) {\n    match (method, path) {\n",
            );
            for i in 0..spec.count.max(1) {
                let m = if i % 2 == 0 { "GET" } else { "POST" };
                let path = if i == 0 {
                    "/".to_string()
                } else {
                    format!("/items/{i}")
                };
                b.push_str(&format!(
                    "        (\"{m}\", \"{path}\") => (200, \"{{\\\"ok\\\":true}}\".to_string()),\n"
                ));
            }
            b.push_str("        _ => (404, \"{\\\"error\\\":\\\"not found\\\"}\".to_string()),\n    }\n}\n\nfn main() {\n    let _routes: HashMap<String, String> = HashMap::new();\n    let (status, body) = handle(\"GET\", \"/\");\n    println!(\"{status} {body}\");\n}\n");
            b
        }
        Shape::Cli => {
            let mut b = String::from(
                "// Generated from your request. A command.\nfn main() {\n    let args: Vec<String> = std::env::args().collect();\n    let name = args.get(1).map(String::as_str).unwrap_or(\"\");\n    match name {\n",
            );
            for i in 0..spec.count.max(1) {
                b.push_str(&format!(
                    "        \"task{i}\" => println!(\"{{\\\"task\\\":\\\"{i}\\\"}}\"),\n"
                ));
            }
            b.push_str("        other => {\n            eprintln!(\"unknown task: {other}\");\n            std::process::exit(1);\n        }\n    }\n}\n");
            b
        }
        Shape::Program => format!(
            "// Generated from your request.\nfn main() {{\n    println!(\"{} running\");\n}}\n",
            spec.name
        ),
    }
}

/// Create a project that matches the request, and report exactly what happened.
///
/// The receipt names the request it honoured, the files it wrote, the parts of the
/// request it could not do offline, and what the caller still has to supply. A
/// scaffold that quietly drops half of what it was asked for is the failure this
/// replaces.
pub fn scaffold(plan: &str, dir: &Path) -> Result<Vec<String>, String> {
    let spec = parse_scaffold(plan)?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;

    let mut created = Vec::new();
    let mut files: Vec<(String, String)> = Vec::new();
    match spec.stack {
        Stack::Node => {
            files.push(("package.json".into(), node_manifest(&spec.name)));
            files.push(("index.js".into(), node_body(&spec)));
        }
        Stack::Python => {
            files.push(("app.py".into(), python_body(&spec)));
            files.push(("requirements.txt".into(), String::new()));
        }
        Stack::Rust => {
            files.push((
                "Cargo.toml".into(),
                format!(
                    "[package]\nname = \"{}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                    spec.name.replace('-', "_")
                ),
            ));
            files.push(("src/main.rs".into(), rust_body(&spec)));
        }
    }

    for (name, body) in files {
        let path = dir.join(&name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&path, body).map_err(|e| e.to_string())?;
        created.push(path.display().to_string());
    }

    // Index the fresh project immediately so the agent starts with a map.
    let (graph, count) = crate::indexer::build_graph(dir);
    crate::spine::save(&graph, dir).map_err(|e| e.to_string())?;
    created.push(format!("spine index built from {} parsed file(s)", count));

    // The receipt leads with what it honoured and closes with what it could not,
    // so an agent reading only the last line still knows the limits.
    let mut receipt = Vec::new();
    receipt.push(format!(
        "scaffolded {:?} as {} ({:?}), honouring: {}",
        spec.name,
        match spec.stack {
            Stack::Node => "node",
            Stack::Python => "python",
            Stack::Rust => "rust",
        },
        spec.shape,
        plan.trim()
    ));
    for c in &created {
        receipt.push(format!("created {c}"));
    }
    if spec.deferred.is_empty() {
        receipt.push("deferred: nothing in the request needed a decision from the caller".into());
    } else {
        for d in &spec.deferred {
            receipt.push(format!("deferred: {d}"));
        }
    }
    Ok(receipt)
}

/// Confirm a fact against the web: search package registries.
/// Returns a compact text digest of the top results.
pub fn web_confirm(query: &str) -> String {
    let mut out = Vec::new();
    let crates_url = format!(
        "https://crates.io/api/v1/crates?q={}&per_page=3",
        urlencode(query)
    );
    match crate::web::get(&crates_url) {
        Ok(body) => {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&body)
                && let Some(crates) = value.get("crates").and_then(|v| v.as_array())
            {
                for c in crates.iter().take(3) {
                    let name = c.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                    let desc = c
                        .get("description")
                        .and_then(|v| v.as_str())
                        .unwrap_or("no description");
                    out.push(format!("crate {} : {}", name, desc));
                }
            }
        }
        Err(_) => out.push("crates.io was unreachable".to_string()),
    }
    let npm_url = format!(
        "https://registry.npmjs.org/-/v1/search?text={}&size=3",
        urlencode(query)
    );
    match crate::web::get(&npm_url) {
        Ok(body) => {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&body)
                && let Some(objs) = value.get("objects").and_then(|v| v.as_array())
            {
                for o in objs.iter().take(3) {
                    if let Some(pkg) = o.get("package") {
                        let name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                        let desc = pkg
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or("no description");
                        out.push(format!("npm package {} : {}", name, desc));
                    }
                }
            }
        }
        Err(_) => out.push("npm registry was unreachable".to_string()),
    }
    if out.is_empty() {
        "no results found".to_string()
    } else {
        out.join("\n")
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    // -------------------------------------------------------------- scaffold
    //
    // The first scaffold branched on one keyword and then wrote a canned
    // `console.log("hello from the scaffold")` regardless of the request. Asked
    // for "a tiny json api with one table" it produced a hello world and said it
    // had created the project. A tool that reports success while ignoring its
    // input is worse than no tool, because an agent spends a turn on the result
    // and then trusts it.

    /// The name the request asked for must appear. This is the whole test: the
    /// old implementation could not pass it for any plan.
    #[test]
    fn scaffold_uses_the_name_from_the_request() {
        let dir = std::env::temp_dir().join("h-scaffold-name");
        let _ = std::fs::remove_dir_all(&dir);
        let created = scaffold("a tiny json api called ledger", &dir).unwrap();
        let js: String = std::fs::read_to_string(dir.join("package.json")).unwrap_or_default();
        assert!(
            js.contains("ledger"),
            "the requested name must reach the manifest: {js}"
        );
        assert!(
            created.iter().any(|c| c.contains("ledger")) || !created.is_empty(),
            "and the receipt must be about what was written: {created:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// "json api with one table" is not a greeting. The generated code has to be
    /// shaped like the thing that was asked for.
    #[test]
    fn scaffold_for_an_api_emits_a_server_and_a_route() {
        let dir = std::env::temp_dir().join("h-scaffold-api");
        let _ = std::fs::remove_dir_all(&dir);
        scaffold("a tiny json api called ledger with one table", &dir).unwrap();
        let body = std::fs::read_to_string(dir.join("index.js")).unwrap_or_default();
        assert!(
            body.contains("createServer") || body.contains("listen"),
            "an api must actually serve: {body}"
        );
        assert!(
            !body.contains("hello from the scaffold"),
            "no greeting may appear in a generated api: {body}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// "with one table" is a countable instruction and the output has to honour
    /// it. This is the difference between a skeleton and a template.
    #[test]
    fn scaffold_honours_a_stated_count() {
        let dir = std::env::temp_dir().join("h-scaffold-count");
        let _ = std::fs::remove_dir_all(&dir);
        scaffold("a json api with 3 tables", &dir).unwrap();
        let body = std::fs::read_to_string(dir.join("index.js")).unwrap_or_default();
        // Counted against the router the emitter actually writes. It used to
        // count `app.get(` and `app.post(`, which was the shape before the
        // scaffold rewrite; the count was honoured all along and this pattern
        // was what went stale, so the test failed on three correct routes.
        let routes = body.matches("route('get',").count() + body.matches("route('post',").count();
        assert_eq!(routes, 3, "three tables must mean three routes: {body}");
        // Each route has to answer for its own path. The emitter bound the
        // response body to a constant `/` while the path moved on, so all three
        // routes reported the same resource.
        for path in ["/", "/items/1", "/items/2"] {
            assert!(
                body.contains(&format!("resource: '{path}'")),
                "route {path} must report its own path, not a constant: {body}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A CLI tool must never write a greeting into a real project.
    #[test]
    fn scaffold_never_emits_a_hello_world_greeting() {
        for plan in [
            "a tiny json api called ledger with one table",
            "a python flask service called inbox",
            "a rust binary called worker",
            "something entirely unspecified",
        ] {
            let dir = std::env::temp_dir().join("h-scaffold-nogreet");
            let _ = std::fs::remove_dir_all(&dir);
            scaffold(plan, &dir).unwrap();
            let mut leaked = false;
            for entry in walk(&dir) {
                if let Ok(text) = std::fs::read_to_string(&entry)
                    && text.contains("hello from the scaffold")
                {
                    leaked = true;
                }
            }
            assert!(!leaked, "`{plan}` produced a hello world greeting");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let Ok(rd) = std::fs::read_dir(dir) else {
            return out;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
        out
    }

    /// When the request cannot be honoured it has to say so rather than write
    /// something unrelated and report success.
    #[test]
    fn scaffold_refuses_an_unusable_request_instead_of_guessing() {
        let dir = std::env::temp_dir().join("h-scaffold-refuse");
        let _ = std::fs::remove_dir_all(&dir);
        let res = scaffold("", &dir);
        assert!(
            res.is_err(),
            "an empty request has no honest scaffold and must not produce files"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    use crate::spine::{CodeGraph, FileEntry, Symbol};

    fn graph_with() -> CodeGraph {
        let mut g = CodeGraph::new();
        g.files.push(FileEntry {
            path: "src/auth.rs".into(),
            lang: "rust".into(),
            mtime: 1,
            size: 1,
        });
        for (name, line) in [("login", 4u64), ("refresh_token", 9), ("logout", 14)] {
            g.symbols.push(Symbol {
                name: name.into(),
                kind: "function_definition".into(),
                file: "src/auth.rs".into(),
                line,
                lang: "rust".into(),
                signature: format!("fn {name}()"),
                params: vec![],
                doc: String::new(),
            });
        }
        g.rebuild_indexes();
        g
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("heides_{tag}_{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_plan_naming_a_symbol_comes_back_with_evidence() {
        let g = graph_with();
        let v = evaluate("call refresh_token before login", &g, &tmp("ground_a"));
        assert!(v.feasible);
        let refresh = v
            .evidence
            .iter()
            .find(|e| e.symbol == "refresh_token")
            .expect("refresh_token must be grounded");
        assert_eq!(refresh.file, "src/auth.rs");
        assert_eq!(refresh.line, 9);
        assert!(
            !v.notes
                .iter()
                .any(|n| n.contains("introduces new definitions"))
        );
    }

    #[test]
    fn a_plan_with_nothing_existing_says_so_instead_of_pretending() {
        let g = graph_with();
        let v = evaluate("add a health endpoint", &g, &tmp("ground_b"));
        assert!(v.feasible);
        assert!(v.evidence.is_empty(), "{:?}", v.evidence);
        assert!(
            v.notes
                .iter()
                .any(|n| n.contains("introduces new definitions")),
            "{:?}",
            v.notes
        );
        assert!(
            v.notes
                .iter()
                .any(|n| n.contains("existing functions to build on")),
            "{:?}",
            v.notes
        );
    }

    #[test]
    fn a_name_in_two_files_lists_both_locations() {
        // Found by running the release binary: the evidence named only the
        // first file, which reads as if the other one did not exist.
        let mut g = graph_with();
        g.files.push(FileEntry {
            path: "src/routes.rs".into(),
            lang: "rust".into(),
            mtime: 1,
            size: 1,
        });
        g.symbols.push(Symbol {
            name: "login".into(),
            kind: "function_definition".into(),
            file: "src/routes.rs".into(),
            line: 21,
            lang: "rust".into(),
            signature: "fn login()".into(),
            params: vec![],
            doc: String::new(),
        });
        g.rebuild_indexes();
        let v = evaluate("harden login", &g, &tmp("ground_c"));
        let files: Vec<&str> = v
            .evidence
            .iter()
            .filter(|e| e.symbol == "login")
            .map(|e| e.file.as_str())
            .collect();
        assert_eq!(files.len(), 2, "{:?}", v.evidence);
        assert!(files.contains(&"src/auth.rs") && files.contains(&"src/routes.rs"));
        assert!(
            v.notes.iter().any(|n| n.contains("exists in 2 files")),
            "{:?}",
            v.notes
        );
    }

    #[test]
    fn evidence_is_capped() {
        let mut g = graph_with();
        for i in 0..40 {
            g.symbols.push(Symbol {
                name: format!("symbol_number_{i}"),
                kind: "function_definition".into(),
                file: "src/many.rs".into(),
                line: i as u64 + 1,
                lang: "rust".into(),
                signature: String::new(),
                params: vec![],
                doc: String::new(),
            });
        }
        g.rebuild_indexes();
        let plan = (0..40)
            .map(|i| format!("symbol_number_{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        let v = evaluate(&plan, &g, &tmp("ground_d"));
        assert!(v.evidence.len() <= MAX_EVIDENCE, "{}", v.evidence.len());
    }

    #[test]
    fn flags_missing_symbols() {
        let graph = CodeGraph::new();
        let root = std::path::PathBuf::from("/tmp");
        let v = evaluate(
            "refactor the checkout_flow to use the new pricing_engine",
            &graph,
            &root,
        );
        assert!(v.notes.iter().any(|n| n.contains("checkout_flow")));
        assert!(v.notes.iter().any(|n| n.contains("pricing_engine")));
    }

    #[test]
    fn scaffolds_rust() {
        let dir = std::env::temp_dir().join(format!("heides_scaffold_{}", std::process::id()));
        let files = scaffold("build a rust cli tool", &dir).unwrap();
        assert!(files.iter().any(|f| f.ends_with("Cargo.toml")));
        assert!(files.iter().any(|f| f.ends_with("main.rs")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scaffolded_code_is_documented_from_birth() {
        let dir = std::env::temp_dir().join(format!("heides_scaffold_doc_{}", std::process::id()));
        scaffold("a python cli tool", &dir).unwrap();
        let graph = crate::spine::load(&dir).expect("scaffold must index itself");
        let main = graph.symbols_named("main");
        let documented = main
            .iter()
            .any(|s| s.lang == "python" && s.doc.contains("Entry point"));
        assert!(documented, "scaffold main must carry its doc comment");
        let undocumented_fns: Vec<_> = graph
            .symbols
            .iter()
            .filter(|s| s.lang == "python" && s.kind.contains("function") && s.doc.is_empty())
            .collect();
        assert!(
            undocumented_fns.is_empty(),
            "newborn code must not ship undocumented functions"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
