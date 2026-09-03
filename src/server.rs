// The MCP server shell of HEIDES.
//
// HEIDES speaks the Model Context Protocol over stdio. Any MCP aware agent,
// editor, CLI or harness can attach to it: Claude Code, Codex, Cursor,
// VS Code, OpenCode, Hermes, custom builds. This one interface makes HEIDES
// available everywhere at once.
//
// Every message is one JSON object per line on stdin and stdout. Logging
// goes to stderr so the protocol stream stays clean.

use std::io::{BufRead, Write};
use std::process::ExitCode;

use serde_json::{Value, json};

use crate::grounding;
use crate::harmony;
use crate::indexer;
use crate::spine;

fn send(msg: &Value) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{}", msg);
    let _ = out.flush();
}

fn ok(id: &Value, result: Value) {
    send(&json!({ "jsonrpc": "2.0", "id": id, "result": result }));
}

fn err(id: &Value, code: i64, message: &str) {
    send(&json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }));
}

fn text_result(text: String) -> Value {
    json!({ "content": [{ "type": "text", "text": text }] })
}

fn report_lines(reports: &[harmony::GuardReport]) -> String {
    if reports.is_empty() {
        return "no findings. the workspace is clean.".to_string();
    }
    let mut lines = vec![harmony::summarize(reports)];
    for r in reports {
        let loc = if r.file.is_empty() {
            String::new()
        } else {
            format!(" at {}:{}", r.file, r.line)
        };
        lines.push(format!(
            "[{}] {} ({}){}{}",
            r.severity, r.message, r.guard, loc, ""
        ));
    }
    lines.join("\n")
}

fn load_graph(root: &str) -> Result<spine::CodeGraph, String> {
    indexer::load_or_build(&std::path::PathBuf::from(root))
}

fn handle(id: &Value, method: &str, params: &Value) {
    match method {
        "initialize" => {
            ok(
                id,
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "heides", "version": env!("CARGO_PKG_VERSION") }
                }),
            );
        }
        "notifications/initialized" => {}
        "tools/list" => {
            ok(
                id,
                json!({
                    "tools": [
                        {
                            "name": "spine.scan",
                            "description": "Map the current codebase into the persistent spine index.",
                            "inputSchema": { "type": "object", "properties": { "root": { "type": "string" } } }
                        },
                        {
                            "name": "spine.query",
                            "description": "Query the spine graph. Ask who calls a symbol, who imports a module, or where a symbol is defined.",
                            "inputSchema": { "type": "object", "properties": {
                                "kind": { "type": "string", "enum": ["callers", "imports", "definition", "calls", "search"] },
                                "name": { "type": "string" }
                            }, "required": ["kind", "name"] }
                        },
                        {
                            "name": "spine.describe",
                            "description": "Read the whole workspace manifest in one shot. Languages, symbol counts, entrypoints, hubs and doc coverage per language.",
                            "inputSchema": { "type": "object", "properties": { "root": { "type": "string" } } }
                        },
                        {
                            "name": "spine.neighbors",
                            "description": "Show every side of a symbol, definition with its captured doc, callers and calls out.",
                            "inputSchema": { "type": "object", "properties": { "name": { "type": "string" } }, "required": ["name"] }
                        },
                        {
                            "name": "harmony.check",
                            "description": "Run every guard on the workspace and return findings with evidence.",
                            "inputSchema": { "type": "object", "properties": { "root": { "type": "string" } } }
                        },
                        {
                            "name": "harmony.staged",
                            "description": "Check a unified diff before applying it. Blocks conflicts and signature breaks.",
                            "inputSchema": { "type": "object", "properties": {
                                "patch": { "type": "string" },
                                "root": { "type": "string" }
                            }, "required": ["patch"] }
                        },
                        {
                            "name": "grounding.plan",
                            "description": "Evaluate a plan against the codebase. Confirms symbols, flags missing ones, checks paths.",
                            "inputSchema": { "type": "object", "properties": { "plan": { "type": "string" } }, "required": ["plan"] }
                        },
                        {
                            "name": "grounding.scaffold",
                            "description": "Scaffold a new project from a plan and index it immediately.",
                            "inputSchema": { "type": "object", "properties": { "plan": { "type": "string" }, "dir": { "type": "string" } }, "required": ["plan"] }
                        },
                        {
                            "name": "deps.check",
                            "description": "Check dependencies for known vulnerabilities and outdated versions.",
                            "inputSchema": { "type": "object", "properties": { "root": { "type": "string" } } }
                        },
                        {
                            "name": "web.confirm",
                            "description": "Confirm a fact against package registries on the web.",
                            "inputSchema": { "type": "object", "properties": { "query": { "type": "string" } }, "required": ["query"] }
                        }
                    ]
                }),
            );
        }
        "tools/call" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let root = args
                .get("root")
                .and_then(|v| v.as_str())
                .unwrap_or(".")
                .to_string();
            match name {
                "spine.scan" => {
                    let mut graph = spine::load(&std::path::PathBuf::from(&root))
                        .unwrap_or_else(|_| spine::CodeGraph::new());
                    let touched =
                        indexer::update_graph(&std::path::PathBuf::from(&root), &mut graph);
                    match spine::save(&graph, &std::path::PathBuf::from(&root)) {
                        Ok(()) => ok(
                            id,
                            text_result(format!(
                                "spine indexed {} files, {} symbols, {} call edges, {} imports ({} touched)",
                                graph.files.len(),
                                graph.symbols.len(),
                                graph.calls.len(),
                                graph.imports.len(),
                                touched
                            )),
                        ),
                        Err(e) => err(id, 1, &format!("save failed. {}", e)),
                    }
                }
                "spine.query" => {
                    let kind = args.get("kind").and_then(|v| v.as_str()).unwrap_or("");
                    let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let graph = match load_graph(&root) {
                        Ok(g) => g,
                        Err(e) => {
                            err(id, 1, &e);
                            return;
                        }
                    };
                    let out = match kind {
                        "callers" => {
                            let callers = graph.callers_of(name);
                            if callers.is_empty() {
                                format!("no recorded callers for {}", name)
                            } else {
                                let mut lines: Vec<String> = callers
                                    .iter()
                                    .map(|c| {
                                        format!(
                                            "{} calls {} at {}:{}",
                                            c.caller, c.callee, c.file, c.line
                                        )
                                    })
                                    .collect();
                                lines.insert(0, format!("{} call site(s)", callers.len()));
                                lines.join("\n")
                            }
                        }
                        "imports" => {
                            let importers = graph.importers_of(name);
                            if importers.is_empty() {
                                format!("no recorded imports of {}", name)
                            } else {
                                let mut lines: Vec<String> = importers
                                    .iter()
                                    .map(|i| {
                                        format!(
                                            "{} imports {} at {}:{}",
                                            i.file, i.imported, i.file, i.line
                                        )
                                    })
                                    .collect();
                                lines.insert(0, format!("{} importer(s)", importers.len()));
                                lines.join("\n")
                            }
                        }
                        "definition" => {
                            let symbols = graph.symbols_named(name);
                            if symbols.is_empty() {
                                format!("no definition for {} in the spine", name)
                            } else {
                                let lines: Vec<String> = symbols
                                    .iter()
                                    .map(|s| {
                                        format!(
                                            "{} defined at {}:{} (kind {})",
                                            s.name, s.file, s.line, s.kind
                                        )
                                    })
                                    .collect();
                                lines.join("\n")
                            }
                        }
                        "calls" => {
                            let calls = graph.calls_from(name);
                            if calls.is_empty() {
                                format!("{} makes no recorded calls", name)
                            } else {
                                let mut lines: Vec<String> = calls
                                    .iter()
                                    .map(|c| {
                                        format!(
                                            "{} calls {} at {}:{}",
                                            c.caller, c.callee, c.file, c.line
                                        )
                                    })
                                    .collect();
                                lines.insert(0, format!("{} call(s)", calls.len()));
                                lines.join("\n")
                            }
                        }
                        "search" => match spine::search(&std::path::PathBuf::from(&root), name) {
                            Ok(hits) if hits.is_empty() => {
                                format!("no symbol matches {}", name)
                            }
                            Ok(hits) => {
                                let mut lines: Vec<String> = vec![format!("{} hit(s)", hits.len())];
                                for h in hits {
                                    let doc = if h.doc.is_empty() {
                                        String::new()
                                    } else {
                                        format!(", doc {}", h.doc)
                                    };
                                    lines.push(format!(
                                        "{} ({} {}) at {}:{}{}",
                                        h.name, h.kind, name, h.file, h.line, doc
                                    ));
                                }
                                lines.join("\n")
                            }
                            Err(e) => e,
                        },
                        _ => {
                            "unknown query kind. use callers, imports, definition, calls or search"
                                .to_string()
                        }
                    };
                    ok(id, text_result(out));
                }
                "spine.neighbors" => {
                    let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let graph = match load_graph(&root) {
                        Ok(g) => g,
                        Err(e) => {
                            err(id, 1, &e);
                            return;
                        }
                    };
                    let symbols = graph.symbols_named(name);
                    if symbols.is_empty() {
                        ok(
                            id,
                            text_result(format!("no symbol named {} in the spine", name)),
                        );
                        return;
                    }
                    let mut lines: Vec<String> = Vec::new();
                    for s in &symbols {
                        lines.push(format!(
                            "{} defined at {}:{} (kind {})",
                            s.name, s.file, s.line, s.kind
                        ));
                        if !s.doc.is_empty() {
                            lines.push(format!("doc {}", s.doc));
                        }
                    }
                    let callers = graph.callers_of(name);
                    if !callers.is_empty() {
                        lines.push(format!("{} caller(s)", callers.len()));
                        for c in callers {
                            lines.push(format!(
                                "{} calls {} at {}:{}",
                                c.caller, c.callee, c.file, c.line
                            ));
                        }
                    }
                    let calls = graph.calls_from(name);
                    if !calls.is_empty() {
                        lines.push(format!("{} call(s) out", calls.len()));
                        for c in calls {
                            lines.push(format!(
                                "{} calls {} at {}:{}",
                                c.caller, c.callee, c.file, c.line
                            ));
                        }
                    }
                    ok(id, text_result(lines.join("\n")));
                }
                "spine.describe" => {
                    let graph = match load_graph(&root) {
                        Ok(g) => g,
                        Err(e) => {
                            err(id, 1, &e);
                            return;
                        }
                    };
                    let mut langs: Vec<&str> =
                        graph.files.iter().map(|f| f.lang.as_str()).collect();
                    langs.sort_unstable();
                    langs.dedup();
                    let mut lines: Vec<String> = vec![format!(
                        "files {}, symbols {}, call edges {}, imports {}",
                        graph.files.len(),
                        graph.symbols.len(),
                        graph.calls.len(),
                        graph.imports.len()
                    )];
                    lines.push(format!("languages {}", langs.join(", ")));
                    // Named entrypoints, functions that launch a program.
                    let named = [
                        "main", "run", "start", "handler", "index", "serve", "listen",
                    ];
                    let is_fn = |k: &str| k.contains("function") || k.contains("method");
                    let entries: Vec<&str> = graph
                        .symbols
                        .iter()
                        .filter(|s| named.contains(&s.name.as_str()) && is_fn(&s.kind))
                        .map(|s| s.name.as_str())
                        .collect();
                    if !entries.is_empty() {
                        lines.push(format!("entrypoints {}", entries.join(", ")));
                    }
                    // Hubs, the most wired symbols, calls in plus calls out.
                    let mut degree: Vec<(String, usize)> = Vec::new();
                    for s in &graph.symbols {
                        if s.kind.contains("function") || s.kind.contains("method") {
                            let d =
                                graph.callers_of(&s.name).len() + graph.calls_from(&s.name).len();
                            degree.push((s.name.clone(), d));
                        }
                    }
                    degree.sort_by_key(|(_, d)| std::cmp::Reverse(*d));
                    let hubs: Vec<String> = degree
                        .iter()
                        .take(5)
                        .filter(|(_, d)| *d > 0)
                        .map(|(n, d)| format!("{} {}", n, d))
                        .collect();
                    if !hubs.is_empty() {
                        lines.push(format!("hubs {}", hubs.join(", ")));
                    }
                    // Doc coverage per language, the loop closes itself.
                    for lang in &langs {
                        let syms: Vec<_> =
                            graph.symbols.iter().filter(|s| &s.lang == lang).collect();
                        let with_doc = syms.iter().filter(|s| !s.doc.is_empty()).count();
                        lines.push(format!("doc coverage {} {}/{}", lang, with_doc, syms.len()));
                    }
                    ok(id, text_result(lines.join("\n")));
                }
                "harmony.check" => {
                    let graph = match load_graph(&root) {
                        Ok(g) => g,
                        Err(e) => {
                            err(id, 1, &e);
                            return;
                        }
                    };
                    let reports =
                        harmony::check_workspace(&std::path::PathBuf::from(&root), &graph);
                    ok(id, text_result(report_lines(&reports)));
                }
                "harmony.staged" => {
                    let patch = args.get("patch").and_then(|v| v.as_str()).unwrap_or("");
                    let graph = match load_graph(&root) {
                        Ok(g) => g,
                        Err(e) => {
                            err(id, 1, &e);
                            return;
                        }
                    };
                    match harmony::check_staged(&std::path::PathBuf::from(&root), &graph, patch) {
                        Ok(reports) => ok(id, text_result(report_lines(&reports))),
                        Err(e) => err(id, 2, &format!("patch could not be parsed. {}", e)),
                    }
                }
                "grounding.plan" => {
                    let plan = args.get("plan").and_then(|v| v.as_str()).unwrap_or("");
                    let graph = match load_graph(&root) {
                        Ok(g) => g,
                        Err(e) => {
                            err(id, 1, &e);
                            return;
                        }
                    };
                    let verdict =
                        grounding::evaluate(plan, &graph, &std::path::PathBuf::from(&root));
                    ok(
                        id,
                        json!({ "content": [{ "type": "text", "text": serde_json::to_string_pretty(&verdict).unwrap_or_default() }] }),
                    );
                }
                "grounding.scaffold" => {
                    let plan = args.get("plan").and_then(|v| v.as_str()).unwrap_or("");
                    let dir = args.get("dir").and_then(|v| v.as_str()).unwrap_or(".");
                    match grounding::scaffold(plan, &std::path::PathBuf::from(dir)) {
                        Ok(files) => ok(id, text_result(format!("created:\n{}", files.join("\n")))),
                        Err(e) => err(id, 3, &format!("scaffold failed. {}", e)),
                    }
                }
                "deps.check" => {
                    let (reports, _network) = crate::deps::check(&std::path::PathBuf::from(&root));
                    if reports.is_empty() {
                        ok(id, text_result("no dependency findings".to_string()));
                    } else {
                        let lines: Vec<String> = reports
                            .iter()
                            .map(|r| format!("[{}] {}", r.severity, r.message))
                            .collect();
                        ok(id, text_result(lines.join("\n")));
                    }
                }
                "web.confirm" => {
                    let query = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
                    ok(id, text_result(grounding::web_confirm(query)));
                }
                _ => err(id, 4, &format!("unknown tool, {}", name)),
            }
        }
        _ => err(id, 3, &format!("unknown method, {}", method)),
    }
}

pub fn run() -> ExitCode {
    const MAX_MSG_BYTES: usize = 16 * 1024 * 1024;
    let stdin = std::io::stdin();
    let mut buf: Vec<u8> = Vec::new();
    let mut reader = stdin.lock();
    loop {
        buf.clear();
        // read_until is byte based, so binary junk on the wire can never
        // poison the stream the way a utf8 read line would.
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) => break,
            Ok(_) => {
                // A hostile or broken client must not be able to push the
                // process memory up with one unbounded message.
                if buf.len() > MAX_MSG_BYTES {
                    eprintln!("json rpc message too large, {} bytes dropped", buf.len());
                    continue;
                }
                let trimmed = String::from_utf8_lossy(&buf);
                let trimmed = trimmed.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let msg: Value = match serde_json::from_str(trimmed) {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("invalid json rpc message: {}", e);
                        continue;
                    }
                };
                let id = msg.get("id").cloned().unwrap_or(Value::Null);
                let method = msg.get("method").and_then(|v| v.as_str()).unwrap_or("");
                let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));
                handle(&id, method, &params);
            }
            Err(e) => {
                eprintln!("stdin error: {}", e);
                break;
            }
        }
    }
    ExitCode::SUCCESS
}
