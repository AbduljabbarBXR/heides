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

/// Findings as text, folded by default and split into evidence and advice.
///
/// An agent pays for every token it reads, so the MCP surface collapses unless
/// the caller asks for everything with `all: true`. A 126 line wall of one
/// sentence is how an agent burns its budget and misses the one finding that
/// mattered.
fn report_lines(reports: &[harmony::GuardReport], expand: bool) -> String {
    if reports.is_empty() {
        return "no findings. the workspace is clean.".to_string();
    }
    let mut lines = vec![harmony::summarize(reports)];
    let (proof, advice): (Vec<&harmony::GuardReport>, Vec<&harmony::GuardReport>) = reports
        .iter()
        .partition(|r| harmony::bucket_report(r) == harmony::Bucket::Proof);
    for (label, group) in [("evidence", &proof), ("advice", &advice)] {
        if group.is_empty() {
            continue;
        }
        lines.push(String::new());
        lines.push(format!("{}:", label));
        for line in harmony::collapse(group, expand) {
            match line {
                harmony::Line::One(r) => {
                    let loc = if r.file.is_empty() {
                        String::new()
                    } else {
                        format!(" at {}:{}", r.file, r.line)
                    };
                    lines.push(format!(
                        "[{}] {} ({}){}",
                        r.severity, r.message, r.guard, loc
                    ));
                }
                harmony::Line::Many {
                    severity,
                    message,
                    guard,
                    count,
                    first,
                    files,
                    file_count,
                } => {
                    let loc = harmony::folded_location(first, &files, file_count);
                    lines.push(format!(
                        "[{}] {} x{} ({}){}",
                        severity, message, count, guard, loc
                    ));
                }
            }
        }
    }
    lines.join("\n")
}

/// The structured shape behind harmony.report. One object per finding with
/// the guard, severity, message, file and line, plus severity counts and a
/// clean flag so an agent can gate on the verdict without parsing prose.
/// Run a check with the per-call dependency arguments applied, then restore.
///
/// The previous version called `set_deps_enabled(false)`, which writes a
/// process global and never restores it. In a single-shot CLI that is fine. In
/// an MCP server, which handles many requests in one process, it meant one
/// client passing `offline: true` silently disabled the advisory lookup for
/// every later request from every client. An unrelated argument changing a
/// security setting is exactly the failure class this release exists to close,
/// so the override is now scoped to the call.
///
/// `require_advisories` is the per-call equivalent of the CLI flag of the same
/// name, and it defaults to true here: a human running `heides check` in a
/// terminal can see the posture line, while an agent may only read the result.
/// The safe default is the one that fails loudly.
fn check_policy(args: &serde_json::Value) -> crate::deps::DepsPolicy {
    let offline = args.get("offline").and_then(|v| v.as_bool());
    // Fail closed, and the floor is not the caller's to lower. A human at a
    // terminal can see the posture line and choose; an agent may only read the
    // result, so an agent must not be able to switch the gate off. An explicit
    // `require_advisories: false` is therefore refused rather than honoured,
    // because a default the caller can remove is not a guarantee.
    let require = match args.get("require_advisories").and_then(|v| v.as_bool()) {
        Some(false) => Some(true),
        other => other.or(Some(true)),
    };
    crate::deps::resolve_policy(offline.map(|o| !o), require, None)
}

fn report_json(reports: &[harmony::GuardReport], cov: &harmony::Coverage) -> String {
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for r in reports {
        *counts.entry(&r.severity).or_insert(0) += 1;
    }
    let findings: Vec<serde_json::Value> = reports
        .iter()
        .map(|r| {
            json!({
                "guard": r.guard,
                "severity": r.severity,
                "message": r.message,
                "file": r.file,
                "line": r.line,
            })
        })
        .collect();
    serde_json::to_string_pretty(&json!({
        "clean": reports.is_empty(),
        "coverage": {
            "files": cov.files,
            "files_read": cov.files_read,
            "languages": cov.languages,
            "taint_untested": cov.taint_untested,
            "no_grammar": cov.no_grammar,
            "unreadable": cov.unreadable,
            "receipt": cov.render(),
        },
        "counts": {
            "blocker": counts.get("blocker").copied().unwrap_or(0),
            "critical": counts.get("critical").copied().unwrap_or(0),
            "warning": counts.get("warning").copied().unwrap_or(0),
            "info": counts.get("info").copied().unwrap_or(0),
        },
        "findings": findings,
    }))
    .unwrap_or_default()
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
        "tools/list" => ok(id, json!({ "tools": tool_list() })),
        "tools/call" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            // Validated against the declared schema before dispatch, so a wrong
            // type is a request error rather than a silently coerced empty
            // string that reads as a fact about the codebase.
            if let Err(e) = validate_args(name, &args) {
                err(id, 2, &e);
                return;
            }
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
                    let policy = check_policy(&args);
                    let (reports, cov) = harmony::check_workspace_with_coverage(
                        &std::path::PathBuf::from(&root),
                        &graph,
                        policy,
                    );
                    let expand = args.get("all").and_then(|v| v.as_bool()) == Some(true);
                    let mut out = format!("{}\n\n{}", report_lines(&reports, expand), cov.render());
                    // The MCP equivalent of a non-zero exit. An agent cannot see
                    // an exit code, so a gate that would fail on the CLI has to
                    // fail here too, or the MCP surface is the hollow one.
                    if policy.require_advisories && cov.deps != harmony::DepsState::RanOnline {
                        out.push_str(
                            "\nheides: require_advisories was set but the advisory lookup did not run. this run is not a security gate.",
                        );
                    }
                    if out.contains("not a security gate") {
                        err(id, 1, &out);
                    } else {
                        ok(id, text_result(out));
                    }
                }
                "harmony.report" => {
                    let graph = match load_graph(&root) {
                        Ok(g) => g,
                        Err(e) => {
                            err(id, 1, &e);
                            return;
                        }
                    };
                    let policy = check_policy(&args);
                    let (reports, cov) = harmony::check_workspace_with_coverage(
                        &std::path::PathBuf::from(&root),
                        &graph,
                        policy,
                    );
                    let mut j = report_json(&reports, &cov);
                    // The receipt travels inside the JSON, because an agent
                    // that receives a clean result must be able to see what was
                    // skipped without a second call. So does the gate verdict,
                    // for the same reason.
                    let gate_failed =
                        policy.require_advisories && cov.deps != harmony::DepsState::RanOnline;
                    let inject = format!(
                        "{{\"require_advisories\":{},\"security_gate\":{},\"security_posture\":\"{}\"}}",
                        policy.require_advisories,
                        !gate_failed,
                        cov.deps.as_str()
                    );
                    j.pop();
                    let tail: String = inject.chars().skip(1).collect();
                    j.push_str(&format!(",{}", tail));
                    if gate_failed {
                        err(id, 1, &j);
                    } else {
                        ok(id, text_result(j));
                    }
                }
                "harmony.staged" => {
                    let expand = args.get("all").and_then(|v| v.as_bool()) == Some(true);
                    let patch = args.get("patch").and_then(|v| v.as_str()).unwrap_or("");
                    let graph = match load_graph(&root) {
                        Ok(g) => g,
                        Err(e) => {
                            err(id, 1, &e);
                            return;
                        }
                    };
                    match harmony::check_staged(&std::path::PathBuf::from(&root), &graph, patch) {
                        Ok(reports) => ok(id, text_result(report_lines(&reports, expand))),
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
                "harmony.verify" => {
                    let want_json = args.get("json").and_then(|v| v.as_bool()).unwrap_or(false);
                    let p = std::path::PathBuf::from(&root);
                    let v = crate::verify::verify(&p, false, crate::deps::require_advisories());
                    let body = if want_json {
                        crate::verify::to_json(&v)
                    } else {
                        crate::verify::render(&v)
                    };
                    // A failed definition of done is reported as an MCP error, not
                    // as text saying it failed. An agent that only inspects the
                    // error field would otherwise read a failed gate as a
                    // successful call, which is the exact failure this tool
                    // exists to prevent.
                    if v.ok {
                        ok(id, text_result(body));
                    } else {
                        err(id, 5, &body);
                    }
                }
                "db.schema" | "db.tables" | "db.calls" => {
                    let p = std::path::PathBuf::from(&root);
                    let g = match crate::db::index_schema(&p) {
                        Ok(g) => g,
                        Err(e) => {
                            err(id, 6, &format!("database: {e}"));
                            return;
                        }
                    };
                    if g.tables.is_empty() && g.calls.is_empty() {
                        ok(
                            id,
                            text_result(format!(
                                "no database found under {}. looked for .sql files and \
                                 migration directories, and for ORM or raw SQL call sites",
                                p.display()
                            )),
                        );
                        return;
                    }
                    match name {
                        "db.schema" => {
                            let findings = crate::db::guard_reports(&p, &g);
                            let mut out = format!(
                                "{} table(s), {} call site(s)\n",
                                g.tables.len(),
                                g.calls.len()
                            );
                            if findings.is_empty() {
                                out.push_str("schema: no findings\n");
                            }
                            for (guard, sev, msg) in &findings {
                                out.push_str(&format!("[{sev}] {msg} ({guard})\n"));
                            }
                            if findings.is_empty() {
                                ok(id, text_result(out));
                            } else {
                                err(id, 5, &out);
                            }
                        }
                        "db.tables" => {
                            let mut out = String::new();
                            for (t, (reads, writes)) in crate::db::tables_report(&g) {
                                out.push_str(&format!("{t}: {reads} read, {writes} write\n"));
                            }
                            let orphans = crate::db::orphans(&g);
                            if !orphans.is_empty() {
                                out.push_str(&format!(
                                    "\nnot touched and not referenced: {}\n",
                                    orphans.join(", ")
                                ));
                            }
                            ok(id, text_result(out));
                        }
                        _ => {
                            let only = args.get("table").and_then(|v| v.as_str()).unwrap_or("");
                            let want_op = args.get("op").and_then(|v| v.as_str()).unwrap_or("");
                            let mut out = String::new();
                            for c in &g.calls {
                                if !only.is_empty() && !crate::db::table_names_match(&c.table, only)
                                {
                                    continue;
                                }
                                if !want_op.is_empty() && c.op.as_str() != want_op {
                                    continue;
                                }
                                // The enclosing function is what makes a call
                                // site actionable, so it leads.
                                out.push_str(&format!(
                                    "{} {} in {} at {}:{}\n",
                                    c.op.as_str(),
                                    c.table,
                                    if c.fn_name.is_empty() {
                                        "file scope"
                                    } else {
                                        &c.fn_name
                                    },
                                    c.file,
                                    c.line
                                ));
                            }
                            if out.is_empty() {
                                out = "no matching call sites\n".to_string();
                            }
                            ok(id, text_result(out));
                        }
                    }
                }
                "db.routes" | "db.touch" => {
                    let p = std::path::PathBuf::from(&root);
                    let g = match crate::db::index_schema(&p) {
                        Ok(g) => g,
                        Err(e) => {
                            err(id, 6, &format!("database: {e}"));
                            return;
                        }
                    };
                    let code = match spine::load(&p) {
                        Ok(c) => c,
                        Err(e) => {
                            err(
                                id,
                                6,
                                &format!(
                                    "no code index under {}. run spine.scan first ({e})",
                                    p.display()
                                ),
                            );
                            return;
                        }
                    };
                    let files: Vec<String> = code.files.iter().map(|f| f.path.clone()).collect();
                    let eps = crate::frameworks::endpoints(&files, &p);
                    let surface = crate::frameworks::api_surface(&code, &g, &eps, 6);
                    if name == "db.routes" {
                        if surface.endpoints.is_empty() {
                            ok(
                                id,
                                text_result(
                                    "no routes recognised. recognises Express and Fastify, \
                                     Flask and Django, and Go net/http"
                                        .to_string(),
                                ),
                            );
                            return;
                        }
                        let mut out = String::new();
                        for e in &surface.endpoints {
                            out.push_str(&format!(
                                "{} {} -> {} at {}:{}\n",
                                e.method, e.path, e.handler, e.file, e.line
                            ));
                            out.push_str(&format!(
                                "  writes {}\n",
                                surface.reachable_tables(&e.method, &e.path).join(", ")
                            ));
                            out.push_str(&format!(
                                "  reads {}\n",
                                surface.readable_tables(&e.method, &e.path).join(", ")
                            ));
                        }
                        ok(id, text_result(out));
                    } else {
                        let method = args
                            .get("method")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_ascii_uppercase();
                        if method.is_empty() {
                            err(id, 4, "db.touch needs a method");
                            return;
                        }
                        let want = args.get("path").and_then(|v| v.as_str());
                        let path = match want {
                            Some(p) => p.to_string(),
                            None => match surface.endpoints.iter().find(|e| e.method == method) {
                                Some(e) => e.path.clone(),
                                None => {
                                    err(id, 4, &format!("no {} route here", method));
                                    return;
                                }
                            },
                        };
                        if !surface
                            .endpoints
                            .iter()
                            .any(|e| e.method == method && e.path == path)
                        {
                            let known: Vec<String> = surface
                                .endpoints
                                .iter()
                                .filter(|e| e.path == path)
                                .map(|e| e.method.clone())
                                .collect();
                            let extra = if known.is_empty() {
                                String::new()
                            } else {
                                format!(". {} is registered as {}", path, known.join(", "))
                            };
                            err(id, 4, &format!("no route {} {}{}", method, path, extra));
                            return;
                        }
                        let key = format!("{} {}", method, path);
                        let mut out = String::new();
                        match surface.writes.get(&key) {
                            Some(v) if !v.is_empty() => {
                                for r in v {
                                    out.push_str(&format!(
                                        "writes {} via {}\n  at {}:{} ({})\n",
                                        surface.resolve_table(&r.table),
                                        r.via,
                                        r.file,
                                        r.line,
                                        r.depth_hop()
                                    ));
                                }
                            }
                            _ => out.push_str(&format!("{} {} writes no table\n", method, path)),
                        }
                        if let Some(v) = surface.reads.get(&key) {
                            for r in v {
                                out.push_str(&format!(
                                    "reads {} via {}\n  at {}:{}\n",
                                    surface.resolve_table(&r.table),
                                    r.via,
                                    r.file,
                                    r.line
                                ));
                            }
                        }
                        ok(id, text_result(out));
                    }
                }
                "config.scan" => {
                    // The credential value never leaves the process. Only the
                    // key, file, line, severity and a shape description cross the
                    // wire, and the JSON form is held to the same rule, since it
                    // is the form an agent parses into a transcript.
                    let want_json = args.get("json").and_then(|v| v.as_bool()).unwrap_or(false);
                    let p = std::path::PathBuf::from(&root);
                    let findings = crate::config::scan(&p);
                    if want_json {
                        let arr: Vec<Value> = findings
                            .iter()
                            .map(|f| {
                                json!({
                                    "key": f.key,
                                    "kind": f.kind,
                                    "file": f.file,
                                    "line": f.line,
                                    "severity": f.severity,
                                    "message": f.message
                                })
                            })
                            .collect();
                        let critical = findings.iter().filter(|f| f.severity == "critical").count();
                        ok(
                            id,
                            text_result(
                                json!({
                                    "scanned": crate::config::collect_config_files(&p, 8).len(),
                                    "findings": arr,
                                    "critical": critical,
                                })
                                .to_string(),
                            ),
                        );
                        return;
                    }
                    let mut out = format!("{}\n", crate::config::summarise(&p));
                    if findings.is_empty() {
                        // The summary already said so; nothing to add, and an
                        // empty list under a clean header is the right shape.
                        ok(id, text_result(out));
                        return;
                    }
                    for f in &findings {
                        out.push_str(&format!(
                            "[{}] {}:{} {} ({})\n",
                            f.severity, f.file, f.line, f.message, f.kind
                        ));
                    }
                    // A critical credential is reported as an error so an agent
                    // inspecting only the error field cannot read a repository
                    // with a live key as a successful scan.
                    if findings.iter().any(|f| f.severity == "critical") {
                        err(id, 5, &out);
                    } else {
                        ok(id, text_result(out));
                    }
                }
                "deps.tree" => {
                    let min_depth = args.get("min_depth").and_then(|v| v.as_u64()).unwrap_or(1);
                    let p = std::path::PathBuf::from(&root);
                    let graphs = crate::deps::read_lock_graphs(&p);
                    if graphs.is_empty() {
                        ok(
                            id,
                            text_result(format!(
                                "no lockfile found under {}. looked for package-lock.json, \
                                 yarn.lock, pnpm-lock.yaml, poetry.lock, go.sum, Gemfile.lock, \
                                 Cargo.lock",
                                p.display()
                            )),
                        );
                        return;
                    }
                    let mut out = String::new();
                    for g in &graphs {
                        let (reachable, orphan) = g.reachability();
                        out.push_str(&format!(
                            "{}: {} package(s), {} reachable, {} unreachable\n",
                            g.source,
                            g.nodes.len(),
                            reachable,
                            orphan
                        ));
                        for n in g.deepest(min_depth) {
                            out.push_str(&format!(
                                "  {} {} ({} levels, {})\n",
                                n.name,
                                n.version,
                                n.depth.unwrap_or(0),
                                n.path.join(" -> ")
                            ));
                        }
                        for n in g.nodes.iter().filter(|n| n.depth.is_none()) {
                            out.push_str(&format!(
                                "  {} {} is in the lockfile but nothing reaches it\n",
                                n.name, n.version
                            ));
                        }
                    }
                    ok(id, text_result(out));
                }
                "deps.advisories" => {
                    let p = std::path::PathBuf::from(&root);
                    let graphs = crate::deps::read_lock_graphs(&p);
                    if graphs.is_empty() {
                        ok(
                            id,
                            text_result(format!(
                                "no lockfile found under {}, so no pinned version could be \
                                 checked",
                                p.display()
                            )),
                        );
                        return;
                    }
                    // An explicit cache_dir wins over the environment, so a test or
                    // a CI job can point at a seeded cache without mutating the
                    // caller's environment.
                    let dir = args
                        .get("cache_dir")
                        .and_then(|v| v.as_str())
                        .map(std::path::PathBuf::from);
                    let dir = dir.or_else(crate::osv_cache::cache_dir);
                    if dir.is_none() {
                        ok(
                            id,
                            text_result(
                                "no cache directory could be resolved, so nothing was checked. \
                                 set HEIDES_CACHE_DIR or pass cache_dir"
                                    .to_string(),
                            ),
                        );
                        return;
                    }
                    let policy = crate::osv_cache::CachePolicy {
                        enabled: true,
                        allow_offline: true,
                        ..Default::default()
                    };
                    let mut out = String::new();
                    let mut health = crate::osv_cache::CacheHealth::default();
                    for g in &graphs {
                        for n in &g.nodes {
                            let answer = crate::osv_cache::consult(
                                policy,
                                dir.as_deref(),
                                n.ecosystem,
                                &n.name,
                                &n.version,
                            );
                            match answer {
                                Some(crate::osv_cache::Answer::Found {
                                    detail,
                                    cached,
                                    age_secs,
                                }) => {
                                    let age = age_secs
                                        .map(crate::osv_cache::human_age)
                                        .unwrap_or_default();
                                    out.push_str(&format!(
                                        "[critical] {} {} is vulnerable, {detail}{}\n",
                                        n.name,
                                        n.version,
                                        if cached {
                                            format!(
                                                " (from cache{})",
                                                if age.is_empty() {
                                                    String::new()
                                                } else {
                                                    format!(" {age} old")
                                                }
                                            )
                                        } else {
                                            String::new()
                                        }
                                    ));
                                    health.note_hit(age_secs);
                                }
                                Some(crate::osv_cache::Answer::Clean { cached, age_secs }) => {
                                    let age = age_secs
                                        .map(crate::osv_cache::human_age)
                                        .unwrap_or_default();
                                    out.push_str(&format!(
                                        "[info] {} {} has no known advisory{}\n",
                                        n.name,
                                        n.version,
                                        if cached {
                                            format!(
                                                " (from cache{})",
                                                if age.is_empty() {
                                                    String::new()
                                                } else {
                                                    format!(" {age} old")
                                                }
                                            )
                                        } else {
                                            String::new()
                                        }
                                    ));
                                    health.note_hit(age_secs);
                                }
                                Some(crate::osv_cache::Answer::NotChecked { .. }) => {
                                    health.note_stale();
                                    out.push_str(&format!(
                                        "[warning] {} {} was not checked, the cached answer expired\n",
                                        n.name, n.version
                                    ));
                                }
                                None => {
                                    health.note_miss();
                                    out.push_str(&format!(
                                        "[warning] {} {} was not checked, no cached advisory\n",
                                        n.name, n.version
                                    ));
                                }
                            }
                        }
                    }
                    out.push_str(&format!(
                        "\nadvisory cache: {} answered, {} with no entry, {} expired\n",
                        health.hits, health.misses, health.stale
                    ));
                    // A vulnerability is an error; an incomplete check is not,
                    // because the warnings above already say what was not looked
                    // at and a caller that wanted a hard gate has one in `verify`.
                    if out.contains("[critical]") {
                        err(id, 5, &out);
                    } else {
                        ok(id, text_result(out));
                    }
                }
                "spine.changed_since" => {
                    let since = args.get("since").and_then(|v| v.as_u64()).unwrap_or(0);
                    let p = std::path::PathBuf::from(&root);
                    let code = match spine::load(&p) {
                        Ok(c) => c,
                        Err(e) => {
                            err(
                                id,
                                6,
                                &format!(
                                    "no code index under {}. run spine.scan first ({e})",
                                    p.display()
                                ),
                            );
                            return;
                        }
                    };
                    let mut changed: Vec<&spine::FileEntry> =
                        code.files.iter().filter(|f| f.mtime > since).collect();
                    changed.sort_by(|a, b| a.path.cmp(&b.path));
                    if changed.is_empty() {
                        ok(
                            id,
                            text_result(format!(
                                "no indexed file changed after {}. nothing to reindex",
                                since
                            )),
                        );
                        return;
                    }
                    let mut out = format!("{} file(s) changed after {}\n", changed.len(), since);
                    for f in changed {
                        out.push_str(&format!("{} ({})\n", f.path, f.lang));
                    }
                    ok(id, text_result(out));
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

/// The declared tool list, as a value.
///
/// Kept as one function so the schema validator reads the same declarations the
/// client sees. Validating against a second hand written copy is how a tool ends
/// up declared with one schema and dispatched with another.
fn tool_list() -> Value {
    json!([
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
                            "description": "Run every guard on the workspace and return findings with evidence. Pass offline true to skip the dependency guard registry lookups. Returns an error, not a clean result, when require_advisories is true and the advisory lookup did not run, so a misconfigured gate fails instead of passing hollow.",
                            "inputSchema": { "type": "object", "properties": { "root": { "type": "string" }, "offline": { "type": "boolean", "description": "skip the dependency guard registry lookups" }, "require_advisories": { "type": "boolean", "description": "fail rather than return a clean result when advisories were not checked. Defaults to true, and a caller cannot lower it: an agent may only read the result, so the gate is fail closed on this surface." }, "all": { "type": "boolean", "description": "print every finding instead of folding identical ones. Folded by default, because a wall of identical lines is how an agent misses the one finding that mattered" } } }
                        },
                        {
                            "name": "harmony.report",
                            "description": "Run every guard on the workspace and return findings as structured JSON with severity counts, plus security_gate and security_posture so an agent can gate on the verdict without parsing prose. Pass offline true to skip the registry lookups.",
                            "inputSchema": { "type": "object", "properties": { "root": { "type": "string" }, "offline": { "type": "boolean", "description": "skip the dependency guard registry lookups" }, "require_advisories": { "type": "boolean", "description": "fail rather than return a clean result when advisories were not checked. Defaults to true, and a caller cannot lower it: an agent may only read the result, so the gate is fail closed on this surface." }, "all": { "type": "boolean", "description": "print every finding instead of folding identical ones. Folded by default, because a wall of identical lines is how an agent misses the one finding that mattered" } } }
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
                        },
                        {
                            "name": "harmony.verify",
                            "description": "Run the workspace tests plus every guard and return a machine checkable definition of done. This is the stopping condition for an autonomous loop: a clean result means the change is finished, not that nothing was inspected. Returns NOT VERIFIED with reasons when anything fails. Pass json true for a boolean to branch on.",
                            "inputSchema": { "type": "object", "properties": { "root": { "type": "string" }, "json": { "type": "boolean", "description": "return the verdict as json with an ok field" } } }
                        },
                        {
                            "name": "db.schema",
                            "description": "Parse the SQL schema and migration directories into a schema graph and report what is wrong with it: cyclic foreign keys, missing indexes, tables with no primary key, and sensitive columns. Exits non zero when there are findings.",
                            "inputSchema": { "type": "object", "properties": { "root": { "type": "string" } } }
                        },
                        {
                            "name": "db.tables",
                            "description": "List every table with how many reads and writes reach it. A table with zero of both is an orphan: no code touches it and nothing references it.",
                            "inputSchema": { "type": "object", "properties": { "root": { "type": "string" } } }
                        },
                        {
                            "name": "db.calls",
                            "description": "Every table read or write with its file, line and the source text that produced it. Use table to filter to one table.",
                            "inputSchema": { "type": "object", "properties": { "root": { "type": "string" }, "table": { "type": "string" }, "op": { "type": "string", "enum": ["read", "write"] } } }
                        },
                        {
                            "name": "db.routes",
                            "description": "Every recognised route with the tables it reads and writes, resolved through the call graph from handler to service to table. Recognises Express and Fastify, Flask and Django, and Go net/http.",
                            "inputSchema": { "type": "object", "properties": { "root": { "type": "string" } } }
                        },
                        {
                            "name": "db.touch",
                            "description": "What one endpoint writes. Answers the question an agent asks before changing a route, in one call instead of a dozen file reads. Errors when the route does not exist, because a route that writes nothing and a route that is missing are different answers.",
                            "inputSchema": { "type": "object", "properties": { "root": { "type": "string" }, "method": { "type": "string" }, "path": { "type": "string" } }, "required": ["method"] }
                        },
                        {
                            "name": "config.scan",
                            "description": "Find credentials committed in configuration files: .env, Dockerfile, Compose, Terraform, Kubernetes and Helm manifests, and ini files. The credential value is never returned, only the key, the file, the line and a description of the value's shape, because a report that echoes a secret has copied it into every log that reads the output. Reports a clean scan as clean and a workspace with no configuration files as such, because those are different facts. Pass json true for structured findings.",
                            "inputSchema": { "type": "object", "properties": { "root": { "type": "string" }, "json": { "type": "boolean", "description": "return findings as json" } } }
                        },
                        {
                            "name": "deps.tree",
                            "description": "Resolve the lockfile graph and report each package's depth and the path taken to reach it, plus any package nothing reaches. Answers which packages exist only because of something pulled in, which is what decides whether an advisory matters.",
                            "inputSchema": { "type": "object", "properties": { "root": { "type": "string" }, "min_depth": { "type": "integer", "description": "only list packages at or beyond this depth. Defaults to 1" } } }
                        },
                        {
                            "name": "deps.advisories",
                            "description": "Report the advisory status of every pinned package from the OSV cache. A package with no cache entry is reported as not checked, never as clean: an unchecked project and a project with no known vulnerabilities are different facts and an agent acting on the second would be wrong.",
                            "inputSchema": { "type": "object", "properties": { "root": { "type": "string" }, "cache_dir": { "type": "string", "description": "override the cache directory, otherwise HEIDES_CACHE_DIR or the XDG default" } } }
                        },
                        {
                            "name": "spine.changed_since",
                            "description": "List files modified after a unix timestamp, so a resuming agent can refresh only what moved instead of rereading the whole graph. Pass the timestamp from the previous session.",
                            "inputSchema": { "type": "object", "properties": { "root": { "type": "string" }, "since": { "type": "integer", "description": "unix seconds; defaults to 0, which returns every indexed file" } } }
                        }
    ])
}

/// Reject a call whose arguments do not match the declared schema.
///
/// Silently coercing a wrong type to an empty string is worse than an error here:
/// `spine.query` with `name: []` would answer "no recorded callers for ", which
/// reads as a fact about the codebase rather than a mistake in the request. An
/// agent that trusts that answer acts on a false one, and never learns to fix
/// the call.
fn validate_args(tool: &str, args: &Value) -> Result<(), String> {
    // A bare array now, so this is a direct index rather than a pointer walk.
    let tools = tool_list();
    let tools = tools.as_array().map(|a| a.as_slice()).unwrap_or(&[]);
    let Some(decl) = tools
        .iter()
        .find(|t| t.get("name").and_then(|n| n.as_str()) == Some(tool))
    else {
        return Ok(());
    };
    let Some(schema) = decl.get("inputSchema") else {
        return Ok(());
    };

    for req in schema
        .get("required")
        .and_then(|r| r.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
        .unwrap_or_default()
    {
        if args.get(req).map(|v| v.is_null()).unwrap_or(true) {
            return Err(format!("{tool} needs a {req}"));
        }
    }

    let Some(props) = schema.get("properties").and_then(|p| p.as_object()) else {
        return Ok(());
    };
    for (key, value) in args.as_object().into_iter().flatten() {
        let Some(spec) = props.get(key) else {
            // An undeclared argument is not an error: clients add fields, and a
            // strict server here would break on a harmless extra.
            continue;
        };
        let want = spec.get("type").and_then(|t| t.as_str()).unwrap_or("");
        let ok = match want {
            "string" => value.is_string(),
            "boolean" => value.is_boolean(),
            "integer" => value.is_i64() || value.is_u64(),
            // A schema that does not name a type accepts anything.
            _ => true,
        };
        if !ok {
            return Err(format!(
                "{tool} argument {key} must be {want}, got {}",
                match value {
                    serde_json::Value::Null => "null",
                    serde_json::Value::Bool(_) => "a boolean",
                    serde_json::Value::Number(_) => "a number",
                    serde_json::Value::String(_) => "a string",
                    serde_json::Value::Array(_) => "an array",
                    serde_json::Value::Object(_) => "an object",
                }
            ));
        }
    }
    Ok(())
}
