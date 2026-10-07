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
/// Trim a tool result to a byte budget the caller sets with `max_bytes`.
///
/// A tool result lands in the model's context in full, so an unbounded one is a
/// way to lose the conversation rather than spend tokens in it. The cut lands on
/// a line boundary and says how much was dropped, so a caller that hit the cap
/// knows to narrow the question instead of assuming the answer was complete.
fn cap_bytes(text: &str, limit: Option<&Value>) -> String {
    let Some(limit) = limit.and_then(|v| v.as_u64()) else {
        return text.to_string();
    };
    let cap = limit as usize;
    if cap == 0 || text.len() <= cap {
        return text.to_string();
    }
    let mut cut = cap.min(text.len());
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    // Prefer dropping whole lines rather than one truncated line of evidence.
    let cut = match text[..cut].rfind('\n') {
        Some(i) if i > cap / 2 => i,
        _ => cut,
    };
    let mut out = text[..cut].to_string();
    out.push_str(&format!(
        "\n\n[truncated to {cap} bytes by max_bytes. {} bytes not shown. \
         Narrow the question, raise max_bytes, or pass advice=false.]",
        text.len() - cut
    ));
    out
}

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
///
/// This used to run the check with per-call dependency arguments applied and
/// then restore them. The policy helper it called set a process global, which
/// in a single-shot CLI is fine and in an MCP server is not: one client
/// passing an argument changed the behaviour of every later request from every
/// client. The lesson outlives the helper, because the next setting an agent
/// can pass will have the same shape. A setting that changes behaviour is
/// scoped to the call that asked for it, never to the process.
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
                "spine.help" => {
                    // The long guidance `tools/list` deliberately left out.
                    let help = tool_help(args.get("topic").and_then(|v| v.as_str()));
                    ok(id, text_result(help.to_string()))
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
                    let (reports, cov) = harmony::check_workspace_with_coverage(
                        &std::path::PathBuf::from(&root),
                        &graph,
                    );
                    let expand = args.get("all").and_then(|v| v.as_bool()) == Some(true);
                    // An agent pays for every byte of this in its context, and
                    // the advice bucket is style opinion rather than evidence:
                    // on this repository `--no-advice` is an 84% cut and every
                    // blocker, critical and warning survives it. So the MCP
                    // surface defaults to evidence only, and `advice: true`
                    // asks the rest back. The CLI keeps its current default
                    // because a human at a terminal reads the whole receipt.
                    let want_advice = args.get("advice").and_then(|v| v.as_bool()) == Some(true);
                    let scoped: Vec<harmony::GuardReport> = if want_advice {
                        reports.clone()
                    } else {
                        harmony::without_advice(&reports)
                            .into_iter()
                            .cloned()
                            .collect()
                    };
                    let out = format!("{}\n\n{}", report_lines(&scoped, expand), cov.render());
                    let out = cap_bytes(&out, args.get("max_bytes"));
                    // The MCP equivalent of a non-zero exit, and the property that
                    // matters most on this surface: an agent cannot see an exit
                    // code, so a gate that would fail on the command line has to
                    // fail here too. Returning the findings as a normal result
                    // would hand an agent a successful tool call whose text
                    // contains criticals, which is the hollow outcome the whole
                    // design exists to prevent.
                    //
                    // This used to key off the advisory gate. That guard is gone,
                    // but the fail-closed behaviour is not: it belongs to the
                    // tool, not to the one guard that needed it.
                    if harmony::exceeds(&reports, harmony::exit_threshold()) {
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
                    let (reports, cov) = harmony::check_workspace_with_coverage(
                        &std::path::PathBuf::from(&root),
                        &graph,
                    );
                    // The receipt travels inside the JSON, because an agent that
                    // receives a clean result must be able to see how much was
                    // actually inspected without a second call.
                    //
                    // `security_gate` reports the real verdict rather than a
                    // constant true. It used to be the advisory gate, and it is
                    // now the exit threshold, which is the property an agent
                    // actually branches on.
                    let gate_failed = harmony::exceeds(&reports, harmony::exit_threshold());
                    let mut j = report_json(&reports, &cov);
                    j.pop();
                    j.push_str(&format!(
                        ",\"security_gate\":{},\"security_posture\":\"local_only\"}}",
                        !gate_failed
                    ));
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
                "web.confirm" => {
                    let query = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
                    ok(id, text_result(grounding::web_confirm(query)));
                }
                "harmony.verify" => {
                    let want_json = args.get("json").and_then(|v| v.as_bool()).unwrap_or(false);
                    let p = std::path::PathBuf::from(&root);
                    let v = crate::verify::verify(&p, false);
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
                "deps.tree" | "deps.check" | "deps.advisories" => {
                    // Every deps tool is gone, and so is the capability behind them.
                    // They answered one question, whether a pinned version is a known
                    // CVE. Answering it meant either the network, which made a gate's
                    // verdict depend on network conditions rather than on the tree, or a
                    // cache that expired a clean answer after 24 hours. A guard that
                    // cannot tell no vulnerability from has not heard of it yet reports
                    // false confidence, and false confidence is indistinguishable from a
                    // pass.
                    //
                    // The refusal is explicit rather than an unknown-tool error, so an
                    // agent trained on these names learns where the capability went
                    // instead of concluding the server is broken.
                    err(
                        id,
                        4,
                        "this tool is gone. heides no longer checks dependencies for known CVEs, because that is a fact about the world rather than about the code, and answering it here meant either the network or a cache that reported a CVE published this morning as clean. use GRIM for dependencies, secrets and exposure: grim-mcp. heides still reports taint, hardcoded secrets, edge cases, schema defects and config credentials, all provable from the files it read.",
                    );
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
fn tool_help(topic: Option<&str>) -> Value {
    const HELP: &[(&str, &str)] = &[
        (
            "harmony.check",
            "Runs every guard offline. Evidence only by default: style advice is dropped, an 84% cut on this repository with every blocker, critical and warning intact. Pass advice=true to get it back. Dependency and exposure analysis is deliberately absent: use GRIM for that. max_bytes trims the result and says how much it dropped.",
        ),
        (
            "harmony.verify",
            "Runs the workspace tests plus every guard and returns a machine-checkable definition of done. This is the stopping condition for an autonomous loop: clean means finished, not that nothing was inspected. Returns NOT VERIFIED with reasons when anything fails. Pass json=true for a boolean to branch on.",
        ),
        (
            "harmony.report",
            "Folds identical findings together by default, because a wall of identical lines is how an agent misses the one finding that mattered. Pass all=true to print every finding separately.",
        ),
        (
            "db.schema",
            "Parses SQL schema and migration directories into a schema graph: cyclic foreign keys, missing indexes, tables with no primary key, sensitive columns. Exits non-zero when there are findings.",
        ),
        (
            "db.tables",
            "Lists every table with how many reads and writes reach it. A table with zero of both is an orphan: no code touches it and nothing references it.",
        ),
        (
            "spine.query",
            "Asks the graph for callers, imports, definition, calls out, or a search. kind is one of: callers, imports, definition, calls, search.",
        ),
        (
            "spine.describe",
            "Reads the whole workspace manifest in one shot: languages, symbol counts, entrypoints, hubs, doc coverage per language. Also states which files were not indexed and why.",
        ),
        (
            "spine.neighbors",
            "Shows every side of a symbol: definition with its captured doc, callers, and calls out.",
        ),
        (
            "spine.impact",
            "The set heides can reach from a symbol, how much of it is untested, whether an HTTP route is behind it, and whether anything that would catch a regression actually calls it. Caller counts are name-keyed: when the output says upper bound, several definitions share the name.",
        ),
        (
            "spine.coverage",
            "Which languages in this workspace can actually fire a rule, and which are merely recognised. A clean verdict covers only the files it says it read.",
        ),
        (
            "spine.contradictions",
            "Signals that cannot both be true: a route pointing at a handler nothing defines, or a symbol claimed dead that something reachable still calls.",
        ),
    ];
    let want = topic.unwrap_or("").trim();
    let out: Vec<Value> = HELP
        .iter()
        .filter(|(name, _)| want.is_empty() || want.eq_ignore_ascii_case(name))
        .map(|(name, text)| json!({ "tool": name, "guidance": text }))
        .collect();
    let note = if want.is_empty() {
        "Guidance for every tool. Ask for one by name to narrow it.".to_string()
    } else if out.is_empty() {
        format!("No guidance for `{want}`. Ask with no topic for the full list.")
    } else {
        format!("Guidance for {want}.")
    };
    json!({ "count": out.len(), "note": note, "tools": out })
}

fn tool_list() -> Value {
    json!([
                        {
                            "name": "spine.help",
                            "description": "Full guidance for any tool, on demand. tools/list carries one line each to keep the handshake cheap.",
                            "inputSchema": { "type": "object", "properties": { "topic": { "type": "string", "description": "tool name, or omit for all" } } }
                        },
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
                            "description": "Read the workspace manifest in one shot, including what was not indexed.",
                            "inputSchema": { "type": "object", "properties": { "root": { "type": "string" } } }
                        },
                        {
                            "name": "spine.neighbors",
                            "description": "Show every side of a symbol, definition with its captured doc, callers and calls out.",
                            "inputSchema": { "type": "object", "properties": { "name": { "type": "string" } }, "required": ["name"] }
                        },
                        {
                            "name": "harmony.check",
                            "description": "Run every guard offline and return findings with evidence. Call spine.help for details.",
                            "inputSchema": { "type": "object", "properties": { "root": { "type": "string" }, "offline": { "type": "boolean", "description": "skip the dependency guard registry lookups" }, "all": { "type": "boolean", "description": "print every finding instead of folding identical ones" }, "advice": { "type": "boolean", "description": "include style advice; off by default because it is opinion, not defect" }, "max_bytes": { "type": "integer", "description": "trim the result to this many bytes; truncation says how much it dropped" } } }
                        },
                        {
                            "name": "harmony.report",
                            "description": "Run every guard on the workspace and return findings as structured JSON with severity counts, plus security_gate and security_posture so an agent can gate on the verdict without parsing prose. Every guard is local and offline.",
                            "inputSchema": { "type": "object", "properties": { "root": { "type": "string" }, "offline": { "type": "boolean", "description": "skip the dependency guard registry lookups" }, "all": { "type": "boolean", "description": "print every finding instead of folding identical ones. Folded by default, because a wall of identical lines is how an agent misses the one finding that mattered" } } }
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
                            "name": "web.confirm",
                            "description": "Confirm a fact against package registries on the web.",
                            "inputSchema": { "type": "object", "properties": { "query": { "type": "string" } }, "required": ["query"] }
                        },
                        {
                            "name": "harmony.verify",
                            "description": "Tests plus guards: the definition of done, machine checkable. Call spine.help for details.",
                            "inputSchema": { "type": "object", "properties": { "root": { "type": "string" }, "json": { "type": "boolean", "description": "return the verdict as json with an ok field" } } }
                        },
                        {
                            "name": "db.schema",
                            "description": "Check the SQL schema for defects. Call spine.help for details.",
                            "inputSchema": { "type": "object", "properties": { "root": { "type": "string" } } }
                        },
                        {
                            "name": "db.tables",
                            "description": "List tables and their read/write reach. Call spine.help for details.",
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
