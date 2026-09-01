// The MCP server shell of HEIDES.
//
// HEIDES speaks the Model Context Protocol over stdio. Any MCP aware agent,
// editor, CLI or harness can attach to it: Claude Code, Codex, Cursor,
// VS Code, OpenCode, Hermes, custom builds. This one interface makes HEIDES
// available everywhere at once.
//
// This implementation handles the core JSON RPC lifecycle and exposes the
// first tools. Every message is one JSON object per line on stdin and
// stdout. Logging goes to stderr so the protocol stream stays clean.

use std::io::{BufRead, Write};
use std::process::ExitCode;

use serde_json::{json, Value};

use crate::grounding;
use crate::harmony;
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

fn handle(id: &Value, method: &str, params: &Value) {
    match method {
        "initialize" => {
            ok(id, json!({
                "protocolVersion": "2025-06-18",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "heides", "version": env!("CARGO_PKG_VERSION") }
            }));
        }
        "notifications/initialized" => {
            // no response is expected for a notification
        }
        "tools/list" => {
            ok(id, json!({
                "tools": [
                    {
                        "name": "spine.scan",
                        "description": "Map the current codebase into the persistent spine index.",
                        "inputSchema": { "type": "object", "properties": { "root": { "type": "string" } } }
                    },
                    {
                        "name": "harmony.check",
                        "description": "Run every guard and return warnings for the current state.",
                        "inputSchema": { "type": "object", "properties": {} }
                    },
                    {
                        "name": "grounding.plan",
                        "description": "Evaluate a plan against the codebase and return a verdict.",
                        "inputSchema": { "type": "object", "properties": { "plan": { "type": "string" } }, "required": ["plan"] }
                    }
                ]
            }));
        }
        "tools/call" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
            match name {
                "spine.scan" => {
                    let root = args.get("root").and_then(|v| v.as_str()).unwrap_or(".");
                    let graph = match spine::index(&std::path::PathBuf::from(root)) {
                        Ok(g) => g,
                        Err(e) => {
                            err(id, 1, &format!("scan failed: {}", e));
                            return;
                        }
                    };
                    ok(id, json!({ "content": [{ "type": "text", "text": format!("indexed {} files, {} symbols", graph.files.len(), graph.symbols.len()) }] }));
                }
                "harmony.check" => {
                    let graph = match spine::index(&std::path::PathBuf::from(".")) {
                        Ok(g) => g,
                        Err(e) => {
                            err(id, 1, &format!("scan failed: {}", e));
                            return;
                        }
                    };
                    let reports = harmony::run_all(&graph);
                    ok(id, json!({ "content": [{ "type": "text", "text": serde_json::to_string_pretty(&reports).unwrap_or_default() }] }));
                }
                "grounding.plan" => {
                    let plan = args.get("plan").and_then(|v| v.as_str()).unwrap_or("");
                    let verdict = grounding::evaluate(plan);
                    ok(id, json!({ "content": [{ "type": "text", "text": serde_json::to_string_pretty(&verdict).unwrap_or_default() }] }));
                }
                _ => err(id, 2, &format!("unknown tool: {}", name)),
            }
        }
        _ => err(id, 3, &format!("unknown method: {}", method)),
    }
}

pub fn run() -> ExitCode {
    let stdin = std::io::stdin();
    let mut line = String::new();
    let mut reader = stdin.lock();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let trimmed = line.trim();
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
