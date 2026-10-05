// MCP exposure for the config and dependency-tree layers.
//
// Both shipped as CLI commands and neither is reachable by an agent, which makes
// them features that only exist for a person at a terminal. That is the same gap
// the earlier MCP work closed for verify and the database layer.
//
// The tests are driven over the live stdio protocol rather than by calling the
// dispatch functions, because the thing that breaks is the wire: a tool declared
// in the list but not dispatched, or a schema that disagrees with the payload.
// Both are invisible to a test that calls the function directly.
//
// Every tool here gets a benign twin. A tool that cannot fail safely is not
// something to hand an agent.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

struct Session {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: i64,
}

impl Session {
    fn start(root: &Path) -> Session {
        let mut child = Command::new(env!("CARGO_BIN_EXE_heides"))
            .arg("mcp")
            .current_dir(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("heides mcp starts");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut s = Session {
            child,
            stdin,
            stdout,
            next_id: 0,
        };
        s.request("initialize", serde_json::json!({}));
        s
    }

    fn request(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        self.next_id += 1;
        writeln!(
            self.stdin,
            "{}",
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": self.next_id,
                "method": method,
                "params": params
            })
        )
        .expect("write");
        self.stdin.flush().ok();
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read");
        serde_json::from_str(line.trim()).unwrap_or_else(|e| panic!("not json ({e}): {line:?}"))
    }

    fn call(&mut self, name: &str, args: serde_json::Value) -> serde_json::Value {
        self.request(
            "tools/call",
            serde_json::json!({ "name": name, "arguments": args }),
        )
    }

    /// The text of a result, or the message of a protocol error.
    fn text(&mut self, name: &str, args: serde_json::Value) -> String {
        let v = self.call(name, args);
        if let Some(e) = v.get("error") {
            return e
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or_else(|| panic!("{name} errored with no message: {v}"))
                .to_string();
        }
        v.pointer("/result/content/0/text")
            .and_then(|t| t.as_str())
            .unwrap_or_else(|| panic!("{name} returned no text: {v}"))
            .to_string()
    }

    fn tools(&mut self) -> Vec<String> {
        let v = self.request("tools/list", serde_json::json!({}));
        let mut names: Vec<String> = v
            .pointer("/result/tools")
            .and_then(|t| t.as_array())
            .expect("tools array")
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
            .map(|s| s.to_string())
            .collect();
        names.sort();
        names
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn fixture(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("heides-mcp2-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(dir: &Path, rel: &str, body: &str) {
    let p = dir.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(p, body).unwrap();
}

/// A credential shaped like a live provider token, assembled at runtime so the
/// repository carries nothing that reads as a secret and push protection agrees.
fn live_token() -> String {
    format!("sk_{}{}", "live_", "0".repeat(24))
}

// ------------------------------------------------------------- the tool list

#[test]
fn the_new_capabilities_are_reachable_as_tools() {
    let dir = fixture("list");
    let mut s = Session::start(&dir);
    let tools = s.tools();
    // deps.tree and deps.advisories are gone with the rest of the dependency
    // surface. config.scan is what remains of that wave of capabilities.
    assert!(
        tools.iter().any(|t| t == "config.scan"),
        "config.scan must be reachable; have {tools:?}"
    );
}

#[test]
fn every_new_tool_declares_a_description_and_a_schema() {
    let dir = fixture("schemas");
    let mut s = Session::start(&dir);
    let v = s.request("tools/list", serde_json::json!({}));
    let tools = v
        .pointer("/result/tools")
        .unwrap()
        .as_array()
        .unwrap()
        .clone();
    for t in tools {
        let name = t.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        if !name.starts_with("config.") && !name.starts_with("deps.") {
            continue;
        }
        assert!(
            !t.get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .trim()
                .is_empty(),
            "tool {name} has no description"
        );
        assert!(
            t.get("inputSchema").is_some(),
            "tool {name} has no input schema"
        );
    }
}

// ------------------------------------------------------------------ config

#[test]
fn config_scan_reports_a_credential_without_echoing_it() {
    let dir = fixture("cfgfound");
    let secret = live_token();
    write(&dir, ".env", &format!("API_KEY={secret}\n"));
    let mut s = Session::start(&dir);
    let t = s.text("config.scan", serde_json::json!({ "root": "." }));
    assert!(t.contains("API_KEY"), "the key must be named: {t}");
    assert!(
        !t.contains(&secret),
        "the credential must never travel back in the result: {t}"
    );
}

#[test]
fn config_scan_says_so_when_there_is_no_configuration_file() {
    // Silence here would be read as a clean scan by an agent, and only one of the
    // two means the workspace was inspected.
    let dir = fixture("cfgnone");
    write(
        &dir,
        "a.js",
        "export function add(a, b) { return a + b; }\n",
    );
    let mut s = Session::start(&dir);
    let t = s.text("config.scan", serde_json::json!({ "root": "." }));
    assert!(
        t.to_lowercase().contains("no configuration file"),
        "an empty scan must be stated: {t}"
    );
}

#[test]
fn config_scan_is_quiet_about_placeholders() {
    let dir = fixture("cfgclean");
    write(
        &dir,
        ".env",
        "API_KEY=\nDB_PASSWORD=changeme\nHOME=/root\nAPI_KEY_REF=${API_KEY}\n",
    );
    let mut s = Session::start(&dir);
    let t = s.text("config.scan", serde_json::json!({ "root": "." }));
    assert!(
        t.to_lowercase().contains("no credentials found"),
        "placeholders are not credentials: {t}"
    );
}

#[test]
fn config_scan_returns_json_when_asked() {
    let dir = fixture("cfgjson");
    write(&dir, ".env", &format!("API_KEY={}\n", live_token()));
    let mut s = Session::start(&dir);
    let t = s.text(
        "config.scan",
        serde_json::json!({ "root": ".", "json": true }),
    );
    let v: serde_json::Value = serde_json::from_str(&t)
        .unwrap_or_else(|e| panic!("config --json was not json ({e}): {t}"));
    let findings = v
        .get("findings")
        .and_then(|f| f.as_array())
        .expect("findings array");
    assert_eq!(findings.len(), 1, "{t}");
    let f = &findings[0];
    assert_eq!(f.get("key").and_then(|k| k.as_str()), Some("API_KEY"));
    assert_eq!(f.get("severity").and_then(|s| s.as_str()), Some("critical"));
    assert!(f.get("line").is_some(), "a finding needs a line: {f}");
}

#[test]
fn config_scan_json_never_carries_the_credential() {
    // The JSON form is the one an agent parses, so it is the one most likely to
    // end up in a transcript. It must be as safe as the text form.
    let dir = fixture("cfgsafe");
    let secret = live_token();
    write(&dir, ".env", &format!("API_KEY={secret}\n"));
    let mut s = Session::start(&dir);
    let t = s.text(
        "config.scan",
        serde_json::json!({ "root": ".", "json": true }),
    );
    assert!(!t.contains(&secret), "the credential leaked into json: {t}");
}

// ------------------------------------------------------------------- deps

#[test]
fn every_removed_dependency_tool_refuses_instead_of_erroring() {
    // These three tests used to pin the lock graph: depth, reachability and an
    // empty tree stated rather than implied. All of that lived in the lockfile
    // parser, which is gone with the advisory guard because its only consumer
    // was the vulnerability question.
    //
    // The behaviour that matters now is that each removed name is refused
    // explicitly. `unknown tool` would be technically correct and practically
    // useless: an agent holding `deps.tree` in a plan would conclude the server
    // is broken rather than that the capability moved.
    let dir = fixture("treegone");
    let mut s = Session::start(&dir);
    for tool in ["deps.tree", "deps.check", "deps.advisories"] {
        let t = s.text(tool, serde_json::json!({ "root": "." }));
        let lower = t.to_lowercase();
        assert!(
            lower.contains("gone") || lower.contains("no longer"),
            "{tool} must refuse explicitly rather than report an unknown tool: {t}"
        );
        assert!(
            lower.contains("grim"),
            "{tool} must name where the capability went: {t}"
        );
    }
}

// ------------------------------------------------------------- protocol shape

#[test]
fn a_wrong_type_on_a_new_tool_is_rejected() {
    // The shared validator has to cover these like any other tool, or a bad
    // argument reads as a fact about the codebase.
    let dir = fixture("badtype");
    let mut s = Session::start(&dir);
    let v = s.request(
        "tools/call",
        serde_json::json!({
            "name": "spine.changed_since",
            "arguments": { "root": ".", "since": "yesterday" }
        }),
    );
    assert!(v.get("error").is_some(), "expected an error, got {v}");
}

#[test]
fn a_malformed_call_does_not_kill_the_session() {
    let dir = fixture("malformed");
    let mut s = Session::start(&dir);
    let _ = s.call("config.scan", serde_json::json!({ "root": [] }));
    let tools = s.tools();
    assert!(
        tools.contains(&"config.scan".to_string()),
        "the session must survive a bad call"
    );
}
