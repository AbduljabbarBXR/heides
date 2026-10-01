// The MCP surface must expose everything the CLI can answer.
//
// Everything Heides can do is currently reachable only by shelling out. An agent
// does not use a CLI productively: it can, but it has to re-describe the command
// in a prompt, parse prose back into a verdict, and guess again when the output
// changes shape. A tool with a schema does that work once.
//
// These tests are written against the live stdio protocol rather than against
// internal functions, because the thing that breaks in practice is the wire: a
// tool declared in the list but not dispatched, a result shaped one way in the
// schema and another in the payload, a new query kind that works in the CLI and
// is invisible to an agent. All three are invisible to a unit test that calls
// the function directly.
//
// Every tool added here needs a benign twin. A tool that cannot fail safely is
// not something to hand an agent.

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
        // The binary under test, not whatever is on PATH, so the suite tests
        // this build rather than an installed release.
        let binary = PathBuf::from(env!("CARGO_BIN_EXE_heides"));
        let mut child = Command::new(&binary)
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
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": self.next_id,
            "method": method,
            "params": params
        });
        writeln!(self.stdin, "{msg}").expect("write request");
        self.stdin.flush().ok();
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read response");
        let v: serde_json::Value = serde_json::from_str(line.trim())
            .unwrap_or_else(|e| panic!("response was not json ({e}): {line:?}"));
        v
    }

    fn call(&mut self, name: &str, args: serde_json::Value) -> serde_json::Value {
        self.request(
            "tools/call",
            serde_json::json!({ "name": name, "arguments": args }),
        )
    }

    /// The text of a tool result, or the message of an MCP error.
    ///
    /// Both are read deliberately. A failed definition of done and a missing
    /// route are reported as protocol errors rather than as text saying they
    /// failed, so that an agent inspecting only the error field cannot mistake
    /// a failed gate for a successful call. A test that only read content
    /// blocks would therefore miss a tool that stopped answering entirely.
    fn text(&mut self, name: &str, args: serde_json::Value) -> String {
        let v = self.call(name, args);
        if let Some(e) = v.get("error") {
            return e
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or_else(|| panic!("tool {name} errored with no message: {v}"))
                .to_string();
        }
        v.pointer("/result/content/0/text")
            .and_then(|t| t.as_str())
            .unwrap_or_else(|| panic!("tool {name} returned no text: {v}"))
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
    let dir = std::env::temp_dir().join(format!("heides-mcp-{name}"));
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

fn scan(dir: &Path) {
    let mut s = Session::start(dir);
    s.text("spine.scan", serde_json::json!({ "root": "." }));
}

// ------------------------------------------------------------- the tool list

#[test]
fn every_capability_is_reachable_as_a_tool() {
    let dir = fixture("list");
    write(&dir, "a.js", "function f() {}\n");
    let mut s = Session::start(&dir);
    let tools = s.tools();
    for expected in [
        "spine.scan",
        "spine.query",
        "spine.describe",
        "spine.neighbors",
        "harmony.check",
        "harmony.report",
        "harmony.staged",
        "grounding.plan",
        "grounding.scaffold",
        "deps.check",
        "web.confirm",
        // Tier 4 additions. Each one is a capability that exists in the binary
        // and was invisible to an agent before this.
        "harmony.verify",
        "db.schema",
        "db.tables",
        "db.calls",
        "db.routes",
        "db.touch",
        "spine.changed_since",
    ] {
        assert!(
            tools.iter().any(|t| t == expected),
            "missing tool {expected}; have {tools:?}"
        );
    }
}

#[test]
fn every_tool_declares_a_description_and_a_schema() {
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
        let desc = t.get("description").and_then(|d| d.as_str()).unwrap_or("");
        assert!(!desc.trim().is_empty(), "tool {name} has no description");
        assert!(
            t.get("inputSchema").is_some(),
            "tool {name} has no input schema"
        );
    }
}

// ------------------------------------------------------------- verify

#[test]
fn verify_reports_a_pass_as_a_verdict_not_prose() {
    let dir = fixture("verifyclean");
    write(
        &dir,
        "a.js",
        "export function add(a, b) { return a + b; }\n",
    );
    scan(&dir);
    let mut s = Session::start(&dir);
    let t = s.text("harmony.verify", serde_json::json!({ "root": "." }));
    assert!(
        t.contains("VERIFIED. definition of done met"),
        "a clean workspace must say so plainly: {t}"
    );
}

#[test]
fn verify_reports_a_planted_defect_as_a_failure() {
    let dir = fixture("verifybad");
    write(
        &dir,
        "a.py",
        "import subprocess\nsubprocess.call(cmd, shell=True)\n",
    );
    scan(&dir);
    let mut s = Session::start(&dir);
    let t = s.text("harmony.verify", serde_json::json!({ "root": "." }));
    // Substring matching is not enough here: "NOT VERIFIED" contains
    // "VERIFIED", so a naive absence check passes on the very output that
    // proves the gate works. The failing form is the one that matters.
    assert!(
        t.contains("NOT VERIFIED"),
        "a planted shell=True must not verify: {t}"
    );
    assert!(
        !t.contains("VERIFIED. definition of done met"),
        "a failing gate must not also claim the definition of done is met: {t}"
    );
}

#[test]
fn verify_accepts_json_so_an_agent_can_branch_on_the_verdict() {
    let dir = fixture("verifyjson");
    write(
        &dir,
        "a.js",
        "export function add(a, b) { return a + b; }\n",
    );
    scan(&dir);
    let mut s = Session::start(&dir);
    let t = s.text(
        "harmony.verify",
        serde_json::json!({ "root": ".", "json": true }),
    );
    let v: serde_json::Value = serde_json::from_str(&t)
        .unwrap_or_else(|e| panic!("verify --json was not json ({e}): {t}"));
    assert!(
        v.get("ok").is_some(),
        "the json verdict needs a boolean to branch on: {t}"
    );
}

// ------------------------------------------------------------- the database

#[test]
fn db_routes_reports_an_endpoint_and_what_it_writes() {
    let dir = fixture("dbroutes");
    write(
        &dir,
        "schema.sql",
        "CREATE TABLE users (id INT PRIMARY KEY, email TEXT NOT NULL);\n",
    );
    write(
        &dir,
        "routes.js",
        "router.post('/users', createUser);\n\
         function createUser(req) { return insertUser(req.body); }\n",
    );
    write(
        &dir,
        "service.js",
        "function insertUser(data) { return prisma.user.create({ data }); }\n",
    );
    scan(&dir);
    let mut s = Session::start(&dir);
    let t = s.text("db.routes", serde_json::json!({ "root": "." }));
    assert!(t.contains("POST"), "the route must be listed: {t}");
    assert!(
        t.contains("users"),
        "the table it writes must be named: {t}"
    );
}

#[test]
fn db_touch_answers_the_one_question_and_says_when_a_route_is_absent() {
    let dir = fixture("dbtouch");
    write(
        &dir,
        "schema.sql",
        "CREATE TABLE users (id INT PRIMARY KEY, email TEXT NOT NULL);\n",
    );
    write(
        &dir,
        "routes.js",
        "router.post('/users', createUser);\n\
         function createUser(req) { return insertUser(req.body); }\n",
    );
    write(
        &dir,
        "service.js",
        "function insertUser(data) { return prisma.user.create({ data }); }\n",
    );
    scan(&dir);
    let mut s = Session::start(&dir);
    let hit = s.text(
        "db.touch",
        serde_json::json!({ "root": ".", "method": "POST", "path": "/users" }),
    );
    assert!(hit.contains("users"), "the table must be named: {hit}");

    // A route that does not exist is an error, not an empty answer. An agent
    // that read "writes no table" as the answer would carry on and change a
    // route it never found.
    let miss = s.text(
        "db.touch",
        serde_json::json!({ "root": ".", "method": "POST", "path": "/nope" }),
    );
    assert!(
        miss.contains("no route") || miss.contains("not found"),
        "a missing route must say so: {miss}"
    );
}

#[test]
fn db_schema_reports_a_cyclic_cascade() {
    let dir = fixture("dbcycles");
    write(
        &dir,
        "schema.sql",
        "CREATE TABLE a (id INT PRIMARY KEY, b_id INT REFERENCES b(id) ON DELETE CASCADE);\n\
         CREATE TABLE b (id INT PRIMARY KEY, a_id INT REFERENCES a(id) ON DELETE CASCADE);\n",
    );
    let mut s = Session::start(&dir);
    let t = s.text("db.schema", serde_json::json!({ "root": "." }));
    assert!(
        t.to_lowercase().contains("cycle") || t.to_lowercase().contains("critical"),
        "a cyclic cascade must be visible: {t}"
    );
}

#[test]
fn db_schema_says_so_when_there_is_no_database() {
    let dir = fixture("dbnone");
    write(
        &dir,
        "a.js",
        "export function add(a, b) { return a + b; }\n",
    );
    let mut s = Session::start(&dir);
    let t = s.text("db.schema", serde_json::json!({ "root": "." }));
    assert!(
        t.to_lowercase().contains("no database"),
        "silence is not an answer: {t}"
    );
}

#[test]
fn db_tables_names_the_tables_and_who_touches_them() {
    let dir = fixture("dbtables");
    write(
        &dir,
        "schema.sql",
        "CREATE TABLE users (id INT PRIMARY KEY, email TEXT NOT NULL);\n\
         CREATE TABLE logs (id INT PRIMARY KEY, message TEXT);\n",
    );
    write(
        &dir,
        "a.js",
        "function f() { return prisma.user.create({ data: {} }); }\n",
    );
    scan(&dir);
    let mut s = Session::start(&dir);
    let t = s.text("db.tables", serde_json::json!({ "root": "." }));
    assert!(t.contains("users"), "{t}");
    assert!(
        t.contains("logs"),
        "an untouched table is still a table: {t}"
    );
}

// ------------------------------------------------------------- changed since

#[test]
fn changed_since_names_files_touched_after_a_point() {
    let dir = fixture("changed");
    write(&dir, "a.js", "export function one() {}\n");
    write(&dir, "b.js", "export function two() {}\n");
    scan(&dir);

    // The point has to be in the past relative to the second edit, or the
    // timestamp comparison proves nothing.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    write(&dir, "b.js", "export function two() { return 1; }\n");

    let mut s = Session::start(&dir);
    let t = s.text(
        "spine.changed_since",
        serde_json::json!({ "root": ".", "since": 0 }),
    );
    assert!(
        t.contains("a.js") && t.contains("b.js"),
        "everything after the epoch is changed: {t}"
    );
}

#[test]
fn changed_since_omits_untouched_files_when_the_point_is_now() {
    let dir = fixture("changedempty");
    write(&dir, "a.js", "export function one() {}\n");
    scan(&dir);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut s = Session::start(&dir);
    let t = s.text(
        "spine.changed_since",
        serde_json::json!({ "root": ".", "since": now + 60 }),
    );
    assert!(
        !t.contains("a.js"),
        "a file older than the point is not changed: {t}"
    );
}

// ------------------------------------------------------------- protocol shape

#[test]
fn an_unknown_tool_is_an_error_not_an_empty_result() {
    let dir = fixture("unknown");
    let mut s = Session::start(&dir);
    let v = s.call("does.not.exist", serde_json::json!({}));
    assert!(
        v.get("error").is_some(),
        "an unknown tool must not answer as if it worked: {v}"
    );
}

#[test]
fn a_malformed_request_does_not_kill_the_session() {
    let dir = fixture("malformed");
    let mut s = Session::start(&dir);
    // Wrong types for a declared argument. The server must reject the call and
    // stay alive, because an agent that has to reconnect after one bad argument
    // treats the tool as fragile.
    let v = s.request(
        "tools/call",
        serde_json::json!({ "name": "spine.query", "arguments": { "kind": 42, "name": [] } }),
    );
    assert!(v.get("error").is_some(), "expected an error, got {v}");
    // Still usable afterwards.
    let tools = s.tools();
    assert!(tools.contains(&"spine.query".to_string()));
}
