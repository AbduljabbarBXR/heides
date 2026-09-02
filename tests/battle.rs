// HEIDES battle suite.
//
// A serial end to end gauntlet. Every scenario runs in order against a real
// fixture workspace and the real compiled binary. The suite prints a score
// and fails the build if any check fails.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_heides");

struct Battle {
    checks: Vec<(String, bool)>,
    fixture: PathBuf,
}

impl Battle {
    fn check(&mut self, name: &str, cond: bool) {
        let status = if cond { "PASS" } else { "FAIL" };
        println!("[{}] {}", status, name);
        self.checks.push((name.to_string(), cond));
    }

    fn cli(&self, args: &[&str]) -> (String, String, bool) {
        let out = Command::new(BIN)
            .args(args)
            .current_dir(&self.fixture)
            .output()
            .expect("binary must run");
        (
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
            out.status.success(),
        )
    }

    fn write(&self, rel: &str, content: &str) {
        let path = self.fixture.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    fn score(&self) {
        let total = self.checks.len();
        let passed = self.checks.iter().filter(|(_, ok)| *ok).count();
        println!();
        println!("BATTLE SCORE: {}/{} ({}%)", passed, total, passed * 100 / total.max(1));
        assert_eq!(passed, total, "{} battle check(s) failed", total - passed);
    }
}

fn fixture_lib() -> String {
    r#"pub fn add(a: i32, b: i32) -> i32 { a + b }
pub fn greet(name: &str) -> String {
    let v = maybe().unwrap();
    format!("hi {}", name)
}
fn maybe() -> Option<String> { None }
"#
    .to_string()
}

fn fixture_main() -> String {
    r#"fn main() {
    let x = add(1, 2);
    println!("{}", x);
}
"#
    .to_string()
}

fn fixture_js() -> String {
    r#"// TODO: fix the cache later
const SECRET_KEY = "abcdef123456";
function load() {
  const q = req.query.id;
  db.query(q);
  console.log(q);
}
"#
    .to_string()
}

fn fixture_py() -> String {
    r#"def run():
    name = input()
    os.system(name)
"#
    .to_string()
}

fn fixture_php() -> String {
    "<?php\nfunction load() {\n    $q = $_GET['id'];\n    mysqli_query($conn, $q);\n}\n".to_string()
}

fn fixture_go() -> String {
    "package main\n\nfunc load() {\n    q := r.URL.Query().Get(\"id\")\n    db.Query(q)\n}\n".to_string()
}

fn fixture_java() -> String {
    "class App {\n    void load(HttpServletRequest request) {\n        String q = request.getParameter(\"id\");\n        stmt.executeQuery(q);\n    }\n}\n".to_string()
}

fn fixture_cs() -> String {
    "class App {\n    void Load() {\n        var q = Request.QueryString[\"id\"];\n        cmd.ExecuteScalar(q);\n    }\n}\n".to_string()
}

fn has_no_dash(text: &str) -> bool {
    !text.contains('-') && !text.contains('\u{2013}') && !text.contains('\u{2014}')
}

#[test]
fn battle_serial() {
    let mut b = Battle {
        checks: Vec::new(),
        fixture: std::env::temp_dir().join(format!("heides_battle_{}", std::process::id())),
    };
    let _ = std::fs::remove_dir_all(&b.fixture);
    std::fs::create_dir_all(&b.fixture).unwrap();

    // Fixture: a real polyglot workspace with planted bugs.
    b.write("Cargo.toml", "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nserde = \"=1.0.1\"\n");
    b.write("src/lib.rs", &fixture_lib());
    b.write("src/main.rs", &fixture_main());
    b.write("app.js", &fixture_js());
    b.write("app.py", &fixture_py());
    b.write("app.php", &fixture_php());
    b.write("app.go", &fixture_go());
    b.write("app.java", &fixture_java());
    b.write("app.cs", &fixture_cs());

    // 1. Version
    let (out, _, ok) = b.cli(&["version"]);
    b.check("version command exits clean and prints a version", ok && out.contains("0.3"));

    // 2. Scan builds the spine
    let (out, _, ok) = b.cli(&["scan"]);
    b.check("scan exits clean", ok);
    b.check("scan reports symbols and call edges", out.contains("symbols") && out.contains("call edges"));
    b.check("scan writes the persistent index", b.fixture.join(".heides/index.json").exists());

    // 3. Status reads the index back
    let (out, _, ok) = b.cli(&["status"]);
    b.check("status reads the persisted index", ok && out.contains("spine index present"));

    // 4. Query: who calls add
    let (out, _, _) = b.cli(&["query", "callers", "add"]);
    b.check("query callers finds main calling add", out.contains("main") && out.contains("add"));

    // 5. Query: definition of greet
    let (out, _, _) = b.cli(&["query", "definition", "greet"]);
    b.check("query definition locates greet in lib.rs", out.contains("lib.rs") && out.contains("greet"));

    // 6. Query: calls from main
    let (out, _, _) = b.cli(&["query", "calls", "main"]);
    b.check("query calls lists add and println from main", out.contains("add") && out.contains("println"));

    // 7. Full check catches every planted bug class
    let (out, _, ok) = b.cli(&["check"]);
    b.check("check exits clean", ok);
    b.check("check catches SQL taint", out.contains("SQL"));
    b.check("check catches shell taint", out.contains("shell"));
    b.check("check catches PHP SQL taint", out.contains("app.php"));
    b.check("check catches Go SQL taint", out.contains("app.go"));
    b.check("check catches Java SQL taint", out.contains("app.java"));
    b.check("check catches C# SQL taint", out.contains("app.cs"));
    b.check("check catches unwrap panic risk", out.contains("unwrap"));
    b.check("check catches hardcoded secret", out.contains("secret"));
    b.check("check catches debug output", out.contains("debug output"));
    b.check("check catches TODO marker", out.contains("unfinished work"));
    b.check("check summarizes by severity", out.contains("critical"));

    // 8. Staged apply: signature change must be blocked
    let sig_patch = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,4 +1,4 @@\n-pub fn add(a: i32, b: i32) -> i32 { a + b }\n+pub fn add(a: i32, b: i32, c: i32) -> i32 { a + b + c }\n pub fn greet(name: &str) -> String {\n";
    b.write("bad.patch", sig_patch);
    let (out, _, ok) = b.cli(&["staged", "bad.patch"]);
    b.check("staged exits clean on a bad patch", ok);
    b.check("staged blocks a signature change with callers", out.contains("blocker") && out.contains("signature"));

    // 9. Staged apply: safe body change passes
    let safe_patch = "diff --git a/src/main.rs b/src/main.rs\n--- a/src/main.rs\n+++ b/src/main.rs\n@@ -2,2 +2,2 @@\n-    println!(\"{}\", x);\n+    println!(\"value {}\", x);\n";
    b.write("safe.patch", safe_patch);
    let (out, _, _) = b.cli(&["staged", "safe.patch"]);
    b.check("staged allows a body only change", out.contains("safe to apply"));

    // 10. Staged apply: deleting a called file must be blocked
    let del_patch = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,4 +0,0 @@\n-pub fn add(a: i32, b: i32) -> i32 { a + b }\n-pub fn greet(name: &str) -> String {\n-    let v = maybe().unwrap();\n-    format!(\"hi {}\", name)\n";
    b.write("del.patch", del_patch);
    let (out, _, _) = b.cli(&["staged", "del.patch"]);
    b.check("staged blocks deletion of a file with callers", out.contains("deleted") || out.contains("removed"));

    // 11. Staged apply: new file is accepted
    let new_patch = "diff --git a/src/fresh.rs b/src/fresh.rs\n--- /dev/null\n+++ b/src/fresh.rs\n@@ -0,0 +1,2 @@\n+pub fn fresh() -> i32 { 7 }\n+pub fn fresh2() -> i32 { 8 }\n";
    b.write("new.patch", new_patch);
    let (out, _, _) = b.cli(&["staged", "new.patch"]);
    b.check("staged accepts a brand new file", out.contains("safe to apply") || out.contains("no conflicts"));

    // 12. Staged apply: bad diff is rejected
    let (_, _, ok) = b.cli(&["staged", "missing.patch"]);
    b.check("staged rejects a missing patch file", !ok);

    // 13. Grounding: plan refinement flags missing symbols
    let (out, _, ok) = b.cli(&["plan", "refactor the checkout_flow and the pricing_engine"]);
    b.check("plan exits clean", ok);
    b.check("plan flags checkout_flow as missing", out.contains("checkout_flow"));
    b.check("plan flags pricing_engine as missing", out.contains("pricing_engine"));

    // 14. Grounding: plan confirms real symbols
    let (out, _, _) = b.cli(&["plan", "change the signature of add to return a sum"]);
    b.check("plan confirms add exists in the spine", out.contains("add"));

    // 15. Scaffold: new project from a plan
    let scaffold_dir = std::env::temp_dir().join(format!("heides_scaffold_battle_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scaffold_dir);
    let (out, _, ok) = Command::new(BIN)
        .args(["scaffold", "rust cli tool", scaffold_dir.to_str().unwrap()])
        .output()
        .map(|o| (String::from_utf8_lossy(&o.stdout).to_string(), String::from_utf8_lossy(&o.stderr).to_string(), o.status.success()))
        .unwrap();
    b.check("scaffold exits clean", ok);
    b.check("scaffold creates Cargo.toml", scaffold_dir.join("Cargo.toml").exists());
    b.check("scaffold creates src/main.rs", scaffold_dir.join("src/main.rs").exists());
    b.check("scaffold indexes the new project", out.contains("spine index"));
    let _ = std::fs::remove_dir_all(&scaffold_dir);

    // 16. Watch: detects a file change and reindexes
    let mut child = Command::new(BIN)
        .args(["watch", ".", "3"])
        .current_dir(&b.fixture)
        .stdout(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1200));
    let mut lib = fixture_lib();
    lib.push_str("pub fn brand_new() -> i32 { 42 }\n");
    b.write("src/lib.rs", &lib);
    let mut stdout = String::new();
    {
        use std::io::Read;
        let _ = child.stdout.take().unwrap().read_to_string(&mut stdout);
    }
    let _ = child.wait();
    b.check("watch notices the change and reindexes", stdout.contains("spine reindexed"));

    // 17. MCP: full protocol round trip
    let mut mcp = Command::new(BIN)
        .arg("mcp")
        .current_dir(&b.fixture)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = mcp.stdin.take().unwrap();
    stdin
        .write_all(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"spine.query\",\"arguments\":{\"kind\":\"callers\",\"name\":\"add\"}}}\n{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"harmony.check\",\"arguments\":{}}}\n",
        )
        .unwrap();
    drop(stdin);
    let mut mcp_out = String::new();
    {
        use std::io::Read;
        let _ = mcp.stdout.take().unwrap().read_to_string(&mut mcp_out);
    }
    let _ = mcp.wait();
    b.check("mcp answers initialize", mcp_out.contains("\"serverInfo\""));
    b.check("mcp lists all eight tools", mcp_out.contains("spine.scan")
        && mcp_out.contains("spine.query")
        && mcp_out.contains("harmony.check")
        && mcp_out.contains("harmony.staged")
        && mcp_out.contains("grounding.plan")
        && mcp_out.contains("grounding.scaffold")
        && mcp_out.contains("deps.check")
        && mcp_out.contains("web.confirm"));
    b.check("mcp answers a spine.query call", mcp_out.contains("main calls add"));
    b.check("mcp answers harmony.check with taint findings", mcp_out.contains("SQL"));

    // 18. Dash free enforcement on local CLI output
    for (name, args) in [
        ("version", vec!["version"]),
        ("help", vec![]),
        ("scan", vec!["scan"]),
        ("status", vec!["status"]),
        ("query", vec!["query", "callers", "add"]),
        ("plan", vec!["plan", "change the signature of add"]),
    ] {
        let (out, _, _) = b.cli(&args);
        b.check(&format!("{} output is dash free", name), has_no_dash(&out));
    }
    let output = Command::new(BIN)
        .arg("mcp")
        .current_dir(&b.fixture)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            let mut s = c.stdin.take().unwrap();
            s.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n").unwrap();
            drop(s);
            c.wait_with_output()
        })
        .unwrap();
    let mcp_list = String::from_utf8_lossy(&output.stdout).to_string();
    b.check("mcp tools/list is dash free", has_no_dash(&mcp_list));

    // 19. Dependency guard talks to the registries
    let (out, _, _) = b.cli(&["deps"]);
    b.check("deps reports serde from the manifest", out.contains("serde"));

    // 20. Anti cosmetic: a caret range must never be called outdated
    let cosmetic_dir = b.fixture.join("caret_ok");
    std::fs::create_dir_all(&cosmetic_dir).unwrap();
    std::fs::write(
        cosmetic_dir.join("Cargo.toml"),
        "[package]\nname = \"caret_ok\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\n",
    )
    .unwrap();
    let (out, _, _) = Command::new(BIN)
        .args(["deps", "caret_ok"])
        .current_dir(&b.fixture)
        .output()
        .map(|o| {
            (
                String::from_utf8_lossy(&o.stdout).to_string(),
                String::from_utf8_lossy(&o.stderr).to_string(),
                o.status.success(),
            )
        })
        .unwrap();
    b.check(
        "caret range serde 1 is not reported outdated",
        !out.contains("outdated") && !out.contains("falls outside"),
    );

    let _ = std::fs::remove_dir_all(&b.fixture);
    b.score();
}
