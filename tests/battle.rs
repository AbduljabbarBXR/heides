// HEIDES battle suite.
//
// A serial end to end gauntlet. Every scenario runs in order against a real
// fixture workspace and the real compiled binary. The suite prints a score
// and fails the build if any check fails.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;

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
        println!(
            "BATTLE SCORE: {}/{} ({}%)",
            passed,
            total,
            passed * 100 / total.max(1)
        );
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
    "package main\n\nfunc load() {\n    q := r.URL.Query().Get(\"id\")\n    db.Query(q)\n}\n"
        .to_string()
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
    // Two Next.js style route files, each exporting POST. Cross file method
    // name collisions are idiomatic and must never block a staged patch.
    b.write(
        "routes/a.ts",
        "export async function POST(request: Request) {\n  return new Response(\"a\");\n}\n",
    );
    b.write(
        "routes/b.ts",
        "export async function POST(request: Request) {\n  return new Response(\"b\");\n}\n",
    );
    // Cross function taint fixtures. A caller reads a source and passes it
    // into a helper that sinks it, a wrapper hands a source read back and a
    // pass through helper forwards it, and a clean file stays silent.
    b.write(
        "cross.php",
        "<?php\nfunction sink_sql($q) {\n    mysqli_query($conn, $q);\n}\nfunction entry() {\n    $id = $_GET['id'];\n    sink_sql($id);\n}\n",
    );
    b.write(
        "wrapper.php",
        "<?php\nfunction grab() {\n    return $_GET['x'];\n}\nfunction pass($v) { return $v; }\nfunction sink_sql2($q) {\n    mysqli_query($conn, $q);\n}\nfunction use_it() {\n    $v = grab();\n    $w = pass($v);\n    sink_sql2($w);\n}\n",
    );
    b.write(
        "cross_clean.php",
        "<?php\nfunction harmless($x) {\n    echo htmlspecialchars($x);\n}\nfunction ok() {\n    harmless('literal');\n}\n",
    );
    // Module level taint fixtures. Top level code is analyzed as its own
    // scope, a source wrapper feeding a sink call at module level traces
    // through, a direct module source read into a module sink reports, and
    // inert top level code stays silent.
    b.write(
        "module.php",
        "<?php\nfunction grab() {\n    return $_GET['x'];\n}\nfunction sink_sql3($q) {\n    mysqli_query($conn, $q);\n}\n$term = grab();\nsink_sql3($term);\n$direct = $_GET['d'];\nmysqli_query($conn, $direct);\n",
    );
    b.write(
        "module_clean.php",
        "<?php\nfunction harmless2($x) {\n    echo htmlspecialchars($x);\n}\nharmless2('literal');\n$name = 'config value';\necho $name;\n",
    );
    b.write("dup_a.py", "def handle(x):\n    os.system(x)\n");
    b.write("dup_b.py", "def handle(x):\n    os.system(x)\n");
    b.write(
        "dup_caller.py",
        "def go():\n    q = input()\n    handle(q)\n",
    );
    b.write(
        "named.py",
        "import os\n\ndef run_shell(cmd, silent=False):\n    os.system(cmd)\n\ndef entry():\n    q = input()\n    run_shell(silent=True, cmd=q)\n",
    );
    b.write(
        "web_dirty.html",
        "<!doctype html>\n<html>\n<body>\n  <a href=\"javascript:alert(1)\">click</a>\n  <form action=\"/pay\"></form>\n</body>\n</html>\n",
    );

    // 1. Version
    let (out, _, ok) = b.cli(&["version"]);
    b.check(
        "version command exits clean and prints a version",
        ok && out.contains("0.10"),
    );

    // 2. Scan builds the spine
    let (out, _, ok) = b.cli(&["scan"]);
    b.check("scan exits clean", ok);
    b.check(
        "scan reports symbols and call edges",
        out.contains("symbols") && out.contains("call edges"),
    );
    b.check(
        "scan writes the persistent index",
        b.fixture.join(".heides/index.db").exists(),
    );

    // 3. Status reads the index back
    let (out, _, ok) = b.cli(&["status"]);
    b.check(
        "status reads the persisted index",
        ok && out.contains("spine index present"),
    );

    // 4. Query: who calls add
    let (out, _, _) = b.cli(&["query", "callers", "add"]);
    b.check(
        "query callers finds main calling add",
        out.contains("main") && out.contains("add"),
    );

    // 5. Query: definition of greet
    let (out, _, _) = b.cli(&["query", "definition", "greet"]);
    b.check(
        "query definition locates greet in lib.rs",
        out.contains("lib.rs") && out.contains("greet"),
    );

    // 6. Query: calls from main
    let (out, _, _) = b.cli(&["query", "calls", "main"]);
    b.check(
        "query calls lists add and println from main",
        out.contains("add") && out.contains("println"),
    );

    // 6b. Agent eyes, describe manifest and neighbors query
    let (out, _, _) = b.cli(&["describe"]);
    b.check(
        "describe maps the workspace in one read",
        out.contains("files,") && out.contains("languages") && out.contains("talks to"),
    );
    let (out, _, _) = b.cli(&["query", "neighbors", "maybe"]);
    b.check(
        "neighbors shows the callers side",
        out.contains("called by") && out.contains("greet"),
    );
    let (out, _, _) = b.cli(&["query", "neighbors", "greet"]);
    b.check(
        "neighbors shows the calls out side",
        out.contains("call(s) out") && out.contains("maybe"),
    );

    // 7. Full check catches every planted bug class
    let (out, _, ok) = b.cli(&["check"]);
    b.check("check exits clean", ok);
    b.check("check catches SQL taint", out.contains("SQL"));
    b.check("check catches shell taint", out.contains("shell"));
    b.check("check catches PHP SQL taint", out.contains("app.php"));
    b.check("check catches Go SQL taint", out.contains("app.go"));
    b.check("check catches Java SQL taint", out.contains("app.java"));
    b.check("check catches C# SQL taint", out.contains("app.cs"));
    b.check(
        "cross function taint reaches a helper sink",
        out.contains("reaches a SQL sink in sink_sql on line"),
    );
    b.check(
        "source wrapper and pass through chains are traced",
        out.contains("reaches a SQL sink in sink_sql2 on line"),
    );
    b.check(
        "clean cross function file stays silent",
        !out.contains("cross_clean.php"),
    );
    b.check(
        "module level flow through a function is traced",
        out.contains("reaches a SQL sink in sink_sql3 on line 6")
            && out.contains("via module level (module.php:9)"),
    );
    b.check(
        "html javascript URLs are critical and forms without csp report",
        out.contains("javascript URL in an html attribute")
            && out.contains("content security policy meta tag")
            && !out.contains("web_dirty.html clean"),
    );
    b.check(
        "duplicate definitions merge when every shape agrees",
        out.contains("reaches a shell sink in handle on line 2") && out.contains("via go"),
    );
    b.check(
        "named arguments bind by name not position",
        out.contains("reaches a shell sink in run_shell on line 4") && out.contains("via entry"),
    );
    b.check(
        "direct module level source to sink reports",
        out.contains("reaches a SQL sink in module.php on line 11"),
    );
    b.check(
        "named arguments bind by name not position",
        out.contains("reaches a shell sink in run_shell on line 4") && out.contains("via entry"),
    );
    b.check(
        "inert module level code stays silent",
        !out.contains("module_clean.php"),
    );
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
    b.check(
        "staged blocks a signature change with callers",
        out.contains("blocker") && out.contains("signature"),
    );

    // 9. Staged apply: safe body change passes
    let safe_patch = "diff --git a/src/main.rs b/src/main.rs\n--- a/src/main.rs\n+++ b/src/main.rs\n@@ -2,2 +2,2 @@\n-    println!(\"{}\", x);\n+    println!(\"value {}\", x);\n";
    b.write("safe.patch", safe_patch);
    let (out, _, _) = b.cli(&["staged", "safe.patch"]);
    b.check(
        "staged allows a body only change",
        out.contains("safe to apply"),
    );

    // 10. Staged apply: deleting a called file must be blocked
    let del_patch = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,4 +0,0 @@\n-pub fn add(a: i32, b: i32) -> i32 { a + b }\n-pub fn greet(name: &str) -> String {\n-    let v = maybe().unwrap();\n-    format!(\"hi {}\", name)\n";
    b.write("del.patch", del_patch);
    let (out, _, _) = b.cli(&["staged", "del.patch"]);
    b.check(
        "staged blocks deletion of a file with callers",
        out.contains("deleted") || out.contains("removed"),
    );

    // 11. Staged apply: new file is accepted
    let new_patch = "diff --git a/src/fresh.rs b/src/fresh.rs\n--- /dev/null\n+++ b/src/fresh.rs\n@@ -0,0 +1,2 @@\n+pub fn fresh() -> i32 { 7 }\n+pub fn fresh2() -> i32 { 8 }\n";
    b.write("new.patch", new_patch);
    let (out, _, _) = b.cli(&["staged", "new.patch"]);
    b.check(
        "staged accepts a brand new file",
        out.contains("safe to apply") || out.contains("no conflicts"),
    );

    // 11b. Staged apply: a rename that updates every caller inside the same
    // patch is safe. A real agent produced exactly this shape on a real
    // codebase and was wrongly blocked before the in patch caller fix.
    let rename_patch = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,1 +1,1 @@\n-pub fn add(a: i32, b: i32) -> i32 { a + b }\n+pub fn compute(a: i32, b: i32) -> i32 { a + b }\ndiff --git a/src/main.rs b/src/main.rs\n--- a/src/main.rs\n+++ b/src/main.rs\n@@ -2,1 +2,1 @@\n-    let x = add(1, 2);\n+    let x = compute(1, 2);\n";
    b.write("rename.patch", rename_patch);
    let (out, _, _) = b.cli(&["staged", "rename.patch"]);
    b.check(
        "staged allows a rename with every caller updated in one patch",
        out.contains("safe to apply"),
    );

    // 11c. The same rename without the caller update must block.
    let miss_patch = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,1 +1,1 @@\n-pub fn add(a: i32, b: i32) -> i32 { a + b }\n+pub fn compute(a: i32, b: i32) -> i32 { a + b }\n";
    b.write("miss.patch", miss_patch);
    let (out, _, _) = b.cli(&["staged", "miss.patch"]);
    b.check(
        "staged blocks a rename that misses a caller",
        out.contains("removed by the patch but still called"),
    );

    // 11d. Editing one Next.js route must not collide with the POST that a
    // sibling route file exports.
    let route_patch = "diff --git a/routes/b.ts b/routes/b.ts\n--- a/routes/b.ts\n+++ b/routes/b.ts\n@@ -2,1 +2,1 @@\n-  return new Response(\"b\");\n+  return new Response(\"beta\");\n";
    b.write("route.patch", route_patch);
    let (out, _, _) = b.cli(&["staged", "route.patch"]);
    b.check(
        "staged allows editing a route next to sibling POST exports",
        out.contains("safe to apply"),
    );

    // 12. Staged apply: bad diff is rejected
    let (_, _, ok) = b.cli(&["staged", "missing.patch"]);
    b.check("staged rejects a missing patch file", !ok);

    // 13. Grounding: plan refinement flags missing symbols
    let (out, _, ok) = b.cli(&["plan", "refactor the checkout_flow and the pricing_engine"]);
    b.check("plan exits clean", ok);
    b.check(
        "plan flags checkout_flow as missing",
        out.contains("checkout_flow"),
    );
    b.check(
        "plan flags pricing_engine as missing",
        out.contains("pricing_engine"),
    );

    // 14. Grounding: plan confirms real symbols
    let (out, _, _) = b.cli(&["plan", "change the signature of add to return a sum"]);
    b.check("plan confirms add exists in the spine", out.contains("add"));

    // 15. Scaffold: new project from a plan
    let scaffold_dir =
        std::env::temp_dir().join(format!("heides_scaffold_battle_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scaffold_dir);
    let (out, _, ok) = Command::new(BIN)
        .args(["scaffold", "rust cli tool", scaffold_dir.to_str().unwrap()])
        .output()
        .map(|o| {
            (
                String::from_utf8_lossy(&o.stdout).to_string(),
                String::from_utf8_lossy(&o.stderr).to_string(),
                o.status.success(),
            )
        })
        .unwrap();
    b.check("scaffold exits clean", ok);
    b.check(
        "scaffold creates Cargo.toml",
        scaffold_dir.join("Cargo.toml").exists(),
    );
    b.check(
        "scaffold creates src/main.rs",
        scaffold_dir.join("src/main.rs").exists(),
    );
    b.check(
        "scaffold indexes the new project",
        out.contains("spine index"),
    );
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
    b.check(
        "watch notices the change and reindexes",
        stdout.contains("spine reindexed"),
    );

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
    b.check(
        "mcp lists all eight tools",
        mcp_out.contains("spine.scan")
            && mcp_out.contains("spine.query")
            && mcp_out.contains("harmony.check")
            && mcp_out.contains("harmony.staged")
            && mcp_out.contains("grounding.plan")
            && mcp_out.contains("grounding.scaffold")
            && mcp_out.contains("deps.check")
            && mcp_out.contains("web.confirm"),
    );
    b.check(
        "mcp answers a spine.query call",
        mcp_out.contains("main calls add"),
    );
    b.check(
        "mcp answers harmony.check with taint findings",
        mcp_out.contains("SQL"),
    );

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
            s.write_all(
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n",
            )
            .unwrap();
            drop(s);
            c.wait_with_output()
        })
        .unwrap();
    let mcp_list = String::from_utf8_lossy(&output.stdout).to_string();
    b.check("mcp tools/list is dash free", has_no_dash(&mcp_list));

    // 19. Dependency guard talks to the registries
    let (out, _, _) = b.cli(&["deps"]);
    b.check(
        "deps reports serde from the manifest",
        out.contains("serde"),
    );

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

    // 21. Scale phase. A synthetic workspace of about a hundred thousand
    // lines proves the spine works on a massive codebase, then proves the
    // incremental diff on the very same tree.
    let scale_dir = b.fixture.join("scale");
    let scale_src = scale_dir.join("src");
    std::fs::create_dir_all(&scale_src).unwrap();
    let rust_files = 2200usize;
    let js_files = 200usize;
    for i in 0..rust_files {
        let mut code = String::new();
        code.push_str(&format!(
            "use std::process::Command;\n\npub fn handler_{}(input: &str) -> u32 {{\n",
            i
        ));
        for j in 0..36 {
            code.push_str(&format!("    let v{}: u32 = {};\n", j, (j * 7) % 101));
        }
        code.push_str("    let sum = v0 + v1 + v2 + v3 + v4 + v5 + v6 + v7 + v8 + v9;\n");
        if i % 220 == 0 {
            code.push_str("    let out = Command::new(\"sh\").arg(\"-c\").arg(format!(\"echo {}\", input)).output();\n");
            code.push_str("    out.unwrap();\n");
        }
        code.push_str(&format!(
            "    sum\n}}\n\npub fn call_{}() -> u32 {{\n    handler_{}(\"x\")\n}}\n",
            i, i
        ));
        std::fs::write(scale_src.join(format!("mod_{:04}.rs", i)), code).unwrap();
    }
    for i in 0..js_files {
        let mut code = String::new();
        code.push_str("const data = JSON.parse(raw);\n");
        if i % 100 == 0 {
            code.push_str("console.log(data);\n");
        }
        code.push_str(&format!("module.exports = {{ id: {} }};\n", i));
        std::fs::write(scale_src.join(format!("app_{:03}.js", i)), code).unwrap();
    }

    let run_in = |args: &[&str]| {
        Command::new(BIN)
            .args(args)
            .current_dir(&scale_dir)
            .output()
            .map(|o| {
                (
                    String::from_utf8_lossy(&o.stdout).to_string(),
                    String::from_utf8_lossy(&o.stderr).to_string(),
                    o.status.success(),
                )
            })
            .unwrap()
    };

    let t0 = Instant::now();
    let (out, _err, ok) = run_in(&["scan"]);
    let scan_secs = t0.elapsed().as_secs_f64();
    b.check(
        "scale scan builds the full index",
        ok && out.contains("2400 files") && out.contains("2400 touched"),
    );
    b.check("scale scan finishes well inside budget", scan_secs < 60.0);
    #[cfg(target_os = "linux")]
    {
        let rss_ok = _err
            .split("peak rss ")
            .nth(1)
            .and_then(|s| s.split(" MB").next())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|mb| mb < 512)
            .unwrap_or(false);
        b.check("scale scan stays under the memory budget", rss_ok);
    }

    let (out, _, ok) = run_in(&["scan"]);
    b.check(
        "second scan is a no op diff",
        ok && out.contains("0 touched"),
    );

    // One file changes, the diff touches exactly it and the graph survives.
    let target = scale_src.join("mod_0000.rs");
    let mut code = std::fs::read_to_string(&target).unwrap();
    code.push_str("// changed once\n");
    std::fs::write(&target, code).unwrap();
    let (out, _, ok) = run_in(&["scan"]);
    b.check(
        "one changed file touches exactly one",
        ok && out.contains("1 touched"),
    );

    let t1 = Instant::now();
    let (out, _, _) = run_in(&["query", "callers", "handler_0"]);
    let query_ms = t1.elapsed().as_millis();
    b.check(
        "query on the massive graph answers instantly",
        out.contains("1 call site(s)") && out.contains("call_0 calls handler_0") && query_ms < 2000,
    );

    let (out, _, ok) = run_in(&["check"]);
    let json_parse = out.matches("JSON.parse can throw").count();
    let debug_log = out.matches("debug output left").count();
    let unwrap = out.matches("unwrap can panic").count();
    b.check(
        "scale check catches every planted bug",
        ok && json_parse == 200 && debug_log == 2 && unwrap == 10,
    );
    b.check("scale check output is dash free", has_no_dash(&out));

    // The tiny end must still pass after all the scale work. The original
    // fixture index was rebuilt by the earlier no op scans.
    let (out, _, _) = b.cli(&["query", "callers", "add"]);
    b.check(
        "tiny workspace still answers after scale phase",
        out.contains("main calls add"),
    );

    // 22. Hostile phase. Garbage files on disk, then a hostile MCP client.
    let hostile_dir = b.fixture.join("hostile");
    std::fs::create_dir_all(&hostile_dir).unwrap();
    std::fs::write(
        hostile_dir.join("garbage.rs"),
        vec![0u8, 159, 146, 150, 255, 0, 13, 10, 7],
    )
    .unwrap();
    std::fs::write(hostile_dir.join("empty.py"), "").unwrap();
    std::fs::write(
        hostile_dir.join("nul.js"),
        "\u{0}\u{0}\u{0}console.log(1);\n",
    )
    .unwrap();
    std::fs::write(
        hostile_dir.join("deep.rs"),
        format!("let x = {}1{};\n", "(".repeat(600), ")".repeat(600)),
    )
    .unwrap();
    std::fs::write(
        hostile_dir.join("huge.go"),
        format!("package main\n// {}\n", "a".repeat(800_000)),
    )
    .unwrap();
    let (out, _, ok) = Command::new(BIN)
        .args(["scan"])
        .current_dir(&hostile_dir)
        .output()
        .map(|o| {
            (
                String::from_utf8_lossy(&o.stdout).to_string(),
                String::from_utf8_lossy(&o.stderr).to_string(),
                o.status.success(),
            )
        })
        .unwrap();
    b.check("scan survives garbage files", ok && out.contains("indexed"));
    let (_, _, ok) = Command::new(BIN)
        .args(["check"])
        .current_dir(&hostile_dir)
        .output()
        .map(|o| {
            (
                String::from_utf8_lossy(&o.stdout).to_string(),
                String::from_utf8_lossy(&o.stderr).to_string(),
                o.status.success(),
            )
        })
        .unwrap();
    b.check("check survives garbage files", ok);

    // A hostile MCP client: binary junk, a giant message over the cap,
    // then a legitimate request. The server must stay alive and answer.
    let giant = format!("{}x", "z".repeat(17 * 1024 * 1024));
    let mut hostile_mcp = Command::new(BIN)
        .arg("mcp")
        .current_dir(&b.fixture)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    {
        let stdin = hostile_mcp.stdin.as_mut().unwrap();
        stdin
            .write_all(b"\xff\xfe\x00garbage not json\r\n")
            .unwrap();
        stdin.write_all(giant.as_bytes()).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/list\",\"params\":{}}\n")
            .unwrap();
    }
    drop(hostile_mcp.stdin.take());
    let output = hostile_mcp.wait_with_output().unwrap();
    let hostile_out = String::from_utf8_lossy(&output.stdout).to_string();
    b.check(
        "mcp survives garbage and giant messages",
        hostile_out.contains("spine.scan")
            && hostile_out.contains("web.confirm")
            && output.status.success(),
    );

    let _ = std::fs::remove_dir_all(&b.fixture);
    b.score();
}
