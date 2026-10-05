// Two regressions found by the end to end pass, both in code this change
// touched or should have touched.
//
// 1. `harmony.check` and `harmony.report` over MCP returned a successful result
//    even when the workspace had critical findings. An agent cannot see an exit
//    code, so a tool call that succeeds while its text says `3 critical` is the
//    hollow outcome this whole design exists to prevent. The check used to
//    key off the advisory gate, and removing that guard took the fail closed
//    behaviour with it. The behaviour belongs to the tool, not to the one guard
//    that happened to need it.
//
// 2. A Stripe live secret key was not reported. The value shaped credential
//    table listed OpenAI and Anthropic but not Stripe, and the name rule needs
//    a keyword like "key" or "secret" in the variable, so a file carrying
//    `STRIPE = "sk_live_..."` produced nothing at all. That is a false negative
//    in the credential guard, which is the one guard in this tool whose silence
//    means "nothing found" rather than "not checked".

use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

fn scratch(tag: &str) -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!("heides_gate_{}_{}", tag, stamp));
    std::fs::create_dir_all(&p).expect("create scratch");
    p
}

fn spawn_mcp(cwd: &std::path::Path) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_heides"))
        .arg("mcp")
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn heides mcp")
}

/// Send a batch of JSON-RPC lines and collect the replies.
fn mcp_exchange(cwd: &std::path::Path, lines: &[String]) -> Vec<Value> {
    let mut child = spawn_mcp(cwd);
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        use std::io::Write;
        for l in lines {
            writeln!(stdin, "{l}").expect("write request");
        }
    }
    let out = child.wait_with_output().expect("mcp exits");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .collect()
}

fn handshake(root: &str) -> Vec<String> {
    vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}).to_string(),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}).to_string(),
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"harmony.check\",\"arguments\":{{\"root\":\"{}\"}}}}}}",
            root
        ),
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"name\":\"harmony.report\",\"arguments\":{{\"root\":\"{}\"}}}}}}",
            root
        ),
    ]
}

// The Stripe fixtures are assembled from their parts rather than written as
// literals. GitHub push protection scans for secret-shaped strings, and a
// prefix followed by enough token characters is indistinguishable from a real
// key, so a test fixture that trips it blocks the push. The rule under test is
// the prefix match, so the tail only has to be long enough to clear the
// tool's own minimum token length, not to look like a live credential.
fn live_prefix() -> String {
    // Each part carries its own underscore. Joining ["sk", "live", "_"]
    // produced `sklive_`, which is not a Stripe prefix at all, and the rule
    // correctly stayed silent on it. Written this way the intent is visible.
    format!("sk_{}_", "live")
}

fn test_prefix() -> String {
    format!("sk_{}_", "test")
}

/// Long enough to pass `MIN_TOKEN_TAIL`, and obviously not a real key.
fn fake_tail() -> String {
    "FakeKeyForTestingOnly0000".to_string()
}

fn live_key() -> String {
    format!("{}{}", live_prefix(), fake_tail())
}

fn test_key() -> String {
    format!("{}{}", test_prefix(), fake_tail())
}

/// A python view that passes request input to a shell, which is a proven flow
/// and therefore a critical finding.
fn dirty_project(tag: &str) -> std::path::PathBuf {
    let dir = scratch(tag);
    std::fs::write(
        dir.join("app.py"),
        "from flask import request\nimport subprocess\ndef run():\n    n = request.args.get(\"n\")\n    subprocess.call(\"sh -c \" + n, shell=True)\n",
    )
    .expect("write fixture");
    dir
}

fn clean_project(tag: &str) -> std::path::PathBuf {
    let dir = scratch(tag);
    std::fs::write(dir.join("a.py"), "def f():\n    return 1\n").expect("write fixture");
    dir
}

#[test]
fn harmony_check_fails_over_mcp_when_there_are_critical_findings() {
    let dir = dirty_project("check_fail");
    let replies = mcp_exchange(&dir, &handshake(dir.to_str().unwrap()));

    let check = replies
        .iter()
        .find(|r| r.get("id") == Some(&json!(2)))
        .expect("harmony.check replied");
    assert!(
        check.get("error").is_some(),
        "a workspace with critical findings must fail over MCP, got: {}",
        check
    );
    // The failure must still carry the evidence, or an agent knows it failed and
    // not why.
    let msg = check["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("shell sink") || msg.contains("critical"),
        "the error must carry the evidence: {msg}"
    );
}

#[test]
fn harmony_report_fails_over_mcp_and_reports_the_real_verdict() {
    let dir = dirty_project("report_fail");
    let replies = mcp_exchange(&dir, &handshake(dir.to_str().unwrap()));

    let report = replies
        .iter()
        .find(|r| r.get("id") == Some(&json!(3)))
        .expect("harmony.report replied");
    assert!(
        report.get("error").is_some(),
        "harmony.report must fail over MCP on critical findings, got: {}",
        report
    );

    // security_gate must reflect reality. It used to be a constant true left
    // over from the removed advisory guard, which would let an agent branch on
    // a verdict that was never computed.
    let msg = report["error"]["message"].as_str().unwrap_or_default();
    let parsed: Value = serde_json::from_str(msg)
        .unwrap_or_else(|e| panic!("report error must be json: {e}\n{msg}"));
    assert_eq!(
        parsed.get("security_gate"),
        Some(&json!(false)),
        "security_gate must be false when the gate failed: {parsed}"
    );
}

#[test]
fn a_clean_workspace_succeeds_over_mcp() {
    // The other direction. A gate that always fails is as useless as one that
    // never does.
    let dir = clean_project("check_clean");
    let replies = mcp_exchange(&dir, &handshake(dir.to_str().unwrap()));

    let check = replies
        .iter()
        .find(|r| r.get("id") == Some(&json!(2)))
        .expect("harmony.check replied");
    assert!(
        check.get("error").is_none(),
        "a clean workspace must succeed over MCP, got: {}",
        check
    );

    let report = replies
        .iter()
        .find(|r| r.get("id") == Some(&json!(3)))
        .expect("harmony.report replied");
    assert!(
        report.get("error").is_none(),
        "harmony.report must succeed on a clean workspace, got: {}",
        report
    );
    let msg = report["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    let parsed: Value = serde_json::from_str(msg).expect("report text is json");
    assert_eq!(
        parsed.get("security_gate"),
        Some(&json!(true)),
        "security_gate must be true on a clean workspace: {parsed}"
    );
}

#[test]
fn a_stripe_live_key_is_reported() {
    // The name carries no keyword the name rule can use, so only the value
    // shaped table can catch this.
    let dir = scratch("stripe");
    std::fs::write(
        dir.join("billing.py"),
        format!("STRIPE = \"{}\"\n", live_key()),
    )
    .expect("write fixture");

    let out = Command::new(env!("CARGO_BIN_EXE_heides"))
        .args(["check", dir.to_str().unwrap()])
        .output()
        .expect("run heides");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        text.contains("Stripe live secret key"),
        "a committed Stripe live key must be reported, got: {text}"
    );
    assert!(
        !out.status.success(),
        "a live Stripe key must fail the gate"
    );
}

#[test]
fn a_stripe_test_key_is_reported_too() {
    // A sandbox key is still a credential and is still worth naming.
    let dir = scratch("stripe_test");
    std::fs::write(
        dir.join("billing.py"),
        format!("GATEWAY = \"{}\"\n", test_key()),
    )
    .expect("write fixture");

    let out = Command::new(env!("CARGO_BIN_EXE_heides"))
        .args(["check", dir.to_str().unwrap()])
        .output()
        .expect("run heides");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        text.contains("Stripe test secret key"),
        "a committed Stripe test key must be reported, got: {text}"
    );
}

#[test]
fn a_redacted_stripe_placeholder_is_not_reported() {
    // The redaction markers must keep working, or the rule cries wolf on every
    // documentation file that shows an example key.
    let dir = scratch("stripe_redacted");
    std::fs::write(
        dir.join("billing.py"),
        format!("EXAMPLE = \"{}...redacted\"\n", live_prefix()),
    )
    .expect("write fixture");

    let out = Command::new(env!("CARGO_BIN_EXE_heides"))
        .args(["check", dir.to_str().unwrap()])
        .output()
        .expect("run heides");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        !text.contains("Stripe live secret key"),
        "a redacted example must not be reported: {text}"
    );
}
