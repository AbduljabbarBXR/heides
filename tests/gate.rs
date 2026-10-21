// The gate tests.
//
// Everything here is about one question: can a CI job use this tool to decide
// whether a change is safe? That needs four things, and each was measured
// missing:
//
//   1. Noise control. A workspace can exclude what it does not want scanned,
//      and it can silence one finding without silencing the rule.
//   2. A baseline. A gate that fails on every finding the repository has ever
//      had is a gate that gets switched off.
//   3. Machine output. A job reads JSON and SARIF, not prose.
//   4. Coverage of the languages people actually write. Dart and Flutter had
//      no taint rule at all, so a Flutter app was analysed and nothing was
//      found, which is the worst possible answer.
//
// Each test below pins one of those, because each of them was a defect that
// shipped.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct Out {
    ok: bool,
    stdout: String,
    stderr: String,
}

fn run(cwd: &Path, args: &[&str]) -> Out {
    let o = Command::new(env!("CARGO_BIN_EXE_heides"))
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("spawn heides");
    Out {
        ok: o.status.success(),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

fn scratch(tag: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!("heides_gate_{}_{}", tag, stamp));
    std::fs::create_dir_all(&p).expect("create scratch");
    p
}

fn write(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent");
    }
    std::fs::write(path, body).expect("write fixture");
}

/// A python file with a real shell injection: a value read from the user
/// reaches a command.
const DIRTY: &str = "import os\ndef view():\n    name = input()\n    os.system(name)\n";

#[test]
fn an_ignored_path_produces_no_finding() {
    let dir = scratch("ignore");
    write(&dir, "app.py", DIRTY);
    write(&dir, "samples/vulnerable.py", DIRTY);
    write(&dir, ".heidesignore", "samples/\n");

    let out = run(&dir, &["check", "."]);
    assert!(
        !out.stdout.contains("at samples/"),
        "an ignored path must not report a finding, got: {}",
        out.stdout
    );
    assert!(
        out.stdout.contains("app.py"),
        "the rest of the workspace must still be scanned, got: {}",
        out.stdout
    );
    // The receipt says what was left out, so an exclusion is visible rather
    // than a gap in the coverage.
    assert!(
        out.stdout.contains("excluded by policy"),
        "the receipt must name the exclusion, got: {}",
        out.stdout
    );
}

#[test]
fn an_inline_suppression_silences_one_rule_and_nothing_else() {
    let dir = scratch("suppress");
    write(
        &dir,
        "app.py",
        "import os\ndef view():\n    name = input()\n    os.system(name)  # heides-ignore security.taint the value is validated above\n",
    );

    let out = run(&dir, &["check", "."]);
    assert!(
        !out.stdout.contains("security.taint"),
        "the suppressed rule must not fire, got: {}",
        out.stdout
    );
}

#[test]
fn an_expired_inline_suppression_does_not_silence_anything() {
    let dir = scratch("expired");
    write(
        &dir,
        "app.py",
        "import os\ndef view():\n    name = input()\n    os.system(name)  # heides-ignore security.taint until 2020-01-01\n",
    );

    let out = run(&dir, &["check", "."]);
    assert!(
        out.stdout.contains("security.taint"),
        "an expired suppression must not silence the finding, got: {}",
        out.stdout
    );
}

#[test]
fn a_severity_override_changes_the_label_and_the_verdict() {
    let dir = scratch("severity");
    write(&dir, "app.py", DIRTY);
    write(
        &dir,
        ".heides/config.json",
        "{\"severity_overrides\": {\"security.taint\": \"warning\"}}\n",
    );

    let out = run(&dir, &["check", "."]);
    assert!(
        out.stdout.contains("warning"),
        "the override must change the severity, got: {}",
        out.stdout
    );
    assert!(
        out.ok,
        "a warning must not fail the default gate, stderr: {}",
        out.stderr
    );
}

#[test]
fn the_json_report_has_a_stable_schema_and_a_fingerprint() {
    let dir = scratch("json");
    write(&dir, "app.py", DIRTY);

    let out = run(&dir, &["check", "--json", "."]);
    let doc: serde_json::Value = serde_json::from_str(&out.stdout).expect("the json must parse");
    assert_eq!(doc["schema"], "heides.findings/v1");
    let finding = &doc["findings"][0];
    assert!(
        finding["fingerprint"].is_string(),
        "a fingerprint is required"
    );
    assert_eq!(finding["fingerprint"].as_str().unwrap().len(), 16);
    assert_eq!(finding["rule"], "security.taint");
    assert!(finding["cwe"].is_string(), "a cwe is required");
    assert!(
        finding["confidence"].is_string(),
        "a confidence is required"
    );
    assert!(
        finding["suggestion"].is_string(),
        "a suggestion is required"
    );
    assert!(finding["snippet"].is_string(), "a snippet is required");
    assert_eq!(finding["scope"], "source");
}

#[test]
fn the_sarif_report_is_a_sarif_document() {
    let dir = scratch("sarif");
    write(&dir, "app.py", DIRTY);

    let out = run(&dir, &["check", "--sarif", "."]);
    let doc: serde_json::Value = serde_json::from_str(&out.stdout).expect("the sarif must parse");
    assert_eq!(doc["version"], "2.1.0");
    let results = doc["runs"][0]["results"].as_array().expect("results");
    assert!(!results.is_empty(), "the fixture must produce a finding");
    assert_eq!(results[0]["level"], "error");
    assert!(results[0]["partialFingerprints"]["heidesFingerprint"].is_string());
}

#[test]
fn a_baseline_makes_the_gate_fail_only_on_new_findings() {
    let dir = scratch("baseline");
    write(&dir, "app.py", DIRTY);

    // The workspace is dirty, so the gate fails.
    let dirty = run(&dir, &["check", "."]);
    assert!(!dirty.ok, "the dirty workspace must fail");

    // Record the findings the project accepts.
    let saved = run(&dir, &["baseline", "."]);
    assert!(
        saved.ok,
        "saving the baseline must succeed: {}",
        saved.stderr
    );

    // Now the same findings are known, and the gate passes.
    let known = run(&dir, &["check", "--baseline", "."]);
    assert!(
        known.ok,
        "a known finding must not fail the gate, stderr: {}",
        known.stderr
    );
    assert!(
        known.stdout.contains("security.taint"),
        "a known finding is still reported, got: {}",
        known.stdout
    );

    // A new finding fails the gate, and only the new one.
    write(
        &dir,
        "other.py",
        "import os\ndef run():\n    name = input()\n    os.system(name)\n",
    );
    let after = run(&dir, &["check", "--baseline", "."]);
    assert!(
        !after.ok,
        "a new finding must fail the gate, stdout: {}",
        after.stdout
    );

    let only_new = run(&dir, &["check", "--new-only", "--baseline", "."]);
    assert!(
        !only_new.stdout.contains("app.py"),
        "--new-only must print only the new findings, got: {}",
        only_new.stdout
    );
    assert!(
        only_new.stdout.contains("other.py"),
        "--new-only must print the new finding, got: {}",
        only_new.stdout
    );
}

#[test]
fn the_min_severity_flag_decides_what_is_reported() {
    let dir = scratch("min_severity");
    write(&dir, "app.py", DIRTY);
    write(
        &dir,
        ".heides/config.json",
        "{\"severity_overrides\": {\"security.taint\": \"warning\"}}\n",
    );

    let out = run(&dir, &["check", "--min-severity", "critical", "."]);
    assert!(
        !out.stdout.contains("security.taint"),
        "a warning must not be reported at the critical bar, got: {}",
        out.stdout
    );
}

#[test]
fn the_fail_on_flag_sets_the_bar_for_this_run() {
    let dir = scratch("fail_on");
    write(&dir, "app.py", DIRTY);
    write(
        &dir,
        ".heides/config.json",
        "{\"severity_overrides\": {\"security.taint\": \"warning\"}}\n",
    );

    let out = run(&dir, &["check", "--fail-on", "warning", "."]);
    assert!(!out.ok, "a warning must fail the gate at the warning bar");
}

#[test]
fn a_dart_file_is_indexed_and_a_dart_sql_injection_is_found() {
    let dir = scratch("dart");
    write(
        &dir,
        "pubspec.yaml",
        "name: lens\nenvironment:\n  sdk: '>=3.0.0 <4.0.0'\ndependencies:\n  sqflite: ^2.3.0\n",
    );
    write(
        &dir,
        "lib/service.dart",
        "Future<List<Map<String, Object>>> findUser(String id) async {\n  final db = await openDatabase('app.db');\n  return db.rawQuery('SELECT * FROM users WHERE id = ' + id);\n}\n",
    );

    // The file is indexed.
    let described = run(&dir, &["describe", "."]);
    assert!(
        described.stdout.contains("dart"),
        "dart must be in the language list, got: {}",
        described.stdout
    );

    // And the taint is found.
    let out = run(&dir, &["check", "."]);
    assert!(
        out.stdout.contains("SQL sink"),
        "the dart SQL injection must be found, got: {}",
        out.stdout
    );
    assert!(
        out.stdout.contains("lib/service.dart"),
        "the finding must name the dart file, got: {}",
        out.stdout
    );
}

#[test]
fn a_flutter_project_is_analysed_rather_than_skipped() {
    // The gap that started this: a Flutter app indexed 15 vendored files and
    // none of its own Dart, and then reported that it had found nothing.
    let dir = scratch("flutter");
    write(
        &dir,
        "pubspec.yaml",
        "name: lens\ndependencies:\n  flutter:\n    sdk: flutter\n",
    );
    write(
        &dir,
        "lib/main.dart",
        "import 'package:flutter/material.dart';\nvoid main() {\n  runApp(const MyApp());\n}\n",
    );
    write(
        &dir,
        "lib/view.dart",
        "class MyApp extends StatelessWidget {\n  const MyApp({super.key});\n  @override\n  Widget build(BuildContext context) {\n    return const Text('hi');\n  }\n}\n",
    );

    let described = run(&dir, &["describe", "."]);
    assert!(
        described.stdout.contains("dart"),
        "the dart files must be indexed, got: {}",
        described.stdout
    );
    assert!(
        described.stdout.contains("main.dart") || described.stdout.contains("lib/"),
        "the dart files must be in the manifest, got: {}",
        described.stdout
    );
}

#[test]
fn one_call_reports_one_sink_class() {
    // `db.exec(...)` is a SQL sink. It also matches the bare shell row, and
    // reporting both was how the classes came to look unreliable.
    let dir = scratch("classes");
    write(
        &dir,
        "app.js",
        "const id = req.query.id;\ndb.exec(\"SELECT * FROM users WHERE id = \" + id);\n",
    );
    let out = run(&dir, &["check", "."]);
    assert!(
        out.stdout.contains("SQL sink"),
        "the SQL sink must be found, got: {}",
        out.stdout
    );
    assert!(
        !out.stdout.contains("shell sink"),
        "the same call must not also be reported as a shell sink, got: {}",
        out.stdout
    );
}

#[test]
fn a_bare_exec_is_a_shell_sink_and_not_a_sql_sink() {
    let dir = scratch("bare_exec");
    write(&dir, "app.js", "const cmd = req.query.cmd;\nexec(cmd);\n");
    let out = run(&dir, &["check", "."]);
    assert!(
        out.stdout.contains("shell sink"),
        "a bare exec is a shell sink, got: {}",
        out.stdout
    );
    assert!(
        !out.stdout.contains("SQL sink"),
        "a bare exec must not be reported as SQL, got: {}",
        out.stdout
    );
}

#[test]
fn a_plan_that_names_missing_symbols_is_not_feasible() {
    let dir = scratch("plan");
    write(&dir, "app.py", "def real_function():\n    return 1\n");

    let out = run(&dir, &["plan", "refactor the missing_function", "."]);
    assert!(
        out.stdout.contains("feasible false"),
        "a plan naming a missing symbol must not be feasible, got: {}",
        out.stdout
    );
    assert!(
        out.stdout.contains("missing_function"),
        "the missing symbol must be named, got: {}",
        out.stdout
    );

    let good = run(
        &dir,
        &["plan", "change the signature of real_function", "."],
    );
    assert!(
        good.stdout.contains("feasible true"),
        "a plan naming a real symbol is feasible, got: {}",
        good.stdout
    );
}

#[test]
fn the_scaffold_refuses_a_stack_it_cannot_generate() {
    let dir = scratch("scaffold");
    let out = run(
        &dir,
        &[
            "scaffold",
            "a flutter app with sqlite",
            dir.to_str().unwrap(),
        ],
    );
    assert!(!out.ok, "an unsupported stack must not be scaffolded");
    assert!(
        out.stderr.contains("flutter") || out.stdout.contains("flutter"),
        "the refusal must name the stack, stdout: {} stderr: {}",
        out.stdout,
        out.stderr
    );
    assert!(
        !dir.join("package.json").exists(),
        "no file may be written for a refused scaffold"
    );
}

#[test]
fn a_language_can_be_switched_off_by_policy() {
    let dir = scratch("languages");
    write(&dir, "app.py", DIRTY);
    write(
        &dir,
        ".heides/config.json",
        "{\"languages\": [\"javascript\"]}\n",
    );

    let out = run(&dir, &["check", "."]);
    assert!(
        !out.stdout.contains("security.taint"),
        "a language that is switched off must not be scanned, got: {}",
        out.stdout
    );
}
