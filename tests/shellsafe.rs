// The negative half of the shell=True and verify=False rules.
//
// rules.rs proves the rules fire. This proves they stay quiet on the correct
// spellings of the same intent, which is the half that decides whether the
// rules are usable. A rule that fires on `subprocess.run(["ls", "-l"])` is not
// a security control, it is noise.

use std::path::PathBuf;

fn practice_findings(file: &str, content: &str) -> Vec<String> {
    let path = PathBuf::from(file);
    let lang = heides::parser::detect_language(&path).unwrap_or_default();
    heides::practice::scan_file(&path, content, &lang)
        .into_iter()
        .map(|r| r.message)
        .collect()
}

fn assert_quiet(name: &str, file: &str, content: &str) {
    let found = practice_findings(file, content);
    assert!(
        found.is_empty(),
        "{} must stay quiet, got: {:?}",
        name,
        found
    );
}

#[test]
fn subprocess_with_an_argument_list_is_correct() {
    assert_quiet(
        "subprocess arg list",
        "run.py",
        r#"import subprocess

def list_dir(path):
    return subprocess.run(["ls", "-l", path], check=True, capture_output=True)
"#,
    );
}

#[test]
fn shell_false_is_explicit_and_correct() {
    assert_quiet(
        "shell=False",
        "run2.py",
        r#"import subprocess

def run(cmd):
    return subprocess.run(cmd, shell=False, check=True)
"#,
    );
}

#[test]
fn verify_true_is_correct() {
    assert_quiet(
        "verify=True",
        "net.py",
        r#"import requests

def fetch(url):
    return requests.get(url, verify=True, timeout=10)
"#,
    );
}

#[test]
fn verify_from_the_environment_is_correct() {
    // Reading the CA bundle path from config is the right way to do this and
    // must not be read as disabling verification.
    assert_quiet(
        "verify from config",
        "net2.py",
        r#"import os
import requests

def fetch(url):
    bundle = os.environ.get("REQUESTS_CA_BUNDLE")
    return requests.get(url, verify=bundle, timeout=10)
"#,
    );
}

#[test]
fn shell_true_inside_a_docstring_does_not_fire() {
    // A test file documenting the bad spelling is not a defect.
    assert_quiet(
        "docstring mention",
        "notes.py",
        r#""""Never write subprocess.run(cmd, shell=True); pass an argument list."""
"#,
    );
}

#[test]
fn the_shell_safe_fixtures_still_pass_through_check() {
    // The end-to-end half: a file with correct subprocess usage must produce
    // no critical anywhere in the real pipeline, not just in the practice
    // scanner.
    let dir = std::env::temp_dir().join("heides_shellsafe");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("run.py"),
        "import subprocess\n\ndef list_dir(path):\n    return subprocess.run([\"ls\", path], check=True)\n",
    )
    .unwrap();

    let graph = heides::indexer::load_or_build(&dir).expect("indexes");
    let reports = heides::harmony::check_workspace(&dir, &graph);
    let bad: Vec<_> = reports
        .iter()
        .filter(|r| r.severity == "critical" || r.severity == "blocker")
        .map(|r| r.message.clone())
        .collect();
    assert!(bad.is_empty(), "correct code must not be critical: {:?}", bad);
    let _ = std::fs::remove_dir_all(&dir);
}