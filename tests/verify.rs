// The verify command: a machine checkable definition of done.
//
// An autonomous loop needs to know when to stop. `check` answers "is this
// code safe"; it does not answer "is this task finished". `verify` runs the
// test suite and every guard in one pass and returns a single boolean plus the
// reasons, so a loop can branch on it without parsing prose.
//
// The tests below are written against the behaviour, not the implementation:
// each one fails if the command silently passes, silently fails, or reports
// success on a workspace it did not actually analyse.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_heides")
}

struct Case {
    dir: PathBuf,
}

impl Case {
    fn new(name: &str, files: &[(&str, &str)]) -> Case {
        let dir = std::env::temp_dir().join(format!("heides_verify_{}", name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (rel, body) in files {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&p, body).unwrap();
        }
        Case { dir }
    }

    fn run(&self, args: &[&str]) -> (i32, String) {
        let out = Command::new(bin())
            .args(args)
            .current_dir(&self.dir)
            .output()
            .expect("heides binary runs");
        (
            out.status.code().unwrap_or(-1),
            format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)),
        )
    }

    fn verify(&self, extra: &[&str]) -> (i32, String) {
        let mut args = vec!["verify"];
        args.extend_from_slice(extra);
        self.run(&args)
    }
}

impl Drop for Case {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A workspace with nothing wrong in it must pass, and must say what it ran.
#[test]
fn verify_passes_on_a_clean_workspace() {
    let c = Case::new("clean", &[("app.py", "def add(a, b):\n    return a + b\n")]);
    let (code, out) = c.verify(&[]);
    assert_eq!(code, 0, "clean workspace must exit 0, got: {}", out);
    assert!(
        out.contains("guard") || out.contains("guard"),
        "verify must name the guards it ran, got: {}",
        out
    );
}

/// A real defect must fail, and name the file. This is the case that matters:
/// a verify that always passes is worse than no verify, because a loop trusts it.
#[test]
fn verify_fails_on_a_planted_defect() {
    let c = Case::new(
        "defect",
        &[("app.py", "import subprocess\n\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n")],
    );
    let (code, out) = c.verify(&[]);
    assert_ne!(code, 0, "planted shell=True must exit non-zero, got: {}", out);
    assert!(
        out.contains("app.py") || out.contains("shell"),
        "verify must locate the finding, got: {}",
        out
    );
}

/// A workspace with no tests at all is not a failure by itself, but it must be
/// reported as untested rather than silently counted as passing tests.
#[test]
fn verify_reports_a_missing_test_suite_honestly() {
    let c = Case::new("notests", &[("app.py", "def add(a, b):\n    return a + b\n")]);
    let (_code, out) = c.verify(&[]);
    assert!(
        out.to_lowercase().contains("no test") || out.to_lowercase().contains("skipped")
            || out.to_lowercase().contains("notest"),
        "verify must say it found no tests instead of implying tests passed: {}",
        out
    );
}

/// `--json` must emit parseable JSON carrying the boolean, because a loop
/// branches on it and should not have to scrape prose.
#[test]
fn verify_json_is_machine_readable() {
    let c = Case::new("json", &[("app.py", "def add(a, b):\n    return a + b\n")]);
    let (code, out) = c.verify(&["--json"]);
    assert_eq!(code, 0, "clean json verify must exit 0, got: {}", out);
    let start = out.find('{').expect("verify --json must emit a JSON object");
    let json = &out[start..];
    assert!(json.contains("\"ok\""), "json must carry an ok field: {}", json);
}

/// `--skip-tests` lets a caller run only the guards, and must still not report
/// a clean result without saying tests were skipped.
#[test]
fn verify_skip_tests_says_so() {
    let c = Case::new("skiptests", &[("app.py", "def add(a, b):\n    return a + b\n")]);
    let (code, out) = c.verify(&["--skip-tests"]);
    assert_eq!(code, 0, "guards-only on clean code must exit 0: {}", out);
    assert!(
        out.to_lowercase().contains("skip"),
        "--skip-tests must be visible in the receipt: {}",
        out
    );
}

/// An unindexed workspace must not be reported as verified. This is the
/// 0.15.2 class of bug: silent success because nothing was analysed.
#[test]
fn verify_does_not_claim_success_on_an_empty_workspace() {
    let dir = std::env::temp_dir().join("heides_verify_empty");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let out = Command::new(bin())
        .args(["verify"])
        .current_dir(&dir)
        .output()
        .expect("runs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.to_lowercase().contains("no file") || text.to_lowercase().contains("empty"),
        "an empty workspace must say so, not report success: {}",
        text
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = Path::new("");
}