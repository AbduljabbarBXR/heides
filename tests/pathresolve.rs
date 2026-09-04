// Regression for the false clean: an index scanned from a parent directory
// must produce the same findings when checked from inside the repo. Stored
// paths are keys relative to the recorded scan root, so the working
// directory of the check must not matter.
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn run(cwd: &std::path::Path, args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_heides"))
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("spawn heides");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn check_matches_across_working_directories() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let parent = std::env::temp_dir().join(format!("heides_pathtest_{}", stamp));
    let child = parent.join("child");
    std::fs::create_dir_all(&child).expect("create temp child");
    let fixture = "def render(request):\n    name = input()\n    return mark_safe(name)\n";
    std::fs::write(child.join("view.py"), fixture).expect("write fixture");

    // Scan from the parent with the repo path as the root argument, the
    // sweep style invocation that used to store prefixed paths.
    let (ok_scan, _) = run(&parent, &["scan", "child"]);
    assert!(ok_scan, "scan from parent must succeed");

    // Check from inside the repo, the invocation that used to read nothing.
    let (ok_inside, inside) = run(&child, &["check", "."]);
    assert!(ok_inside, "check from inside must succeed");
    assert!(
        inside.contains("mark_safe") && inside.contains("view.py"),
        "check from inside the repo must report the fixture finding"
    );

    // Check from the parent, the same index must report the same finding.
    let (ok_parent, parent_out) = run(&parent, &["check", "child"]);
    assert!(ok_parent, "check from parent must succeed");
    assert!(
        parent_out.contains("mark_safe") && parent_out.contains("view.py"),
        "check from the parent must report the same finding"
    );

    let _ = std::fs::remove_dir_all(&parent);
}
