// Regressions for three defects where a command reported success about work
// it had not done.
//
//   1. An unrecognised flag became the workspace root, so `heides check --json .`
//      scanned a directory literally named `--json`, found nothing, and exited 0.
//   2. A root that does not exist reported a clean workspace and created the
//      directory in order to write an empty index into it.
//   3. `--no-advice` deleted a proven hardcoded credential along with the style
//      opinions the flag exists to remove.
//
// Each of these is a silent pass on a security gate, which is worse than a
// loud failure, so each is pinned here rather than left to a manual check.
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct Out {
    ok: bool,
    stdout: String,
    stderr: String,
}

fn run(cwd: &std::path::Path, args: &[&str]) -> Out {
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

fn scratch(tag: &str) -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!("heides_flags_{}_{}", tag, stamp));
    std::fs::create_dir_all(&p).expect("create scratch");
    p
}

#[test]
fn an_unknown_flag_is_refused_rather_than_used_as_the_root() {
    let dir = scratch("unknown_flag");
    std::fs::write(
        dir.join("app.py"),
        "import subprocess\ndef view(cmd):\n    subprocess.call(\"sh -c \" + cmd, shell=True)\n",
    )
    .expect("write fixture");

    // Sanity: the real root does report the finding.
    let real = run(&dir, &["check", "."]);
    assert!(
        real.stdout.contains("critical"),
        "the fixture must be dirty, got: {}{}",
        real.stdout,
        real.stderr
    );

    // The bug: `--json` is a real flag but `check` does not accept it, and the
    // old parser read it as the root.
    let wrong = run(&dir, &["check", "--json", "."]);
    assert!(
        !wrong.ok,
        "an unaccepted flag must not exit 0, stdout was: {}",
        wrong.stdout
    );
    assert!(
        wrong.stderr.contains("unknown flag"),
        "the refusal must name the flag, stderr was: {}",
        wrong.stderr
    );
    assert!(
        !dir.join("--json").exists(),
        "no directory named after a flag may be created"
    );
}

#[test]
fn a_typo_in_a_flag_cannot_become_a_clean_pass() {
    let dir = scratch("typo");
    std::fs::write(
        dir.join("app.py"),
        "import subprocess\ndef view(cmd):\n    subprocess.call(\"sh -c \" + cmd, shell=True)\n",
    )
    .expect("write fixture");
    let out = run(&dir, &["check", "--no-adivce", "."]);
    assert!(!out.ok, "a misspelled flag must not exit 0");
    assert!(
        out.stderr.contains("unknown flag"),
        "stderr: {}",
        out.stderr
    );
}

#[test]
fn a_root_that_does_not_exist_is_not_a_clean_workspace() {
    let dir = scratch("missing");
    let ghost = dir.join("not_here");
    let out = run(&dir, &["check", ghost.to_str().unwrap()]);
    assert!(!out.ok, "a missing root must fail");
    assert!(
        out.stderr.contains("not a directory"),
        "the refusal must say why, stderr was: {}",
        out.stderr
    );
    assert!(
        !ghost.exists(),
        "the missing root must not be created to hold an index"
    );
}

#[test]
fn a_missing_root_never_prints_a_clean_receipt() {
    let dir = scratch("missing_receipt");
    let ghost = dir.join("also_not_here");
    let out = run(&dir, &["check", ghost.to_str().unwrap()]);
    assert!(
        !out.stdout.contains("the workspace is clean"),
        "a path that was never inspected must not read as clean, got: {}",
        out.stdout
    );
}

#[test]
fn no_advice_keeps_a_proven_credential() {
    let dir = scratch("cred");
    std::fs::write(
        dir.join("x.py"),
        "AWS_KEY = \"AKIAIOSFODNN7EXAMPLEKEY1234\"\n",
    )
    .expect("write fixture");

    let plain = run(&dir, &["check", "."]);
    assert!(
        plain.stdout.contains("AWS access key id"),
        "the credential must be reported at all, got: {}",
        plain.stdout
    );

    let filtered = run(&dir, &["check", "--no-advice", "."]);
    assert!(
        filtered.stdout.contains("AWS access key id"),
        "--no-advice must not delete a proven credential, got: {}",
        filtered.stdout
    );
    assert!(
        !filtered.ok,
        "a credential gate must still fail with --no-advice, stdout: {}",
        filtered.stdout
    );
}

#[test]
fn no_advice_still_drops_the_style_opinions() {
    let dir = scratch("advice_only");
    // A long function with no credential in it: only the style rule can fire.
    let body = "def big():\n    x = 0\n";
    let mut src = String::from(body);
    for i in 0..60 {
        src.push_str(&format!("    x = {} + x\n", i));
    }
    src.push_str("    return x\n");
    std::fs::write(dir.join("long.py"), src).expect("write fixture");

    let filtered = run(&dir, &["check", "--no-advice", "."]);
    assert!(
        !filtered.stdout.contains("spans"),
        "--no-advice must still remove style advice, got: {}",
        filtered.stdout
    );
}

#[test]
fn db_routes_reads_the_directory_it_was_given() {
    // `db routes <dir>` used to skip past the directory and walk `.` instead,
    // so it reported no routes for a project that has them.
    let dir = scratch("dbroutes");
    std::fs::create_dir_all(dir.join("src")).expect("src");
    std::fs::write(
        dir.join("src").join("s.js"),
        "const express=require('express');\n\
         const db=require('mysql');\n\
         const app=express();\n\
         app.get('/thing/:id',(req,res)=>{db.query('SELECT * FROM things WHERE id='+req.params.id,(e,r)=>res.json(r))});\n",
    )
    .expect("write fixture");

    // The api surface walks from an endpoint through the call graph, so it
    // needs an index. Building it against the fixture also proves the command
    // is not reading `.`.
    assert!(
        run(&dir, &["scan", "."]).ok,
        "scanning the fixture must succeed"
    );

    // Somewhere else entirely, so `.` has no database and only <dir> does.
    let elsewhere = scratch("dbroutes_elsewhere");

    let wrong = run(&elsewhere, &["db", "routes", dir.to_str().unwrap()]);
    assert!(
        wrong.stdout.contains("GET /thing/:id"),
        "db routes must honour its directory argument, got: {}",
        wrong.stdout
    );

    // And the same subcommand without a directory must still default to `.`,
    // because that shape has always worked.
    let cwd = run(&dir, &["db", "routes"]);
    assert!(
        cwd.stdout.contains("GET /thing/:id"),
        "db routes with no directory must walk the cwd, got: {}",
        cwd.stdout
    );
}

#[test]
fn db_routes_still_defaults_to_the_working_directory() {
    // Guards the fix above from over-correcting: `routes` moved from root
    // offset 4 to 3, and a directory argument is optional for every subcommand.
    let dir = scratch("dbroutes_cwd");
    std::fs::write(
        dir.join("s.js"),
        "const express=require('express');\n\
         const db=require('mysql');\n\
         const app=express();\n\
         app.post('/make',(req,res)=>{db.query('INSERT INTO things VALUES (1)',()=>{})});\n",
    )
    .expect("write fixture");
    assert!(run(&dir, &["scan", "."]).ok, "scan must succeed");
    let out = run(&dir, &["db", "routes"]);
    assert!(out.stdout.contains("POST /make"), "got: {}", out.stdout);
}
