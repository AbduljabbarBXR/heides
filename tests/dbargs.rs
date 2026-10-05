// Every `db` subcommand has to read the directory it was given.
//
// `db routes` and `db schema` were fixed once and the fix was written as a
// partial list. Every other subcommand kept resolving its root from index 4,
// which is the slot after a table or column name that only some of them take.
// Run from a home directory, `heides db orphans /path/to/svc` therefore walked
// the home directory and reported tables belonging to unrelated projects, with
// no hint that the argument had been ignored.
//
// A partial fix for a shape bug is not a fix, so this walks every subcommand
// and asserts the same thing about each: with a directory argument it inspects
// that directory, and without one it inspects the working directory.
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn run(cwd: &std::path::Path, args: &[&str]) -> String {
    let o = Command::new(env!("CARGO_BIN_EXE_heides"))
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("spawn heides");
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!("heides_dbshape_{}_{}", tag, stamp));
    std::fs::create_dir_all(&p).expect("create scratch");
    p
}

/// A project with exactly one table, reached by one query, plus a route so the
/// api surface layer has something to report.
fn project(tag: &str) -> std::path::PathBuf {
    let dir = scratch(tag);
    std::fs::write(
        dir.join("svc.js"),
        "const express=require('express');\n\
         const db=require('mysql');\n\
         const app=express();\n\
         app.get('/only_table',(req,res)=>{db.query('SELECT * FROM only_table',(e,r)=>res.json(r))});\n",
    )
    .expect("write fixture");
    std::fs::create_dir_all(dir.join("migrations")).expect("migrations");
    std::fs::write(
        dir.join("migrations").join("001.sql"),
        "CREATE TABLE only_table (id INT PRIMARY KEY);\n",
    )
    .expect("write migration");
    run(&dir, &["scan", "."]);
    dir
}

/// Subcommands whose first positional after the subcommand is the root.
const NO_NAME: [&str; 7] = [
    "tables",
    "orphans",
    "missingindex",
    "cycles",
    "policies",
    "routes",
    "schema",
];

#[test]
fn every_db_subcommand_without_a_name_honours_its_directory() {
    let dir = project("noname");
    // A directory with no database at all. If the argument is honoured the
    // output names the target; if it is ignored the output names this.
    let empty = scratch("noname_elsewhere");

    for sub in NO_NAME {
        let out = run(&empty, &["db", sub, dir.to_str().unwrap()]);
        assert!(
            !out.contains(empty.to_str().unwrap()),
            "`db {} <dir>` walked the working directory instead of <dir>.\n\
             working dir: {}\ngot: {}",
            sub,
            empty.display(),
            out
        );
    }
}

#[test]
fn db_tables_reports_the_tables_of_the_given_directory_only() {
    let dir = project("tables_only");
    let empty = scratch("tables_elsewhere");
    let out = run(&empty, &["db", "tables", dir.to_str().unwrap()]);
    assert!(
        out.contains("only_table"),
        "expected the fixture table, got: {}",
        out
    );
    // A walk of the working directory would pick up unrelated tables. Assert on
    // a name that exists in no fixture but is common in a real home directory.
    for foreign in ["API_MODELS", "ALIASES", "skills_db_locks"] {
        assert!(
            !out.contains(foreign),
            "`db tables <dir>` leaked table `{}` from an unrelated project:\n{}",
            foreign,
            out
        );
    }
}

#[test]
fn db_orphans_does_not_invent_tables_from_the_working_directory() {
    let dir = project("orphans_only");
    let empty = scratch("orphans_elsewhere");
    let out = run(&empty, &["db", "orphans", dir.to_str().unwrap()]);
    assert!(
        !out.contains("skills_db_locks") && !out.contains("custom_icons"),
        "`db orphans <dir>` reported tables that exist nowhere near <dir>:\n{}",
        out
    );
}

#[test]
fn a_name_taking_subcommand_still_steps_over_the_name() {
    // `columns`, `reads`, `writes` and `sensitive` do take a name, so the root
    // sits one slot further along. Passing name-then-dir must not treat the
    // name as the root.
    let dir = project("withname");
    let out = run(
        &scratch("withname_elsewhere"),
        &["db", "columns", "only_table", dir.to_str().unwrap()],
    );
    assert!(
        !out.contains("is not a directory"),
        "`db columns <name> <dir>` refused a valid directory:\n{}",
        out
    );
}

#[test]
fn every_db_subcommand_still_defaults_to_the_working_directory() {
    // The directory is optional everywhere. Guard against the fix turning an
    // omitted argument into an error.
    let dir = project("defaults");
    for sub in NO_NAME {
        let out = run(&dir, &["db", sub]);
        assert!(
            !out.contains("is not a directory"),
            "`db {}` with no directory must walk the cwd, got: {}",
            sub,
            out
        );
    }
}
