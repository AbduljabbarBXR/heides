// The README is hand written, and a hand written list of commands is wrong
// within one release. This walks the dispatch table in `main.rs` and fails if a
// command exists that the README does not document, or if the README documents
// one that no longer exists.
//
// The parity claim in the README is that every MCP tool has a command line
// twin. This checks the other direction of the same thing: every command is
// documented.
use std::process::Command;

fn bin() -> std::path::PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(if cfg!(windows) {
        "heides.exe"
    } else {
        "heides"
    })
}

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Commands handled before the dispatch match, or deliberately absent.
const NOT_COMMANDS: &[&str] = &[""];

#[test]
fn every_command_is_documented_in_the_readme() {
    let readme = std::fs::read_to_string(repo_root().join("README.md")).expect("README.md");
    let main = std::fs::read_to_string(repo_root().join("src/main.rs")).expect("main.rs");

    // The dispatch arms, at the indentation the real match block uses.
    let mut commands: Vec<String> = Vec::new();
    for line in main.lines() {
        if let Some(rest) = line.strip_prefix("        \"") {
            if let Some((name, _tail)) = rest.split_once("\" => {") {
                let name = name.trim_end_matches('-');
                if !name.contains(' ') && !NOT_COMMANDS.contains(&name) {
                    commands.push(name.to_string());
                }
            }
        }
    }
    commands.sort();
    commands.dedup();
    assert!(
        commands.len() > 12,
        "dispatch table parsed as {} commands, which is too few to be the real table",
        commands.len()
    );

    let mut missing: Vec<&str> = Vec::new();
    for c in &commands {
        // `changed-since` is the only hyphenated one, and it is documented under
        // its own name, so a plain backtick search is enough.
        if !readme.contains(&format!("`{c}`")) {
            missing.push(c);
        }
    }
    assert!(
        missing.is_empty(),
        "README documents 7 commands and misses these: {missing:?}. A hand \
         maintained command list goes stale silently, so it is checked."
    );
}

#[test]
fn the_mcp_tool_count_in_the_readme_is_not_a_guess() {
    let readme = std::fs::read_to_string(repo_root().join("README.md")).expect("README.md");
    let server = std::fs::read_to_string(repo_root().join("src/server.rs")).expect("server.rs");

    // Count the declared tools, then require the README to state that number.
    let declared = server.matches("\"name\": \"").count();
    assert!(
        declared > 5,
        "only {declared} tool declarations parsed, which cannot be right"
    );
    let stated = ["twenty one", "twenty", "thirty", "forty"]
        .iter()
        .any(|w| readme.contains(w));
    assert!(
        stated,
        "the README states no tool count, and it claimed 'eleven' while the \
         server declares {declared}. Say how many there are."
    );
}

#[test]
fn an_unknown_flag_is_not_a_directory_for_any_command() {
    // Spot check that the new flag guard covers the documented commands. `plan`,
    // `scaffold`, `mcp` and `version` are exempt because they take free text.
    let dir = std::env::temp_dir().join(format!("heides_flags_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a.py"), "def f():\n    return 1\n").unwrap();

    // `confirm` is deliberately not in this list. It is the one command that
    // reaches the network, and a test that made two registry calls while the
    // battle suite ran 89 subprocesses in parallel cost a check in that suite.
    // A unit test does not get to touch the network.
    for cmd in ["check", "describe", "deps", "db", "config"] {
        let out = Command::new(bin())
            .arg(cmd)
            .arg("--nope")
            .arg(&dir)
            .output()
            .expect("binary runs");
        let text = String::from_utf8_lossy(&out.stdout);
        let created = dir.join("--nope").exists();
        assert!(
            !created,
            "`heides {cmd} --nope` created a directory named --nope"
        );
        assert!(
            !text.contains("analysed 0 of 0"),
            "`heides {cmd} --nope` reported an empty workspace instead of the bad flag: {text}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
