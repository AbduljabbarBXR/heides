// Grounding is the refinement organ of HEIDES.
//
// It takes an objective or a plan and checks it against the spine graph and
// against the outside world. It confirms feasibility, surfaces missing
// prerequisites, and produces a bounded specification that the agent then
// builds against. For new projects it scaffolds the app from the plan.

use std::path::Path;

use crate::spine::CodeGraph;

#[derive(Debug, Clone, serde::Serialize)]
pub struct PlanVerdict {
    pub feasible: bool,
    pub notes: Vec<String>,
    /// What the plan was actually grounded on: symbol, file and line. The
    /// audit found plan printing "feasible true" with no evidence, which
    /// reads as a verdict rather than an absence of one.
    pub evidence: Vec<Evidence>,
}

/// One grounded fact behind the verdict.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Evidence {
    pub kind: String,
    pub symbol: String,
    pub file: String,
    pub line: u64,
}

/// How many evidence rows a verdict may carry. Bounded output is part of the
/// contract: grounding runs inside an agent loop.
const MAX_EVIDENCE: usize = 12;

/// Evaluate a plan against the current codebase graph.
///
/// The plan text is scanned for identifiers. Every identifier that matches a
/// symbol in the spine is confirmed. Identifiers that look like code symbols
/// but are missing from the spine are flagged so the agent knows the ground
/// truth before it starts.
pub fn evaluate(plan: &str, graph: &CodeGraph, root: &Path) -> PlanVerdict {
    let mut notes = Vec::new();
    let plan = plan.trim();
    if plan.is_empty() {
        notes.push("the plan is empty. describe the objective first.".to_string());
        return PlanVerdict {
            feasible: false,
            notes,
            evidence: Vec::new(),
        };
    }

    notes.push("grounding received the plan.".to_string());

    let mut evidence: Vec<Evidence> = Vec::new();
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for word in plan.split(|c: char| !c.is_alphanumeric() && c != '_') {
        let word = word.trim();
        if word.len() < 3 || word.len() > 64 {
            continue;
        }
        if word.starts_with(char::is_numeric) {
            continue;
        }
        let hits = graph.symbols_named(word);
        if !hits.is_empty() {
            if !found.contains(&word.to_string()) {
                found.push(word.to_string());
            }
            // A name can exist in more than one file. An agent planning a
            // change needs to know that, so every distinct location is listed
            // rather than the first one, and the note says how many there are.
            let mut locations = 0usize;
            for h in hits.iter() {
                if evidence.iter().any(|e| e.symbol == h.name && e.file == h.file) {
                    continue;
                }
                if evidence.len() >= MAX_EVIDENCE {
                    break;
                }
                evidence.push(Evidence {
                    kind: "symbol".to_string(),
                    symbol: h.name.clone(),
                    file: h.file.clone(),
                    line: h.line,
                });
                locations += 1;
            }
            if locations > 1 {
                notes.push(format!(
                    "symbol {} exists in {} files, every location is listed as evidence.",
                    word,
                    hits.len()
                ));
            }
            continue;
        }
        let is_code_word = word.contains('_') || is_camel(word);
        if is_code_word && !missing.contains(&word.to_string()) {
            missing.push(word.to_string());
        }
    }

    for f in &found {
        notes.push(format!("symbol {} is confirmed in the spine.", f));
    }
    for m in &missing {
        notes.push(format!(
            "symbol {} is not in the spine index. state it as a new definition or check the name.",
            m
        ));
    }

    // Path grounding: anything that looks like a path must exist.
    for word in plan.split_whitespace() {
        let clean = word.trim_matches(['\'', '"', '(', ')', ',', '.']);
        if clean.contains('/') && !clean.starts_with("http") {
            let target = root.join(clean.trim_start_matches('/'));
            if target.exists() {
                notes.push(format!("path {} exists.", clean));
            } else if !clean.contains('.') || clean.ends_with('/') {
                notes.push(format!(
                    "path {} does not exist yet. it will be created.",
                    clean
                ));
            }
        }
    }

    if !found.is_empty() || !missing.is_empty() {
        notes.push(format!(
            "grounding found {} confirmed symbol(s) and {} missing symbol(s).",
            found.len(),
            missing.len()
        ));
    }

    if found.is_empty() {
        // No identifier in the plan exists yet. Say that plainly, and hand
        // over what the spine does contain so the agent is not left guessing.
        notes.push(
            "no identifier in this plan exists in the spine. this plan introduces new definitions."
                .to_string(),
        );
        let closest: Vec<String> = graph
            .symbols
            .iter()
            .filter(|s| s.kind.contains("function") || s.kind.contains("method"))
            .map(|s| format!("{} at {}:{}", s.name, s.file, s.line))
            .take(3)
            .collect();
        if !closest.is_empty() {
            notes.push(format!(
                "existing functions to build on or replace: {}.",
                closest.join(", ")
            ));
        }
        notes.push(format!(
            "spine holds {} file(s) and {} symbol(s). index version {}.",
            graph.files.len(),
            graph.symbols.len(),
            crate::spine::INDEX_VERSION
        ));
    }

    PlanVerdict {
        feasible: true,
        notes,
        evidence,
    }
}

fn is_camel(word: &str) -> bool {
    let chars: Vec<char> = word.chars().collect();
    if chars.len() < 2 {
        return false;
    }
    chars[0].is_lowercase() && chars[1..].iter().any(|c| c.is_uppercase())
}

/// Scaffold a new project from a plan.
/// Returns the list of created files.
pub fn scaffold(plan: &str, dir: &Path) -> Result<Vec<String>, String> {
    let plan = plan.to_ascii_lowercase();
    let mut created = Vec::new();
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;

    let (files, _content): (Vec<(&str, String)>, ()) = if plan.contains("rust")
        || plan.contains("cargo")
    {
        (
            vec![
                (
                    "Cargo.toml",
                    r#"name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
"#
                    .to_string(),
                ),
                (
                    "src/main.rs",
                    "// Entry point. Prints the scaffold greeting.\nfn main() {\n    println!(\"hello from the scaffold\");\n}\n"
                        .to_string(),
                ),
            ],
            (),
        )
    } else if plan.contains("python") || plan.contains("flask") || plan.contains("fastapi") {
        (
            vec![
                ("app.py", "# Entry point. Runs the greeting.\ndef main():\n    print(\"hello from the scaffold\")\n\n\nif __name__ == \"__main__\":\n    main()\n".to_string()),
                ("requirements.txt", String::new()),
            ],
            (),
        )
    } else if plan.contains("next") || plan.contains("react") {
        (
            vec![
                ("package.json", r#"{
  "name": "app",
  "version": "0.1.0",
  "scripts": {
    "dev": "next dev"
  },
  "dependencies": {
    "next": "latest",
    "react": "latest"
  }
}
"#
                .to_string()),
                ("app/page.js", "// Home page. Renders the scaffold greeting.\nexport default function Page() {\n  return <main>hello from the scaffold</main>;\n}\n".to_string()),
            ],
            (),
        )
    } else {
        (
            vec![
                (
                    "package.json",
                    r#"{
  "name": "app",
  "version": "0.1.0",
  "scripts": {
    "start": "node index.js"
  }
}
"#
                    .to_string(),
                ),
                (
                    "index.js",
                    "// App entry. Prints the scaffold greeting.\nconsole.log(\"hello from the scaffold\");\n".to_string(),
                ),
            ],
            (),
        )
    };

    for (name, body) in files {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&path, body).map_err(|e| e.to_string())?;
        created.push(path.display().to_string());
    }

    // Index the fresh project immediately so the agent starts with a map.
    let (graph, count) = crate::indexer::build_graph(dir);
    crate::spine::save(&graph, dir).map_err(|e| e.to_string())?;
    created.push(format!("spine index built from {} parsed files", count));
    Ok(created)
}

/// Confirm a fact against the web: search package registries.
/// Returns a compact text digest of the top results.
pub fn web_confirm(query: &str) -> String {
    let mut out = Vec::new();
    let crates_url = format!(
        "https://crates.io/api/v1/crates?q={}&per_page=3",
        urlencode(query)
    );
    match crate::web::get(&crates_url) {
        Ok(body) => {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&body)
                && let Some(crates) = value.get("crates").and_then(|v| v.as_array())
            {
                for c in crates.iter().take(3) {
                    let name = c.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                    let desc = c
                        .get("description")
                        .and_then(|v| v.as_str())
                        .unwrap_or("no description");
                    out.push(format!("crate {} : {}", name, desc));
                }
            }
        }
        Err(_) => out.push("crates.io was unreachable".to_string()),
    }
    let npm_url = format!(
        "https://registry.npmjs.org/-/v1/search?text={}&size=3",
        urlencode(query)
    );
    match crate::web::get(&npm_url) {
        Ok(body) => {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&body)
                && let Some(objs) = value.get("objects").and_then(|v| v.as_array())
            {
                for o in objs.iter().take(3) {
                    if let Some(pkg) = o.get("package") {
                        let name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                        let desc = pkg
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or("no description");
                        out.push(format!("npm package {} : {}", name, desc));
                    }
                }
            }
        }
        Err(_) => out.push("npm registry was unreachable".to_string()),
    }
    if out.is_empty() {
        "no results found".to_string()
    } else {
        out.join("\n")
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spine::{CodeGraph, FileEntry, Symbol};

    fn graph_with() -> CodeGraph {
        let mut g = CodeGraph::new();
        g.files.push(FileEntry {
            path: "src/auth.rs".into(),
            lang: "rust".into(),
            mtime: 1,
            size: 1,
        });
        for (name, line) in [("login", 4u64), ("refresh_token", 9), ("logout", 14)] {
            g.symbols.push(Symbol {
                name: name.into(),
                kind: "function_definition".into(),
                file: "src/auth.rs".into(),
                line,
                lang: "rust".into(),
                signature: format!("fn {name}()"),
                params: vec![],
                doc: String::new(),
            });
        }
        g.rebuild_indexes();
        g
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("heides_{tag}_{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_plan_naming_a_symbol_comes_back_with_evidence() {
        let g = graph_with();
        let v = evaluate("call refresh_token before login", &g, &tmp("ground_a"));
        assert!(v.feasible);
        let refresh = v
            .evidence
            .iter()
            .find(|e| e.symbol == "refresh_token")
            .expect("refresh_token must be grounded");
        assert_eq!(refresh.file, "src/auth.rs");
        assert_eq!(refresh.line, 9);
        assert!(!v.notes.iter().any(|n| n.contains("introduces new definitions")));
    }

    #[test]
    fn a_plan_with_nothing_existing_says_so_instead_of_pretending() {
        let g = graph_with();
        let v = evaluate("add a health endpoint", &g, &tmp("ground_b"));
        assert!(v.feasible);
        assert!(v.evidence.is_empty(), "{:?}", v.evidence);
        assert!(
            v.notes.iter().any(|n| n.contains("introduces new definitions")),
            "{:?}",
            v.notes
        );
        assert!(
            v.notes.iter().any(|n| n.contains("existing functions to build on")),
            "{:?}",
            v.notes
        );
    }

    #[test]
    fn a_name_in_two_files_lists_both_locations() {
        // Found by running the release binary: the evidence named only the
        // first file, which reads as if the other one did not exist.
        let mut g = graph_with();
        g.files.push(FileEntry {
            path: "src/routes.rs".into(),
            lang: "rust".into(),
            mtime: 1,
            size: 1,
        });
        g.symbols.push(Symbol {
            name: "login".into(),
            kind: "function_definition".into(),
            file: "src/routes.rs".into(),
            line: 21,
            lang: "rust".into(),
            signature: "fn login()".into(),
            params: vec![],
            doc: String::new(),
        });
        g.rebuild_indexes();
        let v = evaluate("harden login", &g, &tmp("ground_c"));
        let files: Vec<&str> = v
            .evidence
            .iter()
            .filter(|e| e.symbol == "login")
            .map(|e| e.file.as_str())
            .collect();
        assert_eq!(files.len(), 2, "{:?}", v.evidence);
        assert!(files.contains(&"src/auth.rs") && files.contains(&"src/routes.rs"));
        assert!(
            v.notes.iter().any(|n| n.contains("exists in 2 files")),
            "{:?}",
            v.notes
        );
    }

    #[test]
    fn evidence_is_capped() {
        let mut g = graph_with();
        for i in 0..40 {
            g.symbols.push(Symbol {
                name: format!("symbol_number_{i}"),
                kind: "function_definition".into(),
                file: "src/many.rs".into(),
                line: i as u64 + 1,
                lang: "rust".into(),
                signature: String::new(),
                params: vec![],
                doc: String::new(),
            });
        }
        g.rebuild_indexes();
        let plan = (0..40)
            .map(|i| format!("symbol_number_{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        let v = evaluate(&plan, &g, &tmp("ground_d"));
        assert!(v.evidence.len() <= MAX_EVIDENCE, "{}", v.evidence.len());
    }

    #[test]
    fn flags_missing_symbols() {
        let graph = CodeGraph::new();
        let root = std::path::PathBuf::from("/tmp");
        let v = evaluate(
            "refactor the checkout_flow to use the new pricing_engine",
            &graph,
            &root,
        );
        assert!(v.notes.iter().any(|n| n.contains("checkout_flow")));
        assert!(v.notes.iter().any(|n| n.contains("pricing_engine")));
    }

    #[test]
    fn scaffolds_rust() {
        let dir = std::env::temp_dir().join(format!("heides_scaffold_{}", std::process::id()));
        let files = scaffold("build a rust cli tool", &dir).unwrap();
        assert!(files.iter().any(|f| f.ends_with("Cargo.toml")));
        assert!(files.iter().any(|f| f.ends_with("main.rs")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scaffolded_code_is_documented_from_birth() {
        let dir = std::env::temp_dir().join(format!("heides_scaffold_doc_{}", std::process::id()));
        scaffold("a python cli tool", &dir).unwrap();
        let graph = crate::spine::load(&dir).expect("scaffold must index itself");
        let main = graph.symbols_named("main");
        let documented = main
            .iter()
            .any(|s| s.lang == "python" && s.doc.contains("Entry point"));
        assert!(documented, "scaffold main must carry its doc comment");
        let undocumented_fns: Vec<_> = graph
            .symbols
            .iter()
            .filter(|s| s.lang == "python" && s.kind.contains("function") && s.doc.is_empty())
            .collect();
        assert!(
            undocumented_fns.is_empty(),
            "newborn code must not ship undocumented functions"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
