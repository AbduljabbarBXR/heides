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
}

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
        };
    }

    notes.push("grounding received the plan.".to_string());

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
        if !graph.symbols_named(word).is_empty() {
            if !found.contains(&word.to_string()) {
                found.push(word.to_string());
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
                notes.push(format!("path {} does not exist yet. it will be created.", clean));
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

    PlanVerdict {
        feasible: true,
        notes,
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

    let (files, _content): (Vec<(&str, String)>, ()) = if plan.contains("rust") || plan.contains("cargo") {
        (
            vec![
                ("Cargo.toml", r#"name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
"#
                .to_string()),
                ("src/main.rs", "fn main() {\n    println!(\"hello from the scaffold\");\n}\n".to_string()),
            ],
            (),
        )
    } else if plan.contains("python") || plan.contains("flask") || plan.contains("fastapi") {
        (
            vec![
                ("app.py", "def main():\n    print(\"hello from the scaffold\")\n\n\nif __name__ == \"__main__\":\n    main()\n".to_string()),
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
                ("app/page.js", "export default function Page() {\n  return <main>hello from the scaffold</main>;\n}\n".to_string()),
            ],
            (),
        )
    } else {
        (
            vec![
                ("package.json", r#"{
  "name": "app",
  "version": "0.1.0",
  "scripts": {
    "start": "node index.js"
  }
}
"#
                .to_string()),
                ("index.js", "console.log(\"hello from the scaffold\");\n".to_string()),
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
    crate::spine::save(&graph, &dir.to_path_buf()).map_err(|e| e.to_string())?;
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
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(crates) = value.get("crates").and_then(|v| v.as_array()) {
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
        }
        Err(_) => out.push("crates.io was unreachable".to_string()),
    }
    let npm_url = format!(
        "https://registry.npmjs.org/-/v1/search?text={}&size=3",
        urlencode(query)
    );
    match crate::web::get(&npm_url) {
        Ok(body) => {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(objs) = value.get("objects").and_then(|v| v.as_array()) {
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
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_missing_symbols() {
        let graph = CodeGraph::new();
        let root = std::path::PathBuf::from("/tmp");
        let v = evaluate("refactor the checkout_flow to use the new pricing_engine", &graph, &root);
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
}
