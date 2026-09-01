// Language detection and deterministic code parsing for the Spine.
//
// Uses tree sitter to extract symbols, call edges and import edges from the
// primary language set. Every result carries a file and a line so guards can
// point at exact evidence. No model is involved in this layer.

use std::path::Path;

use tree_sitter::{Node, Parser};

use crate::spine::{CallEdge, ImportEdge, Symbol};

pub fn detect_language(path: &Path) -> Option<String> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    let lang = match ext.as_str() {
        "rs" => "rust",
        "js" | "mjs" | "cjs" => "javascript",
        "ts" => "typescript",
        "tsx" => "typescript",
        "py" => "python",
        _ => return None,
    };
    Some(lang.to_string())
}

pub fn is_indexable(path: &Path) -> bool {
    detect_language(path).is_some()
}

fn language_for(lang: &str) -> Option<tree_sitter::Language> {
    match lang {
        "rust" => Some(tree_sitter_rust::LANGUAGE.into()),
        "javascript" => Some(tree_sitter_javascript::LANGUAGE.into()),
        "typescript" => {
            // Prefer the TSX variant when the file uses JSX, otherwise plain TS.
            Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        }
        "python" => Some(tree_sitter_python::LANGUAGE.into()),
        _ => None,
    }
}

pub struct ParsedFile {
    pub lang: String,
    pub symbols: Vec<Symbol>,
    pub calls: Vec<CallEdge>,
    pub imports: Vec<ImportEdge>,
}

/// Parse one file and return every extraction for it.
pub fn parse_file(path: &Path, content: &str) -> Option<ParsedFile> {
    let lang = detect_language(path)?;
    let grammar = language_for(&lang)?;
    let mut parser = Parser::new();
    parser.set_language(&grammar).ok()?;
    let tree = parser.parse(content.as_bytes(), None)?;
    let root = tree.root_node();

    let mut parsed = ParsedFile {
        lang,
        symbols: Vec::new(),
        calls: Vec::new(),
        imports: Vec::new(),
    };

    walk(root, content, path, &mut parsed, None);
    Some(parsed)
}

fn text<'a>(node: Node<'a>, content: &'a str) -> String {
    node.utf8_text(content.as_bytes()).unwrap_or("").to_string()
}

fn field_text<'a>(node: Node<'a>, content: &'a str, field: &str) -> Option<String> {
    node.child_by_field_name(field).map(|n| text(n, content))
}

fn name_of(node: Node, content: &str) -> Option<String> {
    if let Some(name) = field_text(node, content, "name") {
        if !name.is_empty() {
            return Some(name);
        }
    }
    // Fallback: first identifier leaf below the node.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        if kind == "identifier" || kind == "type_identifier" || kind == "property_identifier" {
            let t = text(child, content);
            if !t.is_empty() {
                return Some(t);
            }
        }
    }
    None
}

fn last_segment(full: &str) -> String {
    full.rsplit(['.', ':']).next().unwrap_or(full).trim().to_string()
}

/// Extract a readable signature for a function node, truncated at the body.
fn signature_of(node: Node, content: &str) -> String {
    let raw = text(node, content);
    let cut = raw.find('{').or_else(|| {
        raw.find(':').and_then(|i| raw[i..].find('\n').map(|j| i + j))
    });
    let end = cut.map(|c| c.min(160)).unwrap_or_else(|| raw.len().min(160));
    raw.get(..end).unwrap_or(&raw).trim().to_string()
}

/// The enclosing function or method name for a call site, if any.
fn enclosing_function(node: Node, content: &str) -> Option<String> {
    let mut cur = node.parent();
    while let Some(n) = cur {
        let kind = n.kind();
        if matches!(
            kind,
            "function_item"
                | "function_declaration"
                | "generator_function_declaration"
                | "method_definition"
                | "function_definition"
                | "arrow_function"
        ) {
            return name_of(n, content);
        }
        cur = n.parent();
    }
    None
}

const SYMBOL_KINDS: &[&str] = &[
    "function_item",
    "function_declaration",
    "generator_function_declaration",
    "function_definition",
    "method_definition",
    "struct_item",
    "class_declaration",
    "class_definition",
    "enum_item",
    "enum_declaration",
    "trait_item",
    "interface_declaration",
    "type_alias_declaration",
    "type_item",
    "mod_item",
    "const_item",
    "static_item",
];

fn walk(node: Node, content: &str, path: &Path, out: &mut ParsedFile, _current: Option<&str>) {
    let kind = node.kind();
    let line = node.start_position().row as u64 + 1;

    // Symbols
    if SYMBOL_KINDS.contains(&kind) {
        if let Some(name) = name_of(node, content) {
            let sig = if kind.contains("function") || kind == "method_definition" {
                signature_of(node, content)
            } else {
                String::new()
            };
            out.symbols.push(Symbol {
                name: name.clone(),
                kind: kind.to_string(),
                file: path.display().to_string(),
                line,
                lang: out.lang.clone(),
                signature: sig,
            });
        }
    }

    // Arrow functions assigned to const / let / var: a function symbol.
    if (kind == "arrow_function" || kind == "function") && out.lang != "python" {
        if let Some(parent) = node.parent() {
            if parent.kind() == "variable_declarator" {
                if let Some(name) = field_text(parent, content, "name") {
                    out.symbols.push(Symbol {
                        name: name.clone(),
                        kind: "function".to_string(),
                        file: path.display().to_string(),
                        line,
                        lang: out.lang.clone(),
                        signature: signature_of(node, content),
                    });
                }
            }
        }
    }

    // Calls
    let is_call = match out.lang.as_str() {
        "python" => kind == "call",
        _ => kind == "call_expression",
    };
    if is_call {
        if let Some(callee) = field_text(node, content, "function") {
            if !callee.is_empty() && !callee.contains('"') {
                let caller = enclosing_function(node, content).unwrap_or_else(|| "module level".to_string());
                out.calls.push(CallEdge {
                    caller,
                    callee: last_segment(&callee),
                    file: path.display().to_string(),
                    line,
                });
            }
        }
    }

    // Rust macro invocations behave like calls (println!, vec!, panic!).
    if out.lang == "rust" && kind == "macro_invocation" {
        if let Some(macro_name) = field_text(node, content, "macro") {
            let caller = enclosing_function(node, content).unwrap_or_else(|| "module level".to_string());
            out.calls.push(CallEdge {
                caller,
                callee: macro_name.trim_end_matches('!').to_string(),
                file: path.display().to_string(),
                line,
            });
        }
    }

    // Imports
    match kind {
        "use_declaration" => {
            // Rust: use a::b::Thing; the argument field holds the path.
            if let Some(imp) = field_text(node, content, "argument") {
                let clean = imp.trim_end_matches(';').trim().to_string();
                if !clean.is_empty() {
                    out.imports.push(ImportEdge {
                        file: path.display().to_string(),
                        imported: clean,
                        line,
                    });
                }
            }
        }
        "import_statement" if out.lang != "python" => {
            let imp = field_text(node, content, "source")
                .map(|s| s.trim_matches(['\'', '"']).to_string())
                .unwrap_or_else(|| "unknown".to_string());
            out.imports.push(ImportEdge {
                file: path.display().to_string(),
                imported: imp,
                line,
            });
        }
        "import_from_statement" => {
            let imp = field_text(node, content, "module_name")
                .unwrap_or_else(|| "unknown".to_string());
            out.imports.push(ImportEdge {
                file: path.display().to_string(),
                imported: imp,
                line,
            });
        }
        "import_statement" if out.lang == "python" => {
            // Python: import os, sys
            let mut parts = Vec::new();
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "dotted_name" || child.kind() == "name" {
                    parts.push(text(child, content));
                }
            }
            for p in parts {
                out.imports.push(ImportEdge {
                    file: path.display().to_string(),
                    imported: p,
                    line,
                });
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    let children: Vec<Node> = node.children(&mut cursor).collect();
    for child in children {
        walk(child, content, path, out, None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_symbols_and_calls() {
        let src = r#"
fn add(a: i32, b: i32) -> i32 { a + b }
fn main() {
    let x = add(1, 2);
    println!("{}", x);
}
"#;
        let p = std::path::Path::new("probe.rs");
        let parsed = parse_file(p, src).unwrap();
        let names: Vec<&str> = parsed.symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"add"));
        assert!(names.contains(&"main"));
        assert!(parsed.calls.iter().any(|c| c.callee == "add" && c.caller == "main"));
        assert!(parsed.calls.iter().any(|c| c.callee == "println"));
    }

    #[test]
    fn js_imports_and_arrows() {
        let src = "import fs from 'fs';\nconst greet = (n) => 'hi ' + n;\ngreet('x');\n";
        let p = std::path::Path::new("probe.js");
        let parsed = parse_file(p, src).unwrap();
        assert!(parsed.imports.iter().any(|i| i.imported == "fs"));
        assert!(parsed.symbols.iter().any(|s| s.name == "greet"));
        assert!(parsed.calls.iter().any(|c| c.callee == "greet"));
    }

    #[test]
    fn python_classes_and_imports() {
        let src = "import os\nfrom pathlib import Path\n\ndef run(name):\n    return Path(name)\n\nclass Worker:\n    def go(self):\n        return run('x')\n";
        let p = std::path::Path::new("probe.py");
        let parsed = parse_file(p, src).unwrap();
        assert!(parsed.imports.iter().any(|i| i.imported == "os"));
        assert!(parsed.imports.iter().any(|i| i.imported == "pathlib"));
        assert!(parsed.symbols.iter().any(|s| s.name == "run"));
        assert!(parsed.symbols.iter().any(|s| s.name == "Worker"));
        assert!(parsed.symbols.iter().any(|s| s.name == "go"));
        assert!(parsed.calls.iter().any(|c| c.callee == "run"));
    }
}
