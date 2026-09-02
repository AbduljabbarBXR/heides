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
        "php" => "php",
        "go" => "go",
        "java" => "java",
        "cs" => "csharp",
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
        "php" => Some(tree_sitter_php::LANGUAGE_PHP.into()),
        "go" => Some(tree_sitter_go::LANGUAGE.into()),
        "java" => Some(tree_sitter_java::LANGUAGE.into()),
        "csharp" => Some(tree_sitter_c_sharp::LANGUAGE.into()),
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
/// Bracket nesting beyond this depth can crash the C parser itself, which
/// is not a failure HEIDES may ever allow. Real source nests under a
/// hundred levels, minified bundles stay under five hundred, so any file
/// past this bound is treated as unparseable and skipped, the same way
/// oversized files are. The bound also leaves a wide safety margin above
/// the measured crash depth of the parser on a grown stack.
const MAX_BRACKET_DEPTH: usize = 500;

/// Lexically track bracket depth, ignoring brackets inside strings and
/// comments, so real files with long comment or string content are never
/// misjudged. Returns true when the file is too deeply nested to parse
/// safely.
fn pathological_nesting(content: &str) -> bool {
    let bytes = content.as_bytes();
    let mut depth: isize = 0;
    let mut in_line: bool = false;
    let mut in_block: bool = false;
    let mut in_str: Option<u8> = None;
    let mut escaped = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if in_line {
            if b == b'\n' {
                in_line = false;
            }
            i += 1;
            continue;
        }
        if in_block {
            if b == b'*' && bytes.get(i + 1) == Some(&b'/') {
                in_block = false;
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if let Some(q) = in_str {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == q {
                in_str = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                in_line = true;
                i += 2;
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                in_block = true;
                i += 2;
            }
            b'#' => {
                in_line = true;
                i += 1;
            }
            b'\'' | b'"' | b'`' => {
                in_str = Some(b);
                i += 1;
            }
            b'(' | b'[' | b'{' => {
                depth += 1;
                if depth > MAX_BRACKET_DEPTH as isize {
                    return true;
                }
                i += 1;
            }
            b')' | b']' | b'}' => {
                depth = (depth - 1).max(0);
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    false
}

pub fn parse_file(path: &Path, content: &str) -> Option<ParsedFile> {
    // Refuse files that could crash the C parser before it ever runs.
    if pathological_nesting(content) {
        return None;
    }
    // Every parse runs on a thread with a grown stack. The C parser
    // recurses with the nesting depth, and a hostile file at the allowed
    // limit must never be able to overflow whatever stack the caller
    // happens to run on. The reservation is virtual, the memory is only
    // committed as the stack actually grows.
    let owned_path = path.to_path_buf();
    let owned_content = content.to_string();
    std::thread::Builder::new()
        .name("heides parse".to_string())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || parse_inner(&owned_path, &owned_content))
        .ok()?
        .join()
        .ok()?
}

fn parse_inner(path: &Path, content: &str) -> Option<ParsedFile> {
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

    walk(root, content, path, &mut parsed, None, 0);
    Some(parsed)
}

fn text<'a>(node: Node<'a>, content: &'a str) -> String {
    node.utf8_text(content.as_bytes()).unwrap_or("").to_string()
}

fn field_text<'a>(node: Node<'a>, content: &'a str, field: &str) -> Option<String> {
    node.child_by_field_name(field).map(|n| text(n, content))
}

fn name_of(node: Node, content: &str) -> Option<String> {
    if let Some(name) = field_text(node, content, "name")
        && !name.is_empty()
    {
        return Some(name);
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
    full.rsplit(['.', ':'])
        .next()
        .unwrap_or(full)
        .trim()
        .to_string()
}

/// Extract the quoted string path from a Go import spec text.
fn quoted_path(spec: &str) -> Option<String> {
    let start = spec.find('"')? + 1;
    let rest = &spec[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Extract a readable signature for a function node, truncated at the body.
fn signature_of(node: Node, content: &str) -> String {
    let raw = text(node, content);
    let cut = raw.find('{').or_else(|| {
        raw.find(':')
            .and_then(|i| raw[i..].find('\n').map(|j| i + j))
    });
    let end = cut
        .map(|c| c.min(160))
        .unwrap_or_else(|| raw.len().min(160));
    raw.get(..end).unwrap_or(&raw).trim().to_string()
}

/// The enclosing function or method name for a call site, if any.
fn enclosing_function(node: Node, content: &str) -> Option<String> {
    let mut cur = node.parent();
    while let Some(n) = cur {
        let kind = n.kind();
        if kind == "function_item"
            || kind == "function_declaration"
            || kind == "generator_function_declaration"
            || kind == "method_definition"
            || kind == "function_definition"
            || kind == "method_declaration"
            || kind == "constructor_declaration"
            || kind == "local_function_statement"
            || kind == "arrow_function"
        {
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
    "method_declaration",
    "constructor_declaration",
    "local_function_statement",
    "struct_item",
    "class_declaration",
    "class_definition",
    "struct_declaration",
    "record_declaration",
    "enum_item",
    "enum_declaration",
    "trait_item",
    "trait_declaration",
    "interface_declaration",
    "type_alias_declaration",
    "type_declaration",
    "type_item",
    "mod_item",
    "const_item",
    "static_item",
];

/// Never descend deeper than this into the syntax tree. Real code nests
/// far shallower, and the cap keeps the walker immune to adversarial
/// nesting that would otherwise overflow the call stack.
const MAX_TREE_DEPTH: usize = 512;

fn walk(
    node: Node,
    content: &str,
    path: &Path,
    out: &mut ParsedFile,
    _current: Option<&str>,
    depth: usize,
) {
    if depth > MAX_TREE_DEPTH {
        return;
    }
    let kind = node.kind();
    let line = node.start_position().row as u64 + 1;

    // Symbols
    if SYMBOL_KINDS.contains(&kind)
        && let Some(name) = name_of(node, content)
    {
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

    // Arrow functions assigned to const / let / var: a function symbol.
    if (kind == "arrow_function" || kind == "function")
        && out.lang != "python"
        && let Some(parent) = node.parent()
        && parent.kind() == "variable_declarator"
        && let Some(name) = field_text(parent, content, "name")
    {
        out.symbols.push(Symbol {
            name: name.clone(),
            kind: "function".to_string(),
            file: path.display().to_string(),
            line,
            lang: out.lang.clone(),
            signature: signature_of(node, content),
        });
    }

    // Calls
    let is_call = match out.lang.as_str() {
        "python" => kind == "call",
        "java" => kind == "method_invocation",
        "php" => kind == "function_call_expression" || kind == "method_call_expression",
        "csharp" => kind == "invocation_expression",
        _ => kind == "call_expression",
    };
    if is_call {
        let callee_field = match out.lang.as_str() {
            "java" | "php" if kind == "method_invocation" || kind == "method_call_expression" => {
                field_text(node, content, "name")
            }
            _ => field_text(node, content, "function"),
        };
        if let Some(callee) = callee_field
            && !callee.is_empty()
            && !callee.contains('"')
            && !callee.contains('(')
        {
            let caller =
                enclosing_function(node, content).unwrap_or_else(|| "module level".to_string());
            out.calls.push(CallEdge {
                caller,
                callee: last_segment(&callee),
                file: path.display().to_string(),
                line,
            });
        }
    }

    // Rust macro invocations behave like calls (println!, vec!, panic!).
    if out.lang == "rust"
        && kind == "macro_invocation"
        && let Some(macro_name) = field_text(node, content, "macro")
    {
        let caller =
            enclosing_function(node, content).unwrap_or_else(|| "module level".to_string());
        out.calls.push(CallEdge {
            caller,
            callee: macro_name.trim_end_matches('!').to_string(),
            file: path.display().to_string(),
            line,
        });
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
            let imp =
                field_text(node, content, "module_name").unwrap_or_else(|| "unknown".to_string());
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
        "import_declaration" if out.lang == "go" => {
            // Go: import ( "fmt" ; alias "path" ) or import "path"
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "import_spec" || child.kind() == "import_spec_list" {
                    if child.kind() == "import_spec_list" {
                        let mut c2 = child.walk();
                        for spec in child.children(&mut c2) {
                            if spec.kind() == "import_spec"
                                && let Some(imp) = quoted_path(&text(spec, content))
                            {
                                out.imports.push(ImportEdge {
                                    file: path.display().to_string(),
                                    imported: imp,
                                    line,
                                });
                            }
                        }
                    } else if let Some(imp) = quoted_path(&text(child, content)) {
                        out.imports.push(ImportEdge {
                            file: path.display().to_string(),
                            imported: imp,
                            line,
                        });
                    }
                }
            }
        }
        "import_declaration" if out.lang == "java" => {
            // Java: import java.util.List;  the path is the node text minus
            // the keyword and the terminator
            let raw = text(node, content);
            let imp = raw
                .trim_start_matches("import")
                .trim_start_matches("static")
                .trim()
                .trim_end_matches(';')
                .trim()
                .to_string();
            if !imp.is_empty() {
                out.imports.push(ImportEdge {
                    file: path.display().to_string(),
                    imported: imp,
                    line,
                });
            }
        }
        "using_directive" if out.lang == "csharp" => {
            // C#: using System.Collections.Generic;  the name is the node
            // text minus the keyword and the terminator
            let raw = text(node, content);
            let imp = raw
                .trim_start_matches("using")
                .trim()
                .trim_end_matches(';')
                .trim()
                .to_string();
            let imp = imp.rsplit('=').next().unwrap_or(&imp).trim().to_string();
            if !imp.is_empty() {
                out.imports.push(ImportEdge {
                    file: path.display().to_string(),
                    imported: imp,
                    line,
                });
            }
        }
        "namespace_use_declaration" if out.lang == "php" => {
            // PHP: use Vendor\Package\Class as Alias;
            let mut imp = None;
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "namespace_use_clause" {
                    imp = Some(text(child, content));
                }
            }
            if let Some(raw) = imp {
                let clean = raw
                    .split(" as ")
                    .next()
                    .unwrap_or(&raw)
                    .trim()
                    .trim_start_matches('\\')
                    .to_string();
                if !clean.is_empty() {
                    out.imports.push(ImportEdge {
                        file: path.display().to_string(),
                        imported: clean,
                        line,
                    });
                }
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    let children: Vec<Node> = node.children(&mut cursor).collect();
    for child in children {
        walk(child, content, path, out, None, depth + 1);
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
        assert!(
            parsed
                .calls
                .iter()
                .any(|c| c.callee == "add" && c.caller == "main")
        );
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
    fn php_symbols_calls_and_imports() {
        let src = "<?php\nuse Vendor\\Package\\Thing;\nfunction greet($name) {\n    return helper($name);\n}\nclass App {\n    public function run() {\n        return greet('x');\n    }\n}\n";
        let p = std::path::Path::new("probe.php");
        let parsed = parse_file(p, src).unwrap();
        assert!(parsed.symbols.iter().any(|s| s.name == "greet"));
        assert!(parsed.symbols.iter().any(|s| s.name == "App"));
        assert!(parsed.symbols.iter().any(|s| s.name == "run"));
        assert!(
            parsed
                .imports
                .iter()
                .any(|i| i.imported == "Vendor\\Package\\Thing")
        );
        assert!(
            parsed
                .calls
                .iter()
                .any(|c| c.callee == "helper" && c.caller == "greet")
        );
        assert!(
            parsed
                .calls
                .iter()
                .any(|c| c.callee == "greet" && c.caller == "run")
        );
    }

    #[test]
    fn go_symbols_calls_and_imports() {
        let src = "package main\n\nimport (\n    \"fmt\"\n)\n\nfunc add(a int, b int) int {\n    return a + b\n}\n\nfunc main() {\n    fmt.Println(add(1, 2))\n}\n";
        let p = std::path::Path::new("probe.go");
        let parsed = parse_file(p, src).unwrap();
        assert!(parsed.symbols.iter().any(|s| s.name == "add"));
        assert!(parsed.symbols.iter().any(|s| s.name == "main"));
        assert!(parsed.imports.iter().any(|i| i.imported == "fmt"));
        assert!(
            parsed
                .calls
                .iter()
                .any(|c| c.callee == "add" && c.caller == "main")
        );
        assert!(parsed.calls.iter().any(|c| c.callee == "Println"));
    }

    #[test]
    fn java_symbols_calls_and_imports() {
        let src = "import java.util.List;\n\nclass App {\n    void load(HttpServletRequest request) {\n        String q = request.getParameter(\"id\");\n        run(q);\n    }\n    void run(String s) {}\n}\n";
        let p = std::path::Path::new("probe.java");
        let parsed = parse_file(p, src).unwrap();
        assert!(parsed.symbols.iter().any(|s| s.name == "App"));
        assert!(parsed.symbols.iter().any(|s| s.name == "load"));
        assert!(
            parsed
                .imports
                .iter()
                .any(|i| i.imported == "java.util.List")
        );
        assert!(
            parsed
                .calls
                .iter()
                .any(|c| c.callee == "getParameter" && c.caller == "load")
        );
        assert!(
            parsed
                .calls
                .iter()
                .any(|c| c.callee == "run" && c.caller == "load")
        );
    }

    #[test]
    fn csharp_symbols_calls_and_imports() {
        let src = "using System.Collections.Generic;\n\nclass App {\n    void Load() {\n        var x = helper(1);\n    }\n    int helper(int n) => n;\n}\n";
        let p = std::path::Path::new("probe.cs");
        let parsed = parse_file(p, src).unwrap();
        assert!(parsed.symbols.iter().any(|s| s.name == "App"));
        assert!(parsed.symbols.iter().any(|s| s.name == "Load"));
        assert!(
            parsed
                .imports
                .iter()
                .any(|i| i.imported == "System.Collections.Generic")
        );
        assert!(
            parsed
                .calls
                .iter()
                .any(|c| c.callee == "helper" && c.caller == "Load")
        );
    }
}
