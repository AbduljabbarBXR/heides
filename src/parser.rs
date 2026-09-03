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

/// A name is a real parameter name only when it is a plain identifier.
/// PHP variable names keep their dollar sign in the tree, strip it here so
/// parameter names line up with the name based taint tracking.
fn clean_param_name(raw: &str) -> Option<String> {
    let t = raw.trim().trim_start_matches('$').trim();
    if t.is_empty() {
        return None;
    }
    if t.chars().all(|c| c.is_alphanumeric() || c == '_')
        && !t.chars().next().is_some_and(|c| c.is_ascii_digit())
    {
        Some(t.to_string())
    } else {
        None
    }
}

/// Extract the name of one parameter child node, defensively across the
/// eight grammars. Tries the name field, then the pattern field (rust
/// patterns, js assignment patterns), then the first identifier shaped
/// child in source order. Returns None when nothing looks like a name.
fn param_name_of(node: Node, content: &str) -> Option<String> {
    // Python, javascript and typescript write plain parameters as bare
    // identifier nodes, no name field, no pattern. The node itself is
    // the name, return it before descending.
    if matches!(
        node.kind(),
        "identifier" | "name" | "variable_name" | "property_identifier"
    ) && let Some(name) = clean_param_name(&text(node, content))
    {
        return Some(name);
    }
    for field in ["name", "pattern"] {
        if let Some(n) = node.child_by_field_name(field)
            && let Some(name) = clean_param_name(&text(n, content))
        {
            return Some(name);
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        if (kind == "identifier"
            || kind == "name"
            || kind == "variable_name"
            || kind == "property_identifier")
            && let Some(name) = clean_param_name(&text(child, content))
        {
            return Some(name);
        }
        // Python typed parameters and csharp pointers nest the identifier
        // one level down (typed_parameter, spread forms), look one level
        // into the child before giving up on it.
        if let Some(name) = first_identifier_descendant(child, content) {
            return Some(name);
        }
    }
    None
}

/// First identifier shaped leaf one level below a parameter child.
fn first_identifier_descendant(node: Node, content: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        if (kind == "identifier" || kind == "name" || kind == "variable_name")
            && let Some(name) = clean_param_name(&text(child, content))
        {
            return Some(name);
        }
    }
    None
}

/// Parameter names of a function node in source order. The parameters
/// child is a field on every function kind in the eight grammars, so the
/// field lookup is the primary path and a kind based search is the
/// defensive fallback. Self and receiver parameters carry no name and are
/// skipped, which keeps their position from shifting later arguments.
fn params_of(node: Node, content: &str) -> Vec<String> {
    let params_node = node.child_by_field_name("parameters").or_else(|| {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            let kind = child.kind();
            if kind == "parameters"
                || kind == "formal_parameters"
                || kind == "parameter_list"
                || (kind.contains("parameter") && kind != "type_parameters")
            {
                return Some(child);
            }
        }
        None
    });
    let Some(pn) = params_node else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut cursor = pn.walk();
    for child in pn.children(&mut cursor) {
        if let Some(name) = param_name_of(child, content) {
            out.push(name);
        }
    }
    out
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

/// True when a value node kind is captured for this language. Rust owned
/// the value capture until every grammar got its own extraction path, the
/// matrix below is that path, one language at a time.
fn value_allowed(lang: &str, kind: &str) -> bool {
    match lang {
        "rust" => matches!(kind, "enum_variant" | "field_declaration"),
        "go" => matches!(kind, "field_declaration" | "const_spec" | "var_spec"),
        "java" => matches!(kind, "field_declaration" | "constant_declaration"),
        "csharp" => matches!(kind, "field_declaration" | "enum_member_declaration"),
        "javascript" | "typescript" => {
            matches!(kind, "field_definition" | "public_field_definition")
        }
        _ => false,
    }
}

/// Value node names, extracted per grammar so the type first languages
/// never name their own type. Java and csharp fields declare inside
/// declarator children, go const and var specs carry a name field, js
/// class fields carry a property name, rust fields are one identifier.
fn value_names_of(node: Node, content: &str, lang: &str) -> Vec<String> {
    let kind = node.kind();
    match lang {
        "rust" => name_of(node, content).into_iter().collect(),
        "go" => {
            let mut names: Vec<String> = Vec::new();
            if let Some(n) = field_text(node, content, "name") {
                names.push(n);
            } else if kind == "field_declaration" {
                // Anonymous layout fields, embed a type name like io.Reader.
                for child in node.children(&mut node.walk()) {
                    if matches!(child.kind(), "type_identifier" | "qualified_type")
                        && let Some(n) = clean_param_name(&text(child, content))
                    {
                        names.push(n);
                    }
                }
            }
            names
        }
        "java" | "csharp" => {
            let mut names: Vec<String> = Vec::new();
            for child in node.children(&mut node.walk()) {
                if child.kind() == "variable_declarator" {
                    if let Some(n) = field_text(child, content, "name")
                        .or_else(|| clean_param_name(&text(child, content)))
                    {
                        names.push(n);
                    }
                } else if child.kind() == "variable_declaration" {
                    // C# wraps the declarator inside a declaration node.
                    for d in child.children(&mut child.walk()) {
                        if d.kind() == "variable_declarator"
                            && let Some(n) = field_text(d, content, "name")
                        {
                            names.push(n);
                        }
                    }
                }
            }
            names
        }
        "javascript" | "typescript" => {
            let mut names: Vec<String> = Vec::new();
            for child in node.children(&mut node.walk()) {
                if matches!(
                    child.kind(),
                    "property_identifier" | "private_property_identifier" | "identifier"
                ) && let Some(n) = clean_param_name(&text(child, content))
                {
                    names.push(n);
                    break;
                }
            }
            names
        }
        _ => Vec::new(),
    }
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
    // Value symbols: one node per declaration in the grammars where that
    // holds, so names stay exact and the index stays clean.
    "enum_variant",
    "field_declaration",
    "const_spec",
    "var_spec",
    "field_definition",
    "public_field_definition",
    "constant_declaration",
    "enum_member_declaration",
];

/// Never descend deeper than this into the syntax tree. Real code nests
/// far shallower, and the cap keeps the walker immune to adversarial
/// nesting that would otherwise overflow the call stack.
const MAX_TREE_DEPTH: usize = 512;

/// Comment markers stripped from doc lines, longest first so a triple
/// slash loses only its own prefix.
const DOC_MARKERS: [&str; 10] = ["///", "//!", "//", "/**", "*/", "/*", "*", "#!", "#", "-->"];

/// True when a trimmed line is comment text in any indexed dialect.
fn comment_line(t: &str) -> bool {
    t.is_empty()
        || t.starts_with("//")
        || t.starts_with("/*")
        || t == "*/"
        || t.starts_with('*')
        || t.starts_with('#')
        || t.starts_with("<!--")
        || t.starts_with("-->")
        || t.starts_with("--")
}

/// Capture the doc comment directly above a declaration line. Blank lines
/// between the comment and the declaration are allowed and skipped, code
/// between them ends the capture. Attribute and decorator lines are
/// transparent, the comment above them documents the declaration they
/// decorate, and Rust attributes are not comments, so a derive line never
/// leaks into its own doc.
fn doc_above(content: &str, line: u64, lang: &str) -> String {
    if line < 2 {
        return String::new();
    }
    let lines: Vec<&str> = content.lines().collect();
    let mut i = (line - 1) as usize;
    if i > lines.len() {
        return String::new();
    }
    // Blank lines and transparent attribute or decorator lines directly
    // above the declaration are skipped, in any order. The walk stops at
    // the first comment line or code line, whichever sits higher.
    loop {
        if i == 0 {
            break;
        }
        let t = lines[i - 1].trim_start();
        if t.is_empty() || transparent_decor(t, lang) {
            i -= 1;
        } else {
            break;
        }
    }
    let mut raw: Vec<&str> = Vec::new();
    while i > 0 {
        let t = lines[i - 1].trim_start();
        if comment_line(t) && !t.starts_with("#[") {
            raw.push(lines[i - 1].trim_end());
            i -= 1;
            if raw.len() >= 24 {
                break;
            }
        } else {
            break;
        }
    }
    if raw.is_empty() {
        return String::new();
    }
    let mut doc: Vec<String> = Vec::new();
    for piece in raw.iter().rev() {
        let mut t = piece.trim();
        loop {
            let before = t;
            for m in DOC_MARKERS {
                if t.starts_with(m) {
                    t = t[m.len()..].trim_start();
                }
            }
            if t == before {
                break;
            }
        }
        if !t.is_empty() {
            doc.push(t.to_string());
        }
    }
    let joined = doc.join(" ");
    let mut out: String = joined.chars().take(1200).collect();
    if out.len() < joined.len() {
        out.push('…');
    }
    out
}

/// True when the trimmed line is an attribute or decorator, per language.
/// Rust and PHP 8 attributes open with #[, python and java decorators
/// open with @, C# attributes open with a bracket.
fn transparent_decor(t: &str, lang: &str) -> bool {
    match lang {
        "rust" | "php" => t.starts_with("#["),
        "python" | "java" => t.starts_with('@'),
        "csharp" => t.starts_with('['),
        _ => false,
    }
}

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
    let value_kind = matches!(
        kind,
        "enum_variant"
            | "field_declaration"
            | "const_spec"
            | "var_spec"
            | "field_definition"
            | "constant_declaration"
            | "enum_member_declaration"
    );
    if SYMBOL_KINDS.contains(&kind) && (!value_kind || value_allowed(&out.lang, kind)) {
        // Value names need grammar aware extraction. Type first languages
        // like java and csharp put the type before the name in the same
        // node, so a generic first identifier scan would name the type.
        let names: Vec<String> = if value_kind {
            value_names_of(node, content, &out.lang)
        } else {
            name_of(node, content).into_iter().collect()
        };
        for name in names {
            let sig = if kind.contains("function") || kind == "method_definition" {
                signature_of(node, content)
            } else {
                String::new()
            };
            // Value symbols keep tidy kinds instead of raw grammar names so
            // queries and practice guards read intent, never parser noise.
            let kind_out = match kind {
                "field_declaration" | "field_definition" | "public_field_definition" => "field",
                "constant_declaration" | "const_spec" => "constant",
                "var_spec" => "variable",
                "enum_member_declaration" => "enum_variant",
                _ => kind,
            };
            out.symbols.push(Symbol {
                name: name.clone(),
                kind: kind_out.to_string(),
                file: path.display().to_string(),
                line,
                lang: out.lang.clone(),
                signature: sig,
                params: params_of(node, content),
                doc: doc_above(content, line, &out.lang),
            });
        }
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
            params: params_of(node, content),
            doc: doc_above(content, line, &out.lang),
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

    #[test]
    fn doc_passes_through_attributes_and_decorators() {
        // Rust attribute above the fn, comment above the attribute.
        let src = "// A documented endpoint.\n#[derive(Clone)]\nfn serve() {}\n";
        let p = std::path::Path::new("probe.rs");
        let parsed = parse_file(p, src).unwrap();
        let serve = parsed.symbols.iter().find(|s| s.name == "serve").unwrap();
        assert_eq!(serve.doc, "A documented endpoint.");
        // Python decorator above the def, comment above the decorator.
        let py = "def route(fn):\n    return fn\n\n# Handles the index page.\n@app.route(\"/\")\ndef index():\n    return \"ok\"\n";
        let p = std::path::Path::new("probe.py");
        let parsed = parse_file(p, py).unwrap();
        let index = parsed.symbols.iter().find(|s| s.name == "index").unwrap();
        assert_eq!(index.doc, "Handles the index page.");
        // No comment above the attribute means no doc, the attribute does
        // not become one.
        let src = "#[derive(Clone)]\nfn plain() {}\n";
        let p = std::path::Path::new("probe.rs");
        let parsed = parse_file(p, src).unwrap();
        let plain = parsed.symbols.iter().find(|s| s.name == "plain").unwrap();
        assert_eq!(plain.doc, "");
    }

    #[test]
    fn rust_enum_variants_and_struct_fields_are_captured() {
        let src = "// A color palette.\nenum Color {\n    Red,\n    Green = 2,\n}\n\nstruct Point {\n    // Horizontal position.\n    x: f64,\n    y: f64,\n}\n";
        let p = std::path::Path::new("probe.rs");
        let parsed = parse_file(p, src).unwrap();
        let variants: Vec<_> = parsed
            .symbols
            .iter()
            .filter(|s| s.kind == "enum_variant")
            .collect();
        let names: Vec<&str> = variants.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["Red", "Green"]);
        let fields: Vec<_> = parsed
            .symbols
            .iter()
            .filter(|s| s.kind == "field")
            .collect();
        let fnames: Vec<&str> = fields.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(fnames, vec!["x", "y"]);
        let x = fields.iter().find(|s| s.name == "x").unwrap();
        assert_eq!(x.doc, "Horizontal position.");
        let e = parsed.symbols.iter().find(|s| s.name == "Color").unwrap();
        assert_eq!(e.doc, "A color palette.");
        assert!(variants.iter().all(|s| s.signature.is_empty()));
    }

    #[test]
    #[allow(clippy::type_complexity)]
    fn value_symbols_capture_in_go_java_csharp_and_typescript() {
        let cases: &[(&str, &str, &[(&str, &str)])] = &[
            (
                "probe.go",
                "package main\n\nconst API_KEY = \"abc\"\nvar Port = 8080\n\ntype User struct {\n\tName string\n\tAdmin bool\n}\n",
                &[
                    ("constant", "API_KEY"),
                    ("variable", "Port"),
                    ("field", "Name"),
                    ("field", "Admin"),
                ],
            ),
            (
                "Probe.java",
                "public class Probe {\n    public static final String KEY = \"abc\";\n    private int count;\n}\n",
                &[("field", "KEY"), ("field", "count")],
            ),
            (
                "Thing.cs",
                "public class Thing {\n    public const string KEY = \"abc\";\n    private int count;\n}\n",
                &[("field", "KEY"), ("field", "count")],
            ),
            (
                "probe.ts",
                "class Thing {\n  name = \"\";\n  static KEY = \"abc\";\n}\n",
                &[("field", "name"), ("field", "KEY")],
            ),
        ];
        for (file, src, want) in cases {
            let p = std::path::Path::new(file);
            let parsed = parse_file(p, src).unwrap();
            for (kind, name) in *want {
                assert!(
                    parsed
                        .symbols
                        .iter()
                        .any(|s| s.kind == *kind && s.name == *name),
                    "{} missing {} {}",
                    file,
                    kind,
                    name
                );
            }
        }
    }

    #[test]
    fn doc_comment_above_symbol_is_captured() {
        let src = "// Parses an order file into line items.\n// Handles both csv and json.\nfn parse_file(path: &str) -> Vec<String> { vec![] }\n\nfn plain() {}\n";
        let p = std::path::Path::new("probe.rs");
        let parsed = parse_file(p, src).unwrap();
        let parse_sym = parsed
            .symbols
            .iter()
            .find(|s| s.name == "parse_file")
            .unwrap();
        assert_eq!(
            parse_sym.doc,
            "Parses an order file into line items. Handles both csv and json."
        );
        let plain = parsed.symbols.iter().find(|s| s.name == "plain").unwrap();
        assert_eq!(plain.doc, "", "symbol without a comment must carry no doc");
    }

    #[test]
    fn doc_skips_blank_lines_but_stops_at_code() {
        let src = "// Documented.\n\nfn spaced() {}\nlet marker = 1;\nfn after_code() {}\n";
        let p = std::path::Path::new("probe.rs");
        let parsed = parse_file(p, src).unwrap();
        let spaced = parsed.symbols.iter().find(|s| s.name == "spaced").unwrap();
        assert_eq!(
            spaced.doc, "Documented.",
            "blank line between doc and symbol is allowed"
        );
        let after = parsed
            .symbols
            .iter()
            .find(|s| s.name == "after_code")
            .unwrap();
        assert_eq!(
            after.doc, "",
            "code between comment and symbol ends the capture"
        );
    }
}
