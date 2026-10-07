// Language detection and deterministic code parsing for the Spine.
//
// Uses tree sitter to extract symbols, call edges and import edges from the
// primary language set. Every result carries a file and a line so guards can
// point at exact evidence. No model is involved in this layer.

use std::path::Path;

use tree_sitter::{Node, Parser};

use crate::spine::{CallEdge, ImportEdge, Symbol};

pub fn detect_language(path: &Path) -> Option<String> {
    // A Dockerfile has no extension. Matching on the name is the only way to
    // reach it, and leaving it out meant the one file where a secret most often
    // lives, `ARG NPM_TOKEN`, was never read at all.
    let file = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    // Dockerfile is deliberately NOT wired. The only published grammar,
    // tree-sitter-dockerfile 0.2, is built against a different tree-sitter ABI
    // than the 0.27 this parser uses, and downgrading the whole stack to admit
    // one grammar is not a trade worth making. Until a compatible release
    // exists, a Dockerfile stays in the coverage receipt as unread, which is
    // the honest state. `ARG NPM_TOKEN` is exactly the line that receipt exists
    // to point at.
    let _ = &file;
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
        // C and C++. They are separate grammars because the languages differ, and
        // parsing a .cpp with the C grammar produces a broken tree rather than a
        // partial one. C is what heides had no answer for at all: a `strcpy` into
        // a fixed buffer in a .c file was invisible to every layer.
        "c" | "h" => "c",
        "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx" => "cpp",
        // Ruby is recognised and parsed, so a .rb file contributes symbols and
        // call edges like every other language here. It is listed separately
        // because its grammar emits `method` and `singleton_method` rather than
        // the `function_item` family, and because the taint rules carry explicit
        // `def`/`end` rows instead of brace rows.
        "rb" => "ruby",
        "html" | "htm" => "html",
        "css" => "css",
        // YAML and shell were named as gaps by heides own coverage receipt and
        // both hold things no other layer was reading: a `run:` step in a
        // workflow that curls a script into bash, and a key in a .env block.
        "yml" | "yaml" => "yaml",
        // Infrastructure and app languages, all of which heides previously read
        // nothing in. Terraform holds the secrets a repo is most embarrassed to
        // have committed, so it earned its place before the rest.
        "tf" | "hcl" | "tfvars" => "terraform",
        "swift" => "swift",
        "scala" | "sc" => "scala",
        "dart" => "dart",
        "sh" | "bash" => "shell",
        _ => return None,
    };
    Some(lang.to_string())
}

pub fn is_indexable(path: &Path) -> bool {
    detect_language(path).is_some()
}

/// Whether a language has a tree sitter grammar, so symbols and call edges can
/// be extracted for it. A language can be recognised and still have no grammar,
/// which is the Ruby case: recognised so the taint guard can scan it, no
/// grammar so it contributes nothing to the graph. The coverage receipt needs
/// this to say which of the two a file is rather than implying parity.
pub fn has_grammar(lang: &str) -> bool {
    language_for(lang).is_some()
}

fn language_for(lang: &str) -> Option<tree_sitter::Language> {
    language_for_path(lang, false)
}

/// The grammar for a language, and for a TypeScript file whether it is JSX.
///
/// `.tsx` was always parsed with the plain TypeScript grammar, so a JSX
/// element opened a node tree the walker could not name and the file yielded
/// fewer symbols than the same code in `.ts`. The two grammars share a
/// superset of the syntax, so asking for TSX is only asked for a `.tsx` path.
fn language_for_path(lang: &str, tsx: bool) -> Option<tree_sitter::Language> {
    match lang {
        "rust" => Some(tree_sitter_rust::LANGUAGE.into()),
        "c" => Some(tree_sitter_c::LANGUAGE.into()),
        "cpp" => Some(tree_sitter_cpp::LANGUAGE.into()),
        "javascript" => Some(tree_sitter_javascript::LANGUAGE.into()),
        "typescript" => {
            // TSX is a separate grammar, not a flag: the JSX node kinds have no
            // name in the plain TypeScript grammar and the walk stops there.
            if tsx {
                Some(tree_sitter_typescript::LANGUAGE_TSX.into())
            } else {
                Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            }
        }
        // Ruby emits `method` and `singleton_method`; both are in the symbol kinds,
        // so `def name` and `def self.name` both land in the index.
        "ruby" => Some(tree_sitter_ruby::LANGUAGE.into()),
        "python" => Some(tree_sitter_python::LANGUAGE.into()),
        "php" => Some(tree_sitter_php::LANGUAGE_PHP.into()),
        "go" => Some(tree_sitter_go::LANGUAGE.into()),
        "java" => Some(tree_sitter_java::LANGUAGE.into()),
        "csharp" => Some(tree_sitter_c_sharp::LANGUAGE.into()),
        "html" => Some(tree_sitter_html::LANGUAGE.into()),
        "css" => Some(tree_sitter_css::LANGUAGE.into()),
        "yaml" => Some(tree_sitter_yaml::LANGUAGE.into()),
        "terraform" => Some(tree_sitter_hcl::LANGUAGE.into()),
        "swift" => Some(tree_sitter_swift::LANGUAGE.into()),
        "scala" => Some(tree_sitter_scala::LANGUAGE.into()),
        "dart" => Some(tree_sitter_dart::LANGUAGE.into()),
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
    let tsx = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("tsx"))
        .unwrap_or(false);
    let grammar = language_for_path(&lang, tsx)?;
    let mut parser = Parser::new();
    parser.set_language(&grammar).ok()?;
    let tree = parser.parse(content.as_bytes(), None)?;
    let root = tree.root_node();

    let mut parsed = ParsedFile {
        lang: lang.clone(),
        symbols: Vec::new(),
        calls: Vec::new(),
        imports: Vec::new(),
    };

    walk(root, content, path, &mut parsed, None, 0);
    if lang == "html" {
        let file = path.display().to_string();
        web_imports(&mut parsed, root, content, &file);
        inline_scripts(&mut parsed, root, content, path);
    } else if lang == "css" {
        css_imports(&mut parsed, root, content, &path.display().to_string());
    }
    Some(parsed)
}

/// Import edges from a css file, at import rules and url references.
/// Line based over the grammar tree leaves, deterministic, one edge per
/// distinct target per line.
fn css_imports(parsed: &mut ParsedFile, root: Node, content: &str, file: &str) {
    let mut cursor = root.walk();
    let mut seen: std::collections::HashSet<(usize, String)> = std::collections::HashSet::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        let is_url_call = kind == "call_expression" && text(node, content).starts_with("url(");
        if kind == "import_statement" || is_url_call {
            let line = node.start_position().row + 1;
            let t = text(node, content);
            let mut target: Option<String> = None;
            for (q, m) in [('"', '"'), ('\'', '\'')] {
                if let Some(a) = t.find(q)
                    && let Some(b) = t[a + 1..].find(m)
                {
                    target = Some(t[a + 1..a + 1 + b].to_string());
                    break;
                }
            }
            if let Some(target) = target
                && !target.is_empty()
                && seen.insert((line, target.clone()))
            {
                parsed.imports.push(ImportEdge {
                    file: file.to_string(),
                    imported: target,
                    line: line as u64,
                });
            }
        }
        cursor.reset(node);
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
}

/// Import edges from an html file, stylesheet link hrefs and script src
/// attributes, from the start tag text of each element. Inline script
/// bodies carry no src and are parsed separately, not imported.
fn web_imports(parsed: &mut ParsedFile, root: Node, content: &str, file: &str) {
    let mut cursor = root.walk();
    let mut seen: std::collections::HashSet<(usize, String)> = std::collections::HashSet::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "element" | "script_element") {
            let line = node.start_position().row + 1;
            let t = text(node, content);
            let lower = t.to_ascii_lowercase();
            let mut target: Option<String> = None;
            if lower.starts_with("<script")
                && let Some(a) = t.find("src")
            {
                let rest = &t[a + 3..];
                for (q, m) in [('"', '"'), ('\'', '\'')] {
                    if let Some(x) = rest.find(q)
                        && let Some(y) = rest[x + 1..].find(m)
                    {
                        target = Some(rest[x + 1..x + 1 + y].to_string());
                        break;
                    }
                }
            } else if lower.starts_with("<link")
                && lower.contains("stylesheet")
                && let Some(a) = lower.find("href")
            {
                let rest = &t[a + 4..];
                for (q, m) in [('"', '"'), ('\'', '\'')] {
                    if let Some(x) = rest.find(q)
                        && let Some(y) = rest[x + 1..].find(m)
                    {
                        target = Some(rest[x + 1..x + 1 + y].to_string());
                        break;
                    }
                }
            }
            if let Some(target) = target
                && !target.is_empty()
                && seen.insert((line, target.clone()))
            {
                parsed.imports.push(ImportEdge {
                    file: file.to_string(),
                    imported: target,
                    line: line as u64,
                });
            }
        }
        cursor.reset(node);
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
}

/// Parse every inline script body as javascript and merge its symbols,
/// calls and imports into the html file records, with line numbers
/// offset to the real html rows so the map points at the page.
fn inline_scripts(parsed: &mut ParsedFile, root: Node, content: &str, path: &Path) {
    let mut cursor = root.walk();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "element" | "script_element") {
            let t = text(node, content);
            let lower = t.to_ascii_lowercase();
            if lower.starts_with("<script")
                && !lower[..lower.find('>').unwrap_or(0)].contains("src")
            {
                // Inner body between the end of the start tag and the
                // start of the closing tag.
                let mut inner = String::new();
                let mut base_byte = 0usize;
                let mut child = node.walk();
                let children: Vec<_> = node.children(&mut child).collect();
                for c in &children {
                    if c.kind() == "start_tag" {
                        base_byte = c.end_byte();
                    }
                }
                if base_byte > 0 && base_byte < content.len() {
                    let mut end = content.len();
                    for c in &children {
                        if c.kind() == "end_tag" {
                            end = c.start_byte();
                            break;
                        }
                    }
                    inner = content[base_byte..end].to_string();
                }
                if !inner.trim().is_empty() {
                    let base_row = content[..base_byte].matches('\n').count() as u64;
                    if let Some(js) = parse_region(&inner, "javascript", path) {
                        for mut s in js.symbols {
                            s.line += base_row;
                            parsed.symbols.push(s);
                        }
                        for c in js.calls {
                            parsed.calls.push(c);
                        }
                        for im in js.imports {
                            parsed.imports.push(im);
                        }
                    }
                }
            }
        }
        cursor.reset(node);
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
}

/// Parse a region of text as one language without touching the path, so
/// inline script bodies and templates can ride the same walker.
fn parse_region(content: &str, lang: &str, path: &Path) -> Option<ParsedFile> {
    let grammar = language_for(lang)?;
    let mut parser = Parser::new();
    parser.set_language(&grammar).ok()?;
    let tree = parser.parse(content.as_bytes(), None)?;
    let root = tree.root_node();
    let mut parsed = ParsedFile {
        lang: lang.to_string(),
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

/// The declared name of a C or C++ function.
///
/// A C function definition has no `name` field. The name sits inside a chain of
/// declarators: `function_definition -> function_declarator -> identifier`, and for
/// a pointer return `function_declarator -> pointer_declarator -> function_declarator
/// -> identifier`. A pointer to a function returning a pointer adds another level.
/// So the declarator chain is followed to its end and the identifier found there is
/// the name.
///
/// The generic `name_of` fallback cannot do this: it scans only direct children,
/// and in C the direct children are the return type and the declarator, never the
/// identifier. That is why C indexed zero symbols even with the grammar present.
fn c_declarator_name(node: Node, content: &str) -> Option<String> {
    let mut cur = node;
    // Bounded so a malformed tree cannot loop forever.
    for _ in 0..12 {
        let kind = cur.kind();
        if kind == "identifier" || kind == "field_identifier" || kind == "type_identifier" {
            let t = text(cur, content).trim().to_string();
            if !t.is_empty() {
                return Some(t);
            }
        }
        // Follow whichever declarator child exists. `declarator` is the usual
        // field; the direct child scan covers grammars that nest without one.
        let next = cur.child_by_field_name("declarator").or_else(|| {
            let mut w = cur.walk();
            cur.children(&mut w)
                .find(|c| c.kind().contains("declarator"))
        });
        cur = next?;
    }
    None
}

/// The name of a C or C++ symbol node, using the declarator chain.
///
/// A `declaration` in C is also used for variables and typedefs, and the same
/// chain gives the right answer for all three, so one helper covers them. The
/// caller filters by kind.
fn c_symbol_name(node: Node, kind: &str, content: &str) -> Option<String> {
    match kind {
        // A namespace, struct or class has a plain name field in both grammars.
        "namespace_definition" | "class_specifier" | "struct_specifier" | "enum_specifier" => {
            name_of(node, content)
        }
        // A function definition's declarator holds the name.
        "function_definition" => {
            let d = node.child_by_field_name("declarator").unwrap_or(node);
            c_declarator_name(d, content)
        }
        // A bare declaration is a prototype or a variable; both name through the
        // declarator chain.
        "declaration" => {
            let d = node.child_by_field_name("declarator").unwrap_or(node);
            c_declarator_name(d, content)
        }
        "template_declaration" | "linkage_specification" | "type_definition" => {
            // These wrap the real declaration, so descend and let the cases above
            // handle it rather than guessing at a name here.
            let mut w = node.walk();
            for child in node.children(&mut w) {
                if matches!(
                    child.kind(),
                    "declaration" | "function_definition" | "type_definition"
                ) {
                    return c_symbol_name(child, child.kind(), content);
                }
            }
            name_of(node, content)
        }
        _ => name_of(node, content),
    }
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
    // C and C++. `function_definition` is already listed for C# and is the node
    // both C grammars use; the rest are C++ specific.
    "function_definition",
    "declaration",
    "template_declaration",
    "namespace_definition",
    "field_declaration",
    "enum_specifier",
    "type_definition",
    "linkage_specification",
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
    // Ruby. `method` covers both `def name` and `def self.name`, since the
    // grammar emits the same node kind and only the receiver differs. Blocks
    // are deliberately absent: an iterator is not a method, and indexing one as
    // a symbol makes dead code analysis report every `each` as dead.
    "method",
    "singleton_method",
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

/// The docstring of a python function, if it opens on the line after the `def`.
///
/// `doc_above` reads comments that sit *above* a declaration, which is where
/// every other language puts its documentation. Python puts it inside the body,
/// so a `def` with a docstring indexed as an undocumented function. That is not
/// a cosmetic gap: `doc` is what `query definition` shows and what the scaffold
/// test asserts on, so every python function looked undocumented no matter what
/// the author wrote.
///
/// Only a string that is the first statement in the body counts, which is what
/// makes it a docstring rather than an ordinary string.
fn docstring_below(content: &str, line: u64, lang: &str) -> String {
    if lang != "python" {
        return String::new();
    }
    let lines: Vec<&str> = content.lines().collect();
    // `line` is 1 based and points at the `def`. The body opens on the next
    // line, or one later still when the signature continues.
    let mut i = line as usize;
    let limit = (i + 4).min(lines.len());
    while i < limit {
        let t = lines[i].trim();
        if t.is_empty() || t.ends_with('\\') || t.starts_with('@') {
            i += 1;
            continue;
        }
        break;
    }
    if i >= lines.len() {
        return String::new();
    }
    let t = lines[i].trim();
    let quote = if t.starts_with("\"\"\"") {
        "\"\"\""
    } else if t.starts_with("'''") {
        "'''"
    } else if t.starts_with('"') {
        "\""
    } else if t.starts_with('\'') {
        "'"
    } else {
        return String::new();
    };
    // Single line docstring: the closing quote ends the line. Testing whether the
    // text after the opening quote *starts* with a quote, as this first did, is
    // never true, so every single line docstring fell through to the branch below
    // and swallowed the rest of the file looking for a closer.
    let after_open = &t[quote.len()..];
    if after_open.ends_with(quote) && after_open.len() >= quote.len() {
        let body = after_open[..after_open.len() - quote.len()].trim();
        return capped_doc(body);
    }
    // Otherwise it runs to a closing quote on a later line. A dedent ends the
    // body, so a missing closing quote cannot absorb real code into the doc: the
    // previous version walked to end of file and reported source lines as prose.
    let def_indent = lines
        .get(i - 1)
        .map_or(0, |l| l.len() - l.trim_start().len());
    let mut parts: Vec<&str> = Vec::new();
    let first = after_open.trim();
    if !first.is_empty() {
        parts.push(first);
    }
    let mut j = i + 1;
    while j < lines.len() && j - i <= 24 {
        let raw = lines[j];
        let l = raw.trim();
        let indent = raw.len() - raw.trim_start().len();
        if !l.is_empty() && indent <= def_indent {
            break;
        }
        match l.find(quote) {
            Some(end) => {
                if !l[..end].trim().is_empty() {
                    parts.push(l[..end].trim());
                }
                break;
            }
            None => {
                if !l.is_empty() {
                    parts.push(l);
                }
                j += 1;
            }
        }
    }
    capped_doc(&parts.join(" "))
}

/// Collapse a docstring to one line and cap its length.
fn capped_doc(body: &str) -> String {
    let joined: Vec<&str> = body.split_whitespace().collect();
    let flat = joined.join(" ");
    let mut out: String = flat.chars().take(1200).collect();
    if out.len() < flat.len() {
        out.push('…');
    }
    out
}

/// The documentation attached to a declaration: a comment block above it, or a
/// docstring inside the body where python puts one.
fn doc_for(content: &str, line: u64, lang: &str) -> String {
    let above = doc_above(content, line, lang);
    if !above.is_empty() {
        return above;
    }
    docstring_below(content, line, lang)
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
        } else if out.lang == "c" || out.lang == "cpp" {
            c_symbol_name(node, kind, content).into_iter().collect()
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
                doc: doc_for(content, line, &out.lang),
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
            doc: doc_for(content, line, &out.lang),
        });
    }

    // Calls
    let is_call = match out.lang.as_str() {
        "python" => kind == "call",
        "ruby" => kind == "call",
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
            "ruby" => field_text(node, content, "method"),
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
        // `#include <stdio.h>` and `#include "local.h"` are the C and C++ import
        // edge. Without this a C file had no import edges at all, so a graph
        // question like "what depends on this header" had no answer.
        "preproc_include" => {
            let t = text(node, content);
            let target = t
                .split_once('<')
                .and_then(|(_, rest)| rest.split_once('>').map(|(a, _)| a.to_string()))
                .or_else(|| {
                    t.split_once('"')
                        .and_then(|(_, rest)| rest.split_once('"').map(|(a, _)| a.to_string()))
                });
            if let Some(imp) = target {
                let clean = imp.trim().to_string();
                if !clean.is_empty() {
                    out.imports.push(ImportEdge {
                        file: path.display().to_string(),
                        imported: clean,
                        line,
                    });
                }
            }
        }
        // `require 'x'` and `require_relative 'x'` are Ruby's import edge. They
        // are the same `call` node as any other method call, so the distinction is
        // the callee name and the string argument. Without this arm a Ruby file
        // had no import edges at all, so the graph could not answer what a file
        // depends on.
        "call"
            if out.lang == "ruby"
                && field_text(node, content, "method")
                    .as_deref()
                    .is_some_and(|m| m == "require" || m == "require_relative") =>
        {
            let target = node
                .child_by_field_name("arguments")
                .map(|a| text(a, content))
                .map(|a| {
                    let a = a.trim().to_string();
                    a.strip_prefix('(')
                        .and_then(|r| r.strip_suffix(')').map(|r| r.to_string()))
                        .unwrap_or(a)
                })
                .map(|a| a.trim().trim_matches(['"', '\'', ' ']).to_string())
                .filter(|a| !a.is_empty());
            if let Some(imp) = target {
                out.imports.push(ImportEdge {
                    file: path.display().to_string(),
                    imported: imp,
                    line,
                });
            }
        }
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

    /// A python docstring is the documentation, so it has to be indexed. It sits
    /// inside the body, not above the `def`, which is why this needed its own
    /// reader rather than the comment scan.
    #[test]
    fn a_single_line_docstring_is_the_documentation() {
        let src = "def documented():\n    \"\"\"Entry point. Does the thing.\"\"\"\n    return 1\n";
        let lines: Vec<&str> = src.lines().collect();
        let at = lines
            .iter()
            .position(|l| l.contains("def documented"))
            .unwrap();
        let doc = doc_for(src, at as u64 + 1, "python");
        assert_eq!(doc, "Entry point. Does the thing.");
    }

    /// Multi line, which is the common shape. Joined to one line.
    #[test]
    fn a_multi_line_docstring_is_joined() {
        let src = "def multi():\n    \"\"\"First line.\n    Second line of the same docstring.\n    \"\"\"\n    return 3\n";
        let lines: Vec<&str> = src.lines().collect();
        let at = lines.iter().position(|l| l.contains("def multi")).unwrap();
        let doc = doc_for(src, at as u64 + 1, "python");
        assert_eq!(doc, "First line. Second line of the same docstring.");
    }

    /// Single quotes are the same construct.
    #[test]
    fn a_single_quoted_docstring_is_the_documentation() {
        let src = "def one():\n    'Uses single quotes.'\n    return 1\n";
        let lines: Vec<&str> = src.lines().collect();
        let at = lines.iter().position(|l| l.contains("def one")).unwrap();
        assert_eq!(doc_for(src, at as u64 + 1, "python"), "Uses single quotes.");
    }

    /// A decorator sits between the previous statement and the `def`.
    #[test]
    fn a_docstring_below_a_decorator_is_found() {
        let src = "@property\ndef decorated(self):\n    \"\"\"A decorated property.\"\"\"\n    return 2\n";
        let lines: Vec<&str> = src.lines().collect();
        let at = lines
            .iter()
            .position(|l| l.contains("def decorated"))
            .unwrap();
        assert_eq!(
            doc_for(src, at as u64 + 1, "python"),
            "A decorated property."
        );
    }

    /// The bug this pins: the single line check asked whether the text after the
    /// opening quote *starts* with a closing quote, which is never true, so every
    /// single line docstring fell through to the multi line branch and reported
    /// the rest of the file as its documentation.
    #[test]
    fn a_docstring_does_not_swallow_the_code_after_it() {
        let src = "def a():\n    \"\"\"First.\"\"\"\n    return 1\n\n\ndef b():\n    return 2\n";
        let lines: Vec<&str> = src.lines().collect();
        let at = lines.iter().position(|l| l.contains("def a")).unwrap();
        let doc = doc_for(src, at as u64 + 1, "python");
        assert_eq!(doc, "First.");
        assert!(
            !doc.contains("return") && !doc.contains("def b"),
            "a docstring must not absorb source lines: {doc}"
        );
    }

    /// An unterminated docstring is malformed, and the honest answer is the text
    /// so far rather than the remainder of the file.
    #[test]
    fn an_unterminated_docstring_stops_at_the_dedent() {
        let src = "def bad():\n    \"\"\"Never closed.\n\ndef after():\n    return 1\n";
        let lines: Vec<&str> = src.lines().collect();
        let at = lines.iter().position(|l| l.contains("def bad")).unwrap();
        let doc = doc_for(src, at as u64 + 1, "python");
        assert!(
            !doc.contains("def after"),
            "a missing closing quote must not absorb the next function: {doc}"
        );
    }

    /// Other languages put documentation in a comment above the declaration, and
    /// this reader is python only, so nothing else may change.
    #[test]
    fn other_languages_still_read_the_comment_above() {
        let src = "// Entry point for main.\nfn main() {\n    let v = vec![1];\n}\n";
        assert_eq!(
            doc_for(src, 2, "rust"),
            "Entry point for main.",
            "rust must be unaffected by the docstring reader"
        );
    }

    /// Python with no docstring and no comment stays empty rather than picking up
    /// the body.
    #[test]
    fn an_undocumented_python_function_has_no_doc() {
        let src = "def bare():\n    return 1\n";
        assert_eq!(doc_for(src, 1, "python"), "");
    }

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
    fn html_imports_inline_scripts_and_css_edges_are_captured() {
        let html = "<!doctype html>\n<html>\n<head>\n  <link rel=\"stylesheet\" href=\"/css/app.css\">\n  <script src=\"/js/vendor.js\"></script>\n</head>\n<body>\n<script>\nfunction greet() {\n  return \"hi\";\n}\n</script>\n</body>\n</html>\n";
        let p = std::path::Path::new("index.html");
        let parsed = parse_file(p, html).unwrap();
        let imports: Vec<&str> = parsed.imports.iter().map(|i| i.imported.as_str()).collect();
        assert!(imports.contains(&"/css/app.css"), "missing stylesheet edge");
        assert!(imports.contains(&"/js/vendor.js"), "missing script edge");
        let greet = parsed
            .symbols
            .iter()
            .find(|s| s.name == "greet")
            .expect("inline script function missing");
        assert_eq!(greet.lang, "javascript");
        assert_eq!(greet.line, 9, "inline symbol must point at the html row");
        let css = "@import \"/base.css\";\nbody { background: url(\"/img/x.png\"); }\n";
        let pc = std::path::Path::new("style.css");
        let parsed_css = parse_file(pc, css).unwrap();
        let cimports: Vec<&str> = parsed_css
            .imports
            .iter()
            .map(|i| i.imported.as_str())
            .collect();
        assert!(cimports.contains(&"/base.css"), "missing at import edge");
        assert!(cimports.contains(&"/img/x.png"), "missing url edge");
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

#[cfg(test)]
mod c_cpp_tests {
    use super::*;
    // ------------------------------------------------------- C and C++ indexing
    //
    // Heides indexed zero files in a C and C++ codebase before this, so a `strcpy`
    // into a fixed buffer was invisible to every layer. That is not a gap in coverage
    // so much as an absence: `language_for` returned None and `detect_language`
    // returned None, so the file was never even a candidate.
    //
    // These assert the three things the graph needs from a C or C++ file: functions
    // with names, calls with names, and includes as import edges. A grammar with no
    // extractor would index files and find nothing, which is worse than not indexing.

    fn parsed(name: &str, src: &str) -> ParsedFile {
        parse_file(Path::new(name), src).unwrap_or_else(|| panic!("{name} must parse"))
    }

    fn symbol_names(p: &ParsedFile) -> Vec<String> {
        let mut v: Vec<String> = p.symbols.iter().map(|s| s.name.clone()).collect();
        v.sort();
        v.dedup();
        v
    }

    fn callees(p: &ParsedFile) -> Vec<String> {
        let mut v: Vec<String> = p.calls.iter().map(|c| c.callee.clone()).collect();
        v.sort();
        v.dedup();
        v
    }

    #[test]
    fn a_c_function_is_a_symbol() {
        let p = parsed("a.c", "int add(int a, int b) {\n    return a + b;\n}\n");
        assert!(
            symbol_names(&p).contains(&"add".to_string()),
            "a C function must be indexed: {:?}",
            symbol_names(&p)
        );
    }

    #[test]
    fn a_c_call_is_an_edge() {
        let p = parsed(
            "a.c",
            "int helper(int x) { return x; }\nint main(void) { return helper(1); }\n",
        );
        assert!(
            callees(&p).contains(&"helper".to_string()),
            "a C call must be an edge: {:?}",
            callees(&p)
        );
    }

    #[test]
    fn a_c_include_is_an_import() {
        let p = parsed(
            "a.c",
            "#include <stdio.h>\n#include \"local.h\"\nint f(void){return 0;}\n",
        );
        let mut imports: Vec<String> = p.imports.iter().map(|i| i.imported.clone()).collect();
        imports.sort();
        assert!(
            imports.iter().any(|m| m.contains("stdio")),
            "an include must be an import edge: {imports:?}"
        );
    }

    /// The shape that motivated all of this: a fixed size buffer overflowed by a
    /// copy. Before C was indexed, a `strcpy` was invisible to every layer.
    ///
    /// The flow here is a value read from a source, not a bare parameter. A parameter
    /// alone is deliberately not a source: blanket "every parameter is untrusted" was
    /// implemented and reverted because it fired on `read_config(path)` and on
    /// `escape`-then-`mark_safe`. A parameter reaching a sink is caught by the
    /// interprocedural pass instead, which seeds from the caller. Asserting it here
    /// would be asserting a capability heides does not claim.
    #[test]
    fn a_c_unbounded_copy_from_a_source_is_reported() {
        let src = "#include <string.h>\n\nvoid run(void) {\n    char buf[8];\n    char *p = getenv(\"NAME\");\n    strcpy(buf, p);\n}\n";
        let reports = crate::taint::scan_file(Path::new("vuln.c"), src);
        assert!(
            reports.iter().any(|r| r.message.contains("unbounded copy")),
            "strcpy of a source derived value must be reported: {reports:?}"
        );
    }

    /// The benign twin. A copy of a literal into a buffer of known size is ordinary
    /// C, and reporting it would put a critical on correct code.
    #[test]
    fn a_c_copy_of_a_literal_stays_quiet() {
        let src = "#include <string.h>\n\nvoid run(void) {\n    char buf[16];\n    strcpy(buf, \"hello\");\n}\n";
        let reports = crate::taint::scan_file(Path::new("ok.c"), src);
        assert!(
            reports.is_empty(),
            "a literal into an ample buffer is not a finding: {reports:?}"
        );
    }

    /// And the documented limit, asserted so it cannot be quietly forgotten: a
    /// parameter reaching a sink is the interprocedural pass's job.
    #[test]
    fn a_c_parameter_alone_is_not_a_source_here() {
        let src = "void copy(char *src) {\n    char buf[8];\n    strcpy(buf, src);\n}\n";
        let reports = crate::taint::scan_file(Path::new("a.c"), src);
        assert!(
            reports.is_empty(),
            "a parameter is not untrusted on its own: {reports:?}"
        );
    }

    #[test]
    fn a_cpp_class_method_and_call_are_indexed() {
        let p = parsed(
            "a.cpp",
            "class Greeter {\npublic:\n    void greet() { helper(); }\n};\nvoid helper() {}\n",
        );
        assert!(
            symbol_names(&p).contains(&"greet".to_string()),
            "a C++ method must be indexed: {:?}",
            symbol_names(&p)
        );
        assert!(
            callees(&p).contains(&"helper".to_string()),
            "a call from inside a C++ method must be an edge: {:?}",
            callees(&p)
        );
    }

    #[test]
    fn a_cpp_namespace_function_is_indexed() {
        let p = parsed(
            "a.cpp",
            "namespace app { void run() { step(); } void step() {} }\n",
        );
        assert!(
            symbol_names(&p).contains(&"run".to_string()),
            "a namespaced function must be indexed: {:?}",
            symbol_names(&p)
        );
    }

    /// The negative that matters most: recognising C must not mean every file in the
    /// tree becomes a symbol. A C file with one function yields one symbol, not one
    /// per line or per token.
    #[test]
    fn a_c_file_yields_one_symbol_per_function_and_no_more() {
        let p = parsed(
            "a.c",
            "int one(void) { return 1; }\nint two(void) { return 2; }\n",
        );
        assert_eq!(
            symbol_names(&p),
            vec!["one".to_string(), "two".to_string()],
            "only the two functions"
        );
    }

    /// A header is a real artefact of a C project and must not be counted as source
    /// twice. It is scanned, and its functions are real, but the receipt must be able
    /// to say what was seen.
    #[test]
    fn a_c_header_is_recognised() {
        assert_eq!(
            detect_language(Path::new("foo.h")).as_deref(),
            Some("c"),
            "a .h file is C by convention when it has no C++ marker"
        );
        assert_eq!(
            detect_language(Path::new("foo.hpp")).as_deref(),
            Some("cpp"),
            "a .hpp file is C++"
        );
    }

    /// A C++ file that is also valid C must be treated as C++, because the grammars
    /// differ and the wrong one produces a broken tree.
    #[test]
    fn cpp_is_not_mistaken_for_c() {
        assert_eq!(detect_language(Path::new("a.cpp")).as_deref(), Some("cpp"));
        assert_eq!(detect_language(Path::new("a.cc")).as_deref(), Some("cpp"));
        assert_eq!(detect_language(Path::new("a.cxx")).as_deref(), Some("cpp"));
        assert_eq!(detect_language(Path::new("a.c")).as_deref(), Some("c"));
    }

    /// C++ has no C-compatible file extension, so the receipt has to be able to say
    /// a language is recognised and parsed rather than recognised and empty.
    #[test]
    fn c_and_cpp_have_grammars() {
        assert!(has_grammar("c"), "C must have a grammar");
        assert!(has_grammar("cpp"), "C++ must have a grammar");
    }
}

#[cfg(test)]
mod ruby_tests {
    use super::*;

    fn parsed_ruby(src: &str) -> ParsedFile {
        let p = std::path::Path::new("a.rb");
        parse_file(p, src).expect("a .rb file must parse")
    }
    fn names(p: &ParsedFile) -> Vec<String> {
        p.symbols.iter().map(|s| s.name.clone()).collect()
    }
    fn callees(p: &ParsedFile) -> Vec<String> {
        p.calls.iter().map(|c| c.callee.clone()).collect()
    }

    /// A Ruby method is a `method` node with the name in a `name` field, which is
    /// the shape the generic walk already handles. This test exists to prove the
    /// grammar is wired, not to prove the extractor is clever.
    #[test]
    fn a_ruby_method_is_a_symbol() {
        let p = parsed_ruby("class Greeter\n  def greet(name)\n    puts name\n  end\nend\n");
        assert!(
            names(&p).contains(&"greet".to_string()),
            "got {:?}",
            names(&p)
        );
    }

    /// The call inside it must produce an edge, otherwise a Ruby graph has
    /// symbols but no relationships and `query callers` silently answers nothing.
    #[test]
    fn a_ruby_call_is_an_edge() {
        let p = parsed_ruby("def run(x)\n  helper(x)\nend\n");
        assert!(
            callees(&p).iter().any(|c| c == "helper"),
            "got {:?}",
            callees(&p)
        );
    }

    /// `require` and `require_relative` are Ruby's import edge. Without them
    /// there is no way to ask what a file depends on.
    #[test]
    fn a_ruby_require_is_an_import() {
        let p = parsed_ruby("require 'json'\nrequire_relative 'helper'\n");
        let mods: Vec<String> = p.imports.iter().map(|i| i.imported.clone()).collect();
        assert!(mods.iter().any(|m| m.contains("json")), "got {:?}", mods);
        assert!(mods.iter().any(|m| m.contains("helper")), "got {:?}", mods);
    }

    /// The singular form, which is what most real files use. A plural-only
    /// implementation would parse every test fixture and miss every real file.
    #[test]
    fn a_singular_def_is_a_symbol() {
        let p = parsed_ruby("def process(x)\n  x\nend\n");
        assert!(
            names(&p).contains(&"process".to_string()),
            "got {:?}",
            names(&p)
        );
    }

    /// Blocks are not methods. `items.each do |x|` must not become a symbol
    /// named "each", or dead code analysis reports every iterator as dead.
    #[test]
    fn a_block_is_not_a_symbol() {
        let p = parsed_ruby("[1,2].each do |x|\n  puts x\nend\n");
        assert!(
            !names(&p).contains(&"each".to_string()),
            "got {:?}",
            names(&p)
        );
    }

    /// The grammar must actually be wired, which is the entire gap being closed.
    #[test]
    fn ruby_has_a_grammar() {
        assert!(
            has_grammar("ruby"),
            "ruby must have a grammar to be indexed"
        );
    }

    /// And the honest negative: C is not Ruby, and a wrong grammar produces a
    /// broken tree rather than a partial one, so this must not silently pass.
    #[test]
    fn ruby_files_are_not_parsed_as_something_else() {
        let p = parsed_ruby("def go\n  system(params[:cmd])\nend\n");
        assert_eq!(p.lang.as_str(), "ruby");
    }

    /// The benign twin of the shell rows. A `system` call with a literal command
    /// is ordinary Ruby and must stay quiet, and so must a method merely named
    /// `execute_system` or a string that happens to contain a backtick. Without
    /// these the new rows would put criticals on correct code, which is the
    /// failure mode that matters most.
    #[test]
    fn a_ruby_shell_call_with_a_literal_stays_quiet() {
        let src = "def build\n  system('make clean')\nend\n";
        let r = crate::taint::scan_file(std::path::Path::new("ok.rb"), src);
        assert!(r.is_empty(), "a literal command is not a finding: {r:?}");
    }

    /// An interpolated string that is not a command is not backticks either.
    #[test]
    fn an_ordinary_interpolated_string_is_not_a_shell_sink() {
        let src = "def label\n  puts \"value: #{name}\"\nend\n";
        let r = crate::taint::scan_file(std::path::Path::new("ok.rb"), src);
        assert!(
            r.is_empty(),
            "string interpolation is not command execution: {r:?}"
        );
    }

    /// Taint: a Rails params value reaching a shell sink. This is the shape the
    /// Ruby source rows were written for and it must fire.
    #[test]
    fn a_rails_param_reaching_a_shell_sink_is_reported() {
        let src = "def run\n  system(params[:cmd])\nend\n";
        let r = crate::taint::scan_file(std::path::Path::new("a.rb"), src);
        assert!(r.iter().any(|x| x.message.contains("sink")), "got {r:?}");
    }
}

#[cfg(test)]
mod tsx_tests {
    use super::*;

    fn parsed_tsx(src: &str) -> ParsedFile {
        parse_file(std::path::Path::new("App.tsx"), src).expect("a .tsx file must parse")
    }

    /// A JSX element opened a node tree the plain TypeScript grammar cannot
    /// name, so a `.tsx` file yielded fewer symbols than the same code in
    /// `.ts`. The component and the plain function either side of it must both
    /// survive, which is the whole reason for the separate TSX grammar.
    #[test]
    fn a_tsx_component_and_its_neighbour_are_both_symbols() {
        let src = concat!(
            "export function App({ name }: { name: string }) {\n",
            "  return <div className=\"x\">{name}</div>;\n",
            "}\n",
            "function helper(n: number) { return n + 1; }\n",
        );
        let names: Vec<String> = parsed_tsx(src)
            .symbols
            .iter()
            .map(|s| s.name.clone())
            .collect();
        assert!(names.contains(&"App".to_string()), "got {names:?}");
        assert!(names.contains(&"helper".to_string()), "got {names:?}");
    }

    #[test]
    fn a_tsx_call_is_an_edge() {
        let src =
            "function helper(n: number) { return n; }\nfunction main() { return helper(1); }\n";
        let p = parsed_tsx(src);
        assert!(
            p.calls.iter().any(|c| c.callee == "helper"),
            "got {:?}",
            p.calls
        );
    }
}
