// Dead-code signal refinement.
//
// `describe` reports uncalled roots: a function nothing in the workspace calls.
// That is weak on its own, because plenty of functions are called by something
// the workspace cannot see, and calling those dead is a false statement about
// live code. The route case was handled and nothing else was: a method
// dispatched through a base class, a job handed to a queue, a test exercising a
// helper, a symbol exported for a consumer, a trait method called through its
// trait.
//
// The rule is deliberately asymmetric. A function that looks dispatched,
// exported, or a test is kept out of the dead list even when no call edge proves
// it, because a false "dead" is a claim that costs more than a missed one: an
// agent acting on it deletes working code. But a function with no call edge, no
// dispatch shape and no export is still reported, so the signal does not decay
// into uselessness. Every report carries a reason, because a list an agent
// cannot act on is not a refinement.

use std::collections::HashSet;
use std::path::Path;

use crate::spine::{CodeGraph, Symbol};

/// One function reported as dead, with everything needed to judge the claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadRoot {
    pub name: String,
    pub file: String,
    pub line: u64,
    pub kind: String,
    /// Why the call graph shows no caller. Not empty, ever: a dead-code entry with
    /// no explanation is a list an agent has to re-derive from scratch.
    pub reason: String,
}

/// Every function in the workspace the call graph cannot account for.
///
/// Sorted by file then line, so the output reads in source order and a list that
/// reorders between runs is a list an agent cannot diff.
pub fn dead_roots(graph: &CodeGraph, root: &Path) -> Vec<DeadRoot> {
    let files: Vec<String> = graph.files.iter().map(|f| f.path.clone()).collect();
    let sources = read_sources(root, &files);
    let dispatched = route_handlers(root, &files);

    let mut out: Vec<DeadRoot> = Vec::new();
    let mut seen: HashSet<(String, String, u64)> = HashSet::new();

    for s in &graph.symbols {
        if !is_fn_kind(&s.kind) {
            continue;
        }
        if !seen.insert((s.name.clone(), s.file.clone(), s.line)) {
            continue;
        }
        // A caller is proof of life. Checked before every heuristic, because an
        // actual edge beats an inference.
        if !graph.callers_of(&s.name).is_empty() {
            continue;
        }
        if reason_not_dead(s, &sources, &dispatched).is_some() {
            continue;
        }
        out.push(DeadRoot {
            name: s.name.clone(),
            file: s.file.clone(),
            line: s.line,
            kind: s.kind.clone(),
            reason: "no call edge reaches it and nothing dispatches, exports or tests it"
                .to_string(),
        });
    }

    out.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
    out
}

/// A one-line statement of the finding, for a receipt that must not be silent.
pub fn summarise(graph: &CodeGraph, root: &Path) -> String {
    let out = dead_roots(graph, root);
    if out.is_empty() {
        return "no dead roots: every function is reached, dispatched, exported or tested"
            .to_string();
    }
    format!(
        "{} dead root(s), each with a file, a line and a reason",
        out.len()
    )
}

/// Why this symbol is not dead, or `None` when nothing excuses it.
fn reason_not_dead(
    s: &Symbol,
    sources: &std::collections::HashMap<String, String>,
    dispatched: &HashSet<String>,
) -> Option<&'static str> {
    // A test is an entrypoint by definition, so nothing inside one is dead.
    if is_test_path(&s.file) {
        return Some("declared in a test");
    }
    // The program itself.
    if s.name == "main" && (s.file.ends_with(".go") || s.lang == "rust") {
        return Some("the program entrypoint");
    }
    // A dunder is called by the runtime, not by name.
    if s.name.starts_with("__") && s.name.ends_with("__") {
        return Some("called by the runtime");
    }
    // A trait member is dispatched through the trait, so no call edge names it.
    if s.kind.contains("trait") {
        return Some("a trait member, dispatched through its trait");
    }
    if dispatched.contains(&s.name) {
        return Some("registered as a route");
    }
    // A symbol whose file could not be read is neither proven live nor proven
    // dead. Returning early here with `?` silently dropped it, which is how a
    // real dead function went unreported.
    let Some(body) = sources.get(&s.file) else {
        return Some("its source could not be read, so nothing can be concluded");
    };
    if is_exported(s, body) {
        return Some("exported for a consumer outside the workspace");
    }
    if is_decorated(body, s.line) {
        return Some("registered by a decorator");
    }
    if is_handed_to_a_registration(body, &s.name) {
        return Some("handed to a framework as a callback");
    }
    if has_an_override_sibling(body, &s.name) {
        return Some("overrides a base method, so it is dispatched through the base");
    }
    None
}

fn is_fn_kind(kind: &str) -> bool {
    kind.contains("function") || kind == "method_definition" || kind == "method_declaration"
}

fn is_test_path(file: &str) -> bool {
    let lower = file.to_ascii_lowercase();
    lower.contains("test")
        || lower.contains("spec")
        || lower.ends_with("_test.go")
        || lower.contains("/tests/")
        || lower.contains("__tests__")
}

/// True when a trimmed line opens with a visibility keyword.
fn starts_with_export(line: &str) -> bool {
    line.starts_with("export ")
        || line.starts_with("pub ")
        || line.starts_with("public ")
        || line.starts_with("open ")
}

/// `export function f`, `pub fn f`, `public void f`, or a Go capitalised name,
/// which is a package's surface by convention.
///
/// The declaration's own line only. An earlier version also read the line above,
/// which is how an unrelated `export function used()` on the preceding line made
/// the function below it look exported. The line above is still consulted for one
/// narrow case, a bare visibility keyword emitted on its own line, and only when
/// it is at most two words so an adjacent declaration can never match.
fn is_exported(s: &Symbol, body: &str) -> bool {
    // Go capitalises for exactly this reason.
    if s.lang == "go"
        && s.name
            .chars()
            .next()
            .map(|c| c.is_ascii_uppercase())
            .unwrap_or(false)
    {
        return true;
    }
    let lines: Vec<&str> = body.lines().collect();
    let idx = s.line.saturating_sub(1) as usize;
    let declaration = lines.get(idx).map(|l| l.trim_start()).unwrap_or("");
    if starts_with_export(declaration) {
        return true;
    }
    // Nested rather than a let chain, because this crate is not on the 2024
    // edition and CI treats that as an error.
    if let Some(above) = idx.checked_sub(1).and_then(|i| lines.get(i)) {
        let above = above.trim();
        if above.split_whitespace().count() <= 2 && starts_with_export(above) {
            return true;
        }
    }
    false
}

/// A decorator on the line above the declaration.
fn is_decorated(body: &str, line: u64) -> bool {
    let lines: Vec<&str> = body.lines().collect();
    let idx = line.saturating_sub(1) as usize;
    if idx == 0 {
        return false;
    }
    lines[idx - 1].trim_start().starts_with('@')
}

/// A function handed to something as a value, which is a registration.
///
/// The shape is "something, then this function as an argument", which is what a
/// dispatch looks like and a call never does. The definition site is excluded, or
/// every function would appear registered to itself.
fn is_handed_to_a_registration(body: &str, name: &str) -> bool {
    for line in body.lines() {
        let Some(at) = line.find(name) else {
            continue;
        };
        let before = &line[..at];
        let after = &line[at + name.len()..];
        if is_definition_site(before) {
            continue;
        }
        if before.contains('(') || before.contains(',') {
            let rest = after.trim_start();
            if rest.starts_with(',') || rest.starts_with(')') || rest.starts_with(';') {
                return true;
            }
        }
    }
    false
}

fn is_definition_site(before: &str) -> bool {
    let t = before.trim_end();
    t.ends_with("function")
        || t.ends_with("func")
        || t.ends_with("def")
        || t.ends_with("fn")
        || t.ends_with("=>")
        || t.ends_with("async")
}

/// A method name declared in both a base class and a subclass.
///
/// An override is dispatched through its base, so no call edge names it, and the
/// name alone cannot tell an override from two unrelated methods that share a
/// name. The `extends`/`implements` marker lives on the *class* line, which does
/// not contain the method, so the class context is resolved separately: filtering
/// declarations and then looking for `extends` among them can never be true.
///
/// Two declarations in the same class are an overload, not an override, and are
/// deliberately not excused.
fn has_an_override_sibling(body: &str, name: &str) -> bool {
    let lines: Vec<&str> = body.lines().collect();
    let declarations: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.contains(name) && l.contains('('))
        .map(|(i, _)| i)
        .collect();
    if declarations.len() < 2 {
        return false;
    }
    let mut base = 0usize;
    let mut subclass = 0usize;
    for at in &declarations {
        let ctx = enclosing_class(&lines, *at);
        if ctx.contains("extends") || ctx.contains("implements") {
            subclass += 1;
        } else {
            base += 1;
        }
    }
    base >= 1 && subclass >= 1
}

/// The class header that owns the declaration on line `at`.
///
/// Scans upwards for the nearest `class`, `struct` or `interface` line. A method
/// belongs to the header above it, and the inheritance marker is on that header,
/// so this is where the evidence has to come from.
fn enclosing_class(lines: &[&str], at: usize) -> String {
    for back in (0..=at).rev() {
        let t = lines[back].trim_start();
        if t.starts_with("class ")
            || t.starts_with("struct ")
            || t.starts_with("interface ")
            || t.contains(" class ")
            || t.contains(" struct ")
        {
            return t.to_string();
        }
    }
    String::new()
}

/// Read every indexed file once, bounded, so the heuristics do not re-read the
/// tree per symbol.
fn read_sources(root: &Path, files: &[String]) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    for f in files.iter().take(600) {
        if let Ok(body) = std::fs::read_to_string(root.join(f)) {
            out.insert(f.clone(), body);
        }
    }
    out
}

fn route_handlers(root: &Path, files: &[String]) -> HashSet<String> {
    // The route classifier takes string slices; the index stores owned paths.
    let borrowed: Vec<&str> = files.iter().map(|s| s.as_str()).collect();
    crate::frameworks::route_handlers(root, &borrowed)
}
