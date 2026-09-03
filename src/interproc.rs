// Interprocedural taint.
//
// The intra procedural engine proves flows inside one function block. This
// pass proves flows that cross function boundaries. A caller passes a value
// derived from a source into a callee parameter, the callee reaches a sink
// with it, or the callee hands it back through its return value and the
// caller sinks it. Everything is deterministic, summary based, and nothing
// is reported without a chain of evidence from a source line to the sink.
//
// Limits, stated honestly in RULES.md. Positional arguments only, no named
// arguments. Whole variable granularity, a tainted object stays tainted
// through its name but per field splitting is not modeled. Only callees
// resolvable to one definition in the scanned workspace propagate, library
// and framework calls stop the flow silently. Operator input, argv, is not
// a source class at all. Provenance chains cap at eight hops, deeper flows
// stay silent rather than guess.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::spine::CodeGraph;
use crate::taint::{
    SINKS, SOURCES, TaintReport, assigned_var, function_blocks, leading_spaces, make_report,
    regex_hit,
};

const MAX_HOPS: usize = 8;

fn is_func_kind(kind: &str) -> bool {
    matches!(
        kind,
        "function_item"
            | "function_declaration"
            | "generator_function_declaration"
            | "function_definition"
            | "method_definition"
            | "method_declaration"
            | "constructor_declaration"
            | "local_function_statement"
            | "function"
    )
}

fn norm(p: &str) -> String {
    p.trim_start_matches("./").replace('\\', "/")
}

type Key = (String, String);

/// One hop in the evidence chain. Base hops name a source line, later hops
/// name the call that moved the value into the next function.
#[derive(Clone, Debug)]
struct Hop {
    /// source at file:line, or call in caller at line passing into callee.
    text: String,
}

#[derive(Clone, Debug)]
struct Prov {
    hops: Vec<Hop>,
}

struct FnInfo {
    key: Key,
    lang: String,
    params: Vec<String>,
    body: Vec<usize>,
    /// per param index, (sink kind, 1 based line), first per kind.
    sink_param: Vec<Vec<(String, usize)>>,
    /// param index flows into a return value.
    param_to_return: Vec<bool>,
    /// the function hands a source read back to its caller.
    returns_source: bool,
}

/// Body span of the function whose signature sits on 1 based line sym_line.
fn body_range(lines: &[&str], lang: &str, sym_line: usize) -> (usize, usize) {
    let start = sym_line
        .saturating_sub(1)
        .min(lines.len().saturating_sub(1));
    if lang == "python" {
        let indent = leading_spaces(lines[start]);
        let mut end = start;
        for (j, &_l) in lines.iter().enumerate().skip(start + 1) {
            if _l.trim().is_empty() {
                end = j;
                continue;
            }
            if leading_spaces(_l) > indent {
                end = j;
            } else {
                break;
            }
        }
        return (start, end);
    }
    // Brace language. Scan characters from the signature line, honoring
    // strings and comments, until the braces balance back to zero.
    let mut depth: isize = 0;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut in_str: Option<char> = None;
    let mut escaped = false;
    let mut end = start;
    let mut saw_open = false;
    'outer: for (i, line) in lines.iter().enumerate().skip(start) {
        // A signature only declaration ends with a semicolon at depth zero.
        // Interfaces and abstract stubs have no body, do not scan the rest
        // of the file pretending they do.
        if !saw_open && i > start + 5 && depth == 0 && line.trim_end().ends_with(';') {
            return (start, start.saturating_sub(1));
        }
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            if in_line_comment {
                continue;
            }
            if in_block_comment {
                if c == '*' && chars.peek() == Some(&'/') {
                    in_block_comment = false;
                    chars.next();
                }
                continue;
            }
            if let Some(q) = in_str {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == q {
                    in_str = None;
                }
                continue;
            }
            match c {
                '/' if chars.peek() == Some(&'/') => {
                    in_line_comment = true;
                    chars.next();
                }
                '/' if chars.peek() == Some(&'*') => {
                    in_block_comment = true;
                    chars.next();
                }
                '"' | '\'' | '`' => in_str = Some(c),
                '{' => {
                    saw_open = true;
                    depth += 1;
                }
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i;
                        break 'outer;
                    }
                }
                _ => {}
            }
        }
        end = i;
    }
    (start, end)
}

/// Top level argument strings of a call to callee on this line.
/// Split the argument text of every call to callee on the line. Each
/// segment carries an optional name, a python keyword argument q=value, a
/// C# or PHP 8 named argument q: value, so the caller can bind by
/// parameter name instead of assuming position. Everything else stays
/// positional, comparison expressions never count as named.
fn call_args(line: &str, callee: &str, lang: &str) -> Vec<(Option<String>, String)> {
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let name = callee.as_bytes();
    let mut i = 0;
    while i + name.len() <= bytes.len() {
        if &bytes[i..i + name.len()] == name
            && (i == 0
                || !(bytes[i - 1].is_ascii_alphanumeric()
                    || bytes[i - 1] == b'_'
                    || bytes[i - 1] == b'$'))
        {
            let mut j = i + name.len();
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'(' {
                // Balanced parens from j, string and comment aware enough.
                let mut depth = 0isize;
                let mut k = j;
                let mut in_str: Option<u8> = None;
                let mut esc = false;
                while k < bytes.len() {
                    let b = bytes[k];
                    if let Some(q) = in_str {
                        if esc {
                            esc = false;
                        } else if b == b'\\' {
                            esc = true;
                        } else if b == q {
                            in_str = None;
                        }
                        k += 1;
                        continue;
                    }
                    match b {
                        b'"' | b'\'' | b'`' => in_str = Some(b),
                        b'(' | b'[' | b'{' => depth += 1,
                        b')' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    k += 1;
                }
                let inner = &line[j + 1..k];
                // Top level comma split.
                let mut seg = String::new();
                let mut d = 0isize;
                let mut q: Option<char> = None;
                for ch in inner.chars() {
                    if let Some(cq) = q {
                        if ch == cq {
                            q = None;
                        }
                        seg.push(ch);
                        continue;
                    }
                    match ch {
                        '"' | '\'' | '`' => {
                            q = Some(ch);
                            seg.push(ch);
                        }
                        '(' | '[' | '{' => {
                            d += 1;
                            seg.push(ch);
                        }
                        ')' | ']' | '}' => {
                            d -= 1;
                            seg.push(ch);
                        }
                        ',' if d == 0 => {
                            out.push(split_named(&seg, lang));
                            seg.clear();
                        }
                        _ => seg.push(ch),
                    }
                }
                if !seg.trim().is_empty() {
                    out.push(split_named(&seg, lang));
                }
                i = k;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Detect a named argument prefix on one segment. Python writes name=
/// and C# plus PHP 8 write name:, only when the prefix is a plain
/// identifier and the previous character is not an operator, so x == 1
/// and x >= 0 stay positional expressions.
fn split_named(seg: &str, lang: &str) -> (Option<String>, String) {
    let t = seg.trim();
    if t.is_empty() {
        return (None, seg.to_string());
    }
    let bytes = t.as_bytes();
    let mut i = 0usize;
    let mut in_str: Option<u8> = None;
    let mut esc = false;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_str {
            if esc {
                esc = false;
            } else if b == b'\\' {
                esc = true;
            } else if b == q {
                in_str = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' | b'\'' | b'`' => in_str = Some(b),
            b'=' | b':' => {
                let sep = b;
                let named = match sep {
                    b'=' => lang == "python",
                    b':' => lang == "csharp" || lang == "php",
                    _ => false,
                };
                if named {
                    let prefix = &t[..i];
                    let prev_is_op = i > 0
                        && matches!(
                            bytes[i - 1],
                            b'=' | b'!' | b'<' | b'>' | b':' | b'+' | b'-' | b'*' | b'/'
                        );
                    let chars = prefix.trim();
                    if !prev_is_op
                        && !chars.is_empty()
                        && (chars.as_bytes()[0].is_ascii_alphabetic()
                            || chars.as_bytes()[0] == b'_')
                        && chars
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b'_')
                    {
                        return (Some(chars.to_string()), t[i + 1..].trim().to_string());
                    }
                }
                return (None, t.to_string());
            }
            _ => {}
        }
        i += 1;
    }
    (None, t.to_string())
}

/// Map parsed call arguments to callee parameter indices. Named segments
/// bind by name, positional segments bind in order. An argument that
/// cannot bind, an unknown keyword or too many positional values, maps to
/// None and stays silent, a false negative boundary not a guess.
fn arg_indices(args: &[(Option<String>, String)], params: &[String]) -> Vec<Option<usize>> {
    let mut out = Vec::with_capacity(args.len());
    let mut positional = 0usize;
    for (name, _text) in args {
        match name {
            Some(n) => {
                let idx = params.iter().position(|p| p == n);
                out.push(idx);
            }
            None => {
                let idx = if positional < params.len() {
                    Some(positional)
                } else {
                    None
                };
                positional += 1;
                out.push(idx);
            }
        }
    }
    out
}

/// True when the line itself reads a source, used for wrappers that return
/// a source read directly.
fn line_is_source(line: &str, lang: &str) -> bool {
    SOURCES
        .iter()
        .any(|(l, pat)| *l == lang && regex_hit(pat, line))
}

fn is_identifier(tok: &str) -> bool {
    let t = tok.trim();
    let t = t.strip_prefix('$').unwrap_or(t);
    !t.is_empty()
        && t.chars()
            .enumerate()
            .all(|(i, c)| c.is_alphanumeric() || c == '_' || (i > 0 && c == '$'))
        && !t.chars().next().is_some_and(|c| c.is_ascii_digit())
}

/// The identifier returned by an explicit return, if any. The return can
/// sit anywhere on the line, single line bodies like
/// function f($x) { return $x; } included.
fn return_ident(line: &str) -> Option<String> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i + 6 <= bytes.len() {
        if &bytes[i..i + 6] == b"return"
            && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric() && bytes[i - 1] != b'_')
        {
            let rest = line[i + 6..].trim_start();
            if rest.is_empty() {
                return None;
            }
            let mut ident = String::new();
            for ch in rest.chars() {
                if ch.is_alphanumeric() || ch == '_' || ch == '$' {
                    ident.push(ch);
                } else {
                    break;
                }
            }
            if ident.is_empty() {
                return None;
            }
            return Some(ident.trim_start_matches('$').to_string());
        }
        i += 1;
    }
    None
}

type BlockList = Vec<(usize, usize, usize)>;

fn build_index(
    graph: &CodeGraph,
    contents: &HashMap<String, String>,
) -> (Vec<FnInfo>, HashMap<String, BlockList>) {
    let mut fns = Vec::new();
    let mut blocks_by_file: HashMap<String, Vec<(usize, usize, usize)>> = HashMap::new();
    for f in &graph.files {
        let fpath = norm(&f.path);
        let Some(content) = contents.get(&fpath) else {
            continue;
        };
        let lines: Vec<&str> = content.lines().collect();
        let blocks = function_blocks(&lines, &f.lang);
        blocks_by_file.insert(fpath.clone(), blocks.clone());
        // Symbols of this file, function kinds, dedup by line.
        let mut seen: std::collections::HashSet<(String, usize)> = std::collections::HashSet::new();
        for s in &graph.symbols {
            if norm(&s.file) != fpath || !is_func_kind(&s.kind) {
                continue;
            }
            if !seen.insert((s.name.clone(), s.line as usize)) {
                continue;
            }
            // Skip symbols whose body does not overlap a real block, parse
            // oddities, and skip zero param constructors that cannot carry
            // caller taint (they still propagate via returns_source).
            let (bs, be) = body_range(&lines, &f.lang, s.line as usize);
            if be < bs {
                continue;
            }
            let body: Vec<usize> = (bs..=be).collect();
            fns.push(FnInfo {
                key: (fpath.clone(), s.name.clone()),
                lang: f.lang.clone(),
                params: s.params.clone(),
                body,
                sink_param: Vec::new(),
                param_to_return: Vec::new(),
                returns_source: false,
            });
        }
        // Module scope complement. Every line outside a function body is
        // analyzed as one implicit function named after the caller label
        // the parser already attaches to top level calls. This is what
        // closes the launch gap, module level code now propagates taint
        // through the same call machinery as function bodies.
        let mut blocked: Vec<bool> = vec![false; lines.len()];
        for &(bs, be, _) in &blocks {
            for b in blocked
                .iter_mut()
                .take(be.min(lines.len().saturating_sub(1)) + 1)
                .skip(bs)
            {
                *b = true;
            }
        }
        let module_body: Vec<usize> = (0..lines.len()).filter(|&i| !blocked[i]).collect();
        if !module_body.is_empty() {
            fns.push(FnInfo {
                key: (fpath.clone(), "module level".to_string()),
                lang: f.lang.clone(),
                params: Vec::new(),
                body: module_body,
                sink_param: Vec::new(),
                param_to_return: Vec::new(),
                returns_source: false,
            });
        }
        // Sorted by start line for module region complement.
        fns.sort_by(|a, b| a.body[0].cmp(&b.body[0]));
    }
    (fns, blocks_by_file)
}

/// Static per function analysis. Seeds each parameter name as tainted and
/// walks the body once. Records which parameters reach which sinks, which
/// parameters flow into returns, and whether a source read reaches a return.
fn analyze(fi: &mut FnInfo, lines: &[&str]) {
    let n = fi.params.len();
    let mut sink_param: Vec<Vec<(String, usize)>> = vec![Vec::new(); n];
    let mut param_to_return = vec![false; n];
    let mut returns_source = false;
    // name -> first param index that seeded it, deterministic first wins.
    let mut tainted: HashMap<String, usize> = HashMap::new();
    for (i, p) in fi.params.iter().enumerate() {
        tainted.insert(p.clone(), i);
    }
    let mut source_vars: std::collections::HashSet<String> = std::collections::HashSet::new();
    for &li in &fi.body {
        let line = lines.get(li).copied().unwrap_or("");
        let lno = li + 1;
        // Source reads assign a tainted variable.
        if line_is_source(line, &fi.lang)
            && let Some(v) = assigned_var(line)
        {
            source_vars.insert(v.clone());
            tainted.entry(v).or_insert(usize::MAX);
        }
        // Sinks reached by any tainted name on this line.
        for (l, pat, kind) in SINKS {
            if *l != fi.lang || !regex_hit(pat, line) {
                continue;
            }
            for (name, pidx) in tainted.iter() {
                if *pidx != usize::MAX && line.contains(name.as_str()) {
                    let k = kind.to_string();
                    if !sink_param[*pidx].iter().any(|(ek, _)| *ek == k) {
                        sink_param[*pidx].push((k, lno));
                    }
                }
            }
        }
        // Assignments move taint forward by name.
        if let Some(v) = assigned_var(line)
            && line.contains('=')
        {
            let mut from: Option<usize> = None;
            for (name, pidx) in tainted.iter() {
                if *pidx != usize::MAX && line.contains(name.as_str()) {
                    from = Some(*pidx);
                    break;
                }
            }
            if let Some(pidx) = from {
                tainted.insert(v, pidx);
            }
        }
        // Returns.
        if let Some(ident) = return_ident(line) {
            if let Some(&pidx) = tainted.get(&ident)
                && pidx != usize::MAX
            {
                param_to_return[pidx] = true;
            }
            if source_vars.contains(&ident) || line_is_source(line, &fi.lang) {
                returns_source = true;
            }
        }
    }
    fi.sink_param = sink_param;
    fi.param_to_return = param_to_return;
    fi.returns_source = returns_source;
}

fn prov_source(file: &str, line: usize) -> Prov {
    Prov {
        hops: vec![Hop {
            text: format!("source at {}:{}", file, line),
        }],
    }
}

fn prov_call(prev: &Prov, caller: &str, file: &str, line: usize) -> Option<Prov> {
    if prev.hops.len() >= MAX_HOPS {
        return None;
    }
    let mut hops = prev.hops.clone();
    hops.push(Hop {
        text: format!("via {} ({}:{})", caller, file, line),
    });
    Some(Prov { hops })
}

fn render(p: &Prov) -> String {
    p.hops
        .iter()
        .map(|h| h.text.clone())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Run the workspace wide pass. Contents keyed by normalized path.
pub fn run_workspace(graph: &CodeGraph, contents: &HashMap<String, String>) -> Vec<TaintReport> {
    let mut reports: Vec<TaintReport> = Vec::new();
    if contents.is_empty() {
        return reports;
    }
    let (mut fns, _blocks) = build_index(graph, contents);
    // lines per file for analysis.
    let mut lines_by_file: HashMap<String, Vec<String>> = HashMap::new();
    for (p, c) in contents {
        lines_by_file.insert(
            p.clone(),
            c.lines().map(|l| l.to_string()).collect::<Vec<_>>(),
        );
    }
    let line_ref = |file: &str| -> Vec<&str> {
        lines_by_file
            .get(file)
            .map(|v| v.iter().map(|s| s.as_str()).collect::<Vec<_>>())
            .unwrap_or_default()
    };

    // Call edges grouped once per file and line so the per body line lookups
    // stay constant time instead of rescanning every edge for every line.
    let mut calls_by_line: HashMap<String, HashMap<usize, Vec<(String, String)>>> = HashMap::new();
    for c in &graph.calls {
        let f = norm(&c.file);
        calls_by_line
            .entry(f)
            .or_default()
            .entry(c.line as usize)
            .or_default()
            .push((c.caller.clone(), c.callee.clone()));
    }
    // Static summaries.
    let mut by_key: HashMap<Key, usize> = HashMap::new();
    let mut order: Vec<Key> = Vec::new();
    let mut has_source: Vec<bool> = Vec::new();
    let mut has_call: Vec<bool> = Vec::new();
    for (i, fi) in fns.iter_mut().enumerate() {
        let ls = line_ref(&fi.key.0);
        analyze(fi, &ls);
        // Activity flags gate processing. A function that neither reads a
        // source nor calls anything can never seed or forward taint, so it
        // is skipped and only ever used as a static summary.
        let src = fi.body.iter().any(|&li| {
            ls.get(li)
                .map(|l| line_is_source(l, &fi.lang))
                .unwrap_or(false)
        });
        let calls = fi.body.iter().any(|&li| {
            calls_by_line.get(&fi.key.0).is_some_and(|m| {
                m.get(&(li + 1))
                    .is_some_and(|v| v.iter().any(|(caller, _)| *caller == fi.key.1))
            })
        });
        by_key.insert(fi.key.clone(), i);
        order.push(fi.key.clone());
        has_source.push(src);
        has_call.push(calls);
    }
    // Entry taint per function parameter, first provenance wins.
    let mut entries: HashMap<Key, Vec<Option<Prov>>> = HashMap::new();
    for fi in &fns {
        entries.insert(fi.key.clone(), vec![None; fi.params.len()]);
    }
    let mut queue: VecDeque<Key> = VecDeque::new();

    // Function definitions per name, for constant time callee resolution.
    let mut defs_by_name: HashMap<String, Vec<(String, String)>> = HashMap::new();
    for s in &graph.symbols {
        if !is_func_kind(&s.kind) {
            continue;
        }
        let f = norm(&s.file);
        let entry = defs_by_name.entry(s.name.clone()).or_default();
        if !entry.iter().any(|(ef, _)| *ef == f) {
            entry.push((f, s.name.clone()));
        }
    }
    let resolve = |caller_file: &str, name: &str| -> Option<Key> {
        let defs = defs_by_name.get(name)?;
        let same: Vec<&(String, String)> = defs.iter().filter(|(f, _)| f == caller_file).collect();
        if same.len() == 1 {
            return Some(same[0].clone());
        }
        if defs.len() == 1 {
            return Some(defs[0].clone());
        }
        None
    };

    // Module scope sink reports, first pass wins per file, line and kind.
    let mut dyn_out: Vec<(String, usize, String, Prov)> = Vec::new();
    let mut seen_dyn: HashSet<String> = HashSet::new();
    // A caller scan walks one body, resolves local calls, and adds callee
    // entries. Returns newly added callee keys.
    let process = |key: Key,
                   entries: &mut HashMap<Key, Vec<Option<Prov>>>,
                   queue: &mut VecDeque<Key>,
                   dyn_out: &mut Vec<(String, usize, String, Prov)>,
                   seen: &mut HashSet<String>| {
        let Some(&fidx) = by_key.get(&key) else {
            return;
        };
        let fi = &fns[fidx];
        let module_scope = fi.params.is_empty() && fi.key.1 == "module level";
        let ls = line_ref(&fi.key.0);
        let mut tainted: HashMap<String, Prov> = HashMap::new();
        for (i, p) in fi.params.iter().enumerate() {
            if let Some(Some(prov)) = entries.get(&key).and_then(|e| e.get(i)) {
                tainted.insert(p.clone(), prov.clone());
            }
        }
        let mut new_keys: Vec<Key> = Vec::new();
        for &li in &fi.body {
            let line = ls.get(li).copied().unwrap_or("");
            let lno = li + 1;
            // A source read on this line makes its assigned variable tainted.
            if line_is_source(line, &fi.lang)
                && let Some(v) = assigned_var(line)
            {
                tainted
                    .entry(v.clone())
                    .or_insert_with(|| prov_source(&fi.key.0, lno));
            }
            // Resolve local calls on this line and propagate.
            let callees_here: Vec<String> = calls_by_line
                .get(&fi.key.0)
                .and_then(|m| m.get(&lno))
                .map(|v| {
                    v.iter()
                        .filter(|(caller, _)| *caller == fi.key.1)
                        .map(|(_, callee)| callee.clone())
                        .collect()
                })
                .unwrap_or_default();
            for callee in callees_here {
                let Some(cfn) = resolve(&fi.key.0, &callee) else {
                    continue;
                };
                let Some(&cidx) = by_key.get(&cfn) else {
                    continue;
                };
                let args = call_args(line, &callee, &fi.lang);
                if args.is_empty() {
                    continue;
                }
                let indices = arg_indices(&args, &fns[cidx].params);
                for ((_name, arg), idx) in args.iter().zip(indices.iter()) {
                    let Some(j) = idx else {
                        continue;
                    };
                    let prov: Option<Prov> = if is_identifier(arg) {
                        let an = arg.trim_start_matches('$').trim();
                        tainted.get(an).cloned()
                    } else if line_is_source(arg, &fns[cidx].lang) {
                        Some(prov_source(&fi.key.0, lno))
                    } else {
                        None
                    };
                    if let Some(p) = prov {
                        let slot = entries
                            .entry(cfn.clone())
                            .or_insert_with(|| vec![None; fns[cidx].params.len()]);
                        if slot[*j].is_none()
                            && let Some(chained) = prov_call(&p, &fi.key.1, &fi.key.0, lno)
                        {
                            slot[*j] = Some(chained);
                            // Requeue only callers whose body makes calls,
                            // a body with no calls cannot forward taint.
                            if has_call[cidx] {
                                new_keys.push(cfn.clone());
                            }
                        }
                    }
                }
            }
            // Call result taint: lhs of this line, callee return behavior.
            if let Some(v) = assigned_var(line) {
                let callees_here: Vec<String> = calls_by_line
                    .get(&fi.key.0)
                    .and_then(|m| m.get(&lno))
                    .map(|v| {
                        v.iter()
                            .filter(|(caller, _)| *caller == fi.key.1)
                            .map(|(_, callee)| callee.clone())
                            .collect()
                    })
                    .unwrap_or_default();
                for callee in callees_here {
                    let Some(cfn) = resolve(&fi.key.0, &callee) else {
                        continue;
                    };
                    let Some(&cidx) = by_key.get(&cfn) else {
                        continue;
                    };
                    let args = call_args(line, &callee, &fi.lang);
                    if fns[cidx].returns_source {
                        tainted.entry(v.clone()).or_insert_with(|| Prov {
                            hops: vec![Hop {
                                text: format!("source wrapper {} ({}:{})", callee, cfn.0, lno),
                            }],
                        });
                        continue;
                    }
                    let indices = arg_indices(&args, &fns[cidx].params);
                    for ((_name, arg), idx) in args.iter().zip(indices.iter()) {
                        let Some(j) = idx else {
                            continue;
                        };
                        if fns[cidx].param_to_return.get(*j).copied().unwrap_or(false)
                            && is_identifier(arg)
                        {
                            let an = arg.trim_start_matches('$').trim();
                            if let Some(p) = tainted.get(an).cloned()
                                && let Some(chained) = prov_call(&p, &fi.key.1, &fi.key.0, lno)
                            {
                                tainted.entry(v.clone()).or_insert(chained);
                            }
                        }
                    }
                }
            }
            // Module scope sinks are reported dynamically because the
            // module function carries no parameters, so the static
            // sink_param table has nothing to hang them on. A module line
            // that reaches a sink with a tainted name, or sinks a source
            // read on the same line, is a real flow and gets the same
            // evidence chain as a function flow. First pass wins per
            // file, line and sink kind.
            if module_scope {
                for (l, pat, kind) in SINKS {
                    if *l != fi.lang || !regex_hit(pat, line) {
                        continue;
                    }
                    let mut prov: Option<Prov> = None;
                    for (name, p) in tainted.iter() {
                        if line.contains(name.as_str()) {
                            prov = Some(p.clone());
                            break;
                        }
                    }
                    if prov.is_none() && line_is_source(line, &fi.lang) {
                        prov = Some(prov_source(&fi.key.0, lno));
                    }
                    if let Some(p) = prov
                        && seen.insert(format!("{}:{}:{}", fi.key.0, lno, kind))
                    {
                        dyn_out.push((fi.key.0.clone(), lno, kind.to_string(), p));
                    }
                }
            }
        }
        for k in new_keys {
            if !queue.iter().any(|q| *q == k) {
                queue.push_back(k);
            }
        }
    };

    // Seed set. A function starts the pass when it reads a source itself,
    // or when it calls a source wrapper whose return is tainted, because the
    // wrapper taint only becomes visible when the caller body is scanned.
    let mut seed_active: Vec<bool> = has_source.clone();
    for (i, fi) in fns.iter().enumerate() {
        if seed_active[i] {
            continue;
        }
        let calls_wrapper = fi.body.iter().any(|&li| {
            let Some(v) = calls_by_line.get(&fi.key.0).and_then(|m| m.get(&(li + 1))) else {
                return false;
            };
            v.iter()
                .filter(|(caller, _)| *caller == fi.key.1)
                .any(|(_, callee)| {
                    resolve(&fi.key.0, callee).is_some_and(|ck| {
                        by_key
                            .get(&ck)
                            .map(|&ci| fns[ci].returns_source)
                            .unwrap_or(false)
                    })
                })
        });
        seed_active[i] = calls_wrapper;
    }
    let initial: Vec<Key> = order
        .iter()
        .enumerate()
        .filter(|(i, _)| seed_active[*i])
        .map(|(_, k)| k.clone())
        .collect();
    for k in initial {
        process(
            k.clone(),
            &mut entries,
            &mut queue,
            &mut dyn_out,
            &mut seen_dyn,
        );
    }
    while let Some(k) = queue.pop_front() {
        process(k, &mut entries, &mut queue, &mut dyn_out, &mut seen_dyn);
    }

    // Reports at end sinks.
    for fi in &fns {
        let Some(entry) = entries.get(&fi.key) else {
            continue;
        };
        for (i, prov) in entry.iter().enumerate() {
            let Some(p) = prov else { continue };
            if i >= fi.sink_param.len() {
                continue;
            }
            for (kind, sink_line) in &fi.sink_param[i] {
                let path = std::path::PathBuf::from(&fi.key.0);
                let trace = render(p);
                let msg = format!(
                    "user controlled input reaches a {} sink in {} on line {}. trace: {}",
                    kind, fi.key.1, sink_line, trace
                );
                reports.push(make_report(&path, *sink_line as u64, msg));
            }
        }
    }
    // Module scope sink findings. The message names the file, the trace
    // carries the same source evidence as any function flow.
    for (file, line, kind, prov) in dyn_out {
        let path = std::path::PathBuf::from(&file);
        let msg = format!(
            "user controlled input reaches a {} sink in {} on line {}. trace: {}",
            kind,
            file,
            line,
            render(&prov)
        );
        reports.push(make_report(&path, line as u64, msg));
    }
    reports.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
    reports
}
