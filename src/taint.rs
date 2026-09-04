// Security taint guard.
//
// Traces user controlled input into dangerous sinks: SQL, shell, filesystem
// and prompt injection. The analysis is conservative and rule based. It
// reports the source line, the sink line, and the file, in the style of a
// database warning. No model is involved.

use std::path::Path;

#[derive(Debug, Clone)]
pub struct TaintReport {
    pub severity: String,
    pub message: String,
    pub file: String,
    pub line: u64,
}

/// Source patterns per language, user input entry points. Shared with the
/// interprocedural engine, which reads the same rows so the two layers can
/// never disagree about what a source is.
pub(crate) const SOURCES: [(&str, &str); 14] = [
    (
        "javascript",
        r"\b(req|request)\.(query|params|body|headers|cookies)\b",
    ),
    ("javascript", r"\bprocess\.env\b"),
    ("javascript", r"\blocalStorage\b"),
    ("javascript", r"\bsessionStorage\b"),
    ("javascript", r"\bwindow\.prompt\b"),
    ("javascript", r"\binput\.value\b"),
    ("python", r"\binput\s*\("),
    ("python", r"\bos\.environ\b"),
    ("python", r"\brequest\.(args|form|json|values)\b"),
    ("php", r"\b\$_\(GET|POST|REQUEST|COOKIE|SERVER)\b"),
    ("go", r"\b(r\.URL\.Query|FormValue|os\.Getenv)\b"),
    (
        "java",
        r"\b(request|req)\.(getParameter|getHeader|getCookies)\b",
    ),
    ("java", r"\bSystem\.(getenv|getProperty)\b"),
    (
        "csharp",
        r"\b(Request\.(QueryString|Form|Headers)|Console\.ReadLine|Environment\.GetEnvironmentVariable)\b",
    ),
];

pub(crate) const SINKS: [(&str, &str, &str); 21] = [
    ("javascript", r"\b(query|execute|exec)\s*\(", "SQL"),
    ("javascript", r"\b(eval|Function)\s*\(", "eval"),
    ("javascript", r"\bexec\s*\(", "shell"),
    ("javascript", r"\bspawn\s*\(", "shell"),
    (
        "javascript",
        r"\bfs\.(readFile|writeFile|unlink|rm)\s*\(",
        "filesystem",
    ),
    ("python", r"\b(sql|execute|executemany)\s*\(", "SQL"),
    (
        "python",
        r"\b(os\.system|subprocess|eval|exec)\s*\(",
        "shell",
    ),
    ("python", r"\bopen\s*\(", "filesystem"),
    (
        "javascript",
        r"\b(prompt|system_message|messages)\b",
        "prompt",
    ),
    ("python", r"\b(prompt|system_message|messages)\b", "prompt"),
    // mark_safe is the only framework sink. Django escapes template output
    // unless a value is marked safe, so user input reaching mark_safe is
    // provable cross site scripting. Literal content stays silent, only a
    // tainted flow fires.
    ("python", r"\bmark_safe\s*\(", "mark_safe"),
    (
        "php",
        r"\b(mysqli_query|query|exec|system|shell_exec|eval|include|unlink)\s*\(",
        "SQL",
    ),
    (
        "php",
        r"\b(file_get_contents|file_put_contents|fopen)\s*\(",
        "filesystem",
    ),
    (
        "go",
        r"\b(db\.Query|QueryRow|Exec|exec\.Command|sql\.Open)\s*\(",
        "SQL",
    ),
    (
        "go",
        r"\b(os\.(Create|WriteFile|Remove)|ioutil\.WriteFile)\s*\(",
        "filesystem",
    ),
    (
        "java",
        r"\b(executeQuery|executeUpdate|execute|createQuery)\s*\(",
        "SQL",
    ),
    (
        "java",
        r"\b(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\(",
        "shell",
    ),
    (
        "java",
        r"\b(Files\.(write|readAllBytes)|FileWriter|FileOutputStream)\s*\(",
        "filesystem",
    ),
    (
        "csharp",
        r"\b(SqlCommand|ExecuteScalar|ExecuteNonQuery|ExecuteReader)\s*\(",
        "SQL",
    ),
    ("csharp", r"\bProcess\.Start\s*\(", "shell"),
    (
        "csharp",
        r"\bFile\.(WriteAllText|ReadAllText|Delete|Move)\s*\(",
        "filesystem",
    ),
];

/// Scan one source file for taint flows.
pub fn scan_file(path: &Path, content: &str) -> Vec<TaintReport> {
    let Some(lang) = crate::parser::detect_language(path) else {
        return Vec::new();
    };
    let mut reports = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let blocks = function_blocks(&lines, &lang);
    for (block_start, block_end, indent) in blocks {
        let mut tainted: Vec<(String, usize)> = Vec::new();
        for i in block_start..=block_end {
            let line = lines[i];
            let line_no = i as u64 + 1;
            for (l, pat) in SOURCES {
                if l == lang
                    && regex_hit(pat, line)
                    && let Some(var) = assigned_var(line)
                {
                    tainted.push((var, i));
                }
            }
            for (l, pat, sink) in SINKS {
                if l != lang {
                    continue;
                }
                if !regex_hit(pat, line) {
                    continue;
                }
                let used = tainted.iter().any(|(v, _)| line.contains(v.as_str()));
                let source = tainted.iter().find(|(_, src_i)| {
                    let src_line = lines[*src_i];
                    let src_indent = leading_spaces(src_line);
                    *src_i < i && src_indent >= indent && (i - *src_i) < 60
                });
                if sink == "prompt" {
                    if used {
                        reports.push(make_report(
                            path,
                            line_no,
                            format!(
                                "user input reaches a prompt construction on this line (prompt injection risk). source at line {}",
                                source.map(|(_, n)| n + 1).unwrap_or(0)
                            ),
                        ));
                    }
                } else if used || source.is_some() {
                    reports.push(make_report(
                        path,
                        line_no,
                        format!(
                            "user controlled input reaches a {} sink on this line. source at line {}",
                            sink,
                            source.map(|(_, n)| n + 1).unwrap_or(0)
                        ),
                    ));
                }
            }
        }
    }
    reports
}

pub(crate) fn make_report(path: &Path, line: u64, message: String) -> TaintReport {
    TaintReport {
        severity: "critical".to_string(),
        message,
        file: path.display().to_string(),
        line,
    }
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Match a rule pattern against a line with word boundary support.
pub(crate) fn regex_hit(pattern: &'static str, line: &str) -> bool {
    let cache = PREPARED.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache.lock().unwrap();
    let (start_bound, end_bound, candidates) =
        guard.entry(pattern).or_insert_with(|| prepare(pattern));
    for cand in candidates.iter() {
        if let Some(pos) = line.find(cand) {
            let before_ok = if *start_bound {
                pos == 0 || !is_word_char(line[..pos].chars().last().unwrap_or(' '))
            } else {
                true
            };
            let end = pos + cand.chars().count();
            let after_ok = if *end_bound {
                end >= line.chars().count() || !is_word_char(line.chars().nth(end).unwrap_or(' '))
            } else {
                true
            };
            if before_ok && after_ok {
                return true;
            }
        }
    }
    false
}

/// Normalize a rule pattern once and enumerate every concrete candidate
/// string it can match. The normalization and expansion used to run on
/// every line, which made the guard passes quadratic in real workspaces.
fn prepare(pattern: &'static str) -> (bool, bool, Vec<String>) {
    let mut pat = pattern
        .replace(r"\b", "\u{1}")
        .replace(r"\s", " ")
        .replace(r"\.", ".")
        .replace(r"\(", "(")
        .replace(r"\)", ")")
        .replace(r"\$", "$");
    let mut start_bound = false;
    let mut end_bound = false;
    if let Some(stripped) = pat.strip_prefix('\u{1}') {
        start_bound = true;
        pat = stripped.to_string();
    }
    if pat.ends_with('\u{1}') {
        end_bound = true;
        pat = pat.trim_end_matches('\u{1}').to_string();
    }
    let mut candidates = Vec::new();
    for concrete in concrete_patterns(&pat) {
        candidates.extend(expand(&concrete));
    }
    (start_bound, end_bound, candidates)
}

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

type PreparedPattern = (bool, bool, Vec<String>);
type PreparedCache = HashMap<&'static str, PreparedPattern>;

static PREPARED: OnceLock<Mutex<PreparedCache>> = OnceLock::new();

/// Expand alternation groups like (a|b|c) into concrete patterns.
/// Handles multiple flat groups; nested groups are supported one level deep.
fn concrete_patterns(pattern: &str) -> Vec<String> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    // Find a group open paren that has a matching close paren with a pipe.
    while i < chars.len() {
        if chars[i] == '(' {
            let mut depth = 1;
            let mut j = i + 1;
            let mut has_pipe = false;
            while j < chars.len() && depth > 0 {
                match chars[j] {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    '|' if depth == 1 => has_pipe = true,
                    _ => {}
                }
                j += 1;
            }
            if depth == 0 && has_pipe {
                // Split the group content on top level pipes.
                let inner = &pattern[i + 1..j];
                let mut variants = Vec::new();
                let mut buf = String::new();
                let mut d = 0;
                for c in inner.chars() {
                    match c {
                        '(' => {
                            d += 1;
                            buf.push(c);
                        }
                        ')' => {
                            d -= 1;
                            buf.push(c);
                        }
                        '|' if d == 0 => {
                            variants.push(std::mem::take(&mut buf));
                        }
                        _ => buf.push(c),
                    }
                }
                if !buf.is_empty() {
                    variants.push(buf);
                }
                let mut out = Vec::new();
                for v in variants {
                    let replaced = format!("{}{}{}", &pattern[..i], v, &pattern[j + 1..]);
                    out.extend(concrete_patterns(&replaced));
                }
                return out;
            }
        }
        i += 1;
    }
    vec![pattern.to_string()]
}

/// Expand quantifiers into a bounded set of candidate strings.
fn expand(pattern: &str) -> Vec<String> {
    let mut candidates: Vec<String> = vec![String::new()];
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let is_quant = i + 1 < chars.len() && matches!(chars[i + 1], '*' | '+' | '?');
        if is_quant {
            let quant = chars[i + 1];
            let mut next = Vec::new();
            for base in &candidates {
                match quant {
                    '*' => {
                        next.push(base.clone());
                        for _ in 0..4 {
                            let mut ext = base.clone();
                            ext.push(c);
                            next.push(ext.clone());
                        }
                    }
                    '+' => {
                        for _ in 0..4 {
                            let mut ext = base.clone();
                            ext.push(c);
                            next.push(ext.clone());
                        }
                    }
                    _ => {
                        next.push(base.clone());
                        let mut ext = base.clone();
                        ext.push(c);
                        next.push(ext);
                    }
                }
            }
            candidates = next;
            i += 2;
        } else {
            for base in candidates.iter_mut() {
                base.push(c);
            }
            i += 1;
        }
    }
    candidates
}

pub(crate) fn leading_spaces(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ' || *c == '\t').count()
}

pub(crate) fn assigned_var(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let eq = trimmed.find('=')?;
    if trimmed[eq..].starts_with("==")
        || trimmed[eq..].starts_with("=>")
        || trimmed[eq..].starts_with("!=")
        || trimmed[eq..].starts_with(">=")
        || trimmed[eq..].starts_with("<=")
    {
        return None;
    }
    let lhs = &trimmed[..eq];
    let mut ident = String::new();
    for ch in lhs
        .trim_end()
        .trim_end_matches(':')
        .trim_end()
        .chars()
        .rev()
    {
        if ch.is_alphanumeric() || ch == '_' {
            ident.insert(0, ch);
        } else {
            break;
        }
    }
    if ident.is_empty() {
        return None;
    }
    if matches!(
        ident.as_str(),
        "if" | "while" | "for" | "return" | "const" | "let" | "var" | "mut" | "fn"
    ) {
        return None;
    }
    Some(ident)
}

/// Split file lines into function blocks. Returns (start, end, indent) per
/// block for brace languages, or per indented suite for python.
pub(crate) fn function_blocks(lines: &[&str], lang: &str) -> Vec<(usize, usize, usize)> {
    let mut blocks = Vec::new();
    if lang == "python" {
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            let indent = leading_spaces(line);
            let trimmed = line.trim_start();
            if (trimmed.starts_with("def ") || trimmed.starts_with("async def "))
                && trimmed.contains('(')
            {
                let mut end = i;
                let mut j = i + 1;
                while j < lines.len() {
                    let l = lines[j];
                    if l.trim().is_empty() {
                        j += 1;
                        continue;
                    }
                    if leading_spaces(l) > indent {
                        end = j;
                        j += 1;
                    } else {
                        break;
                    }
                }
                blocks.push((i, end, indent));
                i = end + 1;
            } else {
                i += 1;
            }
        }
        return blocks;
    }
    let mut depth: isize = 0;
    let mut start: Option<usize> = None;
    for (i, line) in lines.iter().enumerate() {
        let opens = line.matches('{').count() as isize;
        let closes = line.matches('}').count() as isize;
        if start.is_none() && opens > 0 {
            start = Some(i);
        }
        // Stray closing braces (error nodes, garbage text) must never push
        // the depth below zero. Clamp so the scan stays sound.
        depth = (depth + opens - closes).max(0);
        if depth == 0
            && let Some(s) = start.take()
        {
            blocks.push((s, i, 0));
        }
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sql_taint_js() {
        let src = "function load() {\n  const q = req.query.id;\n  db.query(q);\n}\n";
        let p = std::path::Path::new("app.js");
        let reports = scan_file(p, src);
        assert!(reports.iter().any(|r| r.message.contains("SQL")));
    }

    #[test]
    fn detects_shell_taint_python() {
        let src = "def run():\n    name = input()\n    os.system(name)\n";
        let p = std::path::Path::new("app.py");
        let reports = scan_file(p, src);
        assert!(reports.iter().any(|r| r.message.contains("shell")));
    }

    #[test]
    fn detects_prompt_taint() {
        let src = "function ask() {\n  const user = req.body.text;\n  const prompt = 'tell me about ' + user;\n}\n";
        let p = std::path::Path::new("ai.js");
        let reports = scan_file(p, src);
        assert!(
            reports
                .iter()
                .any(|r| r.message.contains("prompt injection"))
        );
    }

    #[test]
    fn detects_mark_safe_taint_python() {
        let src = "def render(request):\n    name = input()\n    return mark_safe(name)\n";
        let p = std::path::Path::new("view.py");
        let reports = scan_file(p, src);
        assert!(
            reports
                .iter()
                .any(|r| r.message.contains("mark_safe") && r.severity == "critical")
        );
    }

    #[test]
    fn literal_content_in_mark_safe_stays_silent() {
        let src = "def render():\n    return mark_safe('<b>safe markup</b>')\n";
        let p = std::path::Path::new("view.py");
        let reports = scan_file(p, src);
        assert!(reports.is_empty());
    }

    #[test]
    fn no_false_positive_on_unrelated_call() {
        let src = "function x() {\n  const q = 5;\n  run(q);\n}\n";
        let p = std::path::Path::new("a.py");
        let reports = scan_file(p, src);
        // "run(" must not trigger shell taint without a source.
        assert!(!reports.iter().any(|r| r.message.contains("shell")));
    }

    #[test]
    fn detects_php_sql_taint() {
        let src =
            "<?php\nfunction load() {\n    $q = $_GET['id'];\n    mysqli_query($conn, $q);\n}\n";
        let p = std::path::Path::new("app.php");
        let reports = scan_file(p, src);
        assert!(reports.iter().any(|r| r.message.contains("SQL")));
    }

    #[test]
    fn detects_go_sql_taint() {
        let src = "package main\n\nfunc load() {\n    q := r.URL.Query().Get(\"id\")\n    db.Query(q)\n}\n";
        let p = std::path::Path::new("app.go");
        let reports = scan_file(p, src);
        assert!(reports.iter().any(|r| r.message.contains("SQL")));
    }

    #[test]
    fn detects_java_sql_taint() {
        let src = "class App {\n    void load(HttpServletRequest request) {\n        String q = request.getParameter(\"id\");\n        stmt.executeQuery(q);\n    }\n}\n";
        let p = std::path::Path::new("app.java");
        let reports = scan_file(p, src);
        assert!(reports.iter().any(|r| r.message.contains("SQL")));
    }

    #[test]
    fn detects_csharp_sql_taint() {
        let src = "class App {\n    void Load() {\n        var q = Request.QueryString[\"id\"];\n        cmd.ExecuteScalar(q);\n    }\n}\n";
        let p = std::path::Path::new("app.cs");
        let reports = scan_file(p, src);
        assert!(reports.iter().any(|r| r.message.contains("SQL")));
    }
}
