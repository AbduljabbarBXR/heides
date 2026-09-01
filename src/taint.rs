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

const SOURCES: [(&str, &str); 10] = [
    ("javascript", r"\b(req|request)\.(query|params|body|headers|cookies)\b"),
    ("javascript", r"\bprocess\.env\b"),
    ("javascript", r"\blocalStorage\b"),
    ("javascript", r"\bsessionStorage\b"),
    ("javascript", r"\bwindow\.prompt\b"),
    ("javascript", r"\binput\.value\b"),
    ("python", r"\binput\s*\("),
    ("python", r"\bos\.environ\b"),
    ("python", r"\bsys\.argv\b"),
    ("python", r"\brequest\.(args|form|json|values)\b"),
];

const SINKS: [(&str, &str, &str); 10] = [
    ("javascript", r"\b(query|execute|exec)\s*\(", "SQL"),
    ("javascript", r"\b(eval|Function)\s*\(", "eval"),
    ("javascript", r"\bexec\s*\(", "shell"),
    ("javascript", r"\bspawn\s*\(", "shell"),
    ("javascript", r"\bfs\.(readFile|writeFile|unlink|rm)\s*\(", "filesystem"),
    ("python", r"\b(sql|execute|executemany)\s*\(", "SQL"),
    ("python", r"\b(os\.system|subprocess|eval|exec)\s*\(", "shell"),
    ("python", r"\bopen\s*\(", "filesystem"),
    ("javascript", r"\b(prompt|system_message|messages)\b", "prompt"),
    ("python", r"\b(prompt|system_message|messages)\b", "prompt"),
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
                if l == lang && regex_hit(pat, line) {
                    if let Some(var) = assigned_var(line) {
                        tainted.push((var, i));
                    }
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

fn make_report(path: &Path, line: u64, message: String) -> TaintReport {
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
fn regex_hit(pattern: &str, line: &str) -> bool {
    let mut pat = pattern
        .replace(r"\b", "\u{1}")
        .replace(r"\s", " ")
        .replace(r"\.", ".")
        .replace(r"\(", "(")
        .replace(r"\)", ")");
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
    let Ok(pos) = match_position(line, &pat) else {
        return false;
    };
    let before_ok = if start_bound {
        pos == 0 || !is_word_char(line[..pos].chars().last().unwrap_or(' '))
    } else {
        true
    };
    let end = pos + pat.chars().count();
    let after_ok = if end_bound {
        end >= line.chars().count() || !is_word_char(line.chars().nth(end).unwrap_or(' '))
    } else {
        true
    };
    before_ok && after_ok
}

/// Find the byte position of a pattern in a line.
/// Handles parenthesized alternation groups and bounded quantifiers.
fn match_position(line: &str, pattern: &str) -> Result<usize, ()> {
    for concrete in concrete_patterns(pattern) {
        for cand in expand(&concrete) {
            if let Some(pos) = line.find(&cand) {
                return Ok(pos);
            }
        }
    }
    Err(())
}

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

fn leading_spaces(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ' || *c == '\t').count()
}

fn assigned_var(line: &str) -> Option<String> {
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
    for ch in lhs.trim_end().chars().rev() {
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
fn function_blocks(lines: &[&str], lang: &str) -> Vec<(usize, usize, usize)> {
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
    let mut depth = 0usize;
    let mut start: Option<usize> = None;
    for (i, line) in lines.iter().enumerate() {
        let opens = line.matches('{').count();
        let closes = line.matches('}').count();
        if start.is_none() && opens > 0 {
            start = Some(i);
        }
        depth = depth + opens - closes;
        if start.is_some() && depth == 0 {
            blocks.push((start.unwrap(), i, 0));
            start = None;
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
        assert!(reports.iter().any(|r| r.message.contains("prompt injection")));
    }

    #[test]
    fn no_false_positive_on_unrelated_call() {
        let src = "function x() {\n  const q = 5;\n  run(q);\n}\n";
        let p = std::path::Path::new("a.py");
        let reports = scan_file(p, src);
        // "run(" must not trigger shell taint without a source.
        assert!(!reports.iter().any(|r| r.message.contains("shell")));
    }
}
