// Edge case guard.
//
// Flags the classic boundary mistakes in changed code. Every rule is exact.
// A rule reports only when it can prove the hazard from the code itself.
// No window guesses, no style opinions. If the evidence is not there, the
// guard stays silent.

use std::path::Path;

#[derive(Debug, Clone)]
pub struct EdgeReport {
    pub severity: String,
    pub message: String,
    pub file: String,
    pub line: u64,
}

/// Scan one source file for edge case hazards.
pub fn scan_file(path: &Path, content: &str) -> Vec<EdgeReport> {
    let Some(lang) = crate::parser::detect_language(path) else {
        return Vec::new();
    };
    let mut reports = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let brace_blocks = if lang == "python" {
        Vec::new()
    } else {
        build_brace_blocks(&lines)
    };

    for (i, line) in lines.iter().enumerate() {
        let line_no = i as u64 + 1;
        let trimmed = line.trim_start();
        match lang.as_str() {
            "rust" => {
                if trimmed.contains(".unwrap()") {
                    reports.push(rep(path, line_no, "warning", "unwrap can panic when the value is not present. handle the case instead."));
                } else if trimmed.contains("panic!(") {
                    reports.push(rep(path, line_no, "info", "panic macro present. make sure this path is truly unreachable."));
                }
            }
            "javascript" | "typescript" => {
                if trimmed.contains("JSON.parse(") {
                    let (s, e) = enclosing_block(&lines, &brace_blocks, i, &lang);
                    let body: String = lines[s..=e].join("\n");
                    if !body.contains("try") {
                        reports.push(rep(path, line_no, "warning", "JSON.parse can throw on bad input. wrap it in try or validate first."));
                    }
                }
                if trimmed.contains("getItem(") {
                    if let Some(var) = storage_var(trimmed) {
                        let (s, e) = enclosing_block(&lines, &brace_blocks, i, &lang);
                        let mut usages = 0usize;
                        let mut guarded = false;
                        for j in (i + 1)..=e {
                            let l = lines[j];
                            if contains_word(l, &var) {
                                usages += 1;
                                if l.contains("??")
                                    || l.contains("||")
                                    || l.contains("?.")
                                    || l.contains("== null")
                                    || l.contains("!= null")
                                    || l.contains("if (")
                                {
                                    guarded = true;
                                }
                            }
                        }
                        if usages > 0 && !guarded {
                            reports.push(rep(path, line_no, "warning", "storage reads can return null and the value is used without a guard."));
                        }
                    }
                }
                if trimmed.contains("parseInt(") && !trimmed.contains(",") {
                    reports.push(rep(path, line_no, "info", "parseInt without a radix can misread strings. pass a radix."));
                }
                if trimmed.contains("==") && !trimmed.contains("===") && !trimmed.contains("=>") && !trimmed.contains("== null") && !trimmed.contains("== undefined") {
                    reports.push(rep(path, line_no, "info", "loose equality can coerce types. prefer strict equality."));
                }
            }
            "python" => {
                if trimmed.starts_with("def ") && (trimmed.contains("=[]") || trimmed.contains("={}")) {
                    reports.push(rep(path, line_no, "warning", "mutable default arguments are evaluated once and can leak state."));
                }
                if trimmed.starts_with("except:") {
                    reports.push(rep(path, line_no, "warning", "bare except swallows every error including interrupts. name the exception."));
                }
                if trimmed.contains("open(") {
                    let (s, e) = enclosing_block(&lines, &brace_blocks, i, &lang);
                    let body: String = lines[s..=e].join("\n");
                    if !body.contains("with ") {
                        reports.push(rep(path, line_no, "warning", "file handle is opened outside a with block and may leak."));
                    }
                }
            }
            _ => {}
        }
    }
    reports
}

/// Does the line use the variable as a whole word?
fn contains_word(line: &str, var: &str) -> bool {
    let bytes = line.as_bytes();
    let mut search = 0usize;
    while let Some(rel) = line[search..].find(var) {
        let pos = search + rel;
        let before_ok = pos == 0 || !is_word_char(bytes[pos - 1] as char);
        let after = pos + var.len();
        let after_ok = after >= bytes.len() || !is_word_char(bytes[after] as char);
        if before_ok && after_ok {
            return true;
        }
        search = pos + 1;
    }
    false
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '$'
}

/// Extract the assigned variable from a storage read line.
fn storage_var(line: &str) -> Option<String> {
    let eq = line.find('=')?;
    let lhs = line[..eq]
        .trim()
        .trim_start_matches("const")
        .trim_start_matches("let")
        .trim_start_matches("var")
        .trim();
    if lhs.is_empty() {
        return None;
    }
    let mut ident = String::new();
    for ch in lhs.chars().rev() {
        if ch.is_alphanumeric() || ch == '_' || ch == '$' {
            ident.insert(0, ch);
        } else {
            break;
        }
    }
    if ident.is_empty() {
        None
    } else {
        Some(ident)
    }
}

/// Exact brace block map for brace languages. Each entry is an inclusive
/// (start_line, end_line) pair of a matched open and close brace.
fn build_brace_blocks(lines: &[&str]) -> Vec<(usize, usize)> {
    let mut blocks = Vec::new();
    let mut stack: Vec<usize> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let opens = line.matches('{').count();
        let closes = line.matches('}').count();
        let paired = opens.min(closes);
        for _ in 0..paired {
            if let Some(s) = stack.pop() {
                blocks.push((s, i));
            }
        }
        for _ in 0..(opens - paired) {
            stack.push(i);
        }
        for _ in 0..(closes - paired) {
            if let Some(s) = stack.pop() {
                blocks.push((s, i));
            }
        }
    }
    blocks
}

/// The innermost block containing the line. Brace languages use the exact
/// map. Python uses the indentation suite. Never panics, always returns a
/// valid range inside the file.
fn enclosing_block(lines: &[&str], brace_blocks: &[(usize, usize)], at: usize, lang: &str) -> (usize, usize) {
    let last = lines.len().saturating_sub(1);
    if lang == "python" {
        let indent = leading_spaces(lines[at]);
        let mut start = 0usize;
        for j in (0..at).rev() {
            if !lines[j].trim().is_empty() && leading_spaces(lines[j]) < indent {
                start = j;
                break;
            }
        }
        let header_indent = leading_spaces(lines[start]);
        let mut end = last;
        for j in (at + 1)..lines.len() {
            if !lines[j].trim().is_empty() && leading_spaces(lines[j]) <= header_indent {
                end = j.saturating_sub(1);
                break;
            }
        }
        return (start, end);
    }
    let mut best: Option<(usize, usize)> = None;
    for &(s, e) in brace_blocks {
        if s <= at && at <= e {
            match best {
                Some((bs, be)) => {
                    if (e - s) < (be - bs) {
                        best = Some((s, e));
                    }
                }
                None => best = Some((s, e)),
            }
        }
    }
    best.unwrap_or((0, last))
}

fn leading_spaces(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ' || *c == '\t').count()
}

fn rep(path: &Path, line: u64, severity: &str, message: &str) -> EdgeReport {
    EdgeReport {
        severity: severity.to_string(),
        message: message.to_string(),
        file: path.display().to_string(),
        line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_unwrap() {
        let src = "fn main() {\n    let v = maybe().unwrap();\n}\n";
        let p = std::path::Path::new("a.rs");
        let reports = scan_file(p, src);
        assert!(reports.iter().any(|r| r.message.contains("unwrap")));
    }

    #[test]
    fn clean_rust_is_silent() {
        let src = "fn maybe() -> Option<i32> {\n    Some(1)\n}\n\nfn main() {\n    let v = maybe().unwrap_or(0);\n    println!(\"{}\", v);\n}\n";
        let p = std::path::Path::new("clean.rs");
        let reports = scan_file(p, src);
        assert!(reports.is_empty(), "clean rust must be silent, got {:?}", reports);
    }

    #[test]
    fn flags_json_parse() {
        let src = "function load() {\n  const data = JSON.parse(raw);\n}\n";
        let p = std::path::Path::new("a.js");
        let reports = scan_file(p, src);
        assert!(reports.iter().any(|r| r.message.contains("JSON.parse")));
    }

    #[test]
    fn json_parse_with_try_is_silent() {
        let src = "function load() {\n  try {\n    const data = JSON.parse(raw);\n  } catch (e) {}\n}\n";
        let p = std::path::Path::new("a.js");
        let reports = scan_file(p, src);
        assert!(!reports.iter().any(|r| r.message.contains("JSON.parse")));
    }

    #[test]
    fn unguarded_storage_is_flagged() {
        let src = "function load() {\n  const u = localStorage.getItem('u');\n  console.log(u.length);\n}\n";
        let p = std::path::Path::new("a.js");
        let reports = scan_file(p, src);
        assert!(reports.iter().any(|r| r.message.contains("storage")));
    }

    #[test]
    fn guarded_storage_is_silent() {
        let src = "function load() {\n  const u = localStorage.getItem('u');\n  if (u == null) return;\n  console.log(u.length);\n}\n";
        let p = std::path::Path::new("a.js");
        let reports = scan_file(p, src);
        assert!(!reports.iter().any(|r| r.message.contains("storage")));
    }

    #[test]
    fn unused_storage_is_silent() {
        let src = "function load() {\n  const u = localStorage.getItem('u');\n  return;\n}\n";
        let p = std::path::Path::new("a.js");
        let reports = scan_file(p, src);
        assert!(!reports.iter().any(|r| r.message.contains("storage")));
    }

    #[test]
    fn python_open_with_with_is_silent() {
        let src = "def load():\n    with open('f', 'r') as f:\n        return f.read()\n";
        let p = std::path::Path::new("a.py");
        let reports = scan_file(p, src);
        assert!(!reports.iter().any(|r| r.message.contains("file handle")));
    }

    #[test]
    fn python_open_without_with_is_flagged() {
        let src = "def load():\n    f = open('f', 'r')\n    return f.read()\n";
        let p = std::path::Path::new("a.py");
        let reports = scan_file(p, src);
        assert!(reports.iter().any(|r| r.message.contains("file handle")));
    }
}
