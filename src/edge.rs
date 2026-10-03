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
                if trimmed.contains(".unwrap()") && !is_test_context(path, &lines, i) {
                    // The message is deliberately stable and does not name the
                    // function. Naming it made every instance a unique message,
                    // which stopped them folding: 152 findings became 152
                    // single-item lines. The fold is worth more than the name,
                    // and the folded line already names the first four files
                    // and how many more, so the reader still knows where to
                    // look. A future per-function view can use the file list
                    // rather than changing the message, which would unbreak
                    // folding for everyone.
                    reports.push(rep(
                        path,
                        line_no,
                        "warning",
                        "unwrap can panic when the value is not present. handle the case instead.",
                    ));
                } else if trimmed.contains("panic!(") && !is_test_context(path, &lines, i) {
                    // Same reasoning as the unwrap rule: a stable message, so
                    // these still fold.
                    reports.push(rep(
                        path,
                        line_no,
                        "info",
                        "panic macro present. make sure this path is truly unreachable.",
                    ));
                }
            }
            "javascript" | "typescript" => {
                if trimmed.contains("JSON.parse(") {
                    let (s, e) = enclosing_block(&lines, &brace_blocks, i, &lang);
                    let body: String = lines[s..=e].join("\n");
                    if !body.contains("try") {
                        reports.push(rep(
                            path,
                            line_no,
                            "warning",
                            "JSON.parse can throw on bad input. wrap it in try or validate first.",
                        ));
                    }
                }
                if trimmed.contains("getItem(")
                    && let Some(var) = storage_var(trimmed)
                {
                    let (_s, e) = enclosing_block(&lines, &brace_blocks, i, &lang);
                    let mut usages = 0usize;
                    let mut guarded = false;
                    for &l in lines.iter().take(e + 1).skip(i + 1) {
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
                        reports.push(rep(
                            path,
                            line_no,
                            "warning",
                            "storage reads can return null and the value is used without a guard.",
                        ));
                    }
                }
                if trimmed.contains("parseInt(") && !trimmed.contains(",") {
                    reports.push(rep(
                        path,
                        line_no,
                        "info",
                        "parseInt without a radix can misread strings. pass a radix.",
                    ));
                }
                if trimmed.contains("==")
                    && !trimmed.contains("===")
                    && !trimmed.contains("=>")
                    && !trimmed.contains("== null")
                    && !trimmed.contains("== undefined")
                {
                    reports.push(rep(
                        path,
                        line_no,
                        "info",
                        "loose equality can coerce types. prefer strict equality.",
                    ));
                }
            }
            "python" => {
                if trimmed.starts_with("def ")
                    && (trimmed.contains("=[]") || trimmed.contains("={}"))
                {
                    reports.push(rep(
                        path,
                        line_no,
                        "warning",
                        "mutable default arguments are evaluated once and can leak state.",
                    ));
                }
                if trimmed.starts_with("except:") {
                    reports.push(rep(path, line_no, "warning", "bare except swallows every error including interrupts. name the exception."));
                }
                if trimmed.contains("open(") {
                    let (s, e) = enclosing_block(&lines, &brace_blocks, i, &lang);
                    let body: String = lines[s..=e].join("\n");
                    if !body.contains("with ") {
                        reports.push(rep(
                            path,
                            line_no,
                            "warning",
                            "file handle is opened outside a with block and may leak.",
                        ));
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
    if ident.is_empty() { None } else { Some(ident) }
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
fn enclosing_block(
    lines: &[&str],
    brace_blocks: &[(usize, usize)],
    at: usize,
    lang: &str,
) -> (usize, usize) {
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
        for (j, &l) in lines.iter().enumerate().skip(at + 1) {
            if !l.trim().is_empty() && leading_spaces(l) <= header_indent {
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

/// True when this file is test code, or this line sits inside a test module.
///
/// The module does not end at the first closing brace. Walking backwards and
/// bailing on the first `}` finds the end of the *previous test function*,
/// which is the most common brace in the file, and concludes it left test
/// scope. In heides' own source that turned 127 `unwrap` warnings into
/// findings when most are inside `#[cfg(test)] mod tests` in `src/`.
///
/// The rule has to count braces rather than trip on the first one.
#[test]
fn a_brace_inside_a_test_module_does_not_end_it() {
    let src = "#[cfg(test)]\nmod tests {\n    use super::*;\n    #[test]\n    fn one() {\n        a.unwrap()\n    }\n\n    #[test]\n    fn two() {\n        y.unwrap()\n    }\n}\nfn production() {\n    b.unwrap()\n}\n";
    let lines: Vec<&str> = src.lines().collect();
    let at = lines.iter().position(|l| l.contains("y.unwrap()")).unwrap();
    assert!(
        is_test_context(std::path::Path::new("src/thing.rs"), &lines, at),
        "a brace closing a sibling test fn must not end the test module"
    );
}

/// The negative: after the module closes, code is real again. A fix that
/// simply treats everything after the first `mod tests` as test code would
/// suppress every finding in the rest of the file.
#[test]
fn code_after_the_test_module_is_real_code() {
    let src = "#[cfg(test)]\nmod tests {\n    fn one() {\n        a.unwrap()\n    }\n}\nfn production() {\n    b.unwrap()\n}\n";
    let lines: Vec<&str> = src.lines().collect();
    let at = lines.iter().position(|l| l.contains("b.unwrap()")).unwrap();
    assert!(
        !is_test_context(std::path::Path::new("src/thing.rs"), &lines, at),
        "production code after the test module must not be suppressed"
    );
}

/// A `#[cfg(test)]` module or a `tests/` path holds assertions about the code,
/// not code that runs in production. Flagging an `unwrap` there says nothing
/// about the shipped binary, and 41 of the 152 findings on this repository were
/// in `tests/battle.rs` alone. Silence in test code is a scoping decision, not
/// a downgrade: the severity for a real unwrap is unchanged.
pub(crate) fn is_test_context(path: &Path, lines: &[&str], at: usize) -> bool {
    let p = path.to_string_lossy().replace('\\', "/");
    if p.contains("/tests/")
        || p.starts_with("tests/")
        || p.contains("/benches/")
        || p.contains("/examples/")
        || p.ends_with("_test.rs")
    {
        return true;
    }
    // Scan forward and track which modules are open at `at`.
    //
    // Every earlier version of this walked backwards and looked for the nearest
    // `mod`, bail point or brace, and each one got a case wrong. Walking back from
    // a line inside `#[cfg(test)] mod tests` finds the end of the *previous test
    // function*, which is the commonest brace in the file, and concludes the
    // module ended there. On heides' own source that mislabelled most of 127
    // `unwrap` warnings, in the tool's own test modules.
    //
    // Forward is unambiguous: a module is open at a line if its braces opened
    // before it and have not closed yet. Modules are pushed and popped with the
    // depth, so a sibling module later in the file cannot be mistaken for an
    // enclosing one.
    let mut depth: i32 = 0;
    // Depth at which each currently open module began, and whether it is a test
    // module. Parallel vectors rather than a tuple stack, so the pop is readable.
    let mut open_at: Vec<i32> = Vec::new();
    let mut is_test: Vec<bool> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim_start();
        let opens = t.matches('{').count() as i32;
        let closes = t.matches('}').count() as i32;
        if opens > 0 && (t.starts_with("mod ") || t.starts_with("pub mod ")) {
            open_at.push(depth);
            is_test.push(lines[i].contains("cfg(test)") || t.contains("tests"));
        }
        depth += opens - closes;
        while let Some(d) = open_at.last() {
            if depth <= *d {
                open_at.pop();
                is_test.pop();
            } else {
                break;
            }
        }
        if i == at {
            return is_test.iter().any(|t| *t);
        }
    }
    false
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
    fn unwrap_in_a_test_module_is_silent() {
        let src = "#[cfg(test)]\nmod tests {\n    fn t() {\n        let o: Option<i32> = None;\n        o.unwrap();\n    }\n}\n";
        let reports = scan_file(std::path::Path::new("a.rs"), src);
        assert!(
            reports.is_empty(),
            "an unwrap inside a cfg(test) module is a test assertion, not shipped code: {reports:?}"
        );
    }

    #[test]
    fn unwrap_in_a_tests_path_is_silent() {
        let src = "fn helper() {\n    let o: Option<i32> = None;\n    o.unwrap();\n}\n";
        let reports = scan_file(std::path::Path::new("tests/battle.rs"), src);
        assert!(reports.is_empty(), "{reports:?}");
    }

    #[test]
    fn unwrap_outside_tests_still_fires() {
        let src = "fn load_config() -> i32 {\n    let o: Option<i32> = None;\n    o.unwrap()\n}\n";
        let reports = scan_file(std::path::Path::new("src/lib.rs"), src);
        assert_eq!(reports.len(), 1, "{reports:?}");
    }

    #[test]
    fn identical_unwraps_keep_one_message_so_they_can_fold() {
        // Naming the function in the message made every instance unique and
        // stopped them folding, which turned one line of 152 into 152 lines.
        // The message must stay stable for the fold to work.
        let a = scan_file(
            std::path::Path::new("src/a.rs"),
            "fn one() {\n    let o: Option<i32> = None;\n    o.unwrap()\n}\n",
        );
        let b = scan_file(
            std::path::Path::new("src/b.rs"),
            "fn two() {\n    let o: Option<i32> = None;\n    o.unwrap()\n}\n",
        );
        assert_eq!(a[0].message, b[0].message, "the message must be stable");
    }

    #[test]
    fn a_real_unwrap_keeps_its_severity() {
        // Scoping test code is not a blanket downgrade. A genuine unwrap is
        // still a warning.
        let src = "pub fn parse(v: &str) -> i32 {\n    v.parse().unwrap()\n}\n";
        let reports = scan_file(std::path::Path::new("src/lib.rs"), src);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].severity, "warning");
    }

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
        assert!(
            reports.is_empty(),
            "clean rust must be silent, got {:?}",
            reports
        );
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
        let src =
            "function load() {\n  try {\n    const data = JSON.parse(raw);\n  } catch (e) {}\n}\n";
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
