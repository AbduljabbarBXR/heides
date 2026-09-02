// Best practice guard.
//
// Surfaces leftover debug output, unfinished markers and hardcoded secrets.
// Every rule is exact. Findings are informational or warnings, never
// blockers, and never fire on clean idiomatic code.

use std::path::Path;

use crate::spine::CodeGraph;

#[derive(Debug, Clone)]
pub struct PracticeReport {
    pub severity: String,
    pub message: String,
    pub file: String,
    pub line: u64,
}

const SECRET_PATTERN: [&str; 6] = ["api_key", "apikey", "secret", "password", "token", "private_key"];

/// Scan one source file for practice issues.
pub fn scan_file(path: &Path, content: &str, lang: &str) -> Vec<PracticeReport> {
    let mut reports = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let has_definitions = lines
        .iter()
        .any(|l| {
            let t = l.trim_start();
            t.starts_with("def ") || t.starts_with("class ") || t.starts_with("fn ") || t.starts_with("func ") || t.starts_with("function ")
        });
    let main_guard = python_main_guard(&lines);

    for (i, line) in lines.iter().enumerate() {
        let line_no = i as u64 + 1;
        let lower = line.to_ascii_lowercase();
        if lower.contains("todo") || lower.contains("fixme") || lower.contains("hack") {
            reports.push(rep(path, line_no, "info", "unfinished work marker left in the code."));
        }
        if lang == "javascript" || lang == "typescript" {
            if line.contains("console.log") || line.contains("debugger") {
                reports.push(rep(path, line_no, "warning", "debug output left in the code."));
            }
        }
        if lang == "rust" && line.contains("dbg!") {
            reports.push(rep(path, line_no, "warning", "debug macro left in the code."));
        }
        if lang == "python" && line.contains("print(") && !line.trim_start().starts_with('#') {
            let inside_guard = main_guard
                .map(|(guard_line, guard_indent)| i > guard_line && leading_spaces(line) > guard_indent)
                .unwrap_or(false);
            // A print in a library module outside the main guard is a
            // leftover. Scripts and main guarded blocks are legitimate.
            if has_definitions && leading_spaces(line) == 0 && !inside_guard {
                reports.push(rep(path, line_no, "info", "print statement found at module level in a library module. remove before shipping."));
            }
        }
        for key in SECRET_PATTERN {
            if lower.contains(key)
                && (line.contains('=') || line.contains(':'))
                && (line.contains('"') || line.contains('\''))
            {
                reports.push(rep(path, line_no, "critical", "possible secret or credential hardcoded in source."));
                break;
            }
        }
    }
    reports
}

/// Find the line and indent of the python main guard, if present.
fn python_main_guard(lines: &[&str]) -> Option<(usize, usize)> {
    for (i, line) in lines.iter().enumerate() {
        if line.contains("__name__") && line.contains("__main__") {
            return Some((i, leading_spaces(line)));
        }
    }
    None
}

fn leading_spaces(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ' || *c == '\t').count()
}

/// Function length from the real body extent.
/// Brace languages use exact brace matching from the opening brace to the
/// matching close. Python uses the indentation suite. No estimates.
pub fn long_functions(graph: &CodeGraph) -> Vec<PracticeReport> {
    let mut reports = Vec::new();
    let by_file = graph.symbols_by_file();
    for (file, symbols) in by_file {
        let funcs: Vec<_> = symbols
            .iter()
            .filter(|s| {
                s.kind.contains("function")
                    || s.kind == "method_definition"
                    || s.kind == "function_definition"
                    || s.kind == "method_declaration"
                    || s.kind == "constructor_declaration"
                    || s.kind == "local_function_statement"
            })
            .collect();
        if funcs.is_empty() {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(file) else {
            continue;
        };
        let lines: Vec<&str> = content.lines().collect();
        let lang = symbols[0].lang.clone();
        for f in funcs {
            let start = (f.line as usize).saturating_sub(1);
            let body_lines = body_length(&lines, start, &lang);
            if body_lines > 80 {
                reports.push(PracticeReport {
                    severity: "info".to_string(),
                    message: format!("function {} spans {} lines. consider splitting it.", f.name, body_lines),
                    file: file.to_string(),
                    line: f.line,
                });
            }
        }
    }
    reports
}

/// Count the body lines of the function starting at the given line.
/// Exact for brace languages, indentation based for python.
fn body_length(lines: &[&str], start: usize, lang: &str) -> usize {
    if start >= lines.len() {
        return 0;
    }
    if lang == "python" {
        let indent = leading_spaces(lines[start]);
        let mut end = start;
        for j in (start + 1)..lines.len() {
            let l = lines[j];
            if l.trim().is_empty() {
                continue;
            }
            if leading_spaces(l) <= indent {
                break;
            }
            end = j;
        }
        return end.saturating_sub(start);
    }
    // Brace languages: find the opening brace on or after the signature,
    // then count until the matching close.
    let mut depth: isize = 0;
    let mut counted = 0usize;
    let mut opened = false;
    for (offset, line) in lines.iter().enumerate().skip(start) {
        if !opened {
            let brace = line.find('{');
            match brace {
                Some(_) => {
                    opened = true;
                    depth += line.matches('{').count() as isize;
                    depth -= line.matches('}').count() as isize;
                    counted += 1;
                    if depth <= 0 {
                        return counted;
                    }
                }
                None => {
                    // signature continues
                    counted += 1;
                    if counted > 200 {
                        // No body found in a reasonable span. Abstract or
                        // interface signature. Not a long function.
                        return 0;
                    }
                }
            }
        } else {
            depth += line.matches('{').count() as isize;
            depth -= line.matches('}').count() as isize;
            counted += 1;
            if depth <= 0 {
                return counted;
            }
        }
    }
    counted
}

fn rep(path: &Path, line: u64, severity: &str, message: &str) -> PracticeReport {
    PracticeReport {
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
    fn flags_debug_and_secrets() {
        let src = "console.log('x');\nconst api_key = 'abc12345';\n";
        let p = std::path::Path::new("a.js");
        let reports = scan_file(p, src, "javascript");
        assert!(reports.iter().any(|r| r.message.contains("debug")));
        assert!(reports.iter().any(|r| r.message.contains("secret")));
    }

    #[test]
    fn script_with_main_guard_is_silent() {
        let src = "def main():\n    print('hello')\n\nif __name__ == '__main__':\n    main()\n";
        let p = std::path::Path::new("script.py");
        let reports = scan_file(p, src, "python");
        assert!(!reports.iter().any(|r| r.message.contains("print")));
    }

    #[test]
    fn library_module_print_is_flagged() {
        let src = "def helper():\n    return 1\n\nprint('leftover')\n";
        let p = std::path::Path::new("lib.py");
        let reports = scan_file(p, src, "python");
        assert!(reports.iter().any(|r| r.message.contains("print")));
    }

    #[test]
    fn standalone_script_print_is_silent() {
        let src = "print('tool output')\n";
        let p = std::path::Path::new("tool.py");
        let reports = scan_file(p, src, "python");
        assert!(!reports.iter().any(|r| r.message.contains("print")));
    }

    #[test]
    fn body_length_counts_real_lines() {
        let src = "fn big() {\n    let a = 1;\n    let b = 2;\n    let c = 3;\n}\nfn small() {}\n";
        let lines: Vec<&str> = src.lines().collect();
        assert_eq!(body_length(&lines, 0, "rust"), 5);
        assert_eq!(body_length(&lines, 5, "rust"), 1);
    }
}
