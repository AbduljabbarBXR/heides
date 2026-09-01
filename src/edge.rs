// Edge case guard.
//
// Flags the classic boundary mistakes in changed code: panics on unwrap,
// unparsed JSON, missing null checks, loose evaluation, and unsafe python
// patterns. Every rule is deterministic and each finding points at a line.

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

    for (i, line) in lines.iter().enumerate() {
        let line_no = i as u64 + 1;
        let trimmed = line.trim_start();
        match lang.as_str() {
            "rust" => {
                if trimmed.contains(".unwrap()") || trimmed.contains("unwrap_or_else") && trimmed.contains("panic") {
                    reports.push(rep(path, line_no, "warning", "unwrap can panic when the value is not present. handle the case instead."));
                } else if trimmed.contains("panic!(") {
                    reports.push(rep(path, line_no, "info", "panic macro present. make sure this path is truly unreachable."));
                }
                if trimmed.starts_with("fn ") && !trimmed.contains("->") && !trimmed.starts_with("fn main") {
                    reports.push(rep(path, line_no, "info", "function has no return type. add one for clarity."));
                }
            }
            "javascript" | "typescript" => {
                if trimmed.contains("JSON.parse(") {
                    let window: Vec<&str> = lines.iter().copied().skip(i.saturating_sub(20)).take(20).collect();
                    if !window.iter().any(|l| l.contains("try")) {
                        reports.push(rep(path, line_no, "warning", "JSON.parse can throw on bad input. wrap it in try or validate first."));
                    }
                }
                if trimmed.contains("getItem(") {
                    let window: Vec<&str> = lines.iter().copied().skip(i.saturating_sub(20)).take(20).collect();
                    if !window.iter().any(|l| l.contains("||") || l.contains("??")) {
                        reports.push(rep(path, line_no, "warning", "storage reads can return null. provide a fallback."));
                    }
                }
                if trimmed.contains("parseInt(") && !trimmed.contains(",") {
                    reports.push(rep(path, line_no, "info", "parseInt without a radix can misread strings. pass a radix."));
                }
                if trimmed.contains("==") && !trimmed.contains("===") && !trimmed.contains("=>") {
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
                if trimmed.contains("open(") && !window_has(&lines, i, "with") {
                    reports.push(rep(path, line_no, "warning", "file handle is opened without a with block and may leak."));
                }
            }
            _ => {}
        }
    }
    reports
}

fn window_has(lines: &[&str], at: usize, needle: &str) -> bool {
    lines
        .iter()
        .skip(at.saturating_sub(10))
        .take(10)
        .any(|l| l.contains(needle))
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
    fn flags_json_parse() {
        let src = "function load() {\n  const data = JSON.parse(raw);\n}\n";
        let p = std::path::Path::new("a.js");
        let reports = scan_file(p, src);
        assert!(reports.iter().any(|r| r.message.contains("JSON.parse")));
    }
}
