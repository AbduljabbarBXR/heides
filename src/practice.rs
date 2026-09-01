// Best practice guard.
//
// Surfaces leftover debug output, unfinished markers, hardcoded secrets and
// overlong functions. Findings are informational or warnings, never blockers.

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
    for (i, line) in content.lines().enumerate() {
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
        if lang == "python" && (line.contains("print(") && !line.trim_start().starts_with('#')) {
            // Only flag prints in non CLI files
            reports.push(rep(path, line_no, "info", "print statement found. remove before shipping unless intended."));
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

/// Long function detection using the spine symbol positions.
pub fn long_functions(graph: &CodeGraph) -> Vec<PracticeReport> {
    let mut reports = Vec::new();
    let by_file = graph.symbols_by_file();
    for (file, symbols) in by_file {
        let mut funcs: Vec<_> = symbols
            .iter()
            .filter(|s| s.kind.contains("function") || s.kind == "method_definition" || s.kind == "function_definition")
            .collect();
        funcs.sort_by_key(|s| s.line);
        for (idx, f) in funcs.iter().enumerate() {
            let next_line = funcs
                .get(idx + 1)
                .map(|n| n.line)
                .unwrap_or_else(|| f.line + 120);
            if next_line > f.line && next_line - f.line > 80 {
                reports.push(PracticeReport {
                    severity: "info".to_string(),
                    message: format!("function {} spans over 80 lines. consider splitting it.", f.name),
                    file: file.to_string(),
                    line: f.line,
                });
            }
        }
    }
    reports
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
}
