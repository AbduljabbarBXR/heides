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

const SECRET_PATTERN: [&str; 6] = [
    "api_key",
    "apikey",
    "secret",
    "password",
    "token",
    "private_key",
];

/// True when this line binds a secret looking name to a real string literal.
///
/// The name before the binding operator must contain a secret keyword, the
/// operator must be a real assignment and not a comparison or an arrow, the
/// name must not be a dotted config path, and the value must be a non empty
/// quoted literal that is not an interpolated template. Labels, attributes,
/// type declarations, env reads and config path keys stay silent.
fn secret_assignment(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut op: Option<usize> = None;
    let mut quote: u8 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if quote != 0 {
            if b == quote && (i == 0 || bytes[i - 1] != b'\\') {
                quote = 0;
            }
            continue;
        }
        match b {
            b'"' | b'\'' => quote = b,
            b'=' | b':' => {
                op = Some(i);
                break;
            }
            _ => {}
        }
    }
    let Some(at) = op else {
        return false;
    };
    let prev = if at > 0 { bytes[at - 1] } else { 0 };
    let next = bytes.get(at + 1).copied().unwrap_or(0);
    if prev == b'=' || prev == b'!' || prev == b'<' || prev == b'>' {
        return false;
    }
    if next == b'=' || next == b'>' {
        return false;
    }
    let before = &line[..at];
    let mut name_was_quoted = false;
    let mut name = before
        .trim_end()
        .rsplit(|c: char| c.is_whitespace() || c == '(' || c == '[' || c == '{' || c == ',')
        .next()
        .unwrap_or("")
        .trim_end_matches('.');
    if name.len() > 1 && (name.starts_with('"') || name.starts_with('\'')) {
        name_was_quoted = true;
        name = &name[1..name.len() - 1];
    }
    if name.is_empty() || name.contains('.') {
        return false;
    }
    let lower_name = name.to_ascii_lowercase();
    if !SECRET_PATTERN.iter().any(|k| lower_name.contains(k)) {
        return false;
    }
    // Validation rule names like newPasswordRule are not secrets.
    if lower_name.contains("rule") {
        return false;
    }
    // Field label parameters, password1_field_name defaults to the field
    // name, never a credential. Secret values never live in a variable
    // whose name ends in field or label, those hold references.
    let raw_trim = line[at + 1..]
        .trim_start()
        .trim_matches(|c| c == '"' || c == '\'');
    if (lower_name.ends_with("_field_name")
        || lower_name.ends_with("_field")
        || lower_name.ends_with("_label")
        || lower_name.ends_with("_name"))
        && raw_trim.len() <= 36
        && !raw_trim.chars().any(|c| c.is_ascii_uppercase())
    {
        return false;
    }
    // Tokenizer machinery names are not credentials.
    if lower_name.contains("tokeniz") {
        return false;
    }
    let value = line[at + 1..].trim_start();
    let mut chars = value.chars();
    let q = match chars.next() {
        Some(q @ ('"' | '\'')) => q,
        _ => return false,
    };
    let content = value[1..].split(q).next().unwrap_or("");
    // Constant references and env var names are not credentials. Real
    // secrets almost never render as SCREAMING_SNAKE, aws keys, sk and pk
    // prefixed keys and PEM blocks carry lowercase or no underscores, so
    // they keep firing below.
    if !content.is_empty()
        && content
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        && content.contains('_')
    {
        return false;
    }
    // Escaped control sequences and NUL marker strings are not credentials.
    // Real newlines inside multiline PEM bodies stay allowed.
    if content.contains("\\u") || content.contains('\0') {
        return false;
    }
    // Fixture and placeholder values. Truncated keys carry an ellipsis,
    // dummy keys start with a clearly fake marker token. Values that merely
    // contain such a token later, like sk_test keys, still fire.
    if content.contains("...") {
        return false;
    }
    let first = content
        .split(['-', '_', ' '])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(
        first.as_str(),
        "test"
            | "dummy"
            | "example"
            | "fake"
            | "your"
            | "sample"
            | "demo"
            | "mock"
            | "changeme"
            | "placeholder"
            | "xxxx"
            | "invalid"
    ) {
        return false;
    }
    // Prose and display labels are not credentials. Real keys never carry
    // a space, except PEM headers which keep their leading marker.
    if content.contains(' ') && !content.starts_with("-----") {
        return false;
    }
    // Quoted env references, chat template tokens and file names are
    // references, not credentials.
    if content.starts_with("{env") || content.contains("<|") || content.contains("[REDACTED]") {
        return false;
    }
    if content.ends_with(".json")
        || content.ends_with(".yaml")
        || content.ends_with(".yml")
        || content.ends_with(".toml")
        || content.ends_with(".txt")
        || content.ends_with(".csv")
        || content.ends_with(".pem")
        || content.ends_with(".crt")
        || content.ends_with(".key")
        || content.ends_with(".p12")
        || content.ends_with(".env")
    {
        return false;
    }
    // Endpoints and paths are not credentials. PEM bodies keep their
    // leading marker or trailing padding and still fire.
    if content.contains("://") {
        return false;
    }
    if content.contains('/') && !content.starts_with("-----") && !content.ends_with('=') {
        return false;
    }
    // A lowercase word without a single digit or capital is a name, not a
    // credential, unless it carries a known credential prefix.
    let lower = content.to_ascii_lowercase();
    let credential_prefix = [
        "sk-", "pk-", "glpat-", "ghp_", "gho_", "xoxb", "xapp-", "nv-", "hf_", "akia", "ya29",
        "-----",
    ];
    if !content
        .chars()
        .any(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
        && !credential_prefix.iter().any(|p| lower.starts_with(p))
    {
        return false;
    }
    // i18n keys and namespaced identifiers carry dots, credentials do not.
    // JWT and Google OAuth tokens keep their prefixes and still fire.
    if content.contains('.') && !content.starts_with("eyJ") && !content.starts_with("ya29") {
        return false;
    }
    // A quoted map key with a short value is a config entry, not a leak.
    // Strong credential shaped values fire regardless of the key position.
    if name_was_quoted && content.len() < 20 {
        return false;
    }
    let has_non_alpha = content.chars().any(|c| !c.is_ascii_alphabetic());
    content.len() >= 6
        && (has_non_alpha || content.len() >= 16)
        && !content.contains("${")
        && !content.contains("{{")
}

/// Scan one source file for practice issues.
pub fn scan_file(path: &Path, content: &str, lang: &str) -> Vec<PracticeReport> {
    let mut reports = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let has_definitions = lines.iter().any(|l| {
        let t = l.trim_start();
        t.starts_with("def ")
            || t.starts_with("class ")
            || t.starts_with("fn ")
            || t.starts_with("func ")
            || t.starts_with("function ")
    });
    let main_guard = python_main_guard(&lines);
    let is_html = lang == "html";
    let mut form_line: Option<u64> = None;
    // Third party assets carry their own markers, never ours to police.
    let vendor_asset = {
        let fname = path
            .file_name()
            .map(|f| f.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        fname.contains("vendor") || fname.contains(".min.")
    };

    for (i, line) in lines.iter().enumerate() {
        let line_no = i as u64 + 1;
        let lower = line.to_ascii_lowercase();
        if is_html && lower.contains("<form") && form_line.is_none() {
            form_line = Some(line_no);
        }
        // A javascript URL in a link or script attribute runs script when
        // the page user clicks or loads it, provable from the file alone.
        if is_html
            && lower.contains("javascript:")
            && (lower.contains("href=\"javascript:")
                || lower.contains("href='javascript:")
                || lower.contains("src=\"javascript:")
                || lower.contains("src='javascript:"))
        {
            let js_at = lower.find("javascript:").unwrap_or(0);
            let tag_before = lower[..js_at].rfind('<').is_some();
            if tag_before {
                reports.push(rep(
                    path,
                    line_no,
                    "critical",
                    "javascript URL in an html attribute executes script from the page, replace it with a safe destination.",
                ));
            }
        }
    }

    for (i, line) in lines.iter().enumerate() {
        let line_no = i as u64 + 1;
        let lower = line.to_ascii_lowercase();
        if (lower.contains("todo") || lower.contains("fixme") || lower.contains("hack"))
            && !vendor_asset
        {
            reports.push(rep(
                path,
                line_no,
                "info",
                "unfinished work marker left in the code.",
            ));
        }
        if (lang == "javascript" || lang == "typescript")
            && (line.contains("console.log") || line.contains("debugger"))
        {
            reports.push(rep(
                path,
                line_no,
                "warning",
                "debug output left in the code.",
            ));
        } else if (lang == "javascript" || lang == "typescript")
            && (line.contains("console.debug")
                || line.contains("console.info")
                || line.contains("console.warn")
                || line.contains("console.error"))
        {
            // warn and error are sometimes deliberate logging, they stay
            // visible as info so real logging is not treated as dirt.
            reports.push(rep(
                path,
                line_no,
                "info",
                "diagnostic console call left in the code.",
            ));
        } else if (lang == "javascript" || lang == "typescript") && line.contains("alert(") {
            reports.push(rep(
                path,
                line_no,
                "info",
                "alert dialog call left in the code, remove before shipping.",
            ));
        }
        if lang == "rust" && line.contains("dbg!") {
            reports.push(rep(
                path,
                line_no,
                "warning",
                "debug macro left in the code.",
            ));
        }
        if lang == "python" && line.contains("print(") && !line.trim_start().starts_with('#') {
            let inside_guard = main_guard
                .map(|(guard_line, guard_indent)| {
                    i > guard_line && leading_spaces(line) > guard_indent
                })
                .unwrap_or(false);
            // A print in a library module outside the main guard is a
            // leftover. Scripts and main guarded blocks are legitimate.
            if has_definitions && leading_spaces(line) == 0 && !inside_guard {
                reports.push(rep(path, line_no, "info", "print statement found at module level in a library module. remove before shipping."));
            }
        }
        if secret_assignment(line)
            && !is_comment_line(line)
            && !line.contains("process.env")
            && !line.contains("os.environ")
            && !lower.contains("getenv")
        {
            let severity = if is_test_path(path) && !strong_credential_shape(line) {
                // Mock credentials in test files are idiomatic. They stay
                // visible as warnings but only real key structure blocks.
                "warning"
            } else {
                "critical"
            };
            reports.push(rep(
                path,
                line_no,
                severity,
                "possible secret or credential hardcoded in source.",
            ));
        }
    }
    if is_html
        && let Some(form_at) = form_line
        && !content
            .to_ascii_lowercase()
            .contains("content-security-policy")
    {
        reports.push(rep(
            path,
            form_at,
            "info",
            "page renders a form without a content security policy meta tag, add one or confirm the server sends the header.",
        ));
    }
    reports
}

/// True when the line is a comment in any supported dialect. Example keys
/// and config sketches inside comments are prose, not code.
fn is_comment_line(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with('#')
        || t.starts_with("//")
        || t.starts_with("/*")
        || t.starts_with("* ")
        || t.starts_with('%')
        || t.starts_with("--")
        || t.starts_with("<!--")
}

/// True when the path marks test code: a test directory segment or a test
/// file name. Fixture and spec trees are where mock credentials live.
fn is_test_path(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    let lower = text.to_ascii_lowercase();
    if lower.contains("__tests__")
        || lower.contains(".test.")
        || lower.contains(".spec.")
        || lower.contains("_test.")
    {
        return true;
    }
    text.split('/').any(|seg| {
        let s = seg.to_ascii_lowercase();
        s == "test" || s == "tests" || s == "testing"
    })
}

/// True when the quoted value carries real credential structure: a long
/// value under a known key prefix, or a PEM body. Short ambiguous values
/// in test files are mocks and stay warnings.
fn strong_credential_shape(line: &str) -> bool {
    let Some(q) = line.find(['"', '\'']) else {
        return false;
    };
    let quote = line.as_bytes()[q];
    let Some(rest) = line[q + 1..].find(quote as char) else {
        return false;
    };
    let content = &line[q + 1..q + 1 + rest];
    content.len() >= 20
        && (content.starts_with("sk-")
            || content.starts_with("pk-")
            || content.starts_with("glpat-")
            || content.starts_with("ghp_")
            || content.starts_with("gho_")
            || content.starts_with("AKIA")
            || content.starts_with("ya29")
            || content.starts_with("eyJ")
            || content.starts_with("-----"))
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
                    message: format!(
                        "function {} spans {} lines. consider splitting it.",
                        f.name, body_lines
                    ),
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
        for (j, &l) in lines.iter().enumerate().skip(start + 1) {
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
    for line in lines.iter().skip(start) {
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

    #[test]
    fn placeholder_and_fixture_values_stay_silent() {
        // Env var name placeholders, fixture keys, truncated keys and NUL
        // marker strings are not credentials.
        let src = concat!(
            "const sudo_password = \"SUDO_PASSWORD\";\n",
            "const api_key = \"AUXILIARY_VISION_API_KEY\";\n",
            "const apiKey = \"test-key\";\n",
            "const serverToken = \"\\u0000server\\u0000\";\n",
            "const redacted = \"sk-proj-...e999\";\n",
            "const apiKeyDisplay = \"Microsoft Entra ID\";\n",
            "const tokenEvent = \"token_auth_success\";\n",
            "const tokenizer_file = \"tokenizer.json\";\n",
            "const chat_eos_token = \"<|im_end|>\";\n",
            "const providerUrl = \"https://bots.qq.com/app/getAppAccessToken\";\n",
            "\"tencent-tokenhub\": \"hy3-preview\",\n",
            "const apiKeyRequired = \"error.apiKeyRequired\";\n",
            "// api_key: \"sk-live-1234567890abcdef1234567890abcdef\"\n",
            "//     secret: \"-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEA5XyZ\"\n",
            "const token: string = \"[REDACTED]\";\n",
        );
        let p = std::path::Path::new("clean.js");
        let reports = scan_file(p, src, "javascript");
        assert!(
            !reports.iter().any(|r| r.message.contains("secret")),
            "placeholders must not fire, got {:?}",
            reports
        );
    }

    #[test]
    fn html_security_rules_fire_only_on_provable_pages() {
        let dirty = "<html>\n<body>\n  <a href=\"javascript:alert(1)\">x</a>\n  <form action=\"/pay\"></form>\n</body>\n</html>\n";
        let p = std::path::Path::new("probe.html");
        let r = scan_file(p, dirty, "html");
        assert!(
            r.iter()
                .any(|x| x.message.contains("javascript URL") && x.severity == "critical"),
            "javascript url must be critical"
        );
        assert!(
            r.iter()
                .any(|x| x.message.contains("content security policy") && x.severity == "info"),
            "form without csp meta must report"
        );
        // A page with a CSP meta and no javascript URL stays silent, and
        // css with url references never fires anything.
        let clean = "<html>\n<head>\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'\">\n</head>\n<body>\n  <form action=\"/ok\"></form>\n  <a href=\"/real\">ok</a>\n</body>\n</html>\n";
        let rc = scan_file(p, clean, "html");
        assert!(
            rc.is_empty(),
            "clean html reported: {:?}",
            rc.iter().map(|x| x.message.as_str()).collect::<Vec<_>>()
        );
        let css = "body { background: url(\"/img/x.png\"); }\n";
        let pc = std::path::Path::new("probe.css");
        let rcss = scan_file(pc, css, "css");
        assert!(rcss.is_empty(), "css reported: {:?}", rcss);
    }

    #[test]
    fn debug_console_calls_split_by_intent() {
        let src = "function go() {\n  console.log('a');\n  console.debug('b');\n  console.warn('c');\n  console.error('d');\n  debugger;\n  alert('e');\n}\n";
        let out = scan_file(Path::new("probe.js"), src, "javascript");
        assert_eq!(out.len(), 6);
        assert_eq!(out[0].severity, "warning");
        assert_eq!(out[0].line, 2);
        assert_eq!(out[1].severity, "info");
        assert_eq!(out[1].line, 3);
        assert_eq!(out[2].severity, "info");
        assert_eq!(out[2].line, 4);
        assert_eq!(out[3].severity, "info");
        assert_eq!(out[3].line, 5);
        assert_eq!(out[4].severity, "warning");
        assert_eq!(out[4].line, 6);
        assert_eq!(out[5].severity, "info");
        assert_eq!(out[5].line, 7);
    }

    #[test]
    fn label_field_defaults_are_not_credentials() {
        // Django form field label parameters, the default is the field
        // name itself, idiomatic clean code.
        assert!(!secret_assignment(
            "    password1_field_name=\"password1\","
        ));
        assert!(!secret_assignment(
            "    password2_field_name=\"password2\","
        ));
        assert!(!secret_assignment("def f(user_field=\"username\"):"));
        // A real weak password in a variable named password still fires.
        assert!(secret_assignment("password = \"Password123!\";"));
        assert!(secret_assignment("api_key = \"AKIAIOSFODNN7EXAMPLE\";"));
    }

    #[test]
    fn real_credential_shapes_still_fire() {
        let src = concat!(
            "const apiKey = \"sk-proj-9f3a7c2e11b4d50891aab3c4d5e6f7a8\";\n",
            "const aws_secret_key = \"AKIAIOSFODNN7EXAMPLE\";\n",
            "PRIVATE_KEY = \"-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEA5XyZ2bQ8Jk3f7pL9mVn0cRdU4Hs\"\n",
        );
        let p = std::path::Path::new("dirty.py");
        let reports = scan_file(p, src, "python");
        let secrets: Vec<_> = reports
            .iter()
            .filter(|r| r.message.contains("secret"))
            .collect();
        assert_eq!(secrets.len(), 3, "real keys must fire, got {:?}", reports);
    }

    #[test]
    fn weak_mock_in_test_path_is_warning_strong_stays_critical() {
        let p = std::path::Path::new("specs/login.test.ts");
        let weak = "const api_key = \"sk-12345abc\";\n";
        let reports = scan_file(p, weak, "typescript");
        let hits: Vec<_> = reports
            .iter()
            .filter(|r| r.message.contains("secret"))
            .collect();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, "warning", "mock in test must downgrade");
        let strong = "const api_key = \"sk-proj-9f3a7c2e11b4d50891aab3c4d5e6f7a8\";\n";
        let reports = scan_file(p, strong, "typescript");
        let hits: Vec<_> = reports
            .iter()
            .filter(|r| r.message.contains("secret"))
            .collect();
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].severity, "critical",
            "real key in test stays critical"
        );
    }
}
