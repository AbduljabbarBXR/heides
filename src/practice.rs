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

/// Credentials whose *value* is self identifying, independent of the name.
///
/// The name-keyword rule above is right for `DB_PASSWORD = "..."` and wrong
/// for everything below. `AWS_ACCESS_KEY_ID`, `SLACK_TOKEN`, `HOOK_URL` and
/// `KEY` all bind a real credential to a name that contains no keyword, so
/// the keyword match never fires and the secret is missed. grims scanner
/// catches four of these on the same fixtures; this table is the equivalent.
///
/// Each entry is (substring, reason). Matched case insensitively against the
/// literal value only, never the whole line, so a mention in a comment or a
/// docstring cannot trigger it. The shapes are deliberately vendor prefixes
/// and PEM headers, which do not appear in prose by accident.
/// How much material must follow a vendor prefix before the value counts as a
/// credential rather than a mention of one.
///
/// Taken from the token shapes rather than guessed: a GitHub personal access
/// token carries 36 characters after `ghp_`, and a Slack token a second
/// hyphenated segment. A word in a sentence never carries 16 more token
/// characters after a prefix, which is what keeps prose quiet.
const MIN_TOKEN_TAIL: usize = 16;

const VALUE_SHAPED_CREDENTIALS: [(&str, &str); 13] = [
    ("AKIA", "AWS access key id"),
    ("ASIA", "AWS temporary access key id"),
    ("ghp_", "GitHub personal access token"),
    ("gho_", "GitHub OAuth token"),
    ("github_pat_", "GitHub fine grained token"),
    ("xoxb-", "Slack bot token"),
    ("xoxp-", "Slack user token"),
    ("xoxa-", "Slack app token"),
    ("xoxr-", "Slack refresh token"),
    ("sk-proj-", "OpenAI project key"),
    ("sk-ant-", "Anthropic API key"),
    ("-----BEGIN", "private key block"),
    // A Slack incoming webhook carries three secret path segments after the
    // host. Matched on the host alone it would fire on any mention of
    // hooks.slack.com in documentation, so the segments are what count.
    ("hooks.slack.com/services/", "Slack webhook URL"),
];

/// True when a quoted literal on this line carries a self identifying
/// credential shape, whatever the variable is called.
///
/// Runs before the keyword rule so that a correctly named secret is still
/// reported once, with the more specific reason.
///
/// Only the *value* is inspected, never the whole line. Two false positives
/// forced that: prose reading "rotate your ghp_ token" fired because the shape
/// appeared anywhere after the `=`, and so did a variable literally named
/// `comment`. Prose about a credential is not a credential.
fn value_shaped_credential(line: &str) -> Option<&'static str> {
    // Only the region after a real assignment, so function bodies and
    // comparisons cannot fire it.
    let at = line.find(['=', ':'])?;
    let rest = line[at + 1..].trim();
    // The credential must be a quoted literal. An unquoted remainder means this
    // is an env read, a concatenation or prose rather than a hardcoded value.
    let quote = match rest.chars().next() {
        Some(c @ ('"' | '\'')) => c,
        _ => return None,
    };
    let trimmed = rest[1..].trim_end();
    let end = trimmed.rfind(quote)?;
    let inner = &trimmed[..end];
    // An interpolated value is assembled at runtime, so the source does not
    // contain the credential.
    if inner.contains("${") {
        return None;
    }
    // A shape embedded in a longer identifier is a mention, not a token.
    for (needle, reason) in VALUE_SHAPED_CREDENTIALS {
        if !inner.contains(needle) {
            continue;
        }
        if needle == "-----BEGIN" {
            // A PEM header is unambiguous, so the block form is enough.
            return Some(reason);
        }
        // The candidate is the unbroken run of token characters around the
        // shape. Prose like "rotate your ghp_ token" yields the word `ghp_`,
        // which is too short to be a key. A real token is long and unbroken,
        // so the shape must carry enough material after it.
        let ok = if needle.ends_with('/') {
            // URL shaped needles carry their own discriminating suffix, so a
            // bare mention of the host in prose is not enough.
            inner.contains(needle)
        } else {
            inner
                .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
                .any(|w| {
                    let Some(pos) = w.find(needle) else {
                        return false;
                    };
                    w[pos + needle.len()..].len() >= MIN_TOKEN_TAIL
                })
        };
        if ok {
            return Some(reason);
        }
    }
    // PEM blocks are written across lines, so the header alone is enough.
    None
}

/// Weak cryptography and insecure randomness. Every entry is
/// (substring, message, severity).
///
/// These are pattern rules rather than taint sinks on purpose: `pickle.loads`
/// of a network payload is exploitable whatever the source is, and tying it to
/// a taint flow would mean it stays silent on exactly the archives and caches
/// an attacker controls. Weak hash and non crypto randomness are defects on
/// their own, so they fire unconditionally.
///
/// The safe twins are named explicitly in the comment below, because the
/// corpus gate failed all of these the first time they were written as broad
/// prefixes.
/// `shell=True` and `verify=False`, which are defects on their own.
///
/// These do not need a taint flow to be wrong. `subprocess.run(cmd, shell=True)`
/// hands the string to a shell, so any later interpolation anywhere in the
/// command becomes injection, and the guard cannot see the caller. Treating
/// them as unconditional pattern rules is the only way they get caught at all,
/// and it is why `verify` exists to confirm the whole pipeline agrees.
///
/// Deliberately not a taint sink: the parameter is not a source, per the
/// precision argument in SOURCES, so a sink row would never fire.
const SHELL_UNSAFE: [(&str, &str, &str); 6] = [
    (
        "shell=True",
        "shell=True passes the command through a shell; use an argument list",
        "critical",
    ),
    (
        "shell = True",
        "shell=True passes the command through a shell; use an argument list",
        "critical",
    ),
    (
        "verify=False",
        "verify=False disables TLS certificate verification",
        "critical",
    ),
    (
        "verify = False",
        "verify=False disables TLS certificate verification",
        "critical",
    ),
    (
        "rejectUnauthorized: false",
        "TLS verification disabled",
        "critical",
    ),
    (
        "rejectUnauthorized:false",
        "TLS verification disabled",
        "critical",
    ),
];

const WEAK_CRYPTO: [(&str, &str, &str); 8] = [
    (
        "pickle.loads",
        "pickle deserialization executes arbitrary code",
        "critical",
    ),
    (
        "pickle.load",
        "pickle deserialization executes arbitrary code",
        "critical",
    ),
    (
        "cPickle.loads",
        "pickle deserialization executes arbitrary code",
        "critical",
    ),
    (
        "marshal.loads",
        "marshal deserialization is unsafe on untrusted data",
        "warning",
    ),
    (
        "yaml.load(",
        "yaml.load without SafeLoader executes arbitrary code",
        "critical",
    ),
    (
        "yaml.unsafe_load",
        "unsafe yaml load executes arbitrary code",
        "critical",
    ),
    (
        "hashlib.md5",
        "md5 is broken for security use, use sha256",
        "warning",
    ),
    (
        "hashlib.sha1",
        "sha1 is broken for security use, use sha256",
        "warning",
    ),
];

/// Insecure randomness. `random` is not a CSPRNG; `secrets` is.
///
/// `random.SystemRandom` is the correct member of the same module and must
/// stay silent, hence the guard on the caller below.
const WEAK_RANDOM: [(&str, &str, &str); 3] = [
    (
        "random.random(",
        "random is not a CSPRNG, use the secrets module",
        "warning",
    ),
    (
        "random.randint(",
        "random is not a CSPRNG, use the secrets module",
        "warning",
    ),
    (
        "random.choice(",
        "random is not a CSPRNG, use the secrets module",
        "warning",
    ),
];

/// Rust `unsafe` and null pointer construction.
///
/// `unsafe` is not a defect, it is a promise the compiler cannot check, so
/// this is a warning and never a blocker. Firing on every unsafe block would
/// make the tool unusable on real rust, which is why it is a review hint and
/// not a judgment.
fn rust_unsafe(line: &str) -> Option<&'static str> {
    if !line.contains("unsafe ") {
        return None;
    }
    if line.contains("unsafe impl") || line.contains("unsafe trait") {
        return None;
    }
    if line.trim_start().starts_with("//") {
        return None;
    }
    Some("unsafe block needs a written safety argument")
}

/// Null pointer construction, which is undefined behaviour at the point of
/// use rather than at the point of creation.
fn null_pointer(line: &str) -> Option<&'static str> {
    let needles = ["null_mut()", "NULL", "0 as *mut", "std::ptr::null("];
    for n in needles {
        if line.contains(n) && (line.contains('*') || line.contains("ptr")) {
            return Some("null pointer construction is undefined behaviour when dereferenced");
        }
    }
    None
}

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
    // The guard compares the leading placeholder token, so `changeme123` and
    // `dummy_2024` stay silent the way `changeme` does. Only the token before
    // the first separator is checked, not the whole value.
    let first = content
        .split(['-', '_', ' '])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    // A trailing digit suffix is common on placeholder values, and
    // `changeme123` was a real false positive before this check existed.
    let first = first
        .trim_end_matches(|c: char| c.is_ascii_digit())
        .to_string();
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
        // shell=True and verify=False. Language gated to python because that
        // is where the idiomatic spellings live; the javascript and go forms
        // are covered by their own taint sink rows.
        // A docstring is not code. `is_comment_line` catches `#` and `//` but
        // not a `"""` opener, and a module docstring that says "never write
        // shell=True" is documentation, not a defect.
        let trimmed = line.trim_start();
        let in_docstring = trimmed.starts_with("\"\"\"")
            || trimmed.starts_with("'''")
            || trimmed.starts_with("*\"\"\"");
        if lang == "python" && !is_comment_line(line) && !in_docstring {
            for (needle, msg, sev) in SHELL_UNSAFE {
                if line.contains(needle) {
                    reports.push(rep(path, line_no, sev, msg));
                    break;
                }
            }
        }
        // Weak crypto and insecure randomness. Language gated so a string
        // containing "pickle.loads" in a go or rust file cannot fire them.
        if lang == "python" {
            // `yaml.load(x, Loader=yaml.SafeLoader)` is the documented safe
            // form, so it must stay silent. Naming any loader that is not one of
            // the safe ones counts as unsafe.
            let safe_loader = line.contains("SafeLoader") || line.contains("CSafeLoader");
            for (needle, msg, sev) in WEAK_CRYPTO {
                if needle.starts_with("yaml.load(") && safe_loader {
                    continue;
                }
                if line.contains(needle) {
                    reports.push(rep(path, line_no, sev, msg));
                    break;
                }
            }
            if !line.contains("SystemRandom") {
                for (needle, msg, sev) in WEAK_RANDOM {
                    if line.contains(needle) {
                        reports.push(rep(path, line_no, sev, msg));
                        break;
                    }
                }
            }
        }
        if lang == "rust" {
            if let Some(msg) = rust_unsafe(line) {
                reports.push(rep(path, line_no, "warning", msg));
            }
            if let Some(msg) = null_pointer(line) {
                reports.push(rep(path, line_no, "warning", msg));
            }
        }
        // Value shaped credentials fire first so a correctly named secret is
        // reported once with the specific reason rather than the generic one.
        let value_shaped = value_shaped_credential(line);
        if let Some(reason) = value_shaped {
            // The same env read guards the keyword rule applies below. Without
            // them `AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]` fired,
            // because the key name appears inside the bracket expression. That
            // is the opposite of a hardcoded credential: it is the correct way
            // to read one.
            if !is_comment_line(line)
                && !line.contains("process.env")
                && !line.contains("os.environ")
                && !line.contains("os.getenv")
                && !lower.contains("getenv")
                && !line.contains("Config")
                && !line.contains("settings")
            {
                reports.push(rep(
                    path,
                    line_no,
                    "critical",
                    &format!("{} hardcoded in source.", reason),
                ));
            }
        } else if secret_assignment(line)
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
        let Ok(content) = std::fs::read_to_string(graph.file_path_of(file)) else {
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
        // Matched on "hardcoded in source", not on the word "secret". The
        // value shaped rules report the specific credential, so an OpenAI key
        // says "OpenAI project key hardcoded in source" and never contains
        // the generic word. Asserting the generic wording would have forced
        // these rules to be vaguer than they need to be.
        let secrets: Vec<_> = reports
            .iter()
            .filter(|r| r.message.contains("hardcoded in source"))
            .collect();
        assert_eq!(secrets.len(), 3, "real keys must fire, got {:?}", reports);
        for want in [
            "OpenAI project key",
            "AWS access key id",
            "private key block",
        ] {
            assert!(
                secrets.iter().any(|r| r.message.contains(want)),
                "each fixture must be named specifically, missing {:?}: {:?}",
                want,
                secrets
            );
        }
    }

    #[test]
    fn weak_mock_in_test_path_is_warning_strong_stays_critical() {
        let p = std::path::Path::new("specs/login.test.ts");
        // A bare "sk-12345abc" is a mock, not a real key, so it must NOT take
        // the value shaped path. The table lists "sk-proj-" and "sk-ant-", so
        // the mock falls through to the name keyword rule, which is what
        // downgrades it in a test path.
        let weak = "const api_key = \"sk-12345abc\";\n";
        let reports = scan_file(p, weak, "typescript");
        let hits: Vec<_> = reports
            .iter()
            .filter(|r| r.message.contains("hardcoded in source"))
            .collect();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, "warning", "mock in test must downgrade");
        let strong = "const api_key = \"sk-proj-9f3a7c2e11b4d50891aab3c4d5e6f7a8\";\n";
        let reports = scan_file(p, strong, "typescript");
        let hits: Vec<_> = reports
            .iter()
            .filter(|r| r.message.contains("hardcoded in source"))
            .collect();
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].severity, "critical",
            "real key in test stays critical"
        );
    }
    /// Every rule added in 0.20.0 fires on a planted fault. Without these the
    /// tables are documentation, not behaviour.
    #[test]
    fn value_shaped_credentials_fire_on_real_keys() {
        let src = "AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"\nSLACK = \"xoxb-1234567890-abcdefghij\"\nKEY = \"ghp_abcdefghijklmnopqrstuvwxyz0123456789\"\nOPENAI = \"sk-proj-9f3a7c2e11b4d50891aab3c4d5e6f7a8\"\nHOOK = \"https://hooks.slack.com/services/T0/B0/XXXX\"\n";
        let reports = scan_file(std::path::Path::new("a.py"), src, "python");
        for want in [
            "AWS access key id",
            "Slack bot token",
            "GitHub personal access token",
            "OpenAI project key",
            "Slack webhook URL",
        ] {
            assert!(
                reports.iter().any(|r| r.message.contains(want)),
                "a real {} must be reported: {:?}",
                want,
                reports
            );
        }
    }

    /// The false positives that were measured, not imagined. Each of these was
    /// a real finding before the value only fix, and the whole point of this
    /// table is that it does not buy detection with noise.
    #[test]
    fn value_shaped_credentials_stay_silent_on_prose_and_env_reads() {
        let src = "AWS_ACCESS_KEY_ID = os.environ[\"AWS_ACCESS_KEY_ID\"]\nSLACK_TOKEN = os.getenv(\"SLACK_TOKEN\")\nHOOK_URL = config[\"hook\"]\ncomment = \"rotate your ghp_ token\"\ndocs = \"see AKIA prefix docs\"\n";
        let reports = scan_file(std::path::Path::new("a.py"), src, "python");
        let hits: Vec<&str> = reports
            .iter()
            .map(|r| r.message.as_str())
            .filter(|m| m.contains("hardcoded in source"))
            .collect();
        assert!(
            hits.is_empty(),
            "an env read or prose about a credential is not a credential: {:?}",
            hits
        );
    }

    #[test]
    fn a_shape_inside_a_longer_word_is_a_mention_not_a_token() {
        // The value contains the prefix but as part of an identifier, which is
        // documentation rather than a key.
        let src = "url = \"https://example.com/AKIAPREFIX-guide\"\n";
        let reports = scan_file(std::path::Path::new("a.py"), src, "python");
        assert!(
            !reports
                .iter()
                .any(|r| r.message.contains("AWS access key id")),
            "an embedded prefix is not a key: {:?}",
            reports
        );
    }

    #[test]
    fn weak_crypto_and_randomness_fire() {
        let src = "obj = pickle.loads(raw)\nm = marshal.loads(raw)\ncfg = yaml.load(text)\nh = hashlib.md5(b\"x\")\ns = hashlib.sha1(b\"x\")\nn = random.random()\ni = random.randint(0, 9)\npick = random.choice(items)\n";
        let reports = scan_file(std::path::Path::new("a.py"), src, "python");
        for want in [
            "pickle deserialization",
            "marshal deserialization",
            "without SafeLoader",
            "md5 is broken",
            "sha1 is broken",
            "not a CSPRNG",
        ] {
            assert!(
                reports.iter().any(|r| r.message.contains(want)),
                "{} must be reported: {:?}",
                want,
                reports
            );
        }
        // One row per line, not a cascade: random.choice must not also report
        // random.random's message.
        let random_hits = reports
            .iter()
            .filter(|r| r.message.contains("CSPRNG"))
            .count();
        assert_eq!(random_hits, 3, "one per random call: {:?}", reports);
    }

    /// The safe twins. These are the lines that make the rules above usable,
    /// so they are asserted rather than assumed.
    #[test]
    fn the_safe_twins_stay_silent() {
        let src = "h = hashlib.sha256(b\"x\").hexdigest()\nr = random.SystemRandom().random()\ns = secrets.token_hex(16)\ny = yaml.safe_load(text)\nc = yaml.load(text, Loader=yaml.SafeLoader)\nd = yaml.load(text, Loader=yaml.CSafeLoader)\n";
        let reports = scan_file(std::path::Path::new("a.py"), src, "python");
        let hits: Vec<&str> = reports
            .iter()
            .map(|r| r.message.as_str())
            .filter(|m| {
                m.contains("md5")
                    || m.contains("sha1")
                    || m.contains("CSPRNG")
                    || m.contains("SafeLoader")
                    || m.contains("yaml")
            })
            .collect();
        assert!(hits.is_empty(), "the safe forms must not fire: {:?}", hits);
    }

    #[test]
    fn rust_unsafe_and_null_pointer_fire() {
        let src = "fn f() {\n    unsafe {\n        std::ptr::copy_nonoverlapping(a.as_ptr(), std::ptr::null_mut(), 4);\n    }\n}\n";
        let reports = scan_file(std::path::Path::new("a.rs"), src, "rust");
        assert!(
            reports.iter().any(|r| r.message.contains("unsafe block")),
            "an unsafe block needs a safety argument: {:?}",
            reports
        );
        assert!(
            reports.iter().any(|r| r.message.contains("null pointer")),
            "null pointer construction must be reported: {:?}",
            reports
        );
    }

    #[test]
    fn unsafe_impl_and_comments_stay_silent() {
        // `unsafe impl` is a marker trait signature, not an unsafe block, and a
        // comment mentioning unsafe is documentation.
        let src = "// this needs unsafe to be fast\nunsafe impl Send for Foo {}\nunsafe trait Marker {}\n";
        let reports = scan_file(std::path::Path::new("a.rs"), src, "rust");
        let hits: Vec<&str> = reports
            .iter()
            .map(|r| r.message.as_str())
            .filter(|m| m.contains("unsafe block"))
            .collect();
        assert!(
            hits.is_empty(),
            "marker signatures and prose stay quiet: {:?}",
            hits
        );
    }

    /// The weak crypto rows are python gated, so a rust file holding the same
    /// string must not fire them. Without this gate a doc comment mentioning
    /// `pickle.loads` would be a finding in every language.
    #[test]
    fn weak_crypto_rows_do_not_leak_into_other_languages() {
        let src = "// never use pickle.loads here\nconst x = \"hashlib.md5\";\n";
        let reports = scan_file(std::path::Path::new("a.ts"), src, "typescript");
        let hits: Vec<&str> = reports
            .iter()
            .map(|r| r.message.as_str())
            .filter(|m| m.contains("pickle") || m.contains("md5"))
            .collect();
        assert!(
            hits.is_empty(),
            "python only rules must not fire in ts: {:?}",
            hits
        );
    }
}
