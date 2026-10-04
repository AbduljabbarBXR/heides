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
pub(crate) const SOURCES: [(&str, &str); 32] = [
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
    // A python function parameter is deliberately NOT a source here, and the
    // corpus gate is why. `read_config(path)` calling `open(path)` and
    // `render_message(user, message)` calling `escape` then `mark_safe` are
    // both idiomatic, correct, and flagged by a blanket parameter rule. It also
    // fails the other way: a parameter is only untrusted if some caller passes
    // user input, and this scanner does not know the callers yet, so the rule
    // is simultaneously too noisy on internal helpers and too blind on real
    // entry points.
    //
    // Doing it properly needs interprocedural argument tracking: taint a
    // parameter only where a caller supplies a tainted argument, which is what
    // `crate::interproc` already does for python function symbols. Until that
    // exists the honest answer is a documented gap, not a false positive on
    // every well written helper.
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
    // Ruby had no source row at all, so no Ruby file could ever taint, not even
    // the SSRF and NoSQL sinks. params[] is Rack, Sinatra and Rails, and
    // request.GET/POST/body covers the plain framework shapes.
    //
    // Two rows, not one. This rule dialect expands alternation only inside a
    // group, so a top level `|` outside one is kept as a literal character and
    // the pattern silently stops matching anything.
    ("ruby", r"\bparams\s*["),
    ("ruby", r"\brequest\s*\.\s*(GET|POST|params|body|cookies)\b"),
    // C and C++. `getenv` is the canonical untrusted input in C: it is the
    // environment, which on a web service is attacker controlled often enough
    // that treating it as a source is the safe default. `scanf` reads from a
    // stream rather than the environment but is the same class of taint.
    //
    // `argv` is included: command line arguments reach a fixed size buffer in
    // real programs often enough that the copy is the thing worth seeing.
    ("c", r"\bgetenv\s*\("),
    ("c", r"\bsecure_getenv\s*\("),
    ("c", r"\bgetenv_s\s*\("),
    ("c", r"\bread\s*\(\s*0\s*\)"),
    ("c", r"\bfgets\s*\("),
    ("c", r"\bgetline\s*\("),
    ("c", r"\bargv\b"),
    ("c", r"\benviron\b"),
    ("c", r"\bread\s*\(\s*STDIN_FILENO"),
    ("c", r"\brecv\s*\("),
    ("cpp", r"\bgetenv\s*\("),
    ("cpp", r"\bsecure_getenv\s*\("),
    ("cpp", r"\bcin\s*>>"),
    ("cpp", r"\bstd::cin\b"),
    ("cpp", r"\bgetline\s*\("),
    ("cpp", r"\bargv\b"),
];

/// Sinks are per language. Where a name is ambiguous between SQL and something
/// harmless, it only counts when it is called on a database-ish receiver, so
/// `run(` in a task runner stays silent while `db.run(` is SQL.
/// Whether a line can only be a constant, so no source can flow through it.
///
/// The narrow form matters more than the broad one. This returns true only when
/// the line contains a quoted literal and nothing that could read input, which
/// means `strcpy(b, "hi")` is recognised as constant while
/// `strcpy(b, getenv("X"))` is not, because `getenv` is not a literal. A looser
/// "does it mention a string" rule would silence the very findings this tool
/// exists to raise.
fn is_only_literal_or_sanitizer(line: &str) -> bool {
    let t = line.trim();
    if t.is_empty() {
        return false;
    }
    // Every argument that a sink actually reads has to be a constant. This is a
    // decision about argument positions rather than about identifiers, which is
    // what replaces a list of known type and keyword names: such a list is a trap,
    // because a type it does not contain makes a constant line stop looking like
    // one and the rule decays without anything failing.
    //
    // `wchar_t b[16]; strcpy(b, L"hi");` is constant whatever the type is called,
    // and `mystery_reader()` is not constant whatever the sink is called.
    if !t.contains('(') {
        // No call at all: an assignment whose right hand side is entirely literal.
        return rhs_is_constant(t);
    }
    // A call on the line can only be neutral if it is a sanitizer. A sink call is
    // of course not one, so the arguments of every other call must be constant and
    // the callee itself must not read anything.
    let mut saw_sanitizer = false;
    for (_, pat) in SANITIZERS {
        if regex_hit(pat, line) {
            saw_sanitizer = true;
            break;
        }
    }
    if saw_sanitizer {
        return true;
    }
    // Every call on the line must have constant arguments, and no call may be an
    // unknown one. Identifiers sitting outside call parentheses, such as a buffer
    // name or a type, are deliberately not consulted: they cannot read input.
    for (name, args) in calls_in(line) {
        if !is_known_sink(&name) {
            // An unknown callee can produce anything, so the line is not constant
            // unless it reads nothing at all, which a call by definition might.
            return false;
        }
        if !args_are_constant(&args) {
            return false;
        }
    }
    rhs_is_constant(t)
}

/// The part of a statement outside string literals, used only to spot the
/// identifiers that appear as callees.
fn calls_in(line: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes: Vec<char> = line.chars().collect();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == '"' || bytes[i] == '\'' {
            let quote = bytes[i];
            i += 1;
            let mut escaped = false;
            while i < bytes.len() {
                if escaped {
                    escaped = false;
                } else if bytes[i] == '\\' {
                    escaped = true;
                } else if bytes[i] == quote {
                    break;
                }
                i += 1;
            }
            i += 1;
            continue;
        }
        if bytes[i].is_alphanumeric() || bytes[i] == '_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_alphanumeric() || bytes[i] == '_') {
                i += 1;
            }
            let name: String = bytes[start..i].iter().collect();
            // Skip whitespace to see whether this is a callee.
            let mut j = i;
            while j < bytes.len() && bytes[j].is_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == '(' {
                // Find the matching close.
                let mut depth = 0i32;
                let mut k = j;
                while k < bytes.len() {
                    if bytes[k] == '(' {
                        depth += 1;
                    } else if bytes[k] == ')' {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    k += 1;
                }
                let args: String = bytes[(j + 1).min(bytes.len())..k.min(bytes.len())]
                    .iter()
                    .collect();
                out.push((name, args));
                i = k + 1;
                continue;
            }
            continue;
        }
        i += 1;
    }
    out
}

/// Whether every argument is a literal. An argument that is a bare identifier is
/// a value read from elsewhere, which is exactly what a sink consumes, so it is
/// not constant. Numbers and literals are.
fn args_are_constant(args: &str) -> bool {
    let t = args.trim();
    if t.is_empty() {
        return true;
    }
    for arg in split_top_level(t) {
        let a = arg.trim();
        if a.is_empty() {
            continue;
        }
        if is_literal_expression(a) {
            continue;
        }
        return false;
    }
    true
}

/// Split on commas that are not inside brackets or string literals.
fn split_top_level(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' || c == '\'' {
            let quote = c;
            cur.push(c);
            i += 1;
            while i < chars.len() {
                cur.push(chars[i]);
                if chars[i] == '\\' && i + 1 < chars.len() {
                    i += 1;
                    cur.push(chars[i]);
                } else if chars[i] == quote {
                    break;
                }
                i += 1;
            }
            i += 1;
            continue;
        }
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            _ => {}
        }
        if c == ',' && depth == 0 {
            out.push(std::mem::take(&mut cur));
            i += 1;
            continue;
        }
        cur.push(c);
        i += 1;
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// A literal expression: a quoted string, a number, or a cast of one, with no
/// interpolation and no concatenation with a name.
fn is_literal_expression(a: &str) -> bool {
    let t = a.trim();
    if t.is_empty() {
        return true;
    }
    // Strip a leading cast such as `(char *)` or `L`.
    let mut body = t;
    if let Some(rest) = body.strip_prefix('L') {
        body = rest;
    }
    while body.starts_with('(') {
        match body.find(')') {
            Some(p) => body = body[p + 1..].trim(),
            None => return false,
        }
    }
    let body = body.trim();
    if body.is_empty() {
        return true;
    }
    // Numeric.
    if body
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '+' || c == 'x')
        && body.chars().any(|c| c.is_ascii_digit())
    {
        return true;
    }
    // Quoted with no interpolation.
    let q = body.chars().next().unwrap_or(' ');
    if q == '"' || q == '\'' {
        return !body.contains("${") && !body.contains("#{") && !body.contains("%s");
    }
    false
}

fn is_known_sink(name: &str) -> bool {
    // The bare function name, without a receiver. A sink is called for its effect
    // on the buffer, not for what it returns, so a constant argument list means
    // the line cannot be carrying input into it.
    let base = name.rsplit('.').next().unwrap_or(name);
    matches!(
        base,
        "strcpy"
            | "strcat"
            | "memcpy"
            | "memmove"
            | "sprintf"
            | "snprintf"
            | "strncpy"
            | "strncat"
            | "printf"
            | "fprintf"
            | "puts"
            | "memset"
            | "strlen"
            | "sizeof"
            | "system"
            | "exec"
            | "popen"
    )
}

/// Whether the right hand side of a statement is entirely literal.
fn rhs_is_constant(t: &str) -> bool {
    let Some(eq) = t.find('=') else {
        // No assignment. A bare statement is constant when it is entirely literal.
        return is_literal_expression(t);
    };
    let rhs = t[eq + 1..].trim();
    if rhs.is_empty() {
        return true;
    }
    // Concatenation is constant only when every piece of it is. `'tell me ' +
    // user` is not a constant, and treating the whole right hand side as one
    // literal expression is what made it look like one.
    if rhs.contains('+') {
        return split_top_level_plus(rhs)
            .iter()
            .all(|part| is_literal_expression(part.trim()));
    }
    is_literal_expression(rhs)
}

/// Split a concatenation on `+` at bracket depth zero and outside literals.
fn split_top_level_plus(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = s.chars().collect();
    let mut depth = 0i32;
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' || c == '\'' {
            let quote = c;
            cur.push(c);
            i += 1;
            while i < chars.len() {
                cur.push(chars[i]);
                if chars[i] == '\\' && i + 1 < chars.len() {
                    i += 1;
                    cur.push(chars[i]);
                } else if chars[i] == quote {
                    break;
                }
                i += 1;
            }
            i += 1;
            continue;
        }
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            _ => {}
        }
        if c == '+' && depth == 0 {
            out.push(std::mem::take(&mut cur));
            i += 1;
            continue;
        }
        cur.push(c);
        i += 1;
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// Sanitizers: a value that passes through one of these stops being a finding.
///
/// The rule tables had sources and sinks and nothing in between, so every rule had
/// to be written timid to stay precise. `strncpy` was kept out of a group with
/// `strcpy` because it is often the safe choice, which is the wrong reason to be
/// quiet about a dangerous function: the right reason is that the value was
/// escaped, and that is a property of the data, not of the callee.
///
/// This is the same three table shape semgrep uses in taint mode, and it buys back
/// the precision that costs nothing. Rows are (language, pattern).
pub(crate) const SANITIZERS: &[(&str, &str)] = &[
    // Shell. The value is quoted for the shell, so interpolating it cannot change
    // the command's structure.
    ("ruby", r"\bShellwords\s*\.\s*escape\s*\("),
    ("ruby", r"\bShellwords\s*\.\s*shellescape\s*\("),
    ("ruby", r"\bquote\s*\("),
    ("python", r"\bshlex\s*\.\s*quote\s*\("),
    ("python", r"\bpipes\s*\.\s*quote\s*\("),
    (
        "javascript",
        r"\bescapeShell|\bshellQuote\b|\bexecFileSync\s*\(",
    ),
    ("java", r"\bProcessBuilder\b"),
    // C and C++. `snprintf` bounds the write and NUL terminates; `strlcpy` and
    // `strlcat` bound the copy. These are what makes a broad copy rule safe.
    ("c", r"\bsnprintf\s*\("),
    ("c", r"\bstrlcpy\s*\("),
    ("c", r"\bstrlcat\s*\("),
    ("cpp", r"\bsnprintf\s*\("),
    ("cpp", r"\bstrlcpy\s*\("),
    ("cpp", r"\bstrlcat\s*\("),
    ("cpp", r"\bstd\s*\.\s*snprintf\s*\("),
    // SQL. A parameterised query binds the value instead of interpolating it, so
    // the statement structure cannot change.
    ("python", r"\bexecute\s*\([^)]*,\s*\s*,\s*\s*\)"),
    ("ruby", r"\bsanitize_sql\s*\("),
    ("java", r"\bsetString\s*\("),
    // JavaScript. A `$1` style placeholder cannot have its statement structure
    // changed by the value, so the sink is neutralised. A template literal with
    // `${}` is NOT here: that is interpolation, which is the vulnerable form, and
    // an earlier version of this table had it exactly backwards.
    // A template literal with no `${}` inside it is a constant query string. A
    // parameterised call binds its values, so interpolating into a plain string
    // is the only form that can change the statement.
    ("csharp", r"\bSqlParameter\b"),
    ("go", r"\bPlaceholder|\bQueryContext\b"),
    // Path traversal. Normalising and then taking the base name removes any `..`
    // the caller supplied.
    ("python", r"\bos\.path\s*\.\s*basename\s*\("),
    ("python", r"\bPath\s*\([^)]*\)\s*\.\s*name\b"),
    ("ruby", r"\bFile\s*\.\s*basename\s*\("),
    ("javascript", r"\bpath\s*\.\s*(basename|normalize)\s*\("),
    ("c", r"\brealpath\s*\("),
    ("cpp", r"\bstd\s*\.\s*filesystem\s*\.\s*canonical\s*\("),
    // HTML and template output.
    ("javascript", r"\$1"),
    ("javascript", r"\$2"),
    ("javascript", r"\$3"),
    ("javascript", r"\bDOMPurify\s*\.\s*sanitize\s*\("),
    ("javascript", r"\bescapeHtml\s*\("),
    ("python", r"\bbleach\s*\.\s*clean\s*\("),
    ("python", r"\bmarkupsafe\s*\.\s*escape\s*\("),
    ("ruby", r"\bERB\s*\.\s*Util\s*\.\s*html_escape\s*\("),
    ("ruby", r"\bCGI\s*\.\s*escapeHTML\s*\("),
    // The generic "a name that reads as escaped or validated" heuristic that was
    // here is removed on purpose. It silenced findings on the strength of a
    // variable name, which is a guess, and a guess that suppresses a security
    // finding is the wrong trade. A project that wraps an escape in its own
    // `safe_shell()` now gets a false positive, which is the honest direction:
    // it is visible, and the wrapper can be added as a named row.
];

pub(crate) const SINKS: &[(&str, &str, &str)] = &[
    // C and C++. Memory corruption is the dominant class in these languages and
    // it was entirely absent before: heides indexed no C at all, so a `strcpy`
    // into a fixed buffer was invisible to every layer.
    //
    // The unbounded copies are named individually rather than as a group because
    // `strcpy` with an attacker controlled source is a stack smash and `strncpy`
    // is frequently the safe choice. A single `(strcpy|strcat|sprintf)` row would
    // put a critical on code that is fine.
    ("c", r"\bstrcpy\s*\(", "unbounded copy"),
    ("c", r"\bstrcat\s*\(", "unbounded copy"),
    ("c", r"\bsprintf\s*\(", "unbounded format"),
    ("c", r"\bgets\s*\(", "unbounded read"),
    ("c", r"\bscanf\s*\(", "unbounded read"),
    ("c", r"\bfscanf\s*\(", "unbounded read"),
    ("c", r"\bmemcpy\s*\(", "memory copy"),
    ("c", r"\bmemmove\s*\(", "memory copy"),
    ("c", r"\bprintf\s*\(", "format"),
    ("c", r"\bfprintf\s*\(", "format"),
    // The command and query families, so a C project is not silently unanalysed
    // just because its hazards are spelled differently.
    ("c", r"\bsystem\s*\(", "shell"),
    ("c", r"\bpopen\s*\(", "shell"),
    ("c", r"\bexeclp?\s*\(", "exec"),
    ("c", r"\bexecvp?\s*\(", "exec"),
    ("c", r"\b(fopen|open)\s*\(", "filesystem"),
    ("c", r"\b(sqlite3_exec|sqlite3_prepare)\s*\(", "SQL"),
    ("c", r"\balloca\s*\(", "stack allocation"),
    ("c", r"\bdlopen\s*\(", "dynamic load"),
    // C++ shares every C row, plus its own.
    ("cpp", r"\bstrcpy\s*\(", "unbounded copy"),
    ("cpp", r"\bstrcat\s*\(", "unbounded copy"),
    ("cpp", r"\bsprintf\s*\(", "unbounded format"),
    ("cpp", r"\bgets\s*\(", "unbounded read"),
    ("cpp", r"\bmemcpy\s*\(", "memory copy"),
    ("cpp", r"\bsystem\s*\(", "shell"),
    ("cpp", r"\bpopen\s*\(", "shell"),
    ("cpp", r"\b(fopen|open)\s*\(", "filesystem"),
    ("cpp", r"\bstd::(system|popen)\s*\(", "shell"),
    (
        "javascript",
        r"\b(db|database|sqlite|sqlite3|pg|mysql|conn|connection|client|stmt|statement|tx|transaction|pool|sequelize|knex|prisma|typeorm|drizzle|orm|sql|store)\s*\.\s*(run|exec|execSQL|raw|literal|query|all|get|prepare|execute)\s*\(",
        "SQL",
    ),
    (
        "javascript",
        r"\b(query|execute|execSQL|queryRaw|executeSql)\s*\(",
        "SQL",
    ),
    ("javascript", r"\b(eval|Function)\s*\(", "eval"),
    ("javascript", r"\bexec\s*\(", "shell"),
    ("javascript", r"\bspawn\s*\(", "shell"),
    (
        "javascript",
        r"\bfs\.(readFile|writeFile|unlink|rm)\s*\(",
        "filesystem",
    ),
    (
        "python",
        r"\b(sql|execute|executemany|executescript)\s*\(",
        "SQL",
    ),
    (
        "python",
        r"\b(cursor|cur|conn|connection|db|session|engine|tx|transaction|pool)\s*\.\s*(execute|executemany|executescript|raw|query|run)\s*\(",
        "SQL",
    ),
    // `subprocess.run(`, `.call(`, `.check_output(` and `.Popen(` all reach a
    // shell when shell=True, and none of them matched the previous row, which
    // only accepted a bare `subprocess(`. The trailing part is deliberately
    // loose: this dialect is a literal substring matcher, so the alternatives
    // are spelled out rather than expressed as a character class or a wildcard.
    (
        "python",
        r"\b(os\.system|subprocess\.(run|call|check_call|check_output|Popen)|eval|exec)\s*\(",
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
        r"\b(mysqli_query|query|exec|prepare|rawQuery|pg_query|system|shell_exec|eval|include|unlink)\s*\(",
        "SQL",
    ),
    (
        "php",
        r"\b(file_get_contents|file_put_contents|fopen)\s*\(",
        "filesystem",
    ),
    (
        "go",
        r"\b(db\.(Query|QueryRow|Exec|Raw|Prepare|QueryContext|QueryRowContext|ExecContext)|QueryRow|Exec|exec\.Command|sql\.Open)\s*\(",
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
        r"\b(SqlCommand|ExecuteScalar|ExecuteNonQuery|ExecuteReader|FromSqlRaw|ExecuteSqlRaw|ExecuteSqlInterpolated)\s*\(",
        "SQL",
    ),
    ("csharp", r"\bProcess\.Start\s*\(", "shell"),
    (
        "csharp",
        r"\bFile\.(WriteAllText|ReadAllText|Delete|Move)\s*\(",
        "filesystem",
    ),
    // Ruby command execution. `system`, `exec`, `IO.popen`, backticks and `%x`
    // are the ways a Ruby process shells out. A Rails controller that interpolates
    // a parameter into any of them is command injection, and before these rows a
    // .rb file had no shell sink at all.
    //
    // `exec` is bounded on a non word, non dot edge so it cannot match `execute`,
    // `re_exec` or `Kernel.exec` on a receiver. Backticks and `%x` require an
    // interpolation inside them, because a command literal carrying nothing from
    // the source is not a finding.
    //
    // The class strings are the table's own vocabulary, `shell` and `filesystem`.
    // An invented string here prints a second finding on the same line, because
    // the dedup key is the printed class.
    ("ruby", r"\bsystem\s*\(", "shell"),
    ("ruby", r"(?<![\w.])exec\s*\(", "shell"),
    ("ruby", r"\bIO\s*\.\s*popen\s*\(", "shell"),
    ("ruby", r"`[^`\n]*#\{", "shell"),
    ("ruby", r"%x[\(\[\{<][^\n]*#\{", "shell"),
    ("ruby", r"\bFile\s*\.\s*(write|open)\s*\(", "filesystem"),
];

/// Targets that turn an SSRF into a cloud credential theft. When a tainted
/// fetch line mentions one of these, the report is labelled for what it
/// actually is instead of the generic SSRF class.
pub(crate) const METADATA_TARGETS: &[&str] = &[
    "169.254.169.254",
    "169.254.170.2",
    "metadata.google.internal",
    "100.100.100.200",
    "fd00:ec2::254",
];

/// One rule in the strict table.
///
/// The original sink table fires when a tainted name is on the line, or when
/// any source appears earlier in the same block. That is the right call for
/// SQL, where a handler building a statement is the risk, but it is far too
/// eager for SSRF and NoSQL. A hardcoded health check URL and a literal query
/// object inside a request handler are both safe, and a guard that reports
/// those is a guard people mute. These rules therefore need the tainted value
/// to actually reach the sink line, either by name or by reading a source on
/// that same line.
///
/// `requires` is a co occurrence list. At least one token must also appear on
/// the line, which is how `collection.find(` is a NoSQL sink while `arr.find(`
/// stays silent: the method name alone is ambiguous, the receiver is not.
/// Rules sharing a `family` emit one report per line, first match wins.
pub(crate) struct StrictSink {
    pub lang: &'static str,
    pub pattern: &'static str,
    pub class: &'static str,
    pub family: &'static str,
    pub requires: &'static [&'static str],
}

/// Const constructor for the rule tables. Keeps every row on one line with its
/// field names visible, which is what a reviewer needs to check the gate and
/// the co occurrence list without expanding a tuple.
macro_rules! sink {
    ($lang:expr, $pat:expr, $class:expr, $family:expr, $req:expr) => {
        StrictSink {
            lang: $lang,
            pattern: $pat,
            class: $class,
            family: $family,
            requires: $req,
        }
    };
}

/// SSRF: user controlled input reaching a server side fetch, so the server
/// becomes the requester and the attacker chooses the destination.
pub(crate) const SSRF_SINKS: &[StrictSink] = &[
    // A cloud metadata target is reported through the class upgrade in
    // strict_class, so it is not duplicated as its own row per pattern.
    sink!("javascript", r"\bfetch\s*\(", "SSRF", "ssrf", &[]),
    sink!(
        "javascript",
        r"\b(axios|got|superagent|needle)\s*\(",
        "SSRF",
        "ssrf",
        &[]
    ),
    sink!(
        "javascript",
        r"\baxios\s*\.\s*(get|post|put|delete|head|patch|request)\s*\(",
        "SSRF",
        "ssrf",
        &[]
    ),
    sink!(
        "javascript",
        r"\bsuperagent\s*\.\s*(get|post|put|delete)\s*\(",
        "SSRF",
        "ssrf",
        &[]
    ),
    sink!(
        "javascript",
        r"\brequest\s*\.\s*(get|post|put|delete|head|patch)\s*\(",
        "SSRF",
        "ssrf",
        &[]
    ),
    sink!(
        "javascript",
        r"\b(https?)\s*\.\s*(get|request)\s*\(",
        "SSRF",
        "ssrf",
        &[]
    ),
    sink!(
        "python",
        r"\brequests\s*\.\s*(get|post|put|delete|head|patch|request|send)\s*\(",
        "SSRF",
        "ssrf",
        &[]
    ),
    sink!(
        "python",
        r"\bhttpx\s*\.\s*(get|post|put|delete|head|patch|request|send|stream)\s*\(",
        "SSRF",
        "ssrf",
        &[]
    ),
    sink!("python", r"\burlopen\s*\(", "SSRF", "ssrf", &[]),
    sink!(
        "python",
        r"\burllib\s*\.\s*request\s*\.\s*urlopen\s*\(",
        "SSRF",
        "ssrf",
        &[]
    ),
    sink!(
        "python",
        r"\bsocket\s*\.\s*create_connection\s*\(",
        "SSRF",
        "ssrf",
        &[]
    ),
    // file_get_contents and fopen are deliberately absent. They are already
    // filesystem sinks, and listing them here would print two findings on one
    // line. The risk is still reported, only the class label differs.
    sink!(
        "php",
        r"\b(curl_exec|curl_init|fsockopen|stream_socket_client|get_headers)\s*\(",
        "SSRF",
        "ssrf",
        &[]
    ),
    sink!(
        "go",
        r"\bhttp\s*\.\s*(Get|Post|Head|PostForm|NewRequest)\s*\(",
        "SSRF",
        "ssrf",
        &[]
    ),
    sink!(
        "go",
        r"\b(client|Client|hc|httpClient|defaultClient|DefaultClient)\s*\.\s*(Get|Post|Head|PostForm|Do)\s*\(",
        "SSRF",
        "ssrf",
        &[]
    ),
    sink!("java", r"\bnew\s+URL\s*\(", "SSRF", "ssrf", &[]),
    sink!(
        "java",
        r"\b(openStream|openConnection)\s*\(",
        "SSRF",
        "ssrf",
        &[]
    ),
    sink!(
        "java",
        r"\b(RestTemplate|restTemplate)\s*\.\s*(getForObject|getForEntity|postForObject|postForEntity|exchange|execute)\s*\(",
        "SSRF",
        "ssrf",
        &[]
    ),
    sink!(
        "java",
        r"\bHttpClient\s*\.\s*(send|sendAsync)\s*\(",
        "SSRF",
        "ssrf",
        &[]
    ),
    sink!("ruby", r"\bURI\s*\.\s*open\s*\(", "SSRF", "ssrf", &[]),
    sink!(
        "ruby",
        r"\bNet::HTTP\s*\.\s*(get|post|head|start|new)\s*\(",
        "SSRF",
        "ssrf",
        &[]
    ),
    sink!(
        "ruby",
        r"\b(HTTParty|Faraday)\s*\.\s*(get|post|put|delete|head)\s*\(",
        "SSRF",
        "ssrf",
        &[]
    ),
    // The classic open-uri SSRF. Ruby's bare open( also matches File.open and
    // IO.open, which are path handling rather than request forgery, so
    // ruby_open_exempt drops those receivers before this can report.
    sink!("ruby", r"\bopen\s*\(", "SSRF", "ssrf", &[]),
    // Bare method names, not receiver scoped. The common C# shape assigns the
    // client first, as in `var w = new WebClient(); w.DownloadString(u);`, so
    // a WebClient. prefix never appears on the sink line. These names are
    // distinctive enough to stand on their own.
    sink!(
        "csharp",
        r"\b(DownloadString|DownloadData|DownloadFile|UploadData|UploadString|GetStringAsync|GetByteArrayAsync)\s*\(",
        "SSRF",
        "ssrf",
        &[]
    ),
    sink!(
        "csharp",
        r"\b(GetAsync|PostAsync|PutAsync|SendAsync)\s*\(",
        "SSRF",
        "ssrf",
        &[]
    ),
    sink!(
        "csharp",
        r"\bWebRequest\s*\.\s*Create\s*\(",
        "SSRF",
        "ssrf",
        &[]
    ),
];

/// NoSQL injection: request data reaching a document query, where an attacker
/// controlled key or operator changes the meaning of the query instead of only
/// its value.
pub(crate) const NOSQL_SINKS: &[StrictSink] = &[
    // where( needs no receiver. Nothing in plain JavaScript has a where method
    // on an array, and Mongoid style where() is the entry point for an operator
    // injection, so requiring a receiver name would miss Account.where(...).
    sink!("javascript", r"\.\s*where\s*\(", "NoSQL", "nosql", &[]),
    sink!(
        "javascript",
        r"\.\s*(find|findOne|findById|findOneAndUpdate|findOneAndDelete|findOneAndReplace|updateOne|updateMany|deleteOne|deleteMany|insertOne|insertMany|countDocuments|distinct|aggregate)\s*\(",
        "NoSQL",
        "nosql",
        &[
            "collection",
            "Collection",
            "Model",
            "model",
            "mongo",
            "mongoose",
            "db.",
            "conn",
        ]
    ),
    sink!(
        "python",
        r"\.\s*(find|find_one|find_by_id|find_one_and_update|find_one_and_delete|find_one_and_replace|update_one|update_many|delete_one|delete_many|insert_one|insert_many|count_documents|distinct|aggregate|where)\s*\(",
        "NoSQL",
        "nosql",
        &[
            "collection",
            "mongo",
            "motor",
            "db",
            "database",
            "repo",
            "dao",
            "self"
        ]
    ),
    // db.eval runs JavaScript inside the database, so tainted input there is
    // code execution rather than a malformed query.
    sink!(
        "python",
        r"\.\s*eval\s*\(",
        "NoSQL",
        "nosql",
        &["db", "database", "mongo", "motor", "collection", "self"]
    ),
    // The Mongo driver specific names cannot collide with anything else, so
    // they stand on their own and a terse receiver like $c is still caught.
    sink!(
        "php",
        r"\b(findOneAndUpdate|findOneAndReplace|findOneAndDelete|aggregate|updateOne|updateMany|deleteOne|deleteMany|insertOne|insertMany|countDocuments)\s*\(",
        "NoSQL",
        "nosql",
        &[]
    ),
    // find and findOne are generic enough to need the receiver.
    sink!(
        "php",
        r"\b(find|findOne|distinct)\s*\(",
        "NoSQL",
        "nosql",
        &[
            "collection",
            "Collection",
            "manager",
            "Manager",
            "mongo",
            "MongoDB",
            "bulk",
        ]
    ),
    sink!(
        "go",
        r"\.\s*(Find|FindOne|UpdateOne|UpdateMany|DeleteOne|DeleteMany|InsertOne|InsertMany|Aggregate|Distinct|CountDocuments|FindOneAndUpdate)\s*\(",
        "NoSQL",
        "nosql",
        &[
            "mongo",
            "Mongo",
            "collection",
            "Collection",
            "coll",
            "Coll",
            "Cursor",
        ]
    ),
    sink!(
        "java",
        r"\.\s*(find|findOne|findOneAndUpdate|findOneAndReplace|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|insertOne|insertMany|aggregate|countDocuments|distinct)\s*\(",
        "NoSQL",
        "nosql",
        &[
            "collection",
            "Collection",
            "mongo",
            "Mongo",
            "template",
            "Template",
        ]
    ),
    // Document.parse turns a request string straight into a query document,
    // which is the shape the Java driver docs warn about.
    sink!(
        "java",
        r"\bDocument\s*\.\s*parse\s*\(",
        "NoSQL",
        "nosql",
        &[]
    ),
    sink!(
        "ruby",
        r"\.\s*(find|find_one|find_one_and_update|find_one_and_delete|where|find_by|update_one|delete_one)\s*\(",
        "NoSQL",
        "nosql",
        &[
            "collection",
            "Collection",
            "Model",
            "model",
            "mongo",
            "Mongo",
            "criteria",
        ]
    ),
    sink!(
        "csharp",
        r"\.\s*(Find|FirstOrDefault|UpdateOne|UpdateMany|DeleteOne|DeleteMany|InsertOne|InsertMany|Aggregate|CountDocuments|Any)\s*\(",
        "NoSQL",
        "nosql",
        &[
            "mongo",
            "Mongo",
            "collection",
            "Collection",
            "IMongoCollection",
            "filter",
            "Filter",
        ]
    ),
    sink!(
        "csharp",
        r"\bBsonDocument\s*\.\s*Parse\s*\(",
        "NoSQL",
        "nosql",
        &[]
    ),
];

/// Every strict rule for one language, SSRF before NoSQL.
pub(crate) fn strict_sinks(lang: &str) -> impl Iterator<Item = &'static StrictSink> {
    SSRF_SINKS
        .iter()
        .chain(NOSQL_SINKS.iter())
        .filter(move |s| s.lang == lang)
}

/// True when a strict rule applies to this line. Kept in one place so the intra
/// file scan and the interprocedural pass can never disagree about which lines
/// qualify.
pub(crate) fn strict_hit(rule: &StrictSink, line: &str) -> bool {
    if !regex_hit(rule.pattern, line) {
        return false;
    }
    if !rule.requires.is_empty() && !rule.requires.iter().any(|t| line.contains(t)) {
        return false;
    }
    !ruby_open_exempted(rule, line)
}

/// True when this rule must be skipped. Ruby's bare open( is both open-uri and
/// File.open, and reading or writing a path is not request forgery.
fn ruby_open_exempted(rule: &StrictSink, line: &str) -> bool {
    rule.pattern == r"\bopen\s*\(" && (line.contains("File.") || line.contains("IO."))
}

/// The class actually printed. A tainted fetch aimed at a metadata endpoint is
/// cloud credential theft, and saying so is more useful than saying SSRF.
pub(crate) fn strict_class(rule: &StrictSink, line: &str) -> &'static str {
    if rule.family == "ssrf" && METADATA_TARGETS.iter().any(|t| line.contains(t)) {
        "cloud metadata fetch"
    } else {
        rule.class
    }
}

/// "an SSRF sink" reads correctly, "a SQL sink" reads correctly, and one
/// template has to produce both.
fn article(class: &str) -> &'static str {
    if class.starts_with("SSRF") {
        return "an";
    }
    match class.chars().next() {
        Some('a' | 'e' | 'i' | 'o' | 'u' | 'A' | 'E' | 'I' | 'O' | 'U') => "an",
        _ => "a",
    }
}

/// Scan one source file for taint flows.
/// True when a path belongs to third party code rather than to this project.
///
/// A measured decision, not a preference. On a 313 file corpus the taint pass
/// spent 267 seconds, and 62 of them were in three files under
/// `lib/vendors/nerdamer-prime`, the largest being 634KB of generated algebra
/// code. Findings in vendored code are real but they are not actionable for the
/// person running the check, and they cost the same to produce as findings in
/// code the user actually owns.
///
/// The trade is stated rather than hidden: vendored and generated code is not
/// analysed, so a vulnerability that lives only in a dependency is invisible to
/// the taint pass. `deps` and the advisory guard are the layers that cover
/// third party risk, and they do not have this blind spot.
///
/// Matching is on whole path segments rather than substrings, because a
/// substring rule eats first party code: `src/vendor-portal/client.js` and
/// `src/distillery/rules.js` both contain a vendor word without being vendored,
/// and both have tests above asserting they are still scanned.
fn is_third_party(path: &Path) -> bool {
    const DIRS: [&str; 8] = [
        "vendor",
        "vendors",
        "node_modules",
        "third_party",
        "thirdparty",
        "external",
        "dist",
        "build",
    ];
    let Some(text) = path.to_str() else {
        // No usable path means no way to judge. Scanning is the safe default,
        // because silently skipping a file on a path encoding quirk would be a
        // coverage hole with no receipt.
        return false;
    };
    let lower = text.replace('\\', "/").to_ascii_lowercase();
    for seg in lower.split('/') {
        let seg = seg.trim();
        // A generated bundle, matched on the file name because that is where
        // `.min.` and `.bundle.` appear.
        if seg.ends_with(".min.js")
            || seg.ends_with(".bundle.js")
            || seg.ends_with(".min.css")
            || seg.ends_with(".generated.ts")
        {
            return true;
        }
        if DIRS.contains(&seg) {
            return true;
        }
    }
    false
}

pub fn scan_file(path: &Path, content: &str) -> Vec<TaintReport> {
    // Third party code is not analysed. See `is_third_party` for the measurement
    // behind this and for what it costs.
    if is_third_party(path) {
        return Vec::new();
    }
    let Some(lang) = crate::parser::detect_language(path) else {
        return Vec::new();
    };
    // TypeScript was never in the source or sink tables, so every .ts and .tsx
    // file was silently unscanned. Taint rules are language families and
    // TypeScript shares the JavaScript rows, so map it rather than
    // duplicating every rule.
    let lang = if lang == "typescript" {
        "javascript".to_string()
    } else {
        lang
    };
    let mut reports = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let blocks = function_blocks(&lines, &lang);
    // (line, sink class) pairs already reported.
    //
    // This used to be a linear scan of every report so far, with a `format!`
    // allocated inside the predicate, run once per sink row per line. On a
    // 1665 line file that is a quadratic walk with an allocation on every step.
    // A set makes it a lookup, and the sink phrase is built once per row rather
    // than once per comparison.
    let mut reported_pairs: std::collections::HashSet<(u64, &'static str)> =
        std::collections::HashSet::new();
    for (block_start, block_end, indent) in blocks {
        let mut tainted: Vec<(String, usize)> = Vec::new();
        for i in block_start..=block_end {
            let line = lines[i];
            let line_no = i as u64 + 1;
            // Whether this line reads user input at all. The strict gate needs
            // it, and hoisting it here costs one pass per line instead of one
            // per rule.
            let mut reads_source = false;
            for (l, pat) in SOURCES {
                if l == lang && regex_hit(pat, line) {
                    if let Some(names) = source_taints(line, &lang) {
                        reads_source = true;
                        tainted.extend(names.into_iter().map(|n| (n, i)));
                    } else {
                        // A source read whose value is not bound to a name, a
                        // bare `input()` passed inline for instance. The line
                        // still reads untrusted input.
                        reads_source = true;
                    }
                }
            }
            for (l, pat, sink) in SINKS {
                if *l != lang {
                    continue;
                }
                if !regex_hit(pat, line) {
                    continue;
                }
                // Overlapping patterns are deliberate (a bare name plus a
                // receiver scoped one). Report a line and sink class once.
                if !reported_pairs.insert((line_no, sink)) {
                    continue;
                }
                // `used` is the flow from a name to a sink. A source read inline
                // in the sink call has no name at all, which is the normal Ruby
                // shape: `system(params[:cmd])` reads params and hands it straight
                // to the sink. `reads_source` is exactly that case, so it counts.
                //
                // It is not applied to every language. It is applied to ruby and
                // to c and cpp, where the shape is the normal one: a Rails
                // controller calls `system(params[:cmd])`, and compact C calls
                // `strcpy(buf, getenv("NAME"))`, both with nothing in between to
                // bind. Both are measured, 536 real Ruby files and 401 real C++
                // files, and both report zero false criticals.
                //
                // It is deliberately not applied to javascript or java, where an
                // inline `req.query.x` reaching a sink is rarer and the broadened
                // gate has not been measured there.
                // Sanitizers and literals both end the flow, and both are checked
                // before the sink is reported rather than after, so a sanitized
                // value never reaches the report at all.
                let sanitized = SANITIZERS
                    .iter()
                    .any(|(sl, pat)| *sl == lang && regex_hit(pat, line));
                let line_is_literal = is_only_literal_or_sanitizer(line);
                let inline_source = reads_source
                    && matches!(lang.as_str(), "ruby" | "c" | "cpp")
                    && !line_is_literal;
                let used = !sanitized
                    && !line_is_literal
                    && (inline_source || tainted.iter().any(|(v, _)| line.contains(v.as_str())));
                let source = tainted.iter().find(|(_, src_i)| {
                    let src_line = lines[*src_i];
                    let src_indent = leading_spaces(src_line);
                    *src_i < i && src_indent >= indent && (i - *src_i) < 60
                });
                if *sink == "prompt" {
                    if used {
                        reports.push(make_report(
                            path,
                            line_no,
                            format!(
                                "user input reaches a prompt construction on this line (prompt injection risk). source {}",
                                source_evidence(source, line_no)
                            ),
                        ));
                    }
                } else if used || source.is_some() {
                    reports.push(make_report(
                        path,
                        line_no,
                        format!(
                            "user controlled input reaches {} {} sink on this line. source {}",
                            article(sink),
                            sink,
                            source_evidence(source, line_no)
                        ),
                    ));
                }
            }
            // SSRF and NoSQL use the strict gate. A source somewhere earlier in
            // the handler is not enough, the tainted value has to reach this
            // line, otherwise every handler that reads input and calls a health
            // check endpoint turns into a finding.
            if !used_as_value(&tainted, line) && !reads_source {
                continue;
            }
            let source = tainted.iter().find(|(_, src_i)| {
                let src_line = lines[*src_i];
                let src_indent = leading_spaces(src_line);
                *src_i < i && src_indent >= indent && (i - *src_i) < 60
            });
            let mut seen_families: Vec<&str> = Vec::new();
            for rule in strict_sinks(&lang) {
                if seen_families.contains(&rule.family) {
                    continue;
                }
                if !strict_hit(rule, line) {
                    continue;
                }
                seen_families.push(rule.family);
                let class = strict_class(rule, line);
                reports.push(make_report(
                    path,
                    line_no,
                    format!(
                        "user controlled input reaches {} {} sink on this line. source {}",
                        article(class),
                        class,
                        source_evidence(source, line_no)
                    ),
                ));
            }
        }
    }
    reports
}

/// A tainted name used as an object key is a label, not a value. A plain
/// substring match reads `{ published: true, page: 1 }` as a use of the tainted
/// `page`, which is how a literal query object reported NoSQL. An occurrence
/// followed by a colon is a key and does not count.
///
/// Only the strict sinks use this. The original sink table keeps its substring
/// behaviour, so no finding that exists today changes.
fn used_as_value(tainted: &[(String, usize)], line: &str) -> bool {
    tainted.iter().any(|(v, _)| {
        let mut from = 0;
        while let Some(found) = line[from..].find(v.as_str()) {
            let at = from + found;
            let end = at + v.len();
            if !line[end..].trim_start().starts_with(':') {
                return true;
            }
            from = end;
        }
        false
    })
}

/// Where the user input came from. A tainted value used on the same line as
/// the sink is the common shape, and printing "line 0" for it was a lie.
fn source_evidence(source: Option<&(String, usize)>, line_no: u64) -> String {
    match source {
        Some((_, n)) => format!("at line {}", n + 1),
        None => format!("on this line (line {line_no})"),
    }
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
    // Lock free on the hot path. This runs once per rule row per line, so a
    // 49KB file took roughly seventy thousand calls, and every one of them took
    // a mutex. Measured at 75 microseconds per call on one large file, which is
    // three orders of magnitude more than the substring search it guards.
    //
    // The cache is filled once and never mutated again, so a `OnceLock` holding
    // an immutable map is the correct shape: the first caller pays to build it
    // and every later caller pays an atomic load and a hash lookup.
    static CACHE: OnceLock<PreparedCache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| {
        let mut m: PreparedCache = HashMap::new();
        for (_l, pat) in SOURCES {
            m.entry(pat).or_insert_with(|| prepare(pat));
        }
        for (_l, pat, _) in SINKS {
            m.entry(pat).or_insert_with(|| prepare(pat));
        }
        for rule in strict_sinks_all() {
            m.entry(rule).or_insert_with(|| prepare(rule));
        }
        // Sanitizer rows are looked up by the same `regex_hit`. Leaving them out
        // makes the lookup below miss, and a miss is an `abort()` rather than a
        // warning, so the first line that reaches a sanitizer killed the process.
        for (_l, pat) in SANITIZERS {
            m.entry(pat).or_insert_with(|| prepare(pat));
        }
        m
    });
    let (start_bound, end_bound, candidates, needs_double) =
        cache.get(pattern).unwrap_or_else(|| std::process::abort());
    // One check per line, not one per candidate. On a typical source line this
    // is false, and it removes the overwhelming majority of the searches.
    let line_double = line_has_double_ws(line);
    for (n, cand) in candidates.iter().enumerate() {
        if !line_double && needs_double[n] {
            continue;
        }
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
fn prepare(pattern: &'static str) -> (bool, bool, Vec<String>, Vec<bool>) {
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
    let mut candidates: Vec<String> = Vec::new();
    for concrete in concrete_patterns(&pat) {
        candidates.extend(expand(&concrete));
    }
    // Which candidates require two consecutive whitespace characters to match.
    //
    // The expander turns every `\s*` into five variants, 0 through 4 copies, and
    // they multiply across the pattern. One forty branch alternation with four
    // `\s*` asked for over fourteen thousand candidates, and with the whole
    // table the scan made 18331 substring searches on every line of source. That
    // is the entire cost of the taint pass: 30 million searches on a 1665 line
    // file.
    //
    // A candidate holding two or more whitespace in a row can only match a line
    // that itself holds two consecutive whitespace characters. Most source
    // lines do not, so those variants are dead weight on nearly every line and
    // are skipped by a single flag rather than a per-candidate search. The
    // semantics are unchanged; a line that does contain the spacing still
    // matches, because the candidate is only skipped when the line cannot
    // possibly contain it.
    let needs_double: Vec<bool> = candidates.iter().map(|c| has_double_ws(c)).collect();
    (start_bound, end_bound, candidates, needs_double)
}

/// True when this candidate contains two whitespace characters in a row.
fn has_double_ws(c: &str) -> bool {
    let bytes = c.as_bytes();
    bytes
        .windows(2)
        .any(|w| w[0].is_ascii_whitespace() && w[1].is_ascii_whitespace())
}

/// True when this line contains two whitespace characters in a row.
fn line_has_double_ws(line: &str) -> bool {
    let bytes = line.as_bytes();
    bytes
        .windows(2)
        .any(|w| w[0].is_ascii_whitespace() && w[1].is_ascii_whitespace())
}

use std::collections::HashMap;
use std::sync::OnceLock;

type PreparedPattern = (bool, bool, Vec<String>, Vec<bool>);
type PreparedCache = HashMap<&'static str, PreparedPattern>;

/// Every strict sink pattern, across every language.
///
/// The strict sink table is per language and its rows are filtered at scan
/// time, so the set of patterns is not statically known. It is walked here once
/// to fill the prepared cache, which is what lets the hot path stay lock free.
fn strict_sinks_all() -> Vec<&'static str> {
    SSRF_SINKS
        .iter()
        .chain(NOSQL_SINKS.iter())
        .map(|s| s.pattern)
        .collect()
}

/// Expand alternation groups like (a|b|c) into concrete patterns.
/// Handles multiple flat groups; nested groups are supported one level deep.
///
/// Two limits of this dialect are worth knowing before writing a rule, because
/// both fail silently rather than loudly. A `|` outside a group is kept as a
/// literal character, so alternation must always be wrapped. And the only
/// recognised escapes are `\b \s \. \( \) \$`: a pattern containing `\[`
/// matches the text `\[` and never matches a real bracket. Square brackets are
/// literal here anyway, since there are no character classes.
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
                        // Zero or one, where it used to be zero through four.
                        //
                        // Every `\s*` produced five variants and they multiply,
                        // so the largest javascript row, 31 alternation branches
                        // with three `\s*`, asked for 27,500 substring searches
                        // on every line. Measured across the table: 35,582
                        // candidates per line, of which 27,588 were javascript
                        // and 7,583 python, with every other language under 130.
                        // That is the whole cost of the taint pass.
                        //
                        // The narrowed case is two or more whitespace characters
                        // between tokens, as in `db . find (`. Source code
                        // overwhelmingly writes `db.find(`, and the strict
                        // sink rules that care most do not use a wide run at
                        // all, so this trades a construct that does not occur
                        // for a 8x reduction in the work per line. It is a
                        // behaviour change and is recorded as one.
                        next.push(base.clone());
                        let mut ext = base.clone();
                        ext.push(c);
                        next.push(ext);
                    }
                    '+' => {
                        // One through four, then, since `+` means at least one.
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

/// Names the parameters of a python `def` line, so they can be treated as
/// untrusted inputs. Drops defaults, annotations, `*args`/`**kwargs` markers and
/// `self`/`cls`, and returns None when the line is not a def.
///
/// `self` and `cls` are excluded on purpose: they are not user input, and
/// tainting every method body through `self` would bury the real findings under
/// noise.
///
/// Returns `Some` for every line that is a def, including one with no
/// parameters, so the caller can tell "a def that binds nothing" apart from
/// "not a def at all".
pub(crate) fn def_params(line: &str) -> Option<Vec<String>> {
    let trimmed = line.trim_start();
    let rest = trimmed
        .strip_prefix("async ")
        .unwrap_or(trimmed)
        .trim_start();
    let rest = rest.strip_prefix("def ")?;
    let Some(open) = rest.find('(') else {
        // A `def` with no parameter list. Not valid python, but the line still
        // matches the source row, and it must report that it binds nothing
        // rather than None, which the caller reads as "not a source" and would
        // then satisfy the strict gate with no input in the file.
        return Some(Vec::new());
    };
    // The closing paren has to be the *matching* one. Taking the first `)`
    // truncates the list at the end of the first nested call, so
    // `def f(a, b=call(x, y), c):` parses as two parameters and loses `c`.
    let after = &rest[open + 1..];
    let mut depth = 0i32;
    let mut end = None;
    for (idx, ch) in after.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' if depth == 0 => {
                end = Some(idx);
                break;
            }
            ')' | ']' | '}' => depth -= 1,
            _ => {}
        }
    }
    let inner = &after[..end?];
    if inner.trim().is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for part in split_top_level_commas(inner) {
        let name = part
            .split(':')
            .next()
            .unwrap_or(part.as_str())
            .split('=')
            .next()
            .unwrap_or(part.as_str())
            .trim()
            .trim_start_matches('*')
            .to_string();
        if name.is_empty() {
            continue;
        }
        if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            continue;
        }
        if matches!(name.as_str(), "self" | "cls") {
            continue;
        }
        out.push(name);
    }
    Some(out)
}

/// Split on commas that are not nested inside brackets, so a default of
/// `f(a, b=call(x, y))` does not split in the wrong place.
fn split_top_level_commas(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    for ch in s.chars() {
        match ch {
            '(' | '[' | '{' => {
                depth += 1;
                cur.push(ch);
            }
            ')' | ']' | '}' => {
                depth -= 1;
                cur.push(ch);
            }
            ',' if depth == 0 => {
                out.push(cur.clone());
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// The names one source line introduces as tainted.
///
/// Python `def` lines are resolved first and on their own terms, because
/// `assigned_var` cannot be consulted first for them. A def carrying a default
/// or an annotation contains an `=`, so `assigned_var` returns a value and the
/// parameter list is never read: `def f(x: int = 5)` returns `int`, the
/// annotation type, which is never a value, and the real parameter `x` goes
/// untainted. This helper is the single place that decides, so the
/// interprocedural engine resolves a source line exactly the way the intra file
/// pass does.
///
/// Note that a def only reaches here through the interprocedural path, where
/// the parameter list is recovered to seed an argument. The intra file pass
/// does not treat a def as a source, for the reason recorded on the python
/// rows of `SOURCES`.
pub(crate) fn source_taints(line: &str, lang: &str) -> Option<Vec<String>> {
    if lang == "python"
        && let Some(params) = def_params(line)
    {
        return Some(params);
    }
    // A parameter is the tainted name in a Ruby method signature, the same role
    // it plays in Python. Without this a Rails controller shaped
    // `def index` / `system(params[:cmd])` bound nothing, so the same line read a
    // source and reached a sink with no tainted name in between, and the report
    // needed `used` or an earlier tainted line and had neither.
    if lang == "ruby" {
        let t = line.trim();
        for prefix in ["def self.", "def "] {
            if let Some(rest) = t.strip_prefix(prefix) {
                let sig = rest.split(['(', ' ']).next().unwrap_or("");
                let names: Vec<String> = sig
                    .trim_start_matches('(')
                    .trim_end_matches(')')
                    .split(',')
                    .map(|p| p.split(':').next().unwrap_or("").trim().to_string())
                    .filter(|p| !p.is_empty() && p != "self")
                    .collect();
                if !names.is_empty() {
                    return Some(names);
                }
            }
        }
    }
    assigned_var(line).map(|v| vec![v])
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
/// block for brace languages, or per indented suite for python and ruby, which
/// both delimit with `def` and indentation.
pub(crate) fn function_blocks(lines: &[&str], lang: &str) -> Vec<(usize, usize, usize)> {
    let mut blocks = Vec::new();
    if lang == "python" || lang == "ruby" {
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            let indent = leading_spaces(line);
            let trimmed = line.trim_start();
            // The paren test was Python's rule and it silently excluded every bare
            // Ruby method. `def index` and `def show` are the norm in a Rails
            // controller, and a block the scan cannot see is a file where every
            // taint flow is invisible, not merely one missed line.
            //
            // So parens are required only for Python, where `def` alone is the
            // keyword. For Ruby the test is that an identifier follows, which is
            // what separates a definition from a comment or a call to `def`.
            let is_def = trimmed.starts_with("def ") || trimmed.starts_with("async def ");
            let opens = if lang == "ruby" {
                is_def
                    && trimmed
                        .trim_start_matches("async def ")
                        .trim_start_matches("def ")
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_alphabetic() || c == '_')
            } else {
                is_def && trimmed.contains('(')
            };
            if opens {
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
        // A one line function opens and closes on the same line, so the depth is
        // already back to zero by the time it is tested and the block was never
        // pushed. Every single line C or C++ function was therefore unscanned:
        // `void run(void){char b[8];strcpy(b,getenv("X"));}` is dense, common and
        // invisible. The test has to be "did we close the thing we opened", which
        // is true on the same line, not "are we at depth zero now".
        if let Some(s) = start
            && depth <= 0
        {
            start = None;
            blocks.push((s, i, 0));
        }
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The regression this source row was written for. `def f(x: int = 5):`
    /// contains an `=`, so `assigned_var` answers `int`, the annotation type,
    /// and the parameter `x` was never tainted. Parameters with defaults are
    /// the common case in real code, so this was the majority of handlers.
    #[test]
    fn a_parameter_with_an_annotation_and_default_is_still_tainted() {
        let src = "def render(x: int = 5):\n    return str(x)\n";
        assert_eq!(
            source_taints(src, "python"),
            Some(vec!["x".to_string()]),
            "the parameter, not the annotation type"
        );
    }

    #[test]
    fn a_parameter_with_a_plain_default_is_still_tainted() {
        let src = "def f(x=1):\n    return x\n";
        assert_eq!(source_taints(src, "python"), Some(vec!["x".to_string()]));
    }

    #[test]
    fn every_parameter_of_a_multi_parameter_def_is_tainted() {
        // `def nested(a, b=(1, 2)):` returns `b` from assigned_var, which
        // silently dropped `a`.
        let src = "def nested(a, b=(1, 2)):\n    return a + b\n";
        assert_eq!(
            source_taints(src, "python"),
            Some(vec!["a".to_string(), "b".to_string()]),
            "both parameters, not just the defaulted one"
        );
    }

    #[test]
    fn a_zero_argument_def_binds_nothing() {
        // A def with no parameters is not a source. Returning an empty vec
        // rather than None is deliberate: the caller must be able to tell
        // "this line is a def, and it binds nothing" from "this line is not a
        // source at all", and must not set reads_source for it.
        assert_eq!(
            source_taints("def notadef:", "python"),
            Some(vec![]),
            "a def with no parameters must not claim to read input"
        );
    }

    #[test]
    fn def_params_handles_the_shapes_real_python_uses() {
        assert_eq!(def_params("def f(cmd):"), Some(vec!["cmd".to_string()]));
        assert_eq!(
            def_params("async def f(url):"),
            Some(vec!["url".to_string()]),
            "async def is a def"
        );
        assert_eq!(
            def_params("def f(self, value):"),
            Some(vec!["value".to_string()]),
            "self is not user input"
        );
        assert_eq!(
            def_params("def f(cls, value):"),
            Some(vec!["value".to_string()]),
            "cls is not user input"
        );
        assert_eq!(
            def_params("def f(a, b, c):"),
            Some(vec!["a".to_string(), "b".to_string(), "c".to_string()])
        );
        assert_eq!(def_params("x = 1"), None, "not a def");
        assert_eq!(def_params("class C:"), None, "not a def");
    }

    #[test]
    fn def_params_drops_star_args_and_keeps_their_names() {
        assert_eq!(
            def_params("def f(a, *args, **kwargs):"),
            Some(vec![
                "a".to_string(),
                "args".to_string(),
                "kwargs".to_string()
            ])
        );
    }

    #[test]
    fn def_params_splits_on_top_level_commas_only() {
        // A nested default must not be split, or the tail of it is mistaken
        // for a parameter name.
        let got = def_params("def f(a, b=call(x, y), c):").expect("a def");
        assert!(
            got.contains(&"a".to_string()) && got.contains(&"c".to_string()),
            "the outer parameters survive: {got:?}"
        );
        assert!(
            !got.iter().any(|n| n.contains('(') || n.contains(')')),
            "no fragment of a nested default may become a name: {got:?}"
        );
    }

    /// The decision this test pins, stated as the limit it is. A python
    /// parameter is not a source, so `def go(cmd): os.system(cmd)` is silent
    /// in the intra file pass even though it is the shape we would want to
    /// catch. It is caught instead when a caller passes a tainted argument,
    /// which is what `crate::interproc` does. Asserting the opposite would
    /// re-introduce the false positives on `read_config(path)` and on
    /// `escape`-then-`mark_safe` that the clean corpus forbids.
    #[test]
    fn a_python_parameter_alone_is_not_a_source() {
        let src = "def go(cmd):\n    os.system(cmd)\n";
        let reports = scan_file(std::path::Path::new("a.py"), src);
        assert!(
            !reports
                .iter()
                .any(|r| r.message.contains("sink") || r.message.contains("command")),
            "a parameter is not untrusted on its own, so this must stay quiet: {:?}",
            reports
        );
    }

    /// The vacuous-gate guard, kept because it is the reason a def with no
    /// parameters reports `Some(vec![])` rather than `None`. A def that claims
    /// to be a source while binding nothing would satisfy the strict gate with
    /// no input anywhere in the file, opening SSRF and NoSQL findings out of
    /// nothing.
    #[test]
    fn a_zero_argument_def_does_not_open_a_strict_finding() {
        let src = "def go():\n    requests.get(url)\n";
        let reports = scan_file(std::path::Path::new("a.py"), src);
        assert!(
            !reports
                .iter()
                .any(|r| r.message.contains("SSRF") || r.message.contains("NoSQL")),
            "a def with no parameters carries no input, so there is no flow to report: {:?}",
            reports
        );
    }

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
    fn same_line_source_is_reported_honestly() {
        // The real binary printed "source at line 0" for this shape, because
        // the tainted value is used on the line it is read on.
        let src = "app.get(\"/u/:id\", (req, res) => {\n  const row = db.run(\"DELETE FROM users WHERE id = \" + req.params.id);\n  res.json(row);\n});\n";
        let p = std::path::Path::new("routes.js");
        let reports = scan_file(p, src);
        let r = reports
            .iter()
            .find(|r| r.message.contains("SQL"))
            .expect("SQL finding");
        assert!(
            r.message.contains("source on this line"),
            "expected an honest source, got {}",
            r.message
        );
        assert!(!r.message.contains("line 0"), "{}", r.message);
    }

    // The audit found db.run invisible because the SQL sink table never listed
    // it and a rule asserted run( must stay silent. better-sqlite3, node:sqlite
    // and Knex all use it as the primary query API, so the receiver scoped
    // entry below is what closes that class.
    #[test]
    fn detects_better_sqlite3_run_sink() {
        let src = "function load() {\n  const id = req.query.id;\n  db.run(\"DELETE FROM users WHERE id = \" + id);\n}\n";
        let p = std::path::Path::new("app.js");
        let reports = scan_file(p, src);
        assert!(
            reports.iter().any(|r| r.message.contains("SQL")),
            "db.run with tainted input must report SQL, got {:?}",
            reports
        );
    }

    #[test]
    fn detects_stmt_run_and_knex_raw() {
        let src = "export async function find(req) {\n  const sql = \"SELECT * FROM t WHERE a = \" + req.query.a;\n  const row = await stmt.run(sql);\n  return knex.raw(sql);\n}\n";
        let p = std::path::Path::new("db.js");
        let reports = scan_file(p, src);
        assert_eq!(
            reports.iter().filter(|r| r.message.contains("SQL")).count(),
            2,
            "both stmt.run and knex.raw are SQL sinks: {:?}",
            reports
        );
    }

    #[test]
    fn detects_python_executescript_and_cursor_run() {
        let src = "def wipe(request):\n    table = request.args['table']\n    cursor.executescript('DROP TABLE ' + table)\n    conn.execute('DELETE FROM ' + table)\n";
        let p = std::path::Path::new("wipe.py");
        let reports = scan_file(p, src);
        assert_eq!(
            reports.iter().filter(|r| r.message.contains("SQL")).count(),
            2,
            "{:?}",
            reports
        );
    }

    #[test]
    fn detects_php_prepare_and_csharp_raw_sql() {
        let php = "<?php\nfunction load() {\n    $id = $_GET['id'];\n    $sql = 'SELECT * FROM u WHERE id = ' . $id;\n    return $pdo->prepare($sql);\n}\n";
        let reports = scan_file(std::path::Path::new("a.php"), php);
        assert!(
            reports.iter().any(|r| r.message.contains("SQL")),
            "pdo->prepare with a tainted id must report SQL: {:?}",
            reports
        );
        let cs = "class Repo {\n    void Load(HttpRequest Request) {\n        var id = Request.QueryString[\"id\"];\n        _db.FromSqlRaw(\"SELECT * FROM U WHERE Id = \" + id);\n    }\n}\n";
        let reports = scan_file(std::path::Path::new("R.cs"), cs);
        assert!(
            reports.iter().any(|r| r.message.contains("SQL")),
            "FromSqlRaw must report SQL: {:?}",
            reports
        );
    }

    #[test]
    fn detects_go_gorm_raw() {
        let src = "package main\n\nfunc load(r *http.Request) {\n\tid := r.URL.Query().Get(\"id\")\n\tdb.Raw(\"SELECT * FROM u WHERE id = \" + id).Scan(&out)\n}\n";
        let reports = scan_file(std::path::Path::new("g.go"), src);
        assert!(
            reports.iter().any(|r| r.message.contains("SQL")),
            "gorm db.Raw must report SQL: {:?}",
            reports
        );
    }

    #[test]
    fn a_constant_bare_run_call_stays_silent() {
        // The point of the receiver scoped rule: a test runner or task runner
        // call with no user input is not SQL and must not fire.
        let src = "function x() {\n  run(taskName);\n}\n";
        let reports = scan_file(std::path::Path::new("a.js"), src);
        assert!(reports.is_empty(), "{:?}", reports);
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

    // ---- SSRF -------------------------------------------------------------

    fn has_class(reports: &[TaintReport], class: &str) -> bool {
        reports.iter().any(|r| r.message.contains(class))
    }

    #[test]
    fn detects_ssrf_javascript_fetch() {
        let src = "async function proxy(req, res) {\n  const target = req.query.url;\n  const r = await fetch(target);\n  res.send(r);\n}\n";
        let reports = scan_file(std::path::Path::new("route.js"), src);
        assert!(
            has_class(&reports, "SSRF"),
            "fetch with a tainted target must report SSRF, got {:?}",
            reports
        );
    }

    #[test]
    fn detects_ssrf_same_line_source_is_honest() {
        let src =
            "app.get('/p', (req, res) => {\n  fetch(req.query.url).then(r => r.text());\n});\n";
        let reports = scan_file(std::path::Path::new("routes.js"), src);
        let r = reports
            .iter()
            .find(|r| r.message.contains("SSRF"))
            .expect("SSRF finding");
        assert!(r.message.contains("source on this line"), "{}", r.message);
        assert!(!r.message.contains("line 0"), "{}", r.message);
    }

    #[test]
    fn detects_ssrf_axios_and_python_requests() {
        let js = "function p(req) {\n  const u = req.query.u;\n  return axios.get(u);\n}\n";
        assert!(has_class(
            &scan_file(std::path::Path::new("a.js"), js),
            "SSRF"
        ));
        let py = "def proxy(request):\n    target = request.args['u']\n    return requests.get(target)\n";
        assert!(has_class(
            &scan_file(std::path::Path::new("a.py"), py),
            "SSRF"
        ));
    }

    #[test]
    fn detects_ssrf_go_php_java_csharp() {
        let go = "package main\n\nfunc proxy(r *http.Request) {\n\tu := r.URL.Query().Get(\"u\")\n\thttp.Get(u)\n}\n";
        assert!(has_class(
            &scan_file(std::path::Path::new("a.go"), go),
            "SSRF"
        ));
        let php = "<?php\nfunction p() {\n    $u = $_GET['u'];\n    $c = curl_init($u);\n}\n";
        assert!(has_class(
            &scan_file(std::path::Path::new("a.php"), php),
            "SSRF"
        ));
        let java = "class A {\n    void p(HttpServletRequest request) {\n        String u = request.getParameter(\"u\");\n        new URL(u).openStream();\n    }\n}\n";
        assert!(has_class(
            &scan_file(std::path::Path::new("A.java"), java),
            "SSRF"
        ));
        let cs = "class A {\n    void P() {\n        var u = Request.QueryString[\"u\"];\n        var w = new WebClient();\n        w.DownloadString(u);\n    }\n}\n";
        assert!(has_class(
            &scan_file(std::path::Path::new("A.cs"), cs),
            "SSRF"
        ));
    }

    #[test]
    fn detects_ssrf_ruby_open_uri() {
        let src = "def proxy(params)\n  open(params[:url])\nend\n";
        assert!(has_class(
            &scan_file(std::path::Path::new("a.rb"), src),
            "SSRF"
        ));
    }

    #[test]
    fn ruby_has_sources_and_function_blocks() {
        // Ruby had neither a source row nor a def/end block rule, so no Ruby
        // file could taint at all. This asserts both halves at once.
        let src = "def show(params)\n  collection.find_one(:user => params[:user])\nend\n";
        assert!(
            has_class(&scan_file(std::path::Path::new("m.rb"), src), "NoSQL"),
            "ruby needs a source row and def/end blocks to taint at all: {:?}",
            scan_file(std::path::Path::new("m.rb"), src)
        );
    }

    // ------------------------------------------- constants, argued positionally
    //
    // The first version of this decided a line was constant by checking that no
    // unrecognised identifier appeared on it, against a hand written list of type
    // and keyword names. That list was a trap: add a type it did not know and the
    // line stopped being recognised as constant, so precision decayed silently
    // rather than failing. The tests below pin the replacement, which looks at the
    // argument positions that actually matter.

    /// The general shape, so the rule is not special cased for C: whatever the
    /// sink is called, if the value handed to it is a literal the line is constant.
    /// A type name the tool has never seen does not change the answer.
    #[test]
    fn an_unseen_type_name_does_not_break_the_constant_case() {
        // `wchar_t` appears nowhere in any keyword list and `strcpy` is not
        // special. Both are ordinary and neither carries input.
        let src = "void f(void){\n    wchar_t b[16];\n    strcpy(b, L\"hi\");\n}\n";
        let r = scan_file(std::path::Path::new("a.c"), src);
        assert!(
            r.is_empty(),
            "an unknown type must not defeat a literal: {r:?}"
        );
    }

    /// The negative for the same shape, and the reason argument position matters:
    /// an unknown *function* on the line does carry input, whatever the sink is
    /// called. `mystery_reader()` is not a source on its own, so the source has to
    /// be the environment read it wraps, which is the shape that actually occurs.
    #[test]
    fn an_unseen_function_still_taints() {
        let src = "#include <string.h>\nvoid f(void){\n    char b[8];\n    char *p = mystery_reader(getenv(\"X\"));\n    strcpy(b, p);\n}\n";
        let r = scan_file(std::path::Path::new("a.c"), src);
        assert!(
            has_class(&r, "unbounded copy"),
            "an unknown call must not defeat the flow: {r:?}"
        );
    }

    /// Buffer size is not a source of input. A line naming a large constant must
    /// not be treated as tainted by the mere presence of a number.
    #[test]
    fn a_buffer_size_is_not_tainted() {
        let src = "void f(void){\n    char b[4096];\n    memset(b, 0, sizeof b);\n}\n";
        let r = scan_file(std::path::Path::new("a.c"), src);
        assert!(!has_class(&r, "unbounded copy"), "{r:?}");
    }

    /// The shape that actually matters for the JS gap: a template literal
    /// carrying an interpolation is not a constant and still flows, while the
    /// `$1` placeholder form binds its value and cannot.
    ///
    /// The sanitizer row is written as a literal, not a regex. `prepare` expands
    /// `\b`, `\s`, `.`, `(`, `)` and `$` into substring candidates and matches by
    /// `str::contains`; it is not a regex engine, so a pattern using `\w+` or a
    /// character class silently produces nothing that can ever match. Two earlier
    /// attempts to express "a bound parameter list" that way were dead rows.
    #[test]
    fn js_interpolation_flows_and_a_placeholder_does_not() {
        let bad = "function f(req){ return db.query(`SELECT * FROM t WHERE id=${req.query.id}`); }";
        assert!(
            has_class(&scan_file(std::path::Path::new("a.js"), bad), "SQL"),
            "an interpolated query is still injectable"
        );
        let good =
            "function f(req){ return db.query('SELECT * FROM t WHERE id=$1', [req.query.id]); }";
        assert!(
            !has_class(&scan_file(std::path::Path::new("b.js"), good), "SQL"),
            "a placeholder cannot change the statement: {:?}",
            scan_file(std::path::Path::new("b.js"), good)
        );
    }

    /// Every sanitizer row has to be expressible in the little language the
    /// matcher actually speaks. It is not a regex engine: `prepare` rewrites
    /// `\b`, `\s`, `.`, `(`, `)` and `$`, expands `\s*` into spacing variants, and
    /// splits `(a|b|c)` alternation into separate candidates. Everything else in a
    /// row is literal text.
    ///
    /// So `\w+`, `[abc]` and a bare `|` produce candidates that can never match
    /// anything, which is how two earlier rows in this table ended up dead while
    /// compiling perfectly. A dead row is worse than no row, because the table
    /// looks covered.
    #[test]
    fn every_sanitizer_row_is_expressible_by_the_matcher() {
        // Character classes and quantifiers the matcher has no notion of. A class
        // like `[^)]` is fine because the matcher reads the bracket as ordinary
        // text, so only the two shorthand classes are genuinely dead.
        const DEAD: &[&str] = &[r"\w", r"\d", r"\S", r"\W", r"\D"];
        for (lang, pat) in SANITIZERS {
            for bad in DEAD {
                assert!(
                    !pat.contains(bad),
                    "sanitizer row for {lang} contains `{bad}`, which the literal matcher reads as plain text rather than as a pattern, so the row cannot do what it claims: {pat}"
                );
            }
            // Every row must produce at least one candidate, otherwise it is dead.
            let (_sb, _eb, candidates, _nd) = prepare(pat);
            assert!(
                !candidates.is_empty(),
                "sanitizer row for {lang} produces no candidate and can never match: {pat}"
            );
        }
    }

    /// The generic identifier heuristic is gone, and this pins why. It treated a
    /// variable named `validated` or `escaped` as neutral, which is a guess about
    /// a name, and a guess that silences a security finding is the wrong trade: it
    /// can only ever lose a true positive and never gain one. A project that wraps
    /// an escape in `safe_shell()` now gets a false positive, which is the honest
    /// direction because it is visible and fixable by adding a named row.
    #[test]
    fn an_identifier_called_validated_is_not_treated_as_sanitised() {
        let src = "def run\n  system(\"rsync #{params[:dir]}\" + validated)\nend\n";
        let r = scan_file(std::path::Path::new("a.rb"), src);
        assert!(
            has_class(&r, "shell"),
            "a variable name is not proof of escaping: {r:?}"
        );
    }

    /// A real sanitizer still works, which is what keeps the removal from being a
    /// blanket loss of precision.
    #[test]
    fn a_named_sanitizer_still_neutralises() {
        let src = "def run\n  system(\"rsync #{params[:dir]}\" + Shellwords.escape(x))\nend\n";
        let r = scan_file(std::path::Path::new("a.rb"), src);
        assert!(
            !has_class(&r, "shell"),
            "a named escape must still work: {r:?}"
        );
    }

    // ------------------------------------------------- sanitizers and constants
    //
    // The rule tables had sources and sinks and nothing in between, so precision
    // had to come from writing timid sinks. `strncpy` was excluded from a group
    // with `strcpy` because it is often the safe choice, which is the wrong
    // reason: the right reason is that nothing escaped the value. Sanitizers let
    // the rule be broad and the precision come from the escape.

    /// A value that passes through a sanitizer stops being a finding. This is the
    /// single highest value addition and it is borrowed from semgrep's taint mode,
    /// which has the same three tables and no more.
    #[test]
    fn a_shell_escaped_value_is_not_a_finding() {
        let src = "def run\n  system(\"rsync #{Shellwords.escape(params[:dir])} backup:\")\nend\n";
        let r = scan_file(std::path::Path::new("a.rb"), src);
        assert!(
            r.is_empty(),
            "an escaped argument must not be reported: {r:?}"
        );
    }

    /// And the negative: the same call without the escape still fires. A sanitizer
    /// table that swallowed everything would pass the test above.
    #[test]
    fn an_unescaped_value_is_still_a_finding() {
        let src = "def run\n  system(\"rsync #{params[:dir]} backup:\")\nend\n";
        let r = scan_file(std::path::Path::new("a.rb"), src);
        assert!(has_class(&r, "shell"), "{r:?}");
    }

    /// Python, where `shlex.quote` is the canonical escape.
    #[test]
    fn python_shlex_quote_stops_the_flow() {
        let src = "import shlex\ncmd = \"rsync %s\" % shlex.quote(req.args)\nsubprocess.run(cmd, shell=True)\n";
        let r = scan_file(std::path::Path::new("a.py"), src);
        assert!(
            !has_class(&r, "shell"),
            "a quoted command must not be reported: {r:?}"
        );
    }

    /// The second half of the same idea: a literal is never a source. `strcpy` of a
    /// string constant into a buffer cannot be an overflow driven by input, and
    /// before this the only reason it stayed quiet was a regex that happened to
    /// miss it.
    #[test]
    fn a_literal_cannot_be_tainted() {
        let src =
            "void f(void){\n    char b[8];\n    char *p = \"literal\";\n    strcpy(b, p);\n}\n";
        let r = scan_file(std::path::Path::new("a.c"), src);
        assert!(
            r.is_empty(),
            "a name bound only to a literal is not tainted: {r:?}"
        );
    }

    /// One line, one finding. Five ruby shell rows can all match a single
    /// `system("rsync #{params[:dir]} backup:")`, and when the class strings were
    /// invented locally rather than taken from the table's own vocabulary the
    /// guard printed it twice. The dedup key is the printed class, so an off
    /// vocabulary string silently disables it. A duplicate finding on a real line
    /// trains people to ignore the output, which is worse than missing one.
    #[test]
    fn a_line_matching_several_shell_rows_reports_once() {
        let src = "def run\n  system(\"rsync #{params[:dir]} backup:\")\nend\n";
        let r = scan_file(std::path::Path::new("a.rb"), src);
        let crit: Vec<&TaintReport> = r.iter().filter(|x| x.severity == "critical").collect();
        assert_eq!(
            crit.len(),
            1,
            "one tainted line must produce one finding: {r:?}"
        );
    }

    /// A one line function is dense, ordinary and was completely invisible. It
    /// opens and closes its brace on the same line, so a block rule that only
    /// pushes when the depth reaches zero on some later line drops it. In C this
    /// is not a style, it is how small helpers are written.
    #[test]
    fn a_one_line_c_function_is_still_a_block() {
        let src = "#include <string.h>\nvoid run(void){char b[8];strcpy(b,getenv(\"X\"));}\n";
        let r = scan_file(std::path::Path::new("a.c"), src);
        assert!(
            has_class(&r, "unbounded copy"),
            "a one line C function must be scanned: {r:?}"
        );
    }

    /// The multi line form must keep working, since the fix changed how a block
    /// is closed rather than only adding a case.
    #[test]
    fn a_multi_line_c_function_is_still_a_block() {
        let src = "#include <string.h>\nvoid run(void){\n    char b[8];\n    char *p = getenv(\"X\");\n    strcpy(b, p);\n}\n";
        let r = scan_file(std::path::Path::new("b.c"), src);
        assert!(has_class(&r, "unbounded copy"), "{r:?}");
    }

    /// And the benign twin in the same shape: a one line function whose copy is
    /// a literal must stay quiet. Without this the new case would put a critical
    /// on correct compact C.
    #[test]
    fn a_one_line_c_function_with_a_literal_stays_quiet() {
        let src = "#include <string.h>\nvoid setup(void){char b[16];strcpy(b, \"hi\");}\n";
        let r = scan_file(std::path::Path::new("ok.c"), src);
        assert!(
            r.is_empty(),
            "a literal into an ample buffer is not a finding: {r:?}"
        );
    }

    /// A Rails controller method with no parameters. The block rule required
    /// parentheses, which every Ruby method taking no argument lacks, so `def
    /// index` produced no block and every flow inside it was invisible. This is
    /// the shape a real controller has.
    #[test]
    fn a_bare_def_method_is_still_a_block() {
        let src = "def index\n  system(params[:cmd])\nend\n";
        let r = scan_file(std::path::Path::new("m.rb"), src);
        assert!(
            has_class(&r, "shell"),
            "a parenless def must still be scanned: {r:?}"
        );
    }

    /// The negative for the block rule: a comment that merely starts with `def`
    /// must not open a block, or the file gets a block spanning code it does not
    /// own and the indentation rule starts attributing lines to the wrong method.
    #[test]
    fn a_comment_that_looks_like_a_def_is_not_a_block() {
        let src = "def real\n  x\nend\n# def not_a_method\nsystem(params[:c])\n";
        let lines: Vec<&str> = src.lines().collect();
        let b = function_blocks(&lines, "ruby");
        assert!(
            !b.iter().any(|(_, e, _)| *e >= 3),
            "a commented def must not open a block: {b:?}"
        );
    }

    /// And the benign twin: a literal command is ordinary Ruby and stays quiet,
    /// as does an interpolated string that is not a command.
    #[test]
    fn ordinary_ruby_stays_quiet() {
        let a = scan_file(
            std::path::Path::new("ok.rb"),
            "def build\n  system('make clean')\nend\n",
        );
        assert!(a.is_empty(), "a literal command is not a finding: {a:?}");
        let b = scan_file(
            std::path::Path::new("ok.rb"),
            "def label\n  puts \"value: #{name}\"\nend\n",
        );
        assert!(b.is_empty(), "string interpolation is not execution: {b:?}");
    }

    #[test]
    fn ruby_file_open_is_not_reported_as_ssrf() {
        // Ruby's bare open( is also File.open, which is path handling rather
        // than request forgery. Reporting it as SSRF would be a wrong class.
        let src = "def read(params)\n  File.open(params[:path]) { |f| f.read }\nend\n";
        let reports = scan_file(std::path::Path::new("a.rb"), src);
        assert!(!has_class(&reports, "SSRF"), "{:?}", reports);
    }

    #[test]
    fn a_constant_url_inside_a_handler_stays_silent() {
        // The point of the strict gate. The handler reads user input on the
        // first line, so the old flow gate would have fired here.
        let src = "app.get('/health', async (req, res) => {\n  const id = req.query.id;\n  const r = await fetch('https://api.example.com/health');\n  res.json({ id, r });\n});\n";
        let reports = scan_file(std::path::Path::new("routes.js"), src);
        assert!(!has_class(&reports, "SSRF"), "{:?}", reports);
    }

    #[test]
    fn cloud_metadata_fetch_is_labelled_for_what_it_is() {
        // The metadata address is on the line and the path is user controlled,
        // so this is credential theft rather than a generic SSRF.
        let src = "async function creds(req) {\n  const p = req.query.path;\n  const r = await fetch('http://169.254.169.254/' + p);\n  return r.text();\n}\n";
        let reports = scan_file(std::path::Path::new("meta.js"), src);
        let r = reports
            .iter()
            .find(|r| r.message.contains("metadata"))
            .expect("metadata class finding");
        assert!(
            r.message.contains("a cloud metadata fetch sink"),
            "{}",
            r.message
        );
    }

    #[test]
    fn a_tainted_host_stays_plain_ssrf() {
        // The address is not on the line, it arrives through the variable, so
        // the report must not claim to know the target was metadata.
        let src = "async function proxy(req) {\n  const url = req.query.url;\n  const r = await fetch(url);\n  return r.text();\n}\n";
        let reports = scan_file(std::path::Path::new("m.js"), src);
        assert!(has_class(&reports, "SSRF"), "{:?}", reports);
        assert!(!has_class(&reports, "metadata"), "{:?}", reports);
    }

    // ---- NoSQL ------------------------------------------------------------

    #[test]
    fn detects_nosql_javascript_collection_find() {
        let src = "async function search(req) {\n  const filter = req.query.filter;\n  return UserModel.find(JSON.parse(filter));\n}\n";
        let reports = scan_file(std::path::Path::new("m.js"), src);
        assert!(
            has_class(&reports, "NoSQL"),
            "a tainted filter into a document query must report NoSQL, got {:?}",
            reports
        );
    }

    #[test]
    fn detects_nosql_python_and_document_parse() {
        let py = "def search(request):\n    flt = request.args['filter']\n    return collection.find(flt)\n";
        assert!(has_class(
            &scan_file(std::path::Path::new("m.py"), py),
            "NoSQL"
        ));
        let java = "class A {\n    void p(HttpServletRequest request) {\n        String q = request.getParameter(\"q\");\n        Document doc = Document.parse(q);\n    }\n}\n";
        assert!(has_class(
            &scan_file(std::path::Path::new("A.java"), java),
            "NoSQL"
        ));
    }

    #[test]
    fn detects_nosql_where_and_dollar_where() {
        let js = "function findOne(req) {\n  return Account.where({ user: req.query.user }).exec();\n}\n";
        assert!(has_class(
            &scan_file(std::path::Path::new("m.js"), js),
            "NoSQL"
        ));
        let js2 = "function run(req) {\n  return db.collection('a').find({ $where: 'this.x == ' + req.query.x });\n}\n";
        assert!(has_class(
            &scan_file(std::path::Path::new("m.js"), js2),
            "NoSQL"
        ));
    }

    #[test]
    fn detects_nosql_go_csharp_ruby_php() {
        let go = "package main\n\nfunc find(r *http.Request) {\n\tf := r.URL.Query().Get(\"f\")\n\tcollection.Find(bson.M{\"a\": f})\n}\n";
        assert!(has_class(
            &scan_file(std::path::Path::new("a.go"), go),
            "NoSQL"
        ));
        let cs = "class A {\n    void P() {\n        var f = Request.QueryString[\"f\"];\n        var d = BsonDocument.Parse(f);\n    }\n}\n";
        assert!(has_class(
            &scan_file(std::path::Path::new("A.cs"), cs),
            "NoSQL"
        ));
        let rb = "def find_one(params)\n  Model.where(:user => params[:user])\nend\n";
        assert!(has_class(
            &scan_file(std::path::Path::new("m.rb"), rb),
            "NoSQL"
        ));
        let php = "<?php\nfunction f() {\n    $f = $_GET['f'];\n    $collection->find($f);\n}\n";
        assert!(has_class(
            &scan_file(std::path::Path::new("m.php"), php),
            "NoSQL"
        ));
        // A Mongo driver specific method is caught even with a terse receiver.
        let php2 =
            "<?php\nfunction f() {\n    $f = $_GET['f'];\n    $c->findOneAndUpdate($f);\n}\n";
        assert!(has_class(
            &scan_file(std::path::Path::new("m.php"), php2),
            "NoSQL"
        ));
    }

    #[test]
    fn a_literal_query_object_stays_silent() {
        let src = "function list(req) {\n  const page = req.query.page;\n  return postsCollection.find({ published: true, page: 1 });\n}\n";
        let reports = scan_file(std::path::Path::new("m.js"), src);
        assert!(!has_class(&reports, "NoSQL"), "{:?}", reports);
    }

    #[test]
    fn array_find_is_not_a_nosql_sink() {
        // The co occurrence list is what keeps arr.find( silent while
        // collection.find( reports.
        let src = "function first(req) {\n  const id = req.query.id;\n  return items.find(i => i.id === id);\n}\n";
        let reports = scan_file(std::path::Path::new("m.js"), src);
        assert!(!has_class(&reports, "NoSQL"), "{:?}", reports);
    }

    // ---- TypeScript -------------------------------------------------------

    #[test]
    fn typescript_files_are_scanned_at_all() {
        // .ts mapped to "typescript" and the taint tables had no typescript
        // rows, so every TypeScript file was silently unscanned.
        let src = "export async function load(req: Request) {\n  const id = req.query.id;\n  return db.query(id);\n}\n";
        let reports = scan_file(std::path::Path::new("db.ts"), src);
        assert!(
            has_class(&reports, "SQL"),
            "TypeScript must reach the JavaScript rules, got {:?}",
            reports
        );
    }

    #[test]
    fn typescript_gets_the_new_sinks_too() {
        let src = "export async function proxy(req: Request) {\n  const target = req.query.url;\n  return fetch(target);\n}\n";
        let reports = scan_file(std::path::Path::new("route.ts"), src);
        assert!(has_class(&reports, "SSRF"), "{:?}", reports);
    }

    #[test]
    fn the_article_matches_the_class() {
        assert_eq!(article("SSRF"), "an");
        assert_eq!(article("NoSQL"), "a");
        assert_eq!(article("cloud metadata fetch"), "a");
        assert_eq!(article("SQL"), "a");
    }
    // -------------------------------------------- third party code is not our code
    //
    // The corpus that took 600 seconds contained three vendored files that together
    // accounted for 62 of the 267 seconds the taint pass spent, and the largest was
    // 634KB of generated algebra code. `practice.rs` already declines to police
    // third party assets but its test only looks at the file name, so a file at
    // `lib/vendors/nerdamer-prime/nerdamer.core.js` slipped through even there.
    //
    // These assert the limit rather than the intent: a taint finding inside vendored
    // code is a real finding about code heides did not write, and dropping it is a
    // deliberate trade, not a free win. First party code must be unaffected, so every
    // case has a first party twin.

    // `super::*` is already in scope in this module, so it is not repeated here.

    fn tainted_in(path: &str, src: &str) -> bool {
        !scan_file(std::path::Path::new(path), src).is_empty()
    }

    /// A first party file with the identical flow. If this ever goes quiet, the
    /// vendor rule has eaten real code and that is the bug worth catching.
    #[test]
    fn first_party_code_is_still_scanned() {
        let src = "function load(req) {\n  const q = req.query.id;\n  db.query(q);\n}\n";
        assert!(
            tainted_in("src/routes/users.js", src),
            "first party code must be scanned"
        );
    }

    #[test]
    fn a_vendored_directory_is_not_scanned() {
        let src = "function load(req) {\n  const q = req.query.id;\n  db.query(q);\n}\n";
        assert!(
            !tainted_in("lib/vendors/nerdamer-prime/nerdamer.core.js", src),
            "a vendored directory is third party code"
        );
    }

    #[test]
    fn the_other_vendor_spellings_are_covered() {
        let src = "function load(req) {\n  const q = req.query.id;\n  db.query(q);\n}\n";
        for p in [
            "node_modules/pkg/index.js",
            "third_party/lib/thing.js",
            "vendor/bundle.js",
            "static/vendor.min.js",
            "dist/build.js",
            "build/output.js",
            "external/dep.js",
        ] {
            assert!(!tainted_in(p, src), "should be treated as third party: {p}");
        }
    }

    /// The twin that keeps the rule honest. A directory merely named like one of
    /// these, in a first party location, is still first party.
    #[test]
    fn a_first_party_path_containing_a_vendor_word_is_still_scanned() {
        let src = "function load(req) {\n  const q = req.query.id;\n  db.query(q);\n}\n";
        for p in [
            "src/vendor-portal/client.js",
            "app/distribution/index.js",
            "src/distillery/rules.js",
        ] {
            assert!(tainted_in(p, src), "must stay first party: {p}");
        }
    }

    /// A directory named `vendor` nested deeper, because that is where the measured
    /// cost was and a prefix match on the first segment would miss it.
    #[test]
    fn a_nested_vendor_directory_is_still_recognised() {
        let src = "def go(request):\n    q = request.args['q']\n    db.query(q)\n";
        assert!(
            !tainted_in("app/lib/vendors/pkg/thing.py", src),
            "nesting must not defeat the rule"
        );
    }
}

#[cfg(test)]
mod candidate_probe {
    use super::*;

    /// Diagnostic: what does the pattern expander actually produce per language?
    ///
    /// Three attempts to speed this pass up were based on an estimated candidate
    /// count rather than a measured one, and all three were wrong. This test
    /// exists so the number is read rather than guessed. Quiet unless
    /// `HEIDES_CANDIDATE_PROBE` is set, because a test that prints on every run
    /// is noise in the suite.
    #[test]
    fn measure_the_real_candidate_counts() {
        let mut by_lang: std::collections::BTreeMap<&str, usize> =
            std::collections::BTreeMap::new();
        let mut total = 0usize;
        for (l, pat) in SOURCES {
            let n = prepare(pat).2.len();
            total += n;
            *by_lang.entry(l).or_default() += n;
        }
        for (l, pat, _) in SINKS {
            let n = prepare(pat).2.len();
            total += n;
            *by_lang.entry(l).or_default() += n;
        }
        assert!(total > 0, "the table must not be empty");
        if std::env::var("HEIDES_CANDIDATE_PROBE").is_ok() {
            println!("CANDIDATE TOTAL: {total}");
            let mut v: Vec<_> = by_lang.into_iter().collect();
            v.sort_by_key(|x| std::cmp::Reverse(x.1));
            for (l, n) in v {
                println!("  {n:8}  {l}");
            }
        }
    }

    /// The bound that made this pass viable. Before the whitespace run was
    /// narrowed, one javascript row expanded to 27500 candidates because its
    /// three `\s*` each produced five variants across 31 alternation branches.
    /// This pins the result so a future row cannot quietly reintroduce it.
    #[test]
    fn no_language_costs_a_pathological_number_of_candidates_per_line() {
        let mut by_lang: std::collections::BTreeMap<&str, usize> =
            std::collections::BTreeMap::new();
        for (l, pat) in SOURCES {
            *by_lang.entry(l).or_default() += prepare(pat).2.len();
        }
        for (l, pat, _) in SINKS {
            *by_lang.entry(l).or_default() += prepare(pat).2.len();
        }
        for (lang, n) in &by_lang {
            assert!(
                *n < 4000,
                "{lang} asks for {n} substring searches per line, which is how \
                 the taint pass came to cost 124 seconds on 364 files"
            );
        }
    }
}
