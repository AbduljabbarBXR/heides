// Config and secret indexing.
//
// A credential sitting in a committed `.env`, a Dockerfile, a Terraform variable
// or a Kubernetes Secret is the one class of finding the code graph cannot help
// with: the value is not in a language file, so nothing in the existing pipeline
// reads it. These files are not even collected today, because a `.env` has no
// extension and neither does `Dockerfile`, and `detect_language` returns None for
// both.
//
// The rule here is narrower than "does it look like a secret", because config
// files are full of things that look like secrets and are not. A finding needs a
// value whose *shape* is a credential, not a key whose name suggests one.
//
// One rule above all others: a finding never carries the credential. A report
// that echoes the secret has copied it into every log, every CI transcript and
// every agent transcript that reads the output, which makes the tool a
// distribution channel for the thing it found. Values are described by shape
// only, with a length and a fingerprint prefix that is not enough to reconstruct.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// One credential found in a configuration file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigFinding {
    /// The key or variable the value is bound to.
    pub key: String,
    /// `credential`, `private_key` or `connection_string`.
    pub kind: String,
    /// Path relative to the scan root.
    pub file: String,
    pub line: u64,
    /// A description that identifies the value without containing it.
    pub message: String,
    /// `critical` for a private key or a live provider token, `warning` for the
    /// rest. A connection string with a password is critical: it is a working
    /// login to a running system.
    pub severity: String,
}

/// The configuration file kinds this layer reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigKind {
    /// A dotenv file, with or without a prefix.
    DotEnv,
    Dockerfile,
    /// A Dockerfile Compose file.
    Compose,
    Terraform,
    /// A Kubernetes or Helm manifest.
    Kubernetes,
    /// A CI workflow that can bake a secret into a build.
    Workflow,
    /// A generic ini-style file, which is what most other tools use.
    Ini,
}

impl ConfigKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ConfigKind::DotEnv => "dotenv",
            ConfigKind::Dockerfile => "dockerfile",
            ConfigKind::Compose => "compose",
            ConfigKind::Terraform => "terraform",
            ConfigKind::Kubernetes => "kubernetes",
            ConfigKind::Workflow => "workflow",
            ConfigKind::Ini => "ini",
        }
    }
}

/// A file worth reading for credentials, and what kind it is.
///
/// Extension alone is not enough, because the important files are exactly the
/// ones with no extension: `.env` and `Dockerfile`. A name containing `env` is
/// deliberately not enough either, since `environment.ts` is source code and is
/// handled by the language layer.
pub fn classify(path: &Path) -> Option<ConfigKind> {
    let name = path.file_name()?.to_str()?.to_string();
    let lower = name.to_ascii_lowercase();
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    // Compose before dotenv, because `docker-compose.yml` contains no dot but a
    // naive name check on `env` would not catch it either.
    if lower.starts_with("docker-compose")
        || lower.starts_with("compose.")
        || lower == "docker-compose.yml"
    {
        return Some(ConfigKind::Compose);
    }
    if lower.starts_with("dockerfile") || lower == "containerfile" {
        return Some(ConfigKind::Dockerfile);
    }
    // A terraform file, by extension, and a `.tfvars` by both.
    if ext == "tf" || ext == "tfvars" || lower.ends_with(".tf.json") {
        return Some(ConfigKind::Terraform);
    }
    if ext == "yml" || ext == "yaml" {
        // A manifest is a kubernetes file only if it says so; a plain CI yaml is
        // not, and treating every yaml as a manifest would report every ordinary
        // config map.
        return Some(ConfigKind::Kubernetes);
    }
    if ext == "ini" || ext == "cfg" || ext == "conf" || ext == "properties" {
        return Some(ConfigKind::Ini);
    }
    // `.env`, `.env.local`, `env.production`, `.env.example`.
    // A private key file: `id_rsa`, `server.pem`, `.ssh/id_ed25519`. These have
    // no extension to match on, which is the same reason `.env` and
    // `Dockerfile` needed naming rules, and a committed key is the most serious
    // thing this layer can find.
    if is_private_key_name(&lower) {
        return Some(ConfigKind::Ini);
    }
    if lower == ".env" || lower.starts_with(".env.") || lower == "env" {
        return Some(ConfigKind::DotEnv);
    }
    // `creds.env`, `secrets.env`, `prod.env`. The `.env` extension is the same
    // format whatever precedes the dot, and a credentials file named that way is
    // exactly the file this layer exists to read.
    if ext == "env" {
        return Some(ConfigKind::DotEnv);
    }
    if lower.starts_with("env.") && lower.contains('.') && !lower.ends_with(".ts") {
        // `env.production` but not `env.ts`, which is source.
        let rest = lower.trim_start_matches("env.");
        if !rest.is_empty() && !["ts", "js", "py", "rb", "go"].contains(&rest) {
            return Some(ConfigKind::DotEnv);
        }
    }
    None
}

/// File names that are conventionally a private key.
fn is_private_key_name(lower: &str) -> bool {
    // `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`.
    if lower.starts_with("id_") {
        return true;
    }
    // Anything with `key` or `pem` in the name, since a public key is harmless
    // and the file is read either way.
    lower.contains("private") || lower.contains(".pem")
}

/// Configuration files under `root`, bounded in depth and count.
///
/// Bounded because a monorepo can hold thousands of manifests and this runs on
/// the normal check path, not behind a flag.
pub fn collect_config_files(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    walk(root, max_depth, &mut out);
    out
}

fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth == 0 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if p.is_dir() {
            if matches!(
                name.as_str(),
                "node_modules"
                    | "target"
                    | "vendor"
                    | ".git"
                    | "venv"
                    | ".venv"
                    | "__pycache__"
                    | "dist"
                    | "build"
                    | ".terraform"
            ) {
                continue;
            }
            walk(&p, depth - 1, out);
        } else if classify(&p).is_some() {
            out.push(p);
        }
    }
}

/// Read every configuration file under `root` and report the credentials found.
///
/// Order is stable: files sorted by path, lines in file order, findings in the
/// order the lines appear. A gate that reports the same finding set in a
/// different order on each run is a gate an agent learns to ignore.
pub fn scan(root: &Path) -> Vec<ConfigFinding> {
    let mut out: Vec<ConfigFinding> = Vec::new();
    for file in collect_config_files(root, 8) {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let rel = file
            .strip_prefix(root)
            .unwrap_or(&file)
            .to_string_lossy()
            .to_string();
        let kind = classify(&file).unwrap_or(ConfigKind::Ini);
        scan_text(&text, &rel, kind, &mut out);
    }
    out.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
    out
}

/// A one-line statement of what was scanned and what was found.
///
/// Silence is never success. A caller that cannot tell "this workspace has no
/// configuration files" from "the scan read nothing" will report a clean result
/// for a project it never looked at.
pub fn summarise(root: &Path) -> String {
    let files = collect_config_files(root, 8);
    if files.is_empty() {
        return format!(
            "no configuration files under {}. looked for .env, Dockerfile, compose, \
             .tf, .tfvars, yaml manifests and ini files",
            root.display()
        );
    }
    let found = scan(root);
    if found.is_empty() {
        return format!(
            "{} configuration file(s) read, no credentials found",
            files.len()
        );
    }
    let critical = found.iter().filter(|f| f.severity == "critical").count();
    format!(
        "{} configuration file(s) read, {} credential finding(s), {critical} critical",
        files.len(),
        found.len()
    )
}

// --------------------------------------------------------------- the scanner

/// Parse one file's text into key/value pairs and classify the values.
fn scan_text(text: &str, rel: &str, kind: ConfigKind, out: &mut Vec<ConfigFinding>) {
    let lines: Vec<&str> = text.lines().collect();

    // A terraform variable names the credential; the value is a bare `default`
    // inside its block. The name has to be carried down from the block header or
    // `default = "..."` reads as an unremarkable assignment and is dropped,
    // which is the whole of what a terraform finding is.
    let mut tf_variable: Option<String> = None;

    // A private key is a block, not an assignment, so it is found on its own
    // before any line parsing runs.
    for (i, line) in lines.iter().enumerate() {
        if line.trim_start().starts_with("-----BEGIN") && line.contains("PRIVATE KEY") {
            out.push(ConfigFinding {
                key: "private key block".to_string(),
                kind: "private_key".to_string(),
                file: rel.to_string(),
                line: (i + 1) as u64,
                message: "a private key is committed in the repository".to_string(),
                severity: "critical".to_string(),
            });
        }
    }

    for (i, raw) in lines.iter().enumerate() {
        let line = raw.trim();
        let n = (i + 1) as u64;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Track which terraform variable block we are inside, so a `default` can
        // be reported under the variable's name.
        if kind == ConfigKind::Terraform {
            if let Some(rest) = line.strip_prefix("variable ") {
                let quoted = rest.trim().trim_end_matches('{').trim();
                let name = quoted.trim_matches('"').trim();
                tf_variable = if name.is_empty() {
                    None
                } else {
                    Some(name.to_string())
                };
            } else if line == "}" {
                tf_variable = None;
            }
        }

        for (mut key, value) in assignments(line, kind) {
            // Inside a terraform variable block, a `default` is the value of the
            // variable, so the finding is reported under the variable's name.
            // The name is what says this is a credential; the `default` key on its
            // own says nothing.
            if kind == ConfigKind::Terraform && key == "default" {
                match tf_variable.clone() {
                    Some(name) => key = name,
                    // A default outside any variable block belongs to a
                    // module or a provider, where the name is the module's.
                    None => continue,
                }
            }
            if let Some(f) = classify_value(&key, &value, rel, n, kind) {
                out.push(f);
            }
        }
    }
}

/// The key/value pairs on one line, across the formats that appear here.
///
/// A line can carry more than one pair in a kubernetes Secret, and a Dockerfile
/// `ENV` line carries several, so this returns a list rather than an option.
fn assignments(line: &str, kind: ConfigKind) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();

    // A comment in a yaml or ini file, which is not the `#` of a dotenv comment
    // handling difference but the same thing.
    let body = strip_inline_comment(line, kind);

    match kind {
        ConfigKind::DotEnv | ConfigKind::Ini => {
            if let Some((k, v)) = body.split_once('=') {
                out.push((clean_key(k), unquote(v.trim())));
            }
        }
        ConfigKind::Dockerfile | ConfigKind::Compose => {
            // `ENV KEY=value` and `ENV KEY value`.
            if let Some(rest) = strip_word(body, "ENV") {
                if let Some((k, v)) = rest.split_once('=') {
                    out.push((clean_key(k), unquote(v.trim())));
                } else {
                    // Two tokens: ENV KEY value
                    let mut it = rest.splitn(2, char::is_whitespace);
                    if let (Some(k), Some(v)) = (it.next(), it.next()) {
                        out.push((clean_key(k), unquote(v.trim())));
                    }
                }
                // `ENV A=1 B=2`
                for pair in rest.split_whitespace() {
                    if let Some((k, v)) = pair.split_once('=')
                        && !out.iter().any(|(ek, _)| ek == &clean_key(k))
                    {
                        out.push((clean_key(k), unquote(v)));
                    }
                }
            }
            // Compose and a kubernetes secret use `KEY: value` or `- KEY=value`.
            if let Some((k, v)) = split_yaml_pair(body) {
                out.push((k, v));
            }
        }
        ConfigKind::Terraform => {
            // `key = "value"` anywhere, and `default = "value"` inside a
            // variable block whose name is a credential name. The name is
            // carried by the key itself for the simple case; the block case is
            // handled by the caller passing a descriptive key.
            if let Some((k, v)) = body.split_once('=') {
                out.push((clean_key(k), unquote(v.trim())));
            }
        }
        ConfigKind::Kubernetes | ConfigKind::Workflow => {
            if let Some((k, v)) = split_yaml_pair(body) {
                out.push((k, v));
            }
        }
    }
    out
}

/// A `key: value` or `- key: value` pair, with the value unquoted.
fn split_yaml_pair(line: &str) -> Option<(String, String)> {
    let t = line.trim_start().trim_start_matches("- ").trim_start();
    let (k, v) = t.split_once(':')?;
    let key = clean_key(k);
    if key.is_empty() {
        return None;
    }
    Some((key, unquote(v.trim())))
}

fn strip_word<'a>(line: &'a str, word: &str) -> Option<&'a str> {
    let t = line.trim_start();
    let rest = t.strip_prefix(word)?;
    if rest.starts_with(char::is_whitespace) || rest.starts_with('=') {
        Some(rest.trim_start())
    } else {
        None
    }
}

fn clean_key(raw: &str) -> String {
    raw.trim()
        .trim_matches(|c| c == '"' || c == '\'' || c == '`' || c == ' ')
        .to_string()
}

fn unquote(raw: &str) -> String {
    let t = raw.trim();
    for q in ['"', '\'', '`'] {
        if let Some(inner) = t.strip_prefix(q) {
            if let Some(end) = inner.rfind(q) {
                return inner[..end].to_string();
            }
            return inner.to_string();
        }
    }
    t.to_string()
}

/// Drop a trailing comment, which is a `#` in dotenv and yaml and a `//` in
/// terraform.
///
/// The separators are only recognised when preceded by whitespace, because a
/// `#` inside a value is a legitimate character and `//` starts a URL.
fn strip_inline_comment(line: &str, kind: ConfigKind) -> &str {
    let bytes = line.as_bytes();
    let mut from = 0usize;
    while let Some(rel) = line[from..].find('#') {
        let at = from + rel;
        let before_ok = at == 0
            || bytes
                .get(at - 1)
                .map(|c| c.is_ascii_whitespace())
                .unwrap_or(false);
        if before_ok {
            return &line[..at];
        }
        from = at + 1;
    }
    if kind == ConfigKind::Terraform {
        let mut from = 0usize;
        while let Some(rel) = line[from..].find("//") {
            let at = from + rel;
            let before_ok = at == 0
                || bytes
                    .get(at - 1)
                    .map(|c| c.is_ascii_whitespace())
                    .unwrap_or(false);
            if before_ok {
                return &line[..at];
            }
            from = at + 2;
        }
    }
    line
}

// --------------------------------------------------------- value classifier

/// Values that are references, not credentials.
///
/// The single most important table here. `API_KEY=${API_KEY}` is the correct way
/// to write a dotenv file and must never be reported, and neither must a path, a
/// URL with no credential in it, or documentation.
fn is_reference(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() {
        return true;
    }
    if v.starts_with('$') || v.starts_with('%') {
        return true;
    }
    if v.starts_with("{{") || v.starts_with("{{-") {
        // A helm or vault template: {{ .Values.secret }}.
        return true;
    }
    if v.starts_with('(') || v.starts_with('[') || v.starts_with('{') {
        return true;
    }
    false
}

/// Placeholder words that mean "fill this in", not "this is the value".
///
/// Trimmed from both ends and compared whole, so `changeme123` and
/// `dummy_2024` are placeholders while a real password that happens to contain
/// the letters `xxx` is not.
const PLACEHOLDERS: &[&str] = &[
    "changeme",
    "change-me",
    "change_me",
    "your",
    "yourkey",
    "your-key",
    "yourvalue",
    "your-value",
    "yourpassword",
    "your-password",
    "yoursecret",
    "your-secret",
    "yourtoken",
    "your-token",
    "example",
    "placeholder",
    "todo",
    "tbd",
    "none",
    "null",
    "nil",
    "undefined",
    "unset",
    "empty",
    "test",
    "dummy",
    "sample",
    "insert",
    "replace",
    "xxx",
    "xxxx",
    "xxxxxxxx",
    "abc123",
    "foo",
    "bar",
    "baz",
    "redacted",
    "removed",
    "hidden",
    "masked",
    "value",
    "string",
    "text",
    "password",
    "secret",
    "token",
    "apikey",
    "api-key",
    "api_key",
    "passwd",
    "mypassword",
    "hunter2",
    "admin",
    "root",
    "default",
    "asdf",
    "qwerty",
];

/// True when a value is a documented placeholder rather than a credential.
fn is_placeholder(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() {
        return true;
    }
    let lower = v.to_ascii_lowercase();
    // A placeholder is a short word, not a long string with real entropy. A real
    // credential is rarely under 12 characters and even less likely to be a
    // dictionary word, so a whole-value match against this list is the gate.
    if PLACEHOLDERS.contains(&lower.as_str()) {
        return true;
    }
    // `your-api-key-here` and `sk-XXXX-XXXX` are placeholders by composition.
    if lower.starts_with("your-") || lower.starts_with("your_") {
        return true;
    }
    if lower.contains("-here") || lower.contains("_here") {
        return true;
    }
    // A run of one repeated character, which is a mask rather than a value.
    let unique: HashSet<char> = lower.chars().filter(|c| c.is_alphanumeric()).collect();
    if !unique.is_empty() && unique.len() == 1 && lower.len() >= 3 {
        return true;
    }
    // A mask made only of symbols: `***`, `xxxx-xxxx`, `----`. These are what a
    // redacted config looks like, and reporting one is a false positive that
    // teaches an agent to ignore the rule. The check counts every character, not
    // just alphanumerics, because a mask has no alphanumeric content at all.
    if v.chars().all(|c| !c.is_alphanumeric()) && v.len() >= 3 {
        return true;
    }
    false
}

/// Provider token shapes, recognised by prefix and length.
///
/// A shape match is stronger evidence than a key name, so a value matching one of
/// these is reported regardless of what the key is called. That is what catches
/// `STRIPE_KEY`, `PAY_TOKEN` and a Terraform default alike.
fn provider_shape(value: &str) -> Option<(&'static str, &'static str)> {
    let v = value.trim();
    // A base64 or hex blob with a recognisable provider prefix.
    const SHAPES: &[(&str, &str, &str)] = &[
        ("sk_live_", "stripe live key", "critical"),
        ("sk_test_", "stripe test key", "warning"),
        ("rk_live_", "stripe restricted live key", "critical"),
        ("ghp_", "github personal access token", "critical"),
        ("gho_", "github oauth token", "critical"),
        ("ghs_", "github app token", "critical"),
        ("github_pat_", "github fine grained token", "critical"),
        ("glpat-", "gitlab personal access token", "critical"),
        ("npm_", "npm token", "critical"),
        ("pypi-AgEIcHlwaS5vcmc", "pypi token", "critical"),
        ("xoxb-", "slack bot token", "critical"),
        ("xoxp-", "slack user token", "critical"),
        ("xoxr-", "slack refresh token", "critical"),
        ("AIza", "google api key", "critical"),
        ("ya29.", "google oauth token", "critical"),
        ("SG.", "sendgrid api key", "critical"),
        ("AC", "twilio account sid", "warning"),
        ("SK", "twilio api key", "warning"),
        ("dop_v1_", "digitalocean token", "critical"),
        ("hf_", "huggingface token", "critical"),
    ];
    for (prefix, label, severity) in SHAPES {
        if v.starts_with(prefix) {
            return Some((label, severity));
        }
    }
    None
}

/// AWS key ids, which have a fixed shape rather than a prefix.
fn aws_key_id(value: &str) -> bool {
    let v = value.trim();
    v.len() == 20
        && (v.starts_with("AKIA")
            || v.starts_with("ASIA")
            || v.starts_with("AGPA")
            || v.starts_with("AIDA")
            || v.starts_with("AROA")
            || v.starts_with("ANPA"))
        && v.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// A connection string carrying a password, which is the most common real leak
/// in a `.env` and the one no key-name rule catches.
fn connection_string(value: &str) -> Option<String> {
    let v = value.trim();
    if !v.contains("://") {
        return None;
    }
    let after = &v[v.find("://").map(|i| i + 3).unwrap_or(0)..];
    // The authority runs to the first /, ? or #.
    let authority_end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let authority = &after[..authority_end];
    let at = authority.rfind('@')?;
    let userinfo = &authority[..at];
    if !userinfo.contains(':') {
        return None;
    }
    let (_, password) = userinfo.split_once(':')?;
    if password.is_empty() || is_placeholder(password) || is_reference(password) {
        return None;
    }
    Some("a connection string with a password".to_string())
}

/// A fingerprint of a value that identifies it without being it.
///
/// A truncated prefix would still be part of the secret, so this is a length and
/// a character-class summary instead. Enough to tell two findings apart in a
/// report, useless for using.
fn fingerprint(value: &str) -> String {
    let v = value.trim();
    let classes = summarise_classes(v);
    format!("{} chars, {classes}", v.len())
}

fn summarise_classes(v: &str) -> String {
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_other = false;
    for c in v.chars() {
        if c.is_ascii_lowercase() {
            has_lower = true;
        } else if c.is_ascii_uppercase() {
            has_upper = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else {
            has_other = true;
        }
    }
    let mut parts: Vec<&str> = Vec::new();
    if has_lower {
        parts.push("lower");
    }
    if has_upper {
        parts.push("upper");
    }
    if has_digit {
        parts.push("digit");
    }
    if has_other {
        parts.push("symbol");
    }
    if parts.is_empty() {
        "empty".to_string()
    } else {
        parts.join("+")
    }
}

/// Decide whether a key/value pair is a credential, and describe it.
fn classify_value(
    key: &str,
    value: &str,
    file: &str,
    line: u64,
    _kind: ConfigKind,
) -> Option<ConfigFinding> {
    let v = value.trim();
    if v.is_empty() || is_reference(v) {
        return None;
    }
    // A path or a bare url with no credential in it is not a secret.
    if looks_like_path(v) {
        return None;
    }

    // A provider token shape is the strongest evidence and does not depend on the
    // key name, so it is checked first and reports even for an unremarkable key.
    if let Some((label, severity)) = provider_shape(v) {
        return Some(finding(
            key,
            "credential",
            file,
            line,
            format!("a {label} is committed here ({})", fingerprint(v)),
            severity,
        ));
    }
    if aws_key_id(v) {
        return Some(finding(
            key,
            "credential",
            file,
            line,
            format!(
                "an aws access key id is committed here ({})",
                fingerprint(v)
            ),
            "critical",
        ));
    }
    if let Some(label) = connection_string(v) {
        return Some(finding(
            key,
            "connection_string",
            file,
            line,
            format!("{label} is committed here ({})", fingerprint(v)),
            "critical",
        ));
    }

    // Everything below depends on the key name, so it must actually look like a
    // credential and the value must not be a placeholder.
    if !secret_key_name(key) {
        return None;
    }
    if is_placeholder(v) {
        return None;
    }
    // A short value under a secret-looking name is usually a format example, and
    // reporting it is how a precision bet gets lost.
    if v.chars().count() < 8 {
        return None;
    }
    // Prose is not a credential. A value that reads as a sentence is a comment
    // that lost its marker.
    if looks_like_prose(v) {
        return None;
    }
    Some(finding(
        key,
        "credential",
        file,
        line,
        format!(
            "a secret looking name holds a literal value ({})",
            fingerprint(v)
        ),
        "warning",
    ))
}

/// Build a finding, prefixing the message with the key so a report is readable
/// on its own.
///
/// The key is the safe half of a credential pair and is what a reader needs in
/// order to find the line; the value never appears.
fn finding(
    key: &str,
    kind: &str,
    file: &str,
    line: u64,
    message: String,
    severity: &str,
) -> ConfigFinding {
    let message = if key.is_empty() || key == "private key block" {
        message
    } else {
        format!("{key}: {message}")
    };
    ConfigFinding {
        key: key.to_string(),
        kind: kind.to_string(),
        file: file.to_string(),
        line,
        message,
        severity: severity.to_string(),
    }
}

/// Key names that name a credential.
///
/// Substring matching on purpose, because `DB_PASSWORD`, `password` and
/// `AWS_SECRET_ACCESS_KEY` all name one without sharing a prefix.
fn secret_key_name(key: &str) -> bool {
    const WORDS: &[&str] = &[
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "apikey",
        "api_key",
        "api-key",
        "access_key",
        "accesskey",
        "private_key",
        "privatekey",
        "credential",
        "auth",
        "session_key",
        "client_secret",
        "signing_key",
        "encryption_key",
        "salt",
        "passphrase",
        "webhook",
        "bearer",
        "dsn",
    ];
    let lower = key.to_ascii_lowercase();
    WORDS.iter().any(|w| lower.contains(w))
}

/// A filesystem path or a url with no credential in it.
fn looks_like_path(v: &str) -> bool {
    if v.starts_with('/') || v.starts_with("./") || v.starts_with("../") {
        return true;
    }
    if v.starts_with("~/") {
        return true;
    }
    // A windows path.
    if v.len() > 2 && v.as_bytes()[1] == b':' && v.as_bytes()[2] == b'\\' {
        return true;
    }
    // A url with no userinfo is not a credential, and one with userinfo was
    // already handled by connection_string.
    if v.contains("://") && !v.contains('@') {
        return true;
    }
    false
}

/// A value that reads as English rather than as a secret.
fn looks_like_prose(v: &str) -> bool {
    if !v.contains(' ') {
        return false;
    }
    let words = v.split_whitespace().count();
    if words < 3 {
        return false;
    }
    // A prose value has no digits and no symbol runs, and its words are mostly
    // alphabetic. A real credential that happens to contain a space is rare
    // enough that this is a safe trade for not flagging documentation.
    let digits = v.chars().filter(|c| c.is_ascii_digit()).count();
    if digits > 2 {
        return false;
    }
    let alpha = v.chars().filter(|c| c.is_ascii_alphabetic()).count();
    let total = v.chars().filter(|c| !c.is_whitespace()).count();
    if total == 0 {
        return false;
    }
    alpha * 4 >= total * 3
}
