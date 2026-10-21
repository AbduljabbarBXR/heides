// Workspace policy: what gets scanned, what gets trusted, what gets ignored.
//
// A security tool that reports everything is a security tool nobody reads. The
// measurement behind this module: on a 82 file python workspace the guard
// produced 45 findings, most of them `console.log` in a CLI and `unwrap()`
// inside a test, plus the same file reported twice because the repository kept
// a mirrored copy under `npm/python/`. None of those are defects. All of them
// are on the list, and a list a user cannot edit is a list a user will mute
// with `|| true`.
//
// So the policy is a file in the repository, not a flag somewhere else:
//
//   .heidesignore          gitignore style patterns for paths
//   .heides/config.json    include, exclude, severity overrides, size, languages
//
// Both are optional. A workspace with neither is scanned exactly as before.
//
// The rules here are deliberately small and total. A policy language that can
// express everything is a policy language nobody can predict, and a security
// tool that behaves unpredictably is worse than one that behaves plainly.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The ignore file, at the workspace root.
pub const IGNORE_FILE: &str = ".heidesignore";

/// The config file, under the `.heides` directory at the workspace root.
pub const CONFIG_FILE: &str = ".heides/config.json";

/// The baseline file, under the `.heides` directory at the workspace root.
pub const BASELINE_FILE: &str = ".heides/baseline.json";

/// One ignore rule, compiled once and matched many times.
#[derive(Debug, Clone)]
pub struct Pattern {
    /// The rule as written, kept so error messages can quote it.
    pub raw: String,
    /// `!` in front: this rule re-includes a path an earlier rule excluded.
    pub negated: bool,
    /// Trailing `/`: the rule names a directory, not a file.
    pub dir_only: bool,
    /// The rule contains a `/`, so it is matched against the whole path from
    /// the workspace root rather than against a single name.
    pub anchored: bool,
    /// The rule split into path segments.
    segments: Vec<String>,
}

impl Pattern {
    /// Compile one ignore rule.
    pub fn parse(raw: &str) -> Option<Pattern> {
        let mut text = raw.trim();
        if text.is_empty() || text.starts_with('#') {
            return None;
        }
        let mut negated = false;
        if let Some(rest) = text.strip_prefix('!') {
            negated = true;
            text = rest.trim();
        }
        let mut dir_only = false;
        if let Some(rest) = text.strip_suffix('/') {
            dir_only = true;
            text = rest.trim();
        }
        if text.is_empty() {
            return None;
        }
        let anchored = text.contains('/');
        // A leading slash only says "from the root", it does not add a segment.
        let text = text.trim_start_matches('/');
        // `**` is a segment of its own, so `**/generated/**` is three
        // segments and the matcher handles it without a special case.
        let segments: Vec<String> = text
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        if segments.is_empty() {
            return None;
        }
        Some(Pattern {
            raw: raw.to_string(),
            negated,
            dir_only,
            anchored,
            segments,
        })
    }

    /// Whether this rule matches a workspace relative path.
    ///
    /// A rule without a `/` matches any path component, so `tests` excludes
    /// `tests/a.py` and `src/tests/a.py`. A rule with a `/` is matched segment
    /// by segment from the root, with `**` standing for any number of segments.
    pub fn matches(&self, path: &str) -> bool {
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segs.is_empty() {
            return false;
        }
        if !self.anchored {
            // Any component may be the one this rule names.
            return segs.iter().any(|s| glob_match(&self.segments[0], s));
        }
        if matches_segments(&self.segments, &segs) {
            return true;
        }
        // A rule that names a directory excludes everything under it, and the
        // path of a file does not say which of its components are directories.
        // So the rule is also matched against every prefix of the path.
        for k in 1..segs.len() {
            if matches_segments(&self.segments, &segs[..k]) {
                return true;
            }
        }
        false
    }
}

/// Segment by segment match, with `**` standing for any number of segments.
fn matches_segments(pattern: &[String], segs: &[&str]) -> bool {
    if pattern.is_empty() {
        return segs.is_empty();
    }
    if pattern[0] == "**" {
        for skip in 0..=segs.len() {
            if matches_segments(&pattern[1..], &segs[skip..]) {
                return true;
            }
        }
        return false;
    }
    if segs.is_empty() {
        return false;
    }
    if !glob_match(&pattern[0], segs[0]) {
        return false;
    }
    matches_segments(&pattern[1..], &segs[1..])
}

/// Glob match inside one path segment: `*` is any run of characters, `?` is
/// exactly one.
///
/// `*` does not cross a `/`, because the caller splits on `/` first, so a
/// pattern can never reach into another segment by accident.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            mark = ti;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// One workspace policy, loaded from disk.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// Path rules, from `.heidesignore` and the config file, in file order.
    pub patterns: Vec<Pattern>,
    /// When non empty, only paths matching one of these are scanned.
    pub include: Vec<Pattern>,
    /// Extra path rules, applied after the ignore rules.
    pub exclude: Vec<Pattern>,
    /// Rule id to severity. `security.taint` to `warning` is the common one.
    pub severity_overrides: BTreeMap<String, String>,
    /// Largest file the scanner reads. A file over this is not analysed.
    pub max_file_bytes: Option<u64>,
    /// Languages switched off by policy.
    pub disabled_languages: BTreeSet<String>,
    /// Languages switched on by policy. When set, only these are scanned.
    pub enabled_languages: BTreeSet<String>,
    /// Whether a policy file existed at all. A workspace with no policy is
    /// scanned exactly as it was before this module existed.
    pub present: bool,
}

impl Policy {
    /// The policy of a workspace. A missing policy file is not an error.
    pub fn load(root: &Path) -> Policy {
        let mut p = Policy::default();

        let ignore_path = root.join(IGNORE_FILE);
        if let Ok(text) = std::fs::read_to_string(&ignore_path) {
            p.present = true;
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some(pat) = Pattern::parse(line) {
                    p.patterns.push(pat);
                }
            }
        }

        let config_path = root.join(CONFIG_FILE);
        if let Ok(text) = std::fs::read_to_string(&config_path) {
            p.present = true;
            p.apply_config(&text);
        }
        p
    }

    /// Apply the JSON config. A malformed config is ignored rather than fatal:
    /// a broken policy file must not stop the scanner, because the scanner
    /// refusing to run is a way to miss findings.
    pub fn apply_config(&mut self, text: &str) {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
            return;
        };
        let obj = match value.as_object() {
            Some(o) => o,
            None => return,
        };
        for (key, target) in [("ignore", 0usize), ("exclude", 1), ("include", 2)] {
            let Some(items) = obj.get(key).and_then(|v| v.as_array()) else {
                continue;
            };
            for item in items {
                let Some(s) = item.as_str() else { continue };
                let Some(pat) = Pattern::parse(s) else {
                    continue;
                };
                match target {
                    0 => self.patterns.push(pat),
                    1 => self.exclude.push(pat),
                    _ => self.include.push(pat),
                }
            }
        }
        if let Some(size) = obj.get("max_file_bytes").and_then(|v| v.as_u64()) {
            self.max_file_bytes = Some(size);
        }
        if let Some(map) = obj.get("severity_overrides").and_then(|v| v.as_object()) {
            for (rule, sev) in map {
                if let Some(s) = sev.as_str() {
                    self.severity_overrides
                        .insert(rule.to_ascii_lowercase(), s.to_ascii_lowercase());
                }
            }
        }
        if let Some(langs) = obj.get("languages").and_then(|v| v.as_array()) {
            for lang in langs {
                if let Some(s) = lang.as_str() {
                    self.enabled_languages.insert(s.to_ascii_lowercase());
                }
            }
        }
        if let Some(langs) = obj.get("disabled_languages").and_then(|v| v.as_array()) {
            for lang in langs {
                if let Some(s) = lang.as_str() {
                    self.disabled_languages.insert(s.to_ascii_lowercase());
                }
            }
        }
    }

    /// Whether a path is excluded by the policy.
    pub fn is_ignored(&self, path: &str) -> bool {
        let path = path.trim_start_matches("./").replace('\\', "/");
        let mut ignored = false;
        for pat in &self.patterns {
            if pat.matches(&path) {
                ignored = !pat.negated;
            }
        }
        for pat in &self.exclude {
            if pat.matches(&path) {
                ignored = !pat.negated;
            }
        }
        if ignored {
            return true;
        }
        if !self.include.is_empty() {
            // An include list turns into an allow list: a path that matches
            // nothing in it is not scanned. Otherwise a typo in the include
            // list would silently widen the scan instead of narrowing it.
            return !self.include.iter().any(|p| p.matches(&path));
        }
        false
    }

    /// Whether a language is scanned under this policy.
    pub fn language_allowed(&self, lang: &str) -> bool {
        if lang.is_empty() {
            return true;
        }
        let lang = lang.to_ascii_lowercase();
        if self.disabled_languages.contains(&lang) {
            return false;
        }
        if !self.enabled_languages.is_empty() {
            return self.enabled_languages.contains(&lang);
        }
        true
    }

    /// The severity a rule reports under this policy.
    ///
    /// A rule id matches exactly, or as a family when the override ends with a
    /// dot, so `security` covers `security.taint` and `security.taint.truncated`.
    pub fn severity_for(&self, rule: &str, current: &str) -> String {
        let rule = rule.to_ascii_lowercase();
        if let Some(sev) = self.severity_overrides.get(&rule) {
            return sev.clone();
        }
        for (key, sev) in &self.severity_overrides {
            if key.ends_with('.') && rule.starts_with(key.as_str()) {
                return sev.clone();
            }
        }
        current.to_string()
    }
}

/// The suppressions written into one file.
///
/// Two forms, both plain comments so they survive a formatter:
///
///   `heides-ignore security.taint the value is validated upstream`
///       suppresses that one rule on that one line
///   `heides-ignore-file security.taint`
///       suppresses that rule for the whole file
///
/// An expiry is optional and explicit: `heides-ignore security.taint until
/// 2026-12-31`. An expired suppression does not suppress anything, because a
/// suppression that never expires is a hole with a comment in it.
#[derive(Debug, Clone, Default)]
pub struct Suppressions {
    /// Rule ids suppressed for the whole file.
    pub file_level: Vec<String>,
    /// Line number to the rule ids suppressed on that line.
    pub by_line: std::collections::BTreeMap<u64, Vec<String>>,
}

impl Suppressions {
    /// Read the suppressions out of a file's content.
    pub fn parse(content: &str) -> Suppressions {
        let mut s = Suppressions::default();
        for (i, line) in content.lines().enumerate() {
            let Some(rest) = strip_marker(line) else {
                continue;
            };
            let rest = rest.trim();
            let lower = rest.to_ascii_lowercase();
            if lower.starts_with("heides-ignore-file") {
                let tail = rest["heides-ignore-file".len()..].trim();
                if expired(tail) {
                    continue;
                }
                for rule in rules_in(tail) {
                    s.file_level.push(rule);
                }
            } else if lower.starts_with("heides-ignore") {
                let tail = rest["heides-ignore".len()..].trim();
                if expired(tail) {
                    continue;
                }
                let rules = rules_in(tail);
                let rules = if rules.is_empty() {
                    vec!["*".to_string()]
                } else {
                    rules
                };
                for rule in rules {
                    s.by_line.entry(i as u64 + 1).or_default().push(rule);
                }
            }
        }
        s
    }

    /// Whether a rule is suppressed on a line.
    pub fn suppresses(&self, rule: &str, line: u64) -> bool {
        if self.file_level.iter().any(|r| rule_matches(r, rule)) {
            return true;
        }
        self.by_line
            .get(&line)
            .map(|rules| rules.iter().any(|r| rule_matches(r, rule)))
            .unwrap_or(false)
    }

    /// Whether the whole file is suppressed for a rule.
    pub fn suppresses_file(&self, rule: &str) -> bool {
        self.file_level.iter().any(|r| rule_matches(r, rule))
    }
}

/// Whether an expiry in a suppression has passed.
///
/// The date is read from the comment, so the answer does not depend on a clock
/// the tool does not own. "Until 2026-12-31" means the suppression is dead
/// after that day, and a dead suppression suppresses nothing.
pub fn expired(tail: &str) -> bool {
    let lower = tail.to_ascii_lowercase();
    let Some(at) = lower.find("until") else {
        return false;
    };
    let after = &tail[at + "until".len()..];
    let date: String = after
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    if date.len() != 10 {
        return false;
    }
    let y: i64 = date[0..4].parse().unwrap_or(1970);
    let m: i64 = date[5..7].parse().unwrap_or(1);
    let d: i64 = date[8..10].parse().unwrap_or(1);
    if m <= 0 || m > 12 || d <= 0 || d > 31 {
        return false;
    }
    days_from_civil(y, m, d) < today()
}

/// Today, in days since the epoch.
fn today() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    secs.div_euclid(86_400)
}

/// Days since 1970 for a civil date. Howard Hinnant's algorithm, which is
/// exact for the whole range and needs no lookup table.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// The rule names in the tail of a suppression comment.
fn rules_in(tail: &str) -> Vec<String> {
    let tail = tail.trim();
    let mut out = Vec::new();
    for token in tail.split(|c: char| c.is_whitespace() || c == ',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let lower = token.to_ascii_lowercase();
        if lower.starts_with("until")
            || lower.starts_with("because")
            || lower.starts_with("reason")
            || lower.starts_with("the ")
            || lower.starts_with("this ")
        {
            break;
        }
        out.push(token.to_ascii_lowercase());
    }
    out
}

/// Whether a suppression rule name covers a rule id.
fn rule_matches(pattern: &str, rule: &str) -> bool {
    if pattern == "*" || pattern == "all" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return rule.starts_with(prefix);
    }
    pattern == rule
}

/// Strip a comment marker and return what follows it, when the line holds a
/// suppression marker.
///
/// The markers are the ones each language actually uses, because the same
/// file may be read by a human in one language and by the tool in another.
fn strip_marker(line: &str) -> Option<&str> {
    let lower = line.to_ascii_lowercase();
    let at = lower.find("heides-ignore")?;
    // The marker has to start a comment, otherwise a string containing the
    // word would silence a rule.
    let before = &line[..at];
    let trimmed = before.trim_end();
    let is_comment = trimmed.is_empty()
        || trimmed.ends_with("//")
        || trimmed.ends_with('#')
        || trimmed.ends_with("--")
        || trimmed.ends_with("/*")
        || trimmed.ends_with(';')
        || trimmed.ends_with("*")
        || trimmed.ends_with("%");
    if !is_comment {
        return None;
    }
    Some(&line[at..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_without_a_slash_matches_at_any_depth() {
        let p = Pattern::parse("tests").unwrap();
        assert!(p.matches("tests/a.py"));
        assert!(p.matches("src/tests/a.py"));
        assert!(!p.matches("src/testsuite/a.py"));
    }

    #[test]
    fn a_name_with_a_slash_is_anchored_at_the_root() {
        let p = Pattern::parse("src/tests").unwrap();
        assert!(p.matches("src/tests/a.py"));
        assert!(!p.matches("lib/src/tests/a.py"));
    }

    #[test]
    fn a_double_star_matches_any_depth() {
        let p = Pattern::parse("**/generated/**").unwrap();
        assert!(p.matches("lib/generated/x.dart"));
        assert!(p.matches("generated/x.dart"));
        assert!(!p.matches("lib/handwritten/x.dart"));
    }

    #[test]
    fn a_glob_matches_within_one_segment() {
        let p = Pattern::parse("*.g.dart").unwrap();
        assert!(p.matches("lib/model.g.dart"));
        assert!(!p.matches("lib/model.dart"));
    }

    #[test]
    fn a_negated_rule_re_includes() {
        let mut policy = Policy::default();
        policy.patterns.push(Pattern::parse("samples").unwrap());
        policy
            .patterns
            .push(Pattern::parse("!samples/keep").unwrap());
        assert!(policy.is_ignored("samples/bad.php"));
        assert!(!policy.is_ignored("samples/keep/good.php"));
    }

    #[test]
    fn an_include_list_narrows_the_scan() {
        let mut policy = Policy::default();
        policy.include.push(Pattern::parse("src").unwrap());
        assert!(!policy.is_ignored("src/app.py"));
        assert!(policy.is_ignored("scripts/tool.py"));
    }

    #[test]
    fn severity_overrides_match_a_rule_or_a_family() {
        let mut policy = Policy::default();
        policy
            .severity_overrides
            .insert("security.taint".to_string(), "warning".to_string());
        policy
            .severity_overrides
            .insert("best.practice.".to_string(), "info".to_string());
        assert_eq!(policy.severity_for("security.taint", "critical"), "warning");
        assert_eq!(
            policy.severity_for("best.practice.console", "warning"),
            "info"
        );
        assert_eq!(policy.severity_for("edge.cases", "warning"), "warning");
    }

    #[test]
    fn an_inline_suppression_silences_one_rule_on_one_line() {
        let s = Suppressions::parse(
            "const q = input(); // heides-ignore security.taint checked above\n",
        );
        assert!(s.suppresses("security.taint", 1));
        assert!(!s.suppresses("security.taint", 2));
        assert!(!s.suppresses("edge.cases", 1));
    }

    #[test]
    fn a_file_suppression_silences_the_whole_file() {
        let s = Suppressions::parse("// heides-ignore-file security.taint\nexport const x = 1;\n");
        assert!(s.suppresses("security.taint", 2));
        assert!(!s.suppresses("edge.cases", 2));
    }

    #[test]
    fn the_word_inside_a_string_is_not_a_suppression() {
        let s = Suppressions::parse("const m = \"heides-ignore security.taint\";\n");
        assert!(!s.suppresses("security.taint", 1));
    }

    #[test]
    fn an_expired_suppression_does_not_suppress() {
        assert!(expired("security.taint until 2020-01-01"));
        assert!(!expired("security.taint until 2099-01-01"));
        assert!(!expired("security.taint"));
    }
}
