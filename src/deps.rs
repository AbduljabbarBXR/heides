// Dependency guard.
//
// Reads the project manifests, checks every dependency against the OSV
// vulnerability database, and compares against the latest published version.
// When the network is unavailable the guard degrades gracefully and says so.

use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct DepReport {
    pub severity: String,
    pub message: String,
    pub file: String,
    pub line: u64,
}

#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: &'static str,
}

// Semver range handling.
// A requirement string like "1", "^1.2.3", "~1.2", "=1.0.1", "1.x" or
// ">=1.2 <2" is parsed into clauses and checked against a concrete version.
// Outdated means the latest version falls OUTSIDE the declared range.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl Version {
    pub fn parse(raw: &str) -> Option<Version> {
        let raw = raw.trim().trim_start_matches('v').trim_start_matches('=');
        let core = raw.split(['-', '+']).next().unwrap_or(raw);
        let mut parts = core.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next().map(|p| p.parse().unwrap_or(0)).unwrap_or(0);
        let patch = parts.next().map(|p| p.parse().unwrap_or(0)).unwrap_or(0);
        Some(Version {
            major,
            minor,
            patch,
        })
    }
}

#[derive(Debug, Clone)]
pub enum Clause {
    Any,
    Caret(Version),
    Tilde(Version),
    Exact(Version),
    Gte(Version),
    Gt(Version),
    Lte(Version),
    Lt(Version),
    Wildcard(Version, Version),
}

impl Clause {
    fn matches(&self, v: &Version) -> bool {
        match self {
            Clause::Any => true,
            Clause::Exact(base) => v == base,
            Clause::Gte(base) => v >= base,
            Clause::Gt(base) => v > base,
            Clause::Lte(base) => v <= base,
            Clause::Lt(base) => v < base,
            Clause::Caret(base) => {
                if base.major > 0 {
                    v >= base && v.major == base.major
                } else if base.minor > 0 {
                    v >= base && v.major == 0 && v.minor == base.minor
                } else {
                    v >= base && v.major == 0 && v.minor == 0 && v.patch == base.patch
                }
            }
            Clause::Wildcard(min, max) => v >= min && v < max,
            Clause::Tilde(base) => {
                // ~1.2.3 means >=1.2.3 <1.3.0, ~1 means >=1.0.0 <2.0.0,
                // ~0.2 means >=0.2.0 <0.3.0
                if base.major > 0 {
                    if base.minor > 0 || base.patch > 0 {
                        v >= base && v.major == base.major && v.minor == base.minor
                    } else {
                        v >= base && v.major == base.major
                    }
                } else if base.minor > 0 {
                    v >= base && v.major == 0 && v.minor == base.minor
                } else {
                    v >= base && v.major == 0 && v.minor == 0
                }
            }
        }
    }
}

fn parse_clause(raw: &str) -> Option<Clause> {
    let raw = raw.trim();
    if raw.is_empty() || raw == "*" || raw == "x" || raw == "X" || raw == "latest" {
        return Some(Clause::Any);
    }
    if let Some(rest) = raw.strip_prefix('^') {
        return Version::parse(rest).map(Clause::Caret);
    }
    if let Some(rest) = raw.strip_prefix('~') {
        return Version::parse(rest).map(Clause::Tilde);
    }
    if let Some(rest) = raw.strip_prefix(">=") {
        return Version::parse(rest).map(Clause::Gte);
    }
    if let Some(rest) = raw.strip_prefix("<=") {
        return Version::parse(rest).map(Clause::Lte);
    }
    if let Some(rest) = raw.strip_prefix('>') {
        return Version::parse(rest).map(Clause::Gt);
    }
    if let Some(rest) = raw.strip_prefix('<') {
        return Version::parse(rest).map(Clause::Lt);
    }
    if let Some(rest) = raw.strip_prefix('=') {
        return Version::parse(rest).map(Clause::Exact);
    }
    // Wildcard forms like 1.x or 1.2.x
    if raw.contains('x') || raw.contains('X') || raw.contains('*') {
        let base = raw
            .split(['x', 'X', '*'])
            .next()
            .unwrap_or("")
            .trim_end_matches('.');
        let parsed = Version::parse(base).unwrap_or(Version {
            major: 0,
            minor: 0,
            patch: 0,
        });
        if base.is_empty() {
            return Some(Clause::Any);
        }
        let dots = base.matches('.').count();
        if dots == 0 {
            // 1.x means >=1.0.0 <2.0.0
            let min = Version {
                major: parsed.major,
                minor: 0,
                patch: 0,
            };
            let max = Version {
                major: parsed.major + 1,
                minor: 0,
                patch: 0,
            };
            return Some(Clause::Wildcard(min, max));
        }
        if dots == 1 {
            // 1.2.x means >=1.2.0 <1.3.0
            let min = Version {
                major: parsed.major,
                minor: parsed.minor,
                patch: 0,
            };
            let max = Version {
                major: parsed.major,
                minor: parsed.minor + 1,
                patch: 0,
            };
            return Some(Clause::Wildcard(min, max));
        }
        return Some(Clause::Any);
    }
    // Bare version. npm treats it as exact, cargo treats it as caret.
    Version::parse(raw).map(Clause::Exact)
}

pub fn bare_is_caret(ecosystem: &str) -> bool {
    ecosystem == "crates.io"
}

/// Does the latest version satisfy the requirement string?
/// Returns None when the requirement cannot be parsed.
pub fn latest_satisfies(requirement: &str, latest: &str, ecosystem: &str) -> Option<bool> {
    let latest = Version::parse(latest)?;
    let mut any_group = false;
    for group in requirement.split("||") {
        let mut all = true;
        for clause_raw in group.split([',', ' ']).filter(|s| !s.trim().is_empty()) {
            let clause = if let Some(rest) = clause_raw.strip_prefix('^') {
                Version::parse(rest).map(Clause::Caret)
            } else if let Some(rest) = clause_raw.strip_prefix('~') {
                Version::parse(rest).map(Clause::Tilde)
            } else if let Some(rest) = clause_raw.strip_prefix(">=") {
                Version::parse(rest).map(Clause::Gte)
            } else if let Some(rest) = clause_raw.strip_prefix("<=") {
                Version::parse(rest).map(Clause::Lte)
            } else if let Some(rest) = clause_raw.strip_prefix('>') {
                Version::parse(rest).map(Clause::Gt)
            } else if let Some(rest) = clause_raw.strip_prefix('<') {
                Version::parse(rest).map(Clause::Lt)
            } else if let Some(rest) = clause_raw.strip_prefix('=') {
                Version::parse(rest).map(Clause::Exact)
            } else if bare_is_caret(ecosystem) {
                Version::parse(clause_raw).map(Clause::Caret)
            } else {
                parse_clause(clause_raw)
            };
            let c = clause?;
            if !c.matches(&latest) {
                all = false;
                break;
            }
        }
        if all {
            any_group = true;
        }
    }
    Some(any_group)
}

/// Extract dependencies from Cargo.toml, Cargo.lock and package.json.
/// Directories never walked when hunting for nested manifests. A project
/// tree stops at vendored and generated roots so that parent scans find the
/// real manifests without drowning in dependencies.
const MANIFEST_SKIP_DIRS: &[&str] = &[
    "node_modules",
    "vendor",
    ".git",
    ".heides",
    "target",
    "dist",
    "build",
    ".next",
    ".output",
    ".netlify",
    ".vercel",
    "venv",
    ".venv",
    ".tox",
    "__pycache__",
    "coverage",
];

fn collect_manifests(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if !dir.is_dir() {
        return;
    }
    let lock = dir.join("Cargo.lock");
    let toml = dir.join("Cargo.toml");
    if lock.exists() {
        out.push(lock);
    } else if toml.exists() {
        out.push(toml);
    }
    let pkg = dir.join("package.json");
    if pkg.exists() {
        out.push(pkg);
    }
    let gomod = dir.join("go.mod");
    if gomod.exists() {
        out.push(gomod);
    }
    let req = dir.join("requirements.txt");
    if req.exists() {
        out.push(req);
    }
    let pyproject = dir.join("pyproject.toml");
    if pyproject.exists() {
        out.push(pyproject);
    }
    let pom = dir.join("pom.xml");
    if pom.exists() {
        out.push(pom);
    }
    let lock = dir.join("composer.lock");
    let json = dir.join("composer.json");
    if lock.exists() {
        out.push(lock);
    } else if json.exists() {
        out.push(json);
    }
    if depth == 0 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if MANIFEST_SKIP_DIRS.contains(&name) {
            continue;
        }
        collect_manifests(&path, depth - 1, out);
    }
}

/// Reads every manifest reachable from the root, root first then bounded
/// subdirectories, so a check on a project parent does not silently skip the
/// real manifests one level down. Duplicate packages collapse to one entry.
pub fn read_manifests(root: &Path) -> Vec<Dependency> {
    let mut files = Vec::new();
    collect_manifests(root, 6, &mut files);
    let mut deps = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for file in files {
        let parsed: Vec<Dependency> = match file.file_name().and_then(|n| n.to_str()) {
            Some("Cargo.toml") => std::fs::read_to_string(&file)
                .map(|t| parse_cargo_toml(&t))
                .unwrap_or_default(),
            Some("Cargo.lock") => std::fs::read_to_string(&file)
                .map(|t| parse_cargo_lock(&t))
                .unwrap_or_default(),
            Some("package.json") => std::fs::read_to_string(&file)
                .map(|t| parse_package_json(&t))
                .unwrap_or_default(),
            Some("go.mod") => std::fs::read_to_string(&file)
                .map(|t| parse_go_mod(&t))
                .unwrap_or_default(),
            Some("requirements.txt") => std::fs::read_to_string(&file)
                .map(|t| parse_requirements_txt(&t))
                .unwrap_or_default(),
            Some("pyproject.toml") => std::fs::read_to_string(&file)
                .map(|t| parse_pyproject_toml(&t))
                .unwrap_or_default(),
            Some("pom.xml") => std::fs::read_to_string(&file)
                .map(|t| parse_pom_xml(&t))
                .unwrap_or_default(),
            Some("composer.lock") => std::fs::read_to_string(&file)
                .map(|t| parse_composer_lock(&t))
                .unwrap_or_default(),
            Some("composer.json") => std::fs::read_to_string(&file)
                .map(|t| parse_composer_json(&t))
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        for dep in parsed {
            if seen.insert(format!("{}@{}@{}", dep.name, dep.version, dep.ecosystem)) {
                deps.push(dep);
            }
        }
    }
    deps
}

fn parse_go_mod(text: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let mut in_block = false;
    for raw in text.lines() {
        let mut t = raw.trim();
        if t == "require (" || t == "require {" {
            in_block = true;
            continue;
        }
        if in_block && (t == ")" || t == "}") {
            in_block = false;
            continue;
        }
        if !in_block {
            let Some(rest) = t.strip_prefix("require ") else {
                continue;
            };
            if rest.starts_with('(') {
                continue;
            }
            t = rest.trim();
        }
        // One require line, block body or single require form, comments
        // and replacement blocks never look like module version pairs.
        let body = t.split("//").next().unwrap_or(t).trim();
        if body.is_empty() {
            continue;
        }
        let parts: Vec<&str> = body.split_whitespace().collect();
        if parts.len() >= 2 {
            deps.push(Dependency {
                name: parts[0].to_string(),
                version: parts[1].trim_start_matches('v').to_string(),
                ecosystem: "Go",
            });
        }
    }
    deps
}

/// Split a python requirement line into a package name and its pinned
/// version when the spec is exact, else keep the full range spec.
/// Anything that is not a real package line returns None.
fn split_python_req(line: &str) -> Option<(String, String)> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') || t.starts_with('-') {
        return None;
    }
    // Exact pins split on the full == operator first so the version is
    // clean for the OSV query, range specs keep their comparison.
    let (name_part, spec) = if let Some(eq) = t.find("==") {
        (&t[..eq], t[eq + 2..].trim().to_string())
    } else {
        let (n, s) = t.split_once(['<', '>', '~', '!'])?;
        let op = t.chars().nth(n.len())?;
        (n, format!("{}{}", op, s.trim()))
    };
    let mut name = name_part.trim().to_string();
    if let Some(bracket) = name.find('[') {
        name.truncate(bracket);
    }
    if name.is_empty() {
        return None;
    }
    // Inline environment markers after a semicolon are conditions, not
    // part of the version.
    let version = spec.split(';').next().unwrap_or(&spec).trim().to_string();
    if version.is_empty() {
        None
    } else {
        Some((name, version))
    }
}

/// Parse requirements.txt lines, only pinned versions and ranges that
/// carry a comparison survive.
fn parse_requirements_txt(text: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    for line in text.lines() {
        if let Some((name, version)) = split_python_req(line) {
            deps.push(Dependency {
                name,
                version,
                ecosystem: "PyPI",
            });
        }
    }
    deps
}

/// Which pyproject section a line belongs to, and what a key inside it means.
///
/// The section decides how a `key = value` line is read, and getting that
/// wrong is the whole reason this parser needed rewriting. In `[project]` a
/// bare `name = "app"` is the project name, not a dependency, so only
/// `dependencies` may be read there. In `[project.dependencies]` every key is a
/// requirement. Treating `[project]` as a requirement table would invent a
/// dependency called `name`.
#[derive(Clone, Copy, PartialEq)]
enum PySection {
    Other,
    /// `[project]`: only the `dependencies` key holds requirements.
    Project,
    /// `[project.dependencies]`: every key is one requirement.
    RequirementTable,
    /// `[project.optional-dependencies]`, `[project.dependency-groups]`: every
    /// key names a group whose value is a list of requirements.
    ListGroups,
    /// `[build-system]`: only `requires`.
    BuildSystem,
}

fn py_section(header: &str) -> PySection {
    match header {
        "[project]" => PySection::Project,
        "[project.dependencies]" => PySection::RequirementTable,
        "[build-system]" | "[build-system.requires]" => PySection::BuildSystem,
        h if h.starts_with("[project.optional-dependencies")
            || h.starts_with("[project.dependency-groups") =>
        {
            PySection::ListGroups
        }
        _ => PySection::Other,
    }
}

/// Strip one layer of matching surrounding quotes, if present.
fn unquote(s: &str) -> Option<String> {
    let t = s.trim();
    for q in ['"', '\''] {
        if t.len() >= 2 && t.starts_with(q) && t.ends_with(q) {
            return Some(t[1..t.len() - 1].to_string());
        }
    }
    None
}

/// Every quoted string inside a bracketed list, in order, brackets discarded.
///
/// The brackets have to come off first. The first version appended the raw body
/// including `[` and `]`, so `["a==1", "b==2"]` yielded the entries
/// `[a==1` and `b==2]`. The first then had its name truncated at the bracket to
/// nothing and was discarded, so a two dependency file reported one, and the
/// second carried a trailing `]` in its version, which was sent to the advisory
/// API as if it were part of a semver.
fn quoted_entries(list: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut saw_quote = false;
    for ch in list.chars() {
        match quote {
            Some(q) if ch == q => {
                out.push(std::mem::take(&mut cur));
                quote = None;
            }
            Some(_) => cur.push(ch),
            None if ch == '"' || ch == '\'' => {
                quote = Some(ch);
                saw_quote = true;
            }
            // A bracket outside quotes is punctuation, never content. Anything
            // else outside quotes is whitespace or a trailing comma.
            None => {}
        }
    }
    // A quote left open means the list was truncated. Discard the fragment
    // rather than reading half a requirement as a whole one.
    let _ = saw_quote;
    out
}

fn push_py_req(deps: &mut Vec<Dependency>, entry: &str) {
    if let Some((name, version)) = split_python_req(entry) {
        deps.push(Dependency {
            name,
            version,
            ecosystem: "PyPI",
        });
    }
}

fn parse_pyproject_toml(text: &str) -> Vec<Dependency> {
    let mut deps: Vec<Dependency> = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut section = PySection::Other;
    // Set while a `key = [` line is still collecting its entries below.
    let mut collecting = false;

    for (idx, raw) in lines.iter().enumerate() {
        let t = raw.trim();

        // A header only ends a section when we are not in the middle of a
        // multi line list, or a `]` inside the list would be read as a header.
        if !collecting && t.starts_with('[') && t.ends_with(']') && t.len() > 2 {
            section = py_section(t);
            continue;
        }

        if t.is_empty() || t.starts_with('#') {
            continue;
        }

        if collecting {
            if t.contains(']') {
                collecting = false;
            }
            if let Some(entry) = unquote(t.trim_end_matches(']').trim().trim_end_matches(',')) {
                push_py_req(&mut deps, &entry);
            }
            continue;
        }

        if section == PySection::Other {
            continue;
        }

        // A bare quoted entry, the shape a requirements table also accepts.
        // The trailing comma is part of the TOML list, not of the requirement,
        // and unquoting before stripping it never matches.
        if let Some(entry) = unquote(t.trim_end_matches(',').trim()) {
            push_py_req(&mut deps, &entry);
            continue;
        }

        let Some((key, value)) = t.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();

        // PEP 735 group includes are references to other groups, not
        // requirements. Reading one as a dependency would report `dev` as a
        // package that needs an advisory lookup.
        if key == "include-group" {
            continue;
        }

        // Which keys carry requirements depends on the section.
        let wanted = match section {
            PySection::Project => key == "dependencies",
            PySection::BuildSystem => key == "requires",
            PySection::RequirementTable | PySection::ListGroups => true,
            PySection::Other => false,
        };
        if !wanted {
            continue;
        }

        if value.starts_with('[') {
            if value.contains(']') {
                for entry in quoted_entries(value) {
                    push_py_req(&mut deps, &entry);
                }
            } else {
                // A multi line list. Take the rest of the document up to the
                // closing bracket and pull every quoted entry out of it, which
                // avoids tracking continuation state per line.
                let mut body = value.to_string();
                for cont in lines.iter().skip(idx + 1) {
                    let c = cont.trim();
                    body.push(' ');
                    body.push_str(c);
                    if c.contains(']') {
                        break;
                    }
                }
                for entry in quoted_entries(&body) {
                    push_py_req(&mut deps, &entry);
                }
                collecting = false;
            }
        } else if let Some(v) = unquote(value) {
            // `name = "version"`, the shape a requirements table uses.
            push_py_req(&mut deps, &format!("{key}=={v}"));
        }
    }

    let mut seen = std::collections::HashSet::new();
    deps.retain(|d| seen.insert(d.name.clone()));
    deps
}

/// Read one xml tag pair from a single line, so dependency blocks that
/// keep each element on its own line are enough.
fn xml_tag(line: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = line.find(&open)?;
    let rest = &line[start + open.len()..];
    let end = rest.find(&close)?;
    let val = rest[..end].trim().to_string();
    if val.is_empty() { None } else { Some(val) }
}

/// Parse pom.xml dependency coordinates. Versions resolved through
/// properties are unknown at parse time and stay silent.
fn parse_pom_xml(text: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let mut group = String::new();
    let mut artifact = String::new();
    let mut version = String::new();
    let mut in_dep = false;
    for line in text.lines() {
        let t = line.trim();
        if t == "<dependency>" {
            in_dep = true;
            group.clear();
            artifact.clear();
            version.clear();
            continue;
        }
        if t == "</dependency>" {
            // Property resolved versions are unknown, dropping them stays
            // silent rather than guessing.
            if in_dep && !artifact.is_empty() && !version.is_empty() {
                let v = std::mem::take(&mut version);
                deps.push(Dependency {
                    name: format!("{}:{}", group, artifact),
                    version: v,
                    ecosystem: "Maven",
                });
            }
            in_dep = false;
            continue;
        }
        if !in_dep {
            continue;
        }
        if let Some(v) = xml_tag(t, "groupId") {
            group = v;
        } else if let Some(v) = xml_tag(t, "artifactId") {
            artifact = v;
        } else if let Some(v) = xml_tag(t, "version") {
            // Versions resolved through properties are unknown at parse
            // time and stay silent.
            if !v.contains('$') && !v.contains('{') {
                version = v;
            }
        }
    }
    deps
}

/// Parse composer.lock packages and dev packages, the lock carries the
/// exact installed versions.
fn parse_composer_lock(text: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return deps;
    };
    for key in ["packages", "packages-dev"] {
        if let Some(list) = value.get(key).and_then(|v| v.as_array()) {
            for pkg in list {
                let (Some(name), Some(version)) = (
                    pkg.get("name").and_then(|v| v.as_str()),
                    pkg.get("version").and_then(|v| v.as_str()),
                ) else {
                    continue;
                };
                deps.push(Dependency {
                    name: name.to_string(),
                    version: version.trim_start_matches('v').to_string(),
                    ecosystem: "Packagist",
                });
            }
        }
    }
    deps
}

/// Parse composer.json require and require-dev maps, ranges stay ranges
/// and only the lock file pins exact versions.
fn parse_composer_json(text: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return deps;
    };
    for key in ["require", "require-dev"] {
        if let Some(map) = value.get(key).and_then(|v| v.as_object()) {
            for (name, spec) in map {
                deps.push(Dependency {
                    name: name.clone(),
                    version: spec.as_str().unwrap_or("?").to_string(),
                    ecosystem: "Packagist",
                });
            }
        }
    }
    deps
}

fn parse_cargo_toml(text: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let mut in_deps = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_deps = t.starts_with("[dependencies]");
            continue;
        }
        if !in_deps || t.is_empty() || t.starts_with('#') {
            continue;
        }
        if let Some(eq) = t.find('=') {
            let name = t[..eq].trim().trim_matches('"').to_string();
            let version = t[eq + 1..]
                .trim()
                .trim_matches('"')
                .trim_start_matches('{')
                .trim_end_matches('}')
                .split(',')
                .find_map(|kv| kv.trim().strip_prefix("version ="))
                .map(|v| v.trim().trim_matches('"').to_string())
                .unwrap_or_else(|| t[eq + 1..].trim().trim_matches('"').to_string());
            if !name.is_empty() && !name.starts_with('[') {
                deps.push(Dependency {
                    name,
                    version,
                    ecosystem: "crates.io",
                });
            }
        }
    }
    deps
}

fn parse_cargo_lock(text: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let mut name: Option<String> = None;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("name = ") {
            name = Some(
                t.trim_start_matches("name = ")
                    .trim_matches('"')
                    .to_string(),
            );
        } else if t.starts_with("version = ") && name.is_some() {
            let version = t
                .trim_start_matches("version = ")
                .trim_matches('"')
                .to_string();
            if let Some(dep_name) = name.take() {
                deps.push(Dependency {
                    name: dep_name,
                    version,
                    ecosystem: "crates.io",
                });
            }
        } else if t.starts_with("[") {
            name = None;
        }
    }
    deps
}

fn parse_package_json(text: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return deps;
    };
    for key in ["dependencies", "devDependencies"] {
        if let Some(map) = value.get(key).and_then(|v| v.as_object()) {
            for (name, ver) in map {
                deps.push(Dependency {
                    name: name.clone(),
                    version: ver.as_str().unwrap_or("?").to_string(),
                    ecosystem: "npm",
                });
            }
        }
    }
    deps
}

/// Query OSV for known vulnerabilities in a dependency.
/// Returns a short summary line, or None when clean.
/// What the advisory lookup actually established.
///
/// This is a tri-state on purpose. It used to be `Option<String>`, which
/// returned `None` both for "this version has no known vulnerability" and for
/// "the request failed", so an unreachable OSV made the guard report every
/// dependency as clean. That is the same silent-partial-result failure as
/// everywhere else in this release, in the most security relevant place
/// possible: a network failure looked like a clean bill of health.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Advisory {
    Found(String),
    Clean,
    Unreachable,
}

fn osv_check(dep: &Dependency) -> Advisory {
    let body = serde_json::json!({
        "package": { "name": dep.name, "ecosystem": dep.ecosystem },
        "version": dep.version
    });
    let url = "https://api.osv.dev/v1/query";
    let Ok(resp) = crate::web::post_json(url, &body.to_string()) else {
        return Advisory::Unreachable;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&resp) else {
        return Advisory::Unreachable;
    };
    let Some(vulns) = value.get("vulns").and_then(|v| v.as_array()) else {
        return Advisory::Unreachable;
    };
    if vulns.is_empty() {
        return Advisory::Clean;
    }
    let first = &vulns[0];
    let id = first
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let summary = first
        .get("summary")
        .and_then(|v| v.as_str())
        .unwrap_or("no summary");
    Advisory::Found(format!("{}: {}", id, summary))
}

/// How far the dependency guard got, reported per half.
///
/// The advisory half is the security half and the version half is the
/// convenience half. They are tracked separately because conflating them is
/// what made a missing "latest version" lookup mark the whole run as advisory
/// incomplete, which would have failed `--require-advisories` on any repository
/// containing a package whose latest version could not be resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepsHealth {
    /// Every pinned version was actually asked about.
    pub advisories_ok: bool,
    /// Every "is there a newer release" lookup answered.
    pub versions_ok: bool,
}

/// Fetch the latest published version of a dependency.
fn latest_version(dep: &Dependency) -> Option<String> {
    match dep.ecosystem {
        "npm" => {
            let url = format!("https://registry.npmjs.org/{}/latest", dep.name);
            let resp = crate::web::get(&url).ok()?;
            let value: serde_json::Value = serde_json::from_str(&resp).ok()?;
            value
                .get("version")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        }
        "crates.io" => {
            let url = format!("https://crates.io/api/v1/crates/{}", dep.name);
            let resp = crate::web::get(&url).ok()?;
            let value: serde_json::Value = serde_json::from_str(&resp).ok()?;
            value
                .get("crate")
                .and_then(|c| c.get("max_stable_version"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        }
        "PyPI" => {
            let url = format!("https://pypi.org/pypi/{}/json", dep.name);
            let resp = crate::web::get(&url).ok()?;
            let value: serde_json::Value = serde_json::from_str(&resp).ok()?;
            value
                .get("info")
                .and_then(|i| i.get("version"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        }
        "Go" => {
            let url = format!("https://proxy.golang.org/{}/@latest", dep.name);
            let resp = crate::web::get(&url).ok()?;
            let value: serde_json::Value = serde_json::from_str(&resp).ok()?;
            value
                .get("Version")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        }
        "Maven" => {
            let (g, a) = dep.name.split_once(':')?;
            let url = format!(
                "https://search.maven.org/solrsearch/select?q=g:%22{}%22+AND+a:%22{}%22&rows=1&wt=json",
                g, a
            );
            let resp = crate::web::get(&url).ok()?;
            let value: serde_json::Value = serde_json::from_str(&resp).ok()?;
            value
                .get("response")
                .and_then(|r| r.get("docs"))
                .and_then(|d| d.as_array())
                .and_then(|d| d.first())
                .and_then(|doc| doc.get("latestVersion"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        }
        "Packagist" => {
            let url = format!("https://repo.packagist.org/p2/{}.json", dep.name);
            let resp = crate::web::get(&url).ok()?;
            let value: serde_json::Value = serde_json::from_str(&resp).ok()?;
            value
                .get("packages")
                .and_then(|p| p.get(&dep.name))
                .and_then(|v| v.as_array())
                .and_then(|vers| {
                    vers.iter().find(|entry| {
                        entry
                            .get("version")
                            .and_then(|v| v.as_str())
                            .map(|s| !s.contains("dev") && !s.contains("RC"))
                            .unwrap_or(false)
                    })
                })
                .and_then(|entry| entry.get("version"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim_start_matches('v').to_string())
        }
        _ => None,
    }
}

/// Every ecosystem label this guard knows, kept static so Dependency can
/// borrow it for the lifetime of the check.
fn canonical_ecosystem(eco: &str) -> &'static str {
    match eco {
        "npm" => "npm",
        "crates.io" => "crates.io",
        "Go" => "Go",
        "PyPI" => "PyPI",
        "Maven" => "Maven",
        "Packagist" => "Packagist",
        "RubyGems" => "RubyGems",
        _ => "npm",
    }
}

/// Run the dependency guard. Returns reports plus a network status flag.
static DEPS_OVERRIDE: Mutex<Option<bool>> = Mutex::new(None);
static REQUIRE_ADVISORIES: Mutex<bool> = Mutex::new(false);

/// Whether the dependency guard is allowed to run.
///
/// `check` used to reach the network for this one guard without being asked, one
/// HTTP request per dependency, which is why a check took 165 seconds. The
/// README claims analysis never needs the network, and every other guard
/// honours that. This makes the claim true for the last holdout without
/// removing any real protection: lockfile parsing, pinned version extraction
/// and every local check are pure local analysis. What `--no-deps` gives up is
/// the "a newer version exists" reminder, and on a cold cache the known-CVE
/// lookup.
///
/// A skipped dependency check is stated in the coverage receipt, because a
/// partial result presented as a complete one is the exact failure this project
/// is trying to stop shipping.
pub fn deps_enabled() -> bool {
    if let Some(v) = *DEPS_OVERRIDE.lock().unwrap() {
        return v;
    }
    !offline_env()
}

/// Set by `--no-deps`. Wins over the environment.
pub fn set_deps_enabled(v: bool) {
    *DEPS_OVERRIDE.lock().unwrap() = Some(v);
}

/// Set by `--require-advisories`.
///
/// A security gate must fail rather than pass hollow. Without this, wiring
/// `--no-deps` into a required CI status check produces a green build that
/// never asked OSV whether a pinned version has a known vulnerability, and the
/// only clue is a footnote in the log. With this, that misconfiguration is a
/// non-zero exit, which is a red X instead of a silent hole.
pub fn set_require_advisories(v: bool) {
    *REQUIRE_ADVISORIES.lock().unwrap() = v;
}

pub fn require_advisories() -> bool {
    *REQUIRE_ADVISORIES.lock().unwrap()
}

/// Per-call overrides for a long-lived server, set by one MCP request and
/// dropped when it finishes.
///
/// The process globals above are correct for a single-shot CLI: the process
/// exits before another caller can see them. They are wrong for an MCP server,
/// which handles many requests in one process. Without this, one client calling
/// `harmony.check` with `offline: true` silently disabled the advisory lookup
/// for every later request from every client, which is a security setting
/// changed by an unrelated argument. Scoping the override to a single call
/// removes that class of leak entirely.
///
/// Implementation note. The first draft held both locks across the closure and
/// What the dependency guard is allowed to do for one run.
///
/// This is a value, not a setting. It is resolved once at the boundary, from
/// the command line or from an MCP argument, and then passed down the call
/// chain. It used to be three process globals, and the scoped version of those
/// globals leaked between MCP callers and raced inside the test suite. A value
/// cannot leak and cannot race, because there is nothing shared to leak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepsPolicy {
    /// Whether the registry lookups may run at all.
    pub enabled: bool,
    /// Whether a run that did not consult the advisories must fail.
    pub require_advisories: bool,
}

impl Default for DepsPolicy {
    fn default() -> Self {
        DepsPolicy {
            enabled: deps_enabled(),
            require_advisories: require_advisories(),
        }
    }
}

/// Pure resolution, so the decision can be tested without touching process
/// state. `override_deps` and `override_require` are the command line or MCP
/// arguments, `offline` is the raw HEIDES_OFFLINE value.
pub fn resolve_policy(
    override_deps: Option<bool>,
    override_require: Option<bool>,
    offline: Option<&str>,
) -> DepsPolicy {
    DepsPolicy {
        enabled: override_deps.unwrap_or(!offline_env_value(offline)),
        require_advisories: override_require.unwrap_or(false),
    }
}

fn offline_env() -> bool {
    offline_env_value(std::env::var("HEIDES_OFFLINE").ok().as_deref())
}

/// Split out from `offline_env` so the accepted values are testable without
/// mutating process environment state, which is unsafe on this toolchain.
fn offline_env_value(v: Option<&str>) -> bool {
    matches!(v, Some("1") | Some("true") | Some("yes"))
}

pub fn check(root: &Path) -> (Vec<DepReport>, DepsHealth) {
    let deps = read_manifests(root);
    let mut reports = Vec::new();
    if deps.is_empty() {
        reports.push(DepReport {
            severity: "info".to_string(),
            message: "no dependency manifests found (Cargo.toml, Cargo.lock, package.json, go.mod, requirements.txt, pyproject.toml, pom.xml, composer.lock)"
                .to_string(),
            file: root.display().to_string(),
            line: 0,
        });
        return (
            reports,
            DepsHealth {
                advisories_ok: true,
                versions_ok: true,
            },
        );
    }

    // Deduplicate by name and ecosystem.
    let mut seen: BTreeMap<(String, String), String> = BTreeMap::new();
    for d in &deps {
        let key = (d.name.clone(), d.ecosystem.to_string());
        if d.version != "?" && !seen.contains_key(&key) {
            seen.insert(key, d.version.clone());
        }
    }

    let mut health = DepsHealth {
        advisories_ok: true,
        versions_ok: true,
    };
    let mut checked = 0;
    for ((name, ecosystem), version) in &seen {
        let eco = canonical_ecosystem(ecosystem);
        let dep = Dependency {
            name: name.clone(),
            version: version.clone(),
            ecosystem: eco,
        };
        checked += 1;
        // Clean and Unreachable are different answers and must not collapse.
        // Reporting "no vulnerabilities" when the registry was never reached
        // is the one thing this guard must never do.
        match osv_check(&dep) {
            Advisory::Found(vuln) => reports.push(DepReport {
                severity: "critical".to_string(),
                message: format!(
                    "{} {} has a known vulnerability: {}",
                    dep.name, dep.version, vuln
                ),
                file: "manifest".to_string(),
                line: 0,
            }),
            Advisory::Clean => {}
            Advisory::Unreachable => {
                health.advisories_ok = false;
                reports.push(DepReport {
                    severity: "info".to_string(),
                    message: format!(
                        "could not reach the advisory service for {} {}. it is NOT known to be clean.",
                        dep.name, dep.version
                    ),
                    file: "manifest".to_string(),
                    line: 0,
                });
            }
        }
        match latest_version(&dep) {
            Some(latest) => {
                match latest_satisfies(&dep.version, &latest, dep.ecosystem) {
                    Some(true) => {
                        // The latest release is inside the declared range,
                        // so the requirement is honest. No warning.
                    }
                    Some(false) => {
                        reports.push(DepReport {
                            severity: "warning".to_string(),
                            message: format!(
                                "latest {} falls outside the declared range {} for {}. edit the manifest to upgrade",
                                latest, dep.version, dep.name
                            ),
                            file: "manifest".to_string(),
                            line: 0,
                        });
                    }
                    None => {
                        // The requirement could not be parsed. Stay silent
                        // rather than guess.
                    }
                }
            }
            None => {
                // A missing latest-version answer is the convenience half
                // failing. It must not be allowed to mark the security half
                // incomplete, or --require-advisories would fail on any repo
                // holding a package whose latest release cannot be resolved.
                health.versions_ok = false;
            }
        }
    }

    if checked == 0 {
        reports.push(DepReport {
            severity: "info".to_string(),
            message: "no pinned dependencies to check".to_string(),
            file: "manifest".to_string(),
            line: 0,
        });
    }
    (reports, health)
}

/// The local half of the dependency guard, with no network at all.
///
/// Everything a lockfile or manifest can tell you without a registry still
/// holds: which manifests exist, which dependencies are pinned, and to what
/// version. Only the two registry lookups are given up, the known-CVE query
/// and the "a newer version exists" reminder.
///
/// The report says how many pinned versions it read, so an offline run is
/// visibly doing local work rather than silently doing nothing.
pub fn check_offline(root: &Path) -> (Vec<DepReport>, DepsHealth) {
    let deps = read_manifests(root);
    let mut reports = Vec::new();
    if deps.is_empty() {
        reports.push(DepReport {
            severity: "info".to_string(),
            message: "no dependency manifests found (Cargo.toml, Cargo.lock, package.json, go.mod, requirements.txt, pyproject.toml, pom.xml, composer.lock)".to_string(),
            file: root.display().to_string(),
            line: 0,
        });
        return (
            reports,
            DepsHealth {
                advisories_ok: true,
                versions_ok: true,
            },
        );
    }
    let mut pinned: BTreeMap<(String, String), String> = BTreeMap::new();
    for d in &deps {
        let key = (d.name.clone(), d.ecosystem.to_string());
        if d.version != "?" && !pinned.contains_key(&key) {
            pinned.insert(key, d.version.clone());
        }
    }
    let mut ecosystems: std::collections::BTreeSet<&str> =
        deps.iter().map(|d| d.ecosystem).collect();
    let eco_list: Vec<&str> = std::mem::take(&mut ecosystems).into_iter().collect();
    let eco_count = if eco_list.len() == 1 {
        "1 ecosystem".to_string()
    } else {
        format!("{} ecosystems", eco_list.len())
    };
    reports.push(DepReport {
        severity: "info".to_string(),
        message: format!(
            "read {} pinned version(s) across {} ({}). advisory lookup skipped, run without --no-deps to enable it",
            pinned.len(),
            eco_count,
            eco_list.join(", ")
        ),
        file: "manifest".to_string(),
        line: 0,
    });
    // Offline, so nothing was not checked. The caller reports Skipped, which
    // is the honest state: the advisory lookup did not run, and this says so
    // rather than implying both halves succeeded.
    (
        reports,
        DepsHealth {
            advisories_ok: true,
            versions_ok: true,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The leak this release exists to prevent, now tested on a value.
    ///
    /// Before this, an MCP client passing `offline: true` wrote a process
    /// global and never restored it, so every later request from every client
    /// silently ran without advisories. The first fix scoped the global with
    /// three more globals and a depth counter. That still shared state, and its
    /// own tests raced each other under the default parallel test runner.
    ///
    /// The policy is now a plain value built from the arguments, so the
    /// property is structural: one caller's policy cannot appear in another
    /// caller's result because there is no shared state to carry it.
    #[test]
    fn one_callers_policy_cannot_reach_another() {
        let client_a = resolve_policy(Some(false), Some(true), None);
        let client_b = resolve_policy(Some(true), Some(true), None);
        assert!(!client_a.enabled, "client A asked for offline");
        assert!(client_b.enabled, "client B did not");
        // Independent values, so changing one cannot be observed in the other.
        let mut a = client_a;
        a.enabled = true;
        a.require_advisories = false;
        assert_ne!(a, client_a, "the local copy did change");
        assert!(
            a.enabled && !a.require_advisories,
            "and holds the new values"
        );
        assert!(client_b.enabled, "B must be unaffected by A");
        assert!(
            client_a.require_advisories,
            "A is a copy, not a shared handle, so A is unchanged too"
        );
    }

    #[test]
    fn policy_resolution_is_pure_and_reads_nothing() {
        // Default with no arguments and no environment: online, not a gate.
        let d = resolve_policy(None, None, None);
        assert!(d.enabled, "online by default");
        assert!(
            !d.require_advisories,
            "not a gate by default on the CLI path"
        );
        // The env var turns it off.
        assert!(!resolve_policy(None, None, Some("1")).enabled);
        // An explicit argument wins over the env var, in both directions.
        assert!(resolve_policy(Some(true), None, Some("1")).enabled);
        assert!(!resolve_policy(Some(false), None, None).enabled);
        // require is opt in and never inferred.
        assert!(resolve_policy(None, Some(true), None).require_advisories);
    }

    #[test]
    fn the_cli_setters_still_control_the_process_default() {
        // The CLI sets the default once at startup and never changes it again,
        // so a global here is correct rather than dangerous.
        set_deps_enabled(true);
        assert!(deps_enabled());
        set_require_advisories(true);
        assert!(require_advisories());
        assert!(DepsPolicy::default().enabled);
        assert!(DepsPolicy::default().require_advisories);
        set_deps_enabled(true);
        set_require_advisories(false);
    }
    #[test]
    fn offline_env_accepts_the_documented_values_only() {
        assert!(offline_env_value(Some("1")));
        assert!(offline_env_value(Some("true")));
        assert!(offline_env_value(Some("yes")));
        assert!(!offline_env_value(Some("0")));
        assert!(!offline_env_value(Some("false")));
        assert!(!offline_env_value(Some("")));
        assert!(!offline_env_value(None), "unset must mean online");
    }

    #[test]
    fn the_deps_override_wins_over_the_environment() {
        set_deps_enabled(true);
        assert!(deps_enabled(), "default is on");
        set_deps_enabled(false);
        assert!(!deps_enabled(), "an explicit opt out must hold");
        set_deps_enabled(true);
        assert!(deps_enabled());
    }

    #[test]
    fn parses_go_mod() {
        let text = "module example.com/myapp\n\ngo 1.22\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n\tgithub.com/go-sql-driver/mysql v1.7.1 // indirect\n)\n\nrequire golang.org/x/crypto v0.14.0\n\nreplace github.com/old => github.com/new v9.9.9\n";
        let deps = parse_go_mod(text);
        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0].name, "github.com/gin-gonic/gin");
        assert_eq!(deps[0].version, "1.9.1");
        assert_eq!(deps[0].ecosystem, "Go");
        assert_eq!(deps[1].name, "github.com/go-sql-driver/mysql");
        assert_eq!(deps[1].version, "1.7.1");
        assert_eq!(deps[2].name, "golang.org/x/crypto");
        assert_eq!(deps[2].version, "0.14.0");
    }

    #[test]
    fn parses_requirements_and_pyproject() {
        let reqs = "django==4.2.11\nrequests>=2.31.0\npillow~=10.2\nflask==3.0.0 ; python_version<\"3.13\"\n-r base.txt\nbarename\n# comment\n";
        let deps = parse_requirements_txt(reqs);
        assert_eq!(deps.len(), 4);
        assert_eq!(deps[0].name, "django");
        assert_eq!(deps[0].version, "4.2.11");
        assert_eq!(deps[0].ecosystem, "PyPI");
        assert_eq!(deps[1].version, ">=2.31.0");
        assert_eq!(deps[2].version, "~=10.2");
        assert_eq!(deps[3].name, "flask");

        let inline = "[project]\nname = \"app\"\n\n[project.dependencies]\ndependencies = [\"django==4.2.11\", \"requests>=2.31.0\"]\n";
        let deps = parse_pyproject_toml(inline);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "django");
        assert_eq!(deps[0].version, "4.2.11");

        let multiline = "[project.dependencies]\n\"pillow~=10.2\",\n\"sqlalchemy==2.0.29\",\n]\n";
        let deps = parse_pyproject_toml(multiline);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[1].name, "sqlalchemy");
        assert_eq!(deps[1].version, "2.0.29");
    }

    /// The fix this release exists for. A modern pyproject puts dependencies
    /// as a KEY inside `[project]`, and the old parser only read the legacy
    /// table, so the file was located, opened, parsed to nothing, and then
    /// reported as "no dependency manifests found" while naming the very file
    /// it had just found. That silently disabled dependency checking for the
    /// whole PyPI ecosystem.
    #[test]
    fn parses_the_modern_pep621_project_dependencies() {
        let toml = "[project]\nname = \"app\"\nversion = \"1.0.0\"\ndependencies = [\n  \"attrs>=23.1.0\",\n  \"httpx==0.27.0\",\n]\n";
        let deps = parse_pyproject_toml(toml);
        assert_eq!(deps.len(), 2, "the modern form must yield dependencies");
        assert_eq!(deps[0].name, "attrs");
        assert_eq!(deps[0].version, ">=23.1.0");
        assert_eq!(deps[0].ecosystem, "PyPI");
        assert_eq!(deps[1].name, "httpx");
        assert_eq!(
            deps[1].version, "0.27.0",
            "an exact pin keeps a clean version for the OSV query"
        );
    }

    #[test]
    fn parses_pep621_on_a_single_line() {
        let toml = "[project]\nname = \"app\"\ndependencies = [\"django==4.2.11\", \"requests>=2.31.0\"]\n";
        let deps = parse_pyproject_toml(toml);
        assert_eq!(deps.len(), 2, "a single line list must parse too");
        assert_eq!(deps[0].name, "django");
        assert_eq!(deps[1].name, "requests");
    }

    #[test]
    fn parses_pep735_optional_dependency_groups() {
        // These are real requirements too, and they ship in most modern repos.
        let toml = "[project]\nname = \"app\"\n\n[project.optional-dependencies]\ntest = [\"pytest==8.0.0\"]\ndocs = [\"sphinx==7.2.6\"]\n";
        let deps = parse_pyproject_toml(toml);
        assert_eq!(deps.len(), 2, "{deps:?}");
        assert!(deps.iter().any(|d| d.name == "pytest"), "{deps:?}");
        assert!(deps.iter().any(|d| d.name == "sphinx"), "{deps:?}");
    }

    #[test]
    fn parses_build_system_requirements() {
        let toml = "[build-system]\nrequires = [\"setuptools>=68\", \"wheel\"]\nbuild-backend = \"setuptools.build_meta\"\n";
        let deps = parse_pyproject_toml(toml);
        assert!(
            deps.iter()
                .any(|d| d.name == "setuptools" && d.version == ">=68"),
            "the pinned build requirement must be reported: {deps:?}"
        );
        // `wheel` carries no version, so there is no pinned version to look
        // up. Dropping it matches how requirements.txt already behaves, and
        // inventing a version would query the advisory service for something
        // that was never pinned.
        assert!(
            !deps.iter().any(|d| d.name == "wheel"),
            "an unpinned requirement is not a pinnable version: {deps:?}"
        );
    }

    /// The legacy table must keep working. It is still what a large amount of
    /// published code uses, and quietly regressing it would be worse than the
    /// bug being fixed.
    #[test]
    fn the_legacy_dependencies_table_still_parses() {
        let toml = "[project]\nname = \"app\"\n\n[project.dependencies]\ndjango = \"4.2.11\"\n";
        let deps = parse_pyproject_toml(toml);
        assert_eq!(deps.len(), 1, "{deps:?}");
        assert_eq!(deps[0].name, "django");
    }

    /// An unrelated tool table must not be mined for dependencies. `[tool.poetry]`
    /// has its own layout, and scraping it would invent versions.
    #[test]
    fn an_unrelated_table_yields_nothing() {
        let toml = "[project]\nname = \"app\"\n\n[tool.ruff]\nline-length = 100\n";
        let deps = parse_pyproject_toml(toml);
        assert!(
            deps.is_empty(),
            "a tool table is not a dependency table: {deps:?}"
        );
    }

    #[test]
    fn parses_pom_xml() {
        let pom = "<project>\n  <dependencies>\n    <dependency>\n      <groupId>com.google.guava</groupId>\n      <artifactId>guava</artifactId>\n      <version>31.1-jre</version>\n    </dependency>\n    <dependency>\n      <groupId>org.apache.logging.log4j</groupId>\n      <artifactId>log4j-core</artifactId>\n      <version>${log4j.version}</version>\n    </dependency>\n  </dependencies>\n</project>\n";
        let deps = parse_pom_xml(pom);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "com.google.guava:guava");
        assert_eq!(deps[0].version, "31.1-jre");
        assert_eq!(deps[0].ecosystem, "Maven");
    }

    #[test]
    fn parses_composer_manifests() {
        let lock = "{\"packages\":[{\"name\":\"laravel/framework\",\"version\":\"v10.48.4\"},{\"name\":\"guzzlehttp/guzzle\",\"version\":\"7.8.1\"}],\"packages-dev\":[{\"name\":\"phpunit/phpunit\",\"version\":\"10.5.20\"}]}";
        let deps = parse_composer_lock(lock);
        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0].name, "laravel/framework");
        assert_eq!(deps[0].version, "10.48.4");
        assert_eq!(deps[0].ecosystem, "Packagist");
        assert_eq!(deps[2].name, "phpunit/phpunit");

        let json = "{\"require\":{\"laravel/framework\":\"^10.0\",\"guzzlehttp/guzzle\":\"7.8.1\"},\"require-dev\":{\"phpunit/phpunit\":\"^10.5\"}}";
        let deps = parse_composer_json(json);
        assert_eq!(deps.len(), 3);
        let laravel = deps.iter().find(|d| d.name == "laravel/framework").unwrap();
        assert_eq!(laravel.version, "^10.0");
        assert_eq!(
            deps.iter()
                .find(|d| d.name == "guzzlehttp/guzzle")
                .unwrap()
                .version,
            "7.8.1"
        );
    }

    #[test]
    fn parses_cargo_toml() {
        let text =
            "[dependencies]\nserde = \"1\"\nureq = { version = \"3\", features = [\"x\"] }\n";
        let deps = parse_cargo_toml(text);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "serde");
        assert_eq!(deps[1].version, "3");
    }

    #[test]
    fn semver_caret_inside_range_not_outdated() {
        // serde = "1" means any 1.x, latest 1.0.228 is inside
        assert_eq!(latest_satisfies("1", "1.0.228", "crates.io"), Some(true));
        assert_eq!(latest_satisfies("^1.2.3", "1.9.0", "npm"), Some(true));
    }

    #[test]
    fn semver_caret_outside_range() {
        assert_eq!(latest_satisfies("1", "2.0.0", "crates.io"), Some(false));
        assert_eq!(latest_satisfies("^1.2.3", "2.0.0", "npm"), Some(false));
    }

    #[test]
    fn semver_zero_major_caret() {
        // ^0.2.3 means >=0.2.3 <0.3.0
        assert_eq!(latest_satisfies("^0.2.3", "0.2.9", "npm"), Some(true));
        assert_eq!(latest_satisfies("^0.2.3", "0.3.0", "npm"), Some(false));
    }

    #[test]
    fn semver_exact_pin() {
        assert_eq!(
            latest_satisfies("=1.0.1", "1.0.228", "crates.io"),
            Some(false)
        );
        assert_eq!(latest_satisfies("=1.0.1", "1.0.1", "crates.io"), Some(true));
    }

    #[test]
    fn semver_tilde() {
        assert_eq!(latest_satisfies("~1.2.3", "1.2.9", "npm"), Some(true));
        assert_eq!(latest_satisfies("~1.2.3", "1.3.0", "npm"), Some(false));
    }

    #[test]
    fn semver_wildcard() {
        assert_eq!(latest_satisfies("1.x", "1.9.0", "npm"), Some(true));
        assert_eq!(latest_satisfies("1.x", "2.0.0", "npm"), Some(false));
        assert_eq!(latest_satisfies("1.2.x", "1.2.9", "npm"), Some(true));
        assert_eq!(latest_satisfies("1.2.x", "1.3.0", "npm"), Some(false));
    }

    #[test]
    fn semver_npm_bare_is_exact() {
        assert_eq!(latest_satisfies("4.18.0", "4.19.0", "npm"), Some(false));
    }

    #[test]
    fn parses_package_json() {
        let text = r#"{"dependencies": {"express": "^4.18.0"}}"#;
        let deps = parse_package_json(text);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "express");
    }

    #[test]
    fn nested_manifests_are_discovered_but_vendored_are_skipped() {
        let base = std::env::temp_dir().join(format!(
            "heides_deps_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // project root with no manifest, real manifest one level down
        let sub = base.join("app");
        std::fs::create_dir_all(sub.join("node_modules").join("left-pad")).unwrap();
        std::fs::create_dir_all(sub.join("subdir")).unwrap();
        std::fs::write(
            sub.join("package.json"),
            r#"{"dependencies": {"express": "^4.18.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            sub.join("subdir").join("package.json"),
            r#"{"dependencies": {"left-pad": "1.3.0"}}"#,
        )
        .unwrap();
        // vendored manifest must never surface
        std::fs::write(
            sub.join("node_modules")
                .join("left-pad")
                .join("package.json"),
            r#"{"dependencies": {"evil-pkg": "9.9.9"}}"#,
        )
        .unwrap();
        let deps = read_manifests(&base);
        let _ = std::fs::remove_dir_all(&base);
        let names: Vec<_> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(
            names.contains(&"express"),
            "root child manifest missed: {:?}",
            names
        );
        assert!(
            names.contains(&"left-pad"),
            "nested manifest missed: {:?}",
            names
        );
        assert!(
            !names.contains(&"evil-pkg"),
            "vendored manifest surfaced: {:?}",
            names
        );
    }
}
