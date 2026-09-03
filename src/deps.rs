// Dependency guard.
//
// Reads the project manifests, checks every dependency against the OSV
// vulnerability database, and compares against the latest published version.
// When the network is unavailable the guard degrades gracefully and says so.

use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;

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

/// Parse pyproject.toml project dependencies, multiline arrays and the
/// single line inline array form both work.
fn parse_pyproject_toml(text: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let mut in_deps = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') && t.ends_with(']') {
            in_deps = t.starts_with("[project.dependencies]");
            continue;
        }
        if !in_deps {
            continue;
        }
        if t.starts_with(']') || t.is_empty() {
            in_deps = false;
            continue;
        }
        // Inline array lines carry every entry in brackets on one line,
        // peel them and treat each quoted entry as its own requirement.
        let inner = if t.starts_with("dependencies = [") {
            t.trim_start_matches("dependencies = [")
                .trim_end_matches(']')
                .trim_end_matches(',')
                .to_string()
        } else {
            t.trim_end_matches(',').to_string()
        };
        for entry in split_quoted_list(&inner) {
            if let Some((name, version)) = split_python_req(&entry) {
                deps.push(Dependency {
                    name,
                    version,
                    ecosystem: "PyPI",
                });
            }
        }
    }
    deps
}

/// Split a python style list body into its quoted string entries.
fn split_quoted_list(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote = None;
    for ch in body.chars() {
        match quote {
            Some(q) => {
                if ch == q {
                    quote = None;
                } else {
                    cur.push(ch);
                }
            }
            None => {
                if ch == '\'' || ch == '"' {
                    quote = Some(ch);
                } else if ch == ',' {
                    let entry = cur.trim().to_string();
                    if !entry.is_empty() {
                        out.push(entry);
                    }
                    cur.clear();
                } else {
                    cur.push(ch);
                }
            }
        }
    }
    let entry = cur.trim().to_string();
    if !entry.is_empty() {
        out.push(entry);
    }
    out
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
fn osv_check(dep: &Dependency) -> Option<String> {
    let body = serde_json::json!({
        "package": { "name": dep.name, "ecosystem": dep.ecosystem },
        "version": dep.version
    });
    let url = "https://api.osv.dev/v1/query";
    let resp = crate::web::post_json(url, &body.to_string()).ok()?;
    let value: serde_json::Value = serde_json::from_str(&resp).ok()?;
    let vulns = value.get("vulns").and_then(|v| v.as_array())?;
    if vulns.is_empty() {
        return None;
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
    Some(format!("{}: {}", id, summary))
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
pub fn check(root: &Path) -> (Vec<DepReport>, bool) {
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
        return (reports, true);
    }

    // Deduplicate by name and ecosystem.
    let mut seen: BTreeMap<(String, String), String> = BTreeMap::new();
    for d in &deps {
        let key = (d.name.clone(), d.ecosystem.to_string());
        if d.version != "?" && !seen.contains_key(&key) {
            seen.insert(key, d.version.clone());
        }
    }

    let mut network_ok = true;
    let mut checked = 0;
    for ((name, ecosystem), version) in &seen {
        let eco = canonical_ecosystem(ecosystem);
        let dep = Dependency {
            name: name.clone(),
            version: version.clone(),
            ecosystem: eco,
        };
        checked += 1;
        let vuln = osv_check(&dep);
        if let Some(vuln) = vuln {
            reports.push(DepReport {
                severity: "critical".to_string(),
                message: format!(
                    "{} {} has a known vulnerability: {}",
                    dep.name, dep.version, vuln
                ),
                file: "manifest".to_string(),
                line: 0,
            })
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
                network_ok = false;
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
    (reports, network_ok)
}

#[cfg(test)]
mod tests {
    use super::*;

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
