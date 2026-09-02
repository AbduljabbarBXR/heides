// Dependency guard.
//
// Reads the project manifests, checks every dependency against the OSV
// vulnerability database, and compares against the latest published version.
// When the network is unavailable the guard degrades gracefully and says so.

use std::collections::BTreeMap;
use std::path::Path;

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
        Some(Version { major, minor, patch })
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
        let base = raw.split(['x', 'X', '*']).next().unwrap_or("").trim_end_matches('.');
        let parsed = Version::parse(base).unwrap_or(Version { major: 0, minor: 0, patch: 0 });
        if base.is_empty() {
            return Some(Clause::Any);
        }
        let dots = base.matches('.').count();
        if dots == 0 {
            // 1.x means >=1.0.0 <2.0.0
            let min = Version { major: parsed.major, minor: 0, patch: 0 };
            let max = Version { major: parsed.major + 1, minor: 0, patch: 0 };
            return Some(Clause::Wildcard(min, max));
        }
        if dots == 1 {
            // 1.2.x means >=1.2.0 <1.3.0
            let min = Version { major: parsed.major, minor: parsed.minor, patch: 0 };
            let max = Version { major: parsed.major, minor: parsed.minor + 1, patch: 0 };
            return Some(Clause::Wildcard(min, max));
        }
        return Some(Clause::Any);
    }
    // Bare version. npm treats it as exact, cargo treats it as caret.
    Version::parse(raw).map(|v| Clause::Exact(v))
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
            match clause {
                Some(c) => {
                    if !c.matches(&latest) {
                        all = false;
                        break;
                    }
                }
                None => return None,
            }
        }
        if all {
            any_group = true;
        }
    }
    Some(any_group)
}

/// Extract dependencies from Cargo.toml, Cargo.lock and package.json.
pub fn read_manifests(root: &Path) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let cargo_toml = root.join("Cargo.toml");
    let cargo_lock = root.join("Cargo.lock");
    let package_json = root.join("package.json");

    if cargo_toml.exists() {
        if let Ok(text) = std::fs::read_to_string(&cargo_toml) {
            deps.extend(parse_cargo_toml(&text));
        }
    } else if cargo_lock.exists() {
        if let Ok(text) = std::fs::read_to_string(&cargo_lock) {
            deps.extend(parse_cargo_lock(&text));
        }
    }

    if package_json.exists() {
        if let Ok(text) = std::fs::read_to_string(&package_json) {
            deps.extend(parse_package_json(&text));
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
            name = Some(t.trim_start_matches("name = ").trim_matches('"').to_string());
        } else if t.starts_with("version = ") && name.is_some() {
            let version = t.trim_start_matches("version = ").trim_matches('"').to_string();
            deps.push(Dependency {
                name: name.take().unwrap(),
                version,
                ecosystem: "crates.io",
            });
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
    let id = first.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
    let summary = first
        .get("summary")
        .and_then(|v| v.as_str())
        .unwrap_or("no summary");
    Some(format!("{}: {}", id, summary))
}

/// Fetch the latest published version of a dependency.
fn latest_version(dep: &Dependency) -> Option<String> {
    let url = if dep.ecosystem == "npm" {
        format!("https://registry.npmjs.org/{}/latest", dep.name)
    } else {
        format!("https://crates.io/api/v1/crates/{}", dep.name)
    };
    let resp = crate::web::get(&url).ok()?;
    let value: serde_json::Value = serde_json::from_str(&resp).ok()?;
    if dep.ecosystem == "npm" {
        value.get("version").and_then(|v| v.as_str()).map(|s| s.to_string())
    } else {
        value
            .get("crate")
            .and_then(|c| c.get("max_stable_version"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }
}

/// Run the dependency guard. Returns reports plus a network status flag.
pub fn check(root: &Path) -> (Vec<DepReport>, bool) {
    let deps = read_manifests(root);
    let mut reports = Vec::new();
    if deps.is_empty() {
        reports.push(DepReport {
            severity: "info".to_string(),
            message: "no dependency manifests found (Cargo.toml, Cargo.lock, package.json)".to_string(),
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
        let dep = Dependency {
            name: name.clone(),
            version: version.clone(),
            ecosystem: if ecosystem == "npm" { "npm" } else { "crates.io" },
        };
        checked += 1;
        match osv_check(&dep) {
            Some(vuln) => reports.push(DepReport {
                severity: "critical".to_string(),
                message: format!("{} {} has a known vulnerability: {}", dep.name, dep.version, vuln),
                file: "manifest".to_string(),
                line: 0,
            }),
            None => {}
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
    fn parses_cargo_toml() {
        let text = "[dependencies]\nserde = \"1\"\nureq = { version = \"3\", features = [\"x\"] }\n";
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
        assert_eq!(latest_satisfies("=1.0.1", "1.0.228", "crates.io"), Some(false));
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
}
