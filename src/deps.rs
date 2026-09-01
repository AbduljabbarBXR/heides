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
                if latest != dep.version && !dep.version.starts_with(latest.as_str()) {
                    reports.push(DepReport {
                        severity: "warning".to_string(),
                        message: format!(
                            "{} {} is outdated. latest is {}",
                            dep.name, dep.version, latest
                        ),
                        file: "manifest".to_string(),
                        line: 0,
                    });
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
    fn parses_package_json() {
        let text = r#"{"dependencies": {"express": "^4.18.0"}}"#;
        let deps = parse_package_json(text);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "express");
    }
}
