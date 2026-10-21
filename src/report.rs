// Machine readable output: the JSON and SARIF a CI job reads.
//
// The CLI printed prose, and prose is a thing a human reads and a machine
// guesses at. An agent asked to gate a build cannot parse "0 blocker(s), 1
// critical" out of a sentence and should not have to. The MCP surface already
// returned JSON for `harmony.report`; the command line did not, so a pipeline
// that ran the binary and the pipeline that ran the server saw two different
// schemas for the same findings.
//
// The schema here is versioned and stable: `heides.findings/v1`. Fields are
// added, never renamed or removed, because a CI job that reads this file
// should keep working when the tool is upgraded.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{Value, json};

use crate::harmony::{Coverage, GuardReport};

/// The schema version. Bumped when a field changes meaning.
pub const SCHEMA: &str = "heides.findings/v1";

/// One finding, as it appears in the JSON output.
fn finding_json(r: &GuardReport, root: Option<&Path>) -> Value {
    json!({
        // `guard` is the older name for `rule`. Both are in the output
        // because a client that reads one of them is a client that exists,
        // and a field that disappears under it is a broken client.
        "rule": r.guard,
        "guard": r.guard,
        "severity": r.severity,
        "message": r.message,
        "file": r.file,
        "line": r.line,
        "fingerprint": crate::insight::fingerprint(&r.guard, &r.file, &r.message, r.line),
        "key": crate::insight::finding_key(&r.guard, &r.file, &r.message),
        "confidence": confidence_for(r),
        "cwe": cwe_for(r),
        "suggestion": suggestion_for(r),
        "snippet": snippet_for(r, root),
        "scope": scope_for(&r.file),
    })
}

/// Whether a finding sits in test code.
///
/// Test code is not less important, it is a different question: a finding in a
/// test is usually about the test's own fixture, and a finding in shipped code
/// is about the product. A tool that does not tell them apart cannot be told
/// which findings to read first.
pub fn scope_for(file: &str) -> &'static str {
    let lower = file.to_ascii_lowercase();
    for part in lower.split('/') {
        if part == "test"
            || part == "tests"
            || part == "spec"
            || part == "specs"
            || part == "__tests__"
        {
            return "test";
        }
    }
    let name = lower.rsplit('/').next().unwrap_or("");
    if name.starts_with("test_")
        || name.starts_with("test.")
        || name.ends_with("_test.py")
        || name.ends_with("_test.go")
        || name.ends_with("_test.rb")
        || name.ends_with("_spec.rb")
        || name.ends_with(".test.js")
        || name.ends_with(".test.ts")
        || name.ends_with(".spec.js")
        || name.ends_with(".spec.ts")
    {
        return "test";
    }
    "source"
}

/// The JSON report of one run.
pub fn to_json(
    reports: &[GuardReport],
    coverage: &Coverage,
    root: Option<&Path>,
    baseline_info: Option<&BaselineInfo>,
) -> String {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for r in reports {
        *counts.entry(r.severity.as_str()).or_insert(0) += 1;
    }
    let findings: Vec<Value> = reports.iter().map(|r| finding_json(r, root)).collect();
    let mut doc = json!({
        "schema": SCHEMA,
        "tool": { "name": "heides", "version": env!("CARGO_PKG_VERSION") },
        "clean": reports.is_empty(),
        "counts": {
            "blocker": counts.get("blocker").copied().unwrap_or(0),
            "critical": counts.get("critical").copied().unwrap_or(0),
            "warning": counts.get("warning").copied().unwrap_or(0),
            "info": counts.get("info").copied().unwrap_or(0),
        },
        "findings": findings,
        "coverage": {
            "files": coverage.files,
            "files_read": coverage.files_read,
            "languages": coverage.languages,
            "taint_untested": coverage.taint_untested,
            "no_grammar": coverage.no_grammar,
            "unreadable": coverage.unreadable,
        },
    });
    if let Some(b) = baseline_info {
        doc["baseline"] = json!({
            "path": b.path,
            "known": b.known,
            "new": b.new,
        });
    }
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
}

/// What the baseline comparison found, for the report to carry.
#[derive(Debug, Clone, Default)]
pub struct BaselineInfo {
    pub path: String,
    pub known: usize,
    pub new: usize,
}

/// The SARIF 2.1.0 report of one run.
///
/// SARIF is what GitHub code scanning reads, and what a security team pastes
/// into a ticket. It is a different shape from the JSON above on purpose: the
/// JSON is for a program, the SARIF is for a tool that already knows SARIF.
pub fn to_sarif(reports: &[GuardReport]) -> String {
    let mut rules: Vec<Value> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for r in reports {
        if seen.insert(r.guard.clone()) {
            rules.push(json!({
                "id": r.guard,
                "name": r.guard.replace('.', "_"),
                "shortDescription": { "text": describe_rule(&r.guard) },
                "help": { "text": suggestion_for(r) },
                "properties": {
                    "cwe": cwe_for(r),
                    "severity": r.severity,
                },
            }));
        }
    }
    let results: Vec<Value> = reports
        .iter()
        .map(|r| {
            json!({
                "ruleId": r.guard,
                "level": sarif_level(&r.severity),
                "message": { "text": r.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": r.file },
                        "region": { "startLine": r.line.max(1) },
                    }
                }],
                "partialFingerprints": {
                    "heidesFingerprint": crate::insight::fingerprint(&r.guard, &r.file, &r.message, r.line),
                },
            })
        })
        .collect();
    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "heides",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/AbduljabbarBXR/heides",
                    "rules": rules,
                }
            },
            "results": results,
        }]
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
}

/// The SARIF level for a severity.
fn sarif_level(severity: &str) -> &'static str {
    match severity {
        "blocker" | "critical" => "error",
        "warning" => "warning",
        _ => "note",
    }
}

/// A one line description of a rule, for the SARIF rule table.
fn describe_rule(rule: &str) -> String {
    match rule {
        "security.taint" => "user controlled input reaches a dangerous sink".to_string(),
        "security.taint.truncated" => "the interprocedural taint pass stopped early".to_string(),
        "edge.cases" => "an input the code does not handle".to_string(),
        "best.practice" => "a practice worth changing, not a defect".to_string(),
        "config.credential" => "a credential committed to the repository".to_string(),
        "staged.apply" => "the patch does not apply cleanly".to_string(),
        other => {
            if other.starts_with("database.") {
                "a schema or database defect".to_string()
            } else {
                other.to_string()
            }
        }
    }
}

/// How sure the tool is about a finding.
///
/// A finding with the source and the sink on one line is a fact about the
/// code. A finding that follows a name across a function boundary is a
/// judgement, and saying so is what lets a reader decide how much to trust
/// it.
pub fn confidence_for(r: &GuardReport) -> &'static str {
    if r.guard.starts_with("security.taint") {
        if r.message.contains("on this line") {
            return "high";
        }
        return "medium";
    }
    if r.guard == "config.credential" {
        return "high";
    }
    if r.guard == "edge.cases" {
        return "medium";
    }
    "low"
}

/// The CWE a finding maps to, when there is one.
pub fn cwe_for(r: &GuardReport) -> Option<&'static str> {
    if !r.guard.starts_with("security.taint") {
        return match r.guard.as_str() {
            "config.credential" => Some("CWE-798"),
            _ => None,
        };
    }
    let m = r.message.to_ascii_lowercase();
    let cwe = if m.contains("sql") {
        "CWE-89"
    } else if m.contains("shell") || m.contains("command") {
        "CWE-78"
    } else if m.contains("filesystem") || m.contains("path") {
        "CWE-22"
    } else if m.contains("xss") || m.contains("cross site") {
        "CWE-79"
    } else if m.contains("nosql") {
        "CWE-943"
    } else if m.contains("ssrf") || m.contains("metadata fetch") {
        "CWE-918"
    } else if m.contains("eval") || m.contains("code injection") {
        "CWE-95"
    } else if m.contains("deserial") {
        "CWE-502"
    } else if m.contains("prompt") {
        "CWE-77"
    } else {
        return None;
    };
    Some(cwe)
}

/// What to do about a finding.
pub fn suggestion_for(r: &GuardReport) -> String {
    if !r.guard.starts_with("security.taint") {
        return match r.guard.as_str() {
            "config.credential" => {
                "move the credential out of the repository and rotate the exposed value".to_string()
            }
            "edge.cases" => "handle the missing or empty case explicitly".to_string(),
            "best.practice" => {
                "advisory only. change it if the project agrees with the advice".to_string()
            }
            _ => "review the finding".to_string(),
        };
    }
    let m = r.message.to_ascii_lowercase();
    if m.contains("sql") {
        "use a parameterised query and bind the value instead of interpolating it".to_string()
    } else if m.contains("shell") || m.contains("command") {
        "pass the arguments as an array, or quote them, so the value cannot change the command"
            .to_string()
    } else if m.contains("filesystem") || m.contains("path") {
        "resolve the path against a fixed base and reject anything that escapes it".to_string()
    } else if m.contains("xss") || m.contains("cross site") {
        "escape the value for the output it lands in, or write text instead of markup".to_string()
    } else if m.contains("nosql") {
        "validate the query document and reject operator keys that come from the request"
            .to_string()
    } else if m.contains("ssrf") || m.contains("metadata fetch") {
        "allow the destination, do not take it from the request".to_string()
    } else if m.contains("eval") {
        "do not evaluate input. parse it instead".to_string()
    } else if m.contains("deserial") {
        "use a parser that does not instantiate arbitrary types".to_string()
    } else {
        "validate the value before it reaches the sink".to_string()
    }
}

/// The source line a finding points at, when the file can still be read.
fn snippet_for(r: &GuardReport, root: Option<&Path>) -> String {
    if r.file.is_empty() || r.line == 0 {
        return String::new();
    }
    let Some(root) = root else {
        return String::new();
    };
    let path = root.join(&r.file);
    let Ok(content) = std::fs::read_to_string(&path) else {
        return String::new();
    };
    content
        .lines()
        .nth(r.line as usize - 1)
        .map(|l| l.trim().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rep(guard: &str, severity: &str, message: &str) -> GuardReport {
        GuardReport {
            guard: guard.to_string(),
            severity: severity.to_string(),
            message: message.to_string(),
            file: "src/app.py".to_string(),
            line: 12,
        }
    }

    #[test]
    fn the_json_carries_a_fingerprint_for_every_finding() {
        let reports = vec![rep(
            "security.taint",
            "critical",
            "user input reaches a SQL sink",
        )];
        let cov = Coverage::default();
        let text = to_json(&reports, &cov, None, None);
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["schema"], SCHEMA);
        let finding = &doc["findings"][0];
        assert!(finding["fingerprint"].as_str().unwrap().len() >= 16);
        assert_eq!(finding["cwe"], "CWE-89");
        assert_eq!(finding["confidence"], "medium");
    }

    #[test]
    fn the_sarif_is_valid_json_with_one_result_per_finding() {
        let reports = vec![
            rep(
                "security.taint",
                "critical",
                "user input reaches a SQL sink",
            ),
            rep("best.practice", "info", "diagnostic console call"),
        ];
        let doc: Value = serde_json::from_str(&to_sarif(&reports)).unwrap();
        assert_eq!(doc["version"], "2.1.0");
        assert_eq!(doc["runs"][0]["results"].as_array().unwrap().len(), 2);
        assert_eq!(doc["runs"][0]["results"][0]["level"], "error");
        assert_eq!(doc["runs"][0]["results"][1]["level"], "note");
    }
}
