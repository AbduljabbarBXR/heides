// The staged apply guard.
//
// Takes a unified diff that an agent wants to apply and answers one question
// before anything touches disk: does this patch conflict with the current
// codebase? It applies the patch in memory, reparses the changed files, and
// compares the result against the persistent spine graph. Removed symbols,
// changed signatures, and duplicate definitions are reported with the exact
// call sites that would break.

use std::path::{Path, PathBuf};

use crate::parser;
use crate::spine::CodeGraph;

#[derive(Debug, Clone)]
pub struct Hunk {
    pub old_start: u64,
    pub lines: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PatchFile {
    pub old_path: String,
    pub new_path: String,
    pub hunks: Vec<Hunk>,
}

#[derive(Debug, Clone)]
pub struct StagedReport {
    pub severity: String,
    pub message: String,
    pub file: String,
    pub line: u64,
}

/// Parse a unified diff into structured patch files.
pub fn parse_patch(patch: &str) -> Result<Vec<PatchFile>, String> {
    let mut files: Vec<PatchFile> = Vec::new();
    let mut current: Option<PatchFile> = None;
    let mut header_seen = false;

    for raw in patch.lines() {
        let line = raw;
        if let Some(rest) = line.strip_prefix("diff --git ") {
            // diff --git a/old b/new
            if let Some(cur) = current.take() {
                files.push(cur);
            }
            let old = rest
                .split(' ')
                .next()
                .unwrap_or("a/")
                .trim_start_matches("a/");
            let new = rest
                .rsplit(' ')
                .next()
                .unwrap_or("b/")
                .trim_start_matches("b/");
            current = Some(PatchFile {
                old_path: old.to_string(),
                new_path: new.to_string(),
                hunks: Vec::new(),
            });
            header_seen = true;
        } else if line.starts_with("--- ") || line.starts_with("+++ ") {
            // paths are handled by the diff --git line; skip
        } else if let Some(hdr) = line.strip_prefix("@@ ") {
            // @@ -old_start,old_count +new_start,new_count @@
            let cur = current.as_mut().ok_or("hunk before any file header")?;
            let old_part = hdr.split(' ').next().unwrap_or("-0,0");
            let old_start: u64 = old_part
                .trim_start_matches('-')
                .split(',')
                .next()
                .unwrap_or("0")
                .parse()
                .map_err(|_| "bad hunk offset")?;
            cur.hunks.push(Hunk {
                old_start,
                lines: Vec::new(),
            });
        } else if let Some(cur) = current.as_mut()
            && (line.starts_with(' ') || line.starts_with('+') || line.starts_with('-'))
            && let Some(h) = cur.hunks.last_mut()
        {
            h.lines.push(line.to_string());
        }
    }
    if let Some(cur) = current.take() {
        files.push(cur);
    }
    if !header_seen && files.is_empty() {
        return Err("no unified diff found".to_string());
    }
    Ok(files)
}

/// Apply the patch files to the workspace in memory and return the new
/// content for every touched file. Deleted files map to None.
pub fn apply_in_memory(patch: &[PatchFile], root: &Path) -> Vec<(String, Option<String>)> {
    let mut results = Vec::new();
    for pf in patch {
        let target = root.join(pf.old_path.trim_start_matches('/'));
        let original = std::fs::read_to_string(&target).unwrap_or_default();
        let applied = apply_hunks(&original, &pf.hunks);
        let deleted = pf.new_path == "/dev/null" || applied.trim().is_empty();
        results.push((
            pf.old_path.clone(),
            if deleted { None } else { Some(applied) },
        ));
    }
    results
}

fn apply_hunks(original: &str, hunks: &[Hunk]) -> String {
    let mut lines: Vec<String> = original.lines().map(|l| l.to_string()).collect();
    let mut delta: isize = 0;
    for hunk in hunks {
        let mut pos = hunk.old_start.saturating_sub(1) as isize + delta;
        if pos < 0 {
            pos = 0;
        }
        let pos = pos as usize;
        let old_count = hunk
            .lines
            .iter()
            .filter(|l| l.starts_with(' ') || l.starts_with('-'))
            .count();
        let new_lines: Vec<String> = hunk
            .lines
            .iter()
            .filter(|l| l.starts_with(' ') || l.starts_with('+'))
            .map(|l| l[1..].to_string())
            .collect();
        let end = (pos + old_count).min(lines.len());
        lines.splice(pos..end, new_lines.iter().cloned());
        delta += new_lines.len() as isize - (end - pos) as isize;
    }
    lines.join("\n")
}

/// Check a parsed patch against the workspace graph.
pub fn check_patch(graph: &CodeGraph, root: &Path, patch: &[PatchFile]) -> Vec<StagedReport> {
    let norm = |p: &str| p.trim_start_matches("./").replace('\\', "/");
    let mut reports = Vec::new();
    let applied = apply_in_memory(patch, root);

    for (file, content) in &applied {
        let file_norm = norm(file);
        let path = PathBuf::from(file);
        match content {
            None => {
                // File was deleted. Find its symbols and warn every caller.
                let symbols_here: Vec<_> = graph
                    .symbols
                    .iter()
                    .filter(|s| norm(&s.file) == file_norm)
                    .collect();
                for s in symbols_here {
                    let callers = graph.callers_of(&s.name);
                    if !callers.is_empty() {
                        reports.push(StagedReport {
                            severity: "blocker".to_string(),
                            message: format!(
                                "file {} is deleted but {} is still called from {} call site(s)",
                                file,
                                s.name,
                                callers.len()
                            ),
                            file: file.clone(),
                            line: s.line,
                        });
                    }
                }
            }
            Some(new_content) => {
                let proposed = match parser::parse_file(&path, new_content) {
                    Some(p) => p,
                    None => continue,
                };
                let old_symbols: Vec<_> = graph
                    .symbols
                    .iter()
                    .filter(|s| norm(&s.file) == file_norm)
                    .collect();

                let mut proposed_names: Vec<&str> = Vec::new();
                for s in &proposed.symbols {
                    proposed_names.push(s.name.as_str());
                    // Duplicate definition elsewhere in the graph.
                    let elsewhere: Vec<_> = graph
                        .symbols_named(&s.name)
                        .into_iter()
                        .filter(|g| norm(&g.file) != file_norm)
                        .collect();
                    if !elsewhere.is_empty() {
                        reports.push(StagedReport {
                            severity: "blocker".to_string(),
                            message: format!(
                                "{} declares {} which already exists at {}:{}",
                                file, s.name, elsewhere[0].file, elsewhere[0].line
                            ),
                            file: file.clone(),
                            line: s.line,
                        });
                    }
                }

                for old in old_symbols {
                    let still_there = proposed_names.contains(&old.name.as_str());
                    let is_function = old.kind.contains("function")
                        || old.kind == "method_definition"
                        || old.kind == "function_definition";
                    if !still_there && is_function {
                        let callers = graph.callers_of(&old.name);
                        if !callers.is_empty() {
                            reports.push(StagedReport {
                                severity: "blocker".to_string(),
                                message: format!(
                                    "function {} is removed by the patch but still called at {}",
                                    old.name, callers[0].file
                                ),
                                file: file.clone(),
                                line: old.line,
                            });
                        } else {
                            reports.push(StagedReport {
                                severity: "warning".to_string(),
                                message: format!(
                                    "function {} is removed by the patch and has no recorded callers",
                                    old.name
                                ),
                                file: file.clone(),
                                line: old.line,
                            });
                        }
                    } else if still_there && is_function {
                        // Signature change check.
                        if let Some(proposed) = proposed
                            .symbols
                            .iter()
                            .find(|p| p.name == old.name && p.kind == old.kind)
                        {
                            let old_sig = normalize_sig(&old.signature);
                            let new_sig = normalize_sig(&proposed.signature);
                            if !old_sig.is_empty() && old_sig != new_sig {
                                let callers = graph.callers_of(&old.name);
                                reports.push(StagedReport {
                                    severity: if callers.is_empty() {
                                        "warning".to_string()
                                    } else {
                                        "blocker".to_string()
                                    },
                                    message: format!(
                                        "signature of {} changed ({} caller(s) may break: {})",
                                        old.name,
                                        callers.len(),
                                        if callers.is_empty() {
                                            "none recorded".to_string()
                                        } else {
                                            callers[0].caller.clone()
                                        }
                                    ),
                                    file: file.clone(),
                                    line: old.line,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    reports
}

fn normalize_sig(sig: &str) -> String {
    sig.chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .trim_end_matches('{')
        .trim_end_matches(':')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_diff() {
        let patch = "diff --git a/src/a.rs b/src/a.rs\n--- a/src/a.rs\n+++ b/src/a.rs\n@@ -1,3 +1,3 @@\n-old line\n+new line\n context\n";
        let files = parse_patch(patch).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].old_path, "src/a.rs");
        assert_eq!(files[0].hunks.len(), 1);
        assert_eq!(files[0].hunks[0].lines.len(), 3);
    }

    #[test]
    fn applies_hunks_in_memory() {
        let original = "one\ntwo\nthree\n";
        let patch =
            "diff --git a/f b/f\n--- a/f\n+++ b/f\n@@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three\n";
        let files = parse_patch(patch).unwrap();
        let applied = apply_hunks(original, &files[0].hunks);
        assert_eq!(applied, "one\nTWO\nthree");
    }

    #[test]
    fn applies_new_file() {
        let original = "";
        let patch = "diff --git a/new.rs b/new.rs\n--- /dev/null\n+++ b/new.rs\n@@ -0,0 +1,2 @@\n+fn hello() {}\n+fn main() { hello(); }\n";
        let files = parse_patch(patch).unwrap();
        let applied = apply_hunks(original, &files[0].hunks);
        assert!(applied.contains("fn hello"));
    }
}
