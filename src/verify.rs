// `verify`: a machine checkable definition of done.
//
// `check` answers "is this workspace safe". It does not answer "is this task
// finished", which is the question an autonomous loop actually needs answered
// to know when to stop. `verify` runs the project's own test suite and every
// heides guard in one pass and returns a single boolean, the reasons, and the
// coverage receipt.
//
// Two rules shape everything here:
//
// 1. Silence is never success. An unknown test command, an unrunnable suite, an
//    empty workspace and an unreachable advisory service all report a non-zero
//    exit or an explicit "not verified" state. The 0.15.2 defect class, where a
//    guard reported a clean workspace it had analysed nothing in, is the exact
//    failure this command exists to make impossible.
// 2. The receipt says what ran. Every run prints which suites ran, which were
//    skipped, and why, on success and on failure alike, so a human reading a
//    green build knows the scope of the claim.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::deps::DepsPolicy;
use crate::harmony;
use crate::indexer;

/// What one test suite attempt produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuiteOutcome {
    /// Ran to completion and every test passed.
    Passed,
    /// Ran to completion and at least one test failed.
    Failed,
    /// A command was available and produced no machine readable result, so
    /// passing cannot be claimed. Distinct from Failed on purpose.
    Unverified,
    /// No test command for this ecosystem was found. Not a failure by itself.
    Absent,
}

impl SuiteOutcome {
    pub fn label(&self) -> &'static str {
        match self {
            SuiteOutcome::Passed => "pass",
            SuiteOutcome::Failed => "fail",
            SuiteOutcome::Unverified => "unverified",
            SuiteOutcome::Absent => "no test command",
        }
    }

    pub fn is_failure(&self) -> bool {
        matches!(self, SuiteOutcome::Failed | SuiteOutcome::Unverified)
    }
}

/// One ecosystem's test command and how it went.
#[derive(Debug, Clone)]
pub struct Suite {
    pub name: &'static str,
    pub command: &'static str,
    pub outcome: SuiteOutcome,
    pub detail: String,
}

/// The whole verdict.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub ok: bool,
    pub suites: Vec<Suite>,
    pub blockers: usize,
    pub criticals: usize,
    pub warnings: usize,
    pub coverage: String,
    pub advisories_ran: bool,
    pub reasons: Vec<String>,
    /// The findings that made this a failure, as (severity, message,
    /// file:line). `reasons` says how many; this says which. An agent handed
    /// only a count cannot act on it.
    pub findings: Vec<(String, String, String)>,
}

/// The test commands heides knows how to drive, in priority order.
///
/// Each is a shell command string because every one of these ecosystems is
/// driven through its own runner and there is nothing to gain from shelling
/// out argument by argument.
const SUITES: &[(&str, &str, &str)] = &[
    // name, marker file, command
    ("rust", "Cargo.toml", "cargo test --quiet"),
    ("python", "pytest.ini", "pytest -q"),
    ("python", "pyproject.toml", "pytest -q"),
    ("python", "setup.cfg", "pytest -q"),
    ("python", "tox.ini", "pytest -q"),
    ("python", "requirements.txt", "pytest -q"),
    ("node", "package.json", "npm test --silent"),
    ("go", "go.mod", "go test ./..."),
    ("ruby", "Gemfile", "bundle exec rspec"),
];

/// Run the test suite for `root`.
///
/// Returns every suite heides tried, including the ones with no marker file, so
/// the receipt can say "no test command" rather than being silent about it.
pub fn run_suites(root: &Path) -> Vec<Suite> {
    let mut out = Vec::new();
    let mut tried = Vec::new();

    for (name, marker, cmd) in SUITES {
        if !root.join(marker).exists() {
            continue;
        }
        // One command per ecosystem. python appears six times because six
        // marker files can each introduce it, and running pytest six times
        // because a repo has both pytest.ini and pyproject.toml is worse than
        // useless in a verify loop.
        if tried.iter().any(|t| *t == name) {
            continue;
        }
        tried.push(name);
        out.push(run_one(name, cmd, root));
    }

    if out.is_empty() {
        out.push(Suite {
            name: "none",
            command: "",
            outcome: SuiteOutcome::Absent,
            detail: "no recognised test command for this workspace".into(),
        });
    }
    out
}

fn run_one(name: &'static str, cmd: &'static str, root: &Path) -> Suite {
    let spawned = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    let out = match spawned {
        Ok(o) => o,
        Err(e) => {
            return Suite {
                name,
                command: cmd,
                outcome: SuiteOutcome::Unverified,
                detail: format!("could not start `{}`: {}", cmd, e),
            }
        }
    };

    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let code = out.status.code().unwrap_or(-1);

    let outcome = if code == 0 {
        SuiteOutcome::Passed
    } else if text.to_lowercase().contains("no test") 
        || text.to_lowercase().contains("no tests")
        || text.to_lowercase().contains("0 tests")
    {
        // A runner that started, found nothing to run and exited zero has not
        // verified anything. Treating it as Passed is how a green build lies.
        SuiteOutcome::Unverified
    } else {
        SuiteOutcome::Failed
    };

    let tail: String = text
        .lines()
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n");

    Suite {
        name,
        command: cmd,
        outcome,
        detail: tail,
    }
}

/// Run every guard over `root` and the test suites, and decide.
///
/// An empty workspace is not verified. Neither is one whose advisory service
/// could not be reached when the caller asked for advisories.
pub fn verify(root: &Path, skip_tests: bool, require_advisories: bool) -> Verdict {
    let mut reasons = Vec::new();

    let graph = match indexer::load_or_build(root) {
        Ok(g) => g,
        Err(e) => {
            return Verdict {
                ok: false,
                suites: vec![Suite {
                    name: "none",
                    command: "",
                    outcome: SuiteOutcome::Absent,
                    detail: String::new(),
                }],
                blockers: 0,
                criticals: 0,
                warnings: 0,
                coverage: String::new(),
                advisories_ran: false,
                reasons: vec![format!("could not index the workspace: {}", e)],
                findings: Vec::new(),
            }
        }
    };

    let mut policy = DepsPolicy::default();
    policy.require_advisories = require_advisories;

    let (reports, cov) = harmony::check_workspace_with_coverage(root, &graph, policy);

    let mut blockers = 0;
    let mut criticals = 0;
    let mut warnings = 0;
    for r in &reports {
        match r.severity.as_str() {
            "blocker" => blockers += 1,
            "critical" => criticals += 1,
            "warning" => warnings += 1,
            _ => {}
        }
    }

    // The same honesty rule `check` applies, promoted to a reason. An advisory
    // service that did not answer means the workspace was not fully checked,
    // so it cannot be reported as verified.
    let advisories_ran = cov.deps == harmony::DepsState::RanOnline;
    if require_advisories && !advisories_ran {
        reasons.push(
            "advisories were required but the advisory service did not run; this is not a full verification"
                .into(),
        );
    }

    if cov.files_read == 0 {
        reasons.push("no files were analysed, so nothing was verified".into());
    }
    if !cov.no_grammar.is_empty() {
        reasons.push(format!(
            "indexed but no grammar, so these were not analysed: {}",
            cov.no_grammar.join(", ")
        ));
    }

    let suites = if skip_tests {
        vec![Suite {
            name: "skipped",
            command: "",
            outcome: SuiteOutcome::Absent,
            detail: "--skip-tests was passed, so the test suites did not run".into(),
        }]
    } else {
        run_suites(root)
    };

    for s in &suites {
        if s.outcome.is_failure() {
            reasons.push(format!("test suite `{}` {}", s.name, s.outcome.label()));
        }
    }

    if blockers > 0 {
        reasons.push(format!("{} blocking finding(s)", blockers));
    }
    if criticals > 0 && !require_advisories {
        // Criticals fail verify by default. A security gate that ignores them
        // is the heides staged no-op all over again.
        reasons.push(format!("{} critical finding(s)", criticals));
    }

    let findings: Vec<(String, String, String)> = reports
        .iter()
        .filter(|r| r.severity == "blocker" || r.severity == "critical")
        .map(|r| {
            let loc = if r.file.is_empty() {
                r.line.to_string()
            } else {
                format!("{}:{}", r.file, r.line)
            };
            (r.severity.clone(), r.message.clone(), loc)
        })
        .collect();

    let ok = reasons.is_empty();

    Verdict {
        ok,
        suites,
        blockers,
        criticals,
        warnings,
        coverage: cov.render(),
        advisories_ran,
        reasons,
        findings,
    }
}

/// One line per fact. The same shape in a terminal, in JSON and over MCP.
pub fn render(v: &Verdict) -> String {
    let mut out = String::new();
    for s in &v.suites {
        let line = if s.command.is_empty() {
            format!("tests  {}: {}", s.name, s.outcome.label())
        } else {
            format!("tests  {}: {}  `{}`", s.name, s.outcome.label(), s.command)
        };
        out.push_str(&line);
        out.push('\n');
        if !s.detail.is_empty() && !s.outcome.is_failure() && s.outcome != SuiteOutcome::Passed
        {
            for l in s.detail.lines() {
                out.push_str(&format!("        {}\n", l));
            }
        }
    }
    out.push_str(&format!(
        "guards {} blocker, {} critical, {} warning\n",
        v.blockers, v.criticals, v.warnings
    ));
    out.push_str(&coverage_line(&v.coverage));
    out.push_str(if v.advisories_ran {
        "advisories ran\n"
    } else {
        "advisories did not run\n"
    });
    if v.ok {
        out.push_str("VERIFIED. definition of done met.");
    } else {
        out.push_str("NOT VERIFIED:");
        for r in &v.reasons {
            out.push_str(&format!("\n  - {}", r));
        }
        for (sev, msg, loc) in &v.findings {
            out.push_str(&format!("\n  [{}] {} at {}", sev, msg, loc));
        }
    }
    out
}

fn coverage_line(rendered: &str) -> String {
    if rendered.is_empty() {
        "coverage: none\n".to_string()
    } else {
        rendered
            .lines()
            .map(|l| format!("coverage  {}", l))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    }
}

/// The machine readable form. A loop branches on `ok`; prose is for humans.
pub fn to_json(v: &Verdict) -> String {
    let suites: Vec<String> = v
        .suites
        .iter()
        .map(|s| {
            format!(
                "{{\"name\":\"{}\",\"outcome\":\"{}\",\"command\":\"{}\"}}",
                s.name,
                s.outcome.label(),
                s.command
            )
        })
        .collect();
    let reasons: Vec<String> = v.reasons.iter().map(|r| format!("{:?}", r)).collect();
    let findings: Vec<String> = v
        .findings
        .iter()
        .map(|(sev, msg, loc)| {
            format!(
                "{{\"severity\":{:?},\"message\":{:?},\"at\":{:?}}}",
                sev, msg, loc
            )
        })
        .collect();
    format!(
        "{{\"ok\":{},\"blockers\":{},\"criticals\":{},\"warnings\":{},\
\"advisories_ran\":{},\"suites\":[{}],\"reasons\":[{}],\"findings\":[{}],\"coverage\":{:?}}}",
        v.ok,
        v.blockers,
        v.criticals,
        v.warnings,
        v.advisories_ran,
        suites.join(","),
        reasons.join(","),
        findings.join(","),
        v.coverage
    )
}

/// Where the workspace root should be, given the argument list.
pub fn root_from(args: &[String], skip: usize) -> PathBuf {
    for a in args.iter().skip(skip) {
        if !a.starts_with('-') {
            return PathBuf::from(a);
        }
    }
    PathBuf::from(".")
}