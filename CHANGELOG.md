# Changelog

All notable changes to HEIDES are recorded here.

## 0.7.0

* interprocedural taint, a summary and fixpoint engine proves flows across function boundaries with full source to sink traces
* function summaries per call, parameter to sink, parameter to return, source wrapper detection
* argv sources removed, operator input is not attacker input, documented in the rules file
* compiled pattern cache for the taint matcher, real workspace checks ran minutes faster
* schema v4, function symbols carry structured parameter names, old indexes rescan once
* battle suite grown to sixty five checks with cross function fixtures, clean files stay silent

## 0.6.0

* GitHub Actions CI gate, format check, clippy at deny warnings, release build and every test suite on every push and pull request
* byte identical determinism test, two fresh scans of the same tree must print the same output and write the same index bytes
* RULES.md, the full rule specification with exact triggers, severities and guarantees for every guard
* published measurements in the README, taken from a release binary run on an Android phone
* clippy clean across the tree, Path over PathBuf on the public surface

## 0.5.0

* phase three hardening, no panic no crash
* depth capped syntax tree walk, grown stack parsing, lexical pre check against input deep enough to crash the C parser
* MCP server reads messages as raw bytes so binary junk can never poison the stream, caps a single message at sixteen megabytes, stays alive through hostile clients
* hostile test suite, random bytes, code soup, truncated real code and brace storms fed to the parser and every guard in all eight languages
* battle suite grown to fifty nine end to end checks with a hostile phase

## 0.4.0

* phase one hardening, no finding without proof
* semver range aware dependency comparisons, caret tilde wildcard and exact forms with real range semantics
* exact function body length from real brace matching, never an estimate
* storage and file handle guards scan the true enclosing block, not a fixed window
* clean corpus gate, zero findings on idiomatic code in all eight languages, enforced in the build
* phase two scale, parallel parsing on every core, incremental diffs by mtime fingerprint, compact binary index with atomic replace, hash lookup indexes over symbol callee and file

## 0.3.0

* PHP, Go, Java and C# in the deep spine set
* taint rules for SQL, shell and filesystem sinks in all four new languages
* deeper README with guard walkthroughs, MCP tool reference and FAQ
* contributing guide
* battle suite extended to forty seven checks, all passing

## 0.2.0

* tree sitter spine for Rust, JavaScript, TypeScript and Python
* Harmony guards, staged apply, security taint, edge cases, best practices, dependency check
* Grounding, plan evaluation, scaffolding, web confirmation
* battle suite of forty three end to end checks, all passing

## 0.1.0

* first skeleton, one binary with CLI and MCP server over stdio
