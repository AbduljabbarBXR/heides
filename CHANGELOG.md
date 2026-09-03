# Changelog

All notable changes to HEIDES are recorded here.

## 0.9.1

* diagnostic console calls are no longer silent, console.debug, console.info, console.warn and console.error report as info since warn and error are sometimes deliberate logging
* alert dialogs report as info, remove before shipping
* console.log and debugger keep their warning severity

## 0.9.0

* html and css are first class languages, ten dialects in the map
* script and stylesheet references become real import edges, a page shows which files it loads
* inline script bodies are parsed as javascript with line numbers pointing at the real html rows, so page code joins the taint and call graph
* css at import rules and url references become file edges
* javascript URLs in link and script attributes report critical, a form page without a content security policy meta tag reports info
* clean corpus gate extends to html and css, idiomatic pages stay silent

## 0.8.1

* guard phase performance, source line checks memoized and the propagation queue deduped with a hash set, django check 52 to 46 seconds, the largest graphs no longer reprocess
* doc eyes and taint engine hardening, attribute and decorator transparent doc capture, describe reports coverage per language, scaffolds documented from birth
* named arguments bind by parameter name, python keywords and csharp and php 8 named syntax
* python and javascript bare parameters captured, function flows in those languages were dead since schema v4
* duplicate definitions merge when every candidate binds the flow identically, ambiguity stays silent
* value symbols in go java csharp and javascript, fields and constants now part of the map
* MCP server grew to ten tools, spine.describe and spine.neighbors plus a search kind on spine.query
* FTS5 text search over names, kinds, signatures and docs, index schema v6
* export command writes one self contained code map file with a presence ledger, every walked file visible, indexed or not
* credential rule no longer fires on field label defaults, proven on the django tree

## 0.8.0

* the index becomes the agent's eyes, stored in sqlite at .heides/index.db, schema v5, transactional writes, WAL concurrency, agent readable by any sqlite client
* every symbol carries its doc comment, cleaned and capped, so what a function is for reads from the map without opening the file
* rust enum variants and struct fields are first class value symbols with kinds and docs, constants were already captured
* module level code is first class, top level statements outside functions are analyzed as their own scope and taint flows through them with full source to sink traces, closing the biggest documented launch limit
* describe prints the workspace manifest in one read, entrypoints, files that run module level code, most connected symbols, call cycles and which files talk to which
* query neighbors shows definition, doc, callers, calls out and importers for one symbol, query definition now shows doc and signature
* scaffold indexes the newborn workspace immediately, describe works from the first second
* unit suite grown to fifty three checks, battle suite grown to seventy checks with module level and agent eyes fixtures

## 0.7.1

* dependency manifests are discovered recursively under the check root, parent scans no longer skip the real manifests one level down, vendored and generated trees are never walked
* credential rule sharpened against real world false positives, env var name placeholders, labels, chat template tokens, file names, urls, paths, i18n keys and quoted config entries stay silent, mock shaped values in test paths downgrade to warnings
* real key structure stays critical everywhere, long prefixed keys and PEM bodies fire in tests and config maps alike, comments with example keys are prose not code
* unit suite grown to forty eight checks covering every silent and firing shape

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
