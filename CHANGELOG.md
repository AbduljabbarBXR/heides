# Changelog

All notable changes to HEIDES are recorded here.

## 0.19.2

`staged` was a no-op that reported success. It is the pre-commit gate, and it checked nothing but merge conflicts.

* **`staged` ran no security guards at all.** A patch adding `subprocess.run(cmd, shell=True)`, `requests.get(url, verify=False)`, `eval(cmd)` and a hardcoded `ghp_` token reported `no conflicts detected, and the guards found nothing in the patched files` and exited 0. The identical file written to disk produced a critical. This was a regression: the guard pass existed and was dropped during a branch split while the reworded success message was kept, which made the absence read as a considered verdict rather than an admission.
* **The second pass is restored.** `check_staged` reconstructs the post-patch content for every touched file and runs the taint, edge and practice guards over it, tagging findings `[staged]` so a hand can tell the change being made from a pre-existing finding in the same file.
* **Three tests, because the wording and the behaviour have to be tested together.** One plants the four payloads in a patch. One asserts `staged` and `check` agree on byte-identical content, built from one source string so the fixture cannot drift between the two paths, which is the assertion whose absence let this happen. One asserts conflict detection still works alongside the guard pass.
* **`subprocess.run(` was not a shell sink.** The python row matched only a bare `subprocess(`, so `run`, `call`, `check_call`, `check_output` and `Popen` all passed silently while `os.system` and `eval` were caught. Found while writing the staged test: the fixture was built on a `subprocess.run` call that `check` also missed, so the test was failing for a second, independent reason.
* **`[build-system] requires` is no longer discarded.** An unpinned build requirement like `hatchling` was dropped, so a pyproject whose only requirement was one bare name reported no manifests at all. Unpinned build dependencies are kept and marked, because the build resolves them to whatever is current, which is the risk worth naming. 0.19.0 added a test asserting that drop was correct; that test was wrong and is replaced.
* **`staged` now exits non-zero on a blocker or critical.** It returned `SUCCESS` unconditionally, so a pre-commit gate could report three criticals and let the pipeline continue. That is the same defect 0.18.0 fixed for `check`, in the other command. `--exit-zero` restores the old behaviour and `--exit-threshold` works here too.
* **Five battle checks for it,** covering the exit code, the `[staged]` tagging, the secret finding, `--exit-zero`, and that a clean patch still exits 0.
* 175 tests, including the clean corpus, so idiomatic code must still produce nothing.

## 0.19.1

A packaging accident, caught before it was pushed further.

* **0.19.0 on npm shipped a baked-in Linux x64 binary.** `files: ["bin/"]` packed
  whatever was in `bin/`, and a stale local build was sitting there. The launcher
  checks for the binary next to itself, so on macOS and Windows it would have
  found the Linux one and tried to run it. The tarball was 3.3 MB against the
  intended 4.7 kB.
* **npm would not let it be removed.** Unpublishing is refused for granular
  tokens that bypass two-factor authentication, and deprecating a version you
  want gone is not a fix. So this had to be corrected forward.
* **`files` now names `bin/heides.js` explicitly** rather than the directory, and
  `.npmignore` excludes the platform binary as a second line of defence.
* **A test asserts it.** The launcher must be published and the binary must not
  be, and `npm test` fails if either changes.

## 0.19.0

Three fixes and a packaging fix. The packaging one is the reason most people on npm 11.16 or newer could not run `heides` at all.

* **`npm install heides` produced a package that could not run.** The 1KB launcher installed, the 15MB binary never did, because npm 11.16+ blocks dependency lifecycle scripts by default, and `--allow-scripts` is not a workaround: on npm 11.17 the flag makes the CLI throw `Cannot destructure property 'name' of '.for' as it is undefined` and abort before installing anything. Every `heides` command then failed with `binary not found`, and the old advice, reinstall, was the exact operation that had just failed.
* **The launcher repairs itself.** If the binary is absent it runs the same `install.js` the postinstall would have, announcing what it is doing before the network call, and on failure it prints the build-from-source escape hatch and the releases URL.
* **The platform table was deliberately not duplicated.** `install.js` keeps ownership of the asset table and the Termux `android-arm64` case. The launcher only decides whether to call it. Two copies of that table is two places to drift, and the Termux case breaks quietly when it drifts.
* **`pyproject.toml` was found, opened, parsed to nothing, and then reported as absent.** The parser only read the legacy `[project.dependencies]` table, so a modern `[project]` file with `dependencies = [...]` yielded zero dependencies and the run printed "no dependency manifests found" while naming the very file it had just located. That silently disabled dependency checking for the whole PyPI ecosystem, for every project using uv, poetry, hatch or setuptools. PEP 621 inline and multi-line forms, PEP 735 `optional-dependencies` and `dependency-groups`, and `[build-system] requires` are all read now.
* **The fix initially broke a test that had been passing since 0.18.0,** and the parser it replaced could not read the form it was written for. Both are covered now: the modern form, the legacy form, tool tables that must be ignored, and PEP 735 group includes that are references rather than requirements.
* **A python `def` parameter is not a taint source, and the clean corpus is why.** Treating every parameter as untrusted flags `def read_config(path): open(path)` and a function that escapes before calling `mark_safe`, both of which are correct code. It is also too blind where it matters, because a parameter is only untrusted if a caller passes user input, and this scanner does not resolve callers yet. Doing it properly means seeding a parameter from the call graph, which is the recorded next step rather than a false positive on every helper.
* **A source line is now resolved by one function in both engines.** The intra-file pass and the interprocedural pass disagreed about what a `def f(x: int = 5):` line binds, and both asked for an assigned variable, which answers `int`, the annotation type, for a def with a defaulted parameter. One shared resolver closes that, so the two layers cannot drift again.
* **"patch is safe to apply" is gone.** The staged check said the word "safe" when it had only checked whether the hunks conflicted, which is the word a hand trusts most. It now says what it did: no conflicts, and what the guards found in the patched files.
* 12 tests, including the clean corpus, the legacy `pyproject` form, the nested-default parameter parse, and the launcher's repair path.

## 0.18.0

Two changes, one small release. The taint-adjacent rule that violated the project's own contract, and a gate that can finally fail.

* **The `unwrap` rule no longer fires in test code.** `edge.rs` matched any line containing `.unwrap()`, which is 152 findings on this repository, 41 of them in `tests/battle.rs`. A `#[cfg(test)]` module, a `tests/`, `benches/` or `examples/` path now stays silent, because an unwrap in a test asserts something about the code, it is not code that ships. Severity for a real unwrap is unchanged, so this is a scoping decision and not a blanket downgrade.
* **The 0.18.0 notes claimed every unwrap finding names its enclosing function. That was reverted before release** and is not in 0.18.0. Naming the function made every message unique, which stopped identical findings folding: 152 findings became 152 single-item lines, undoing the main win of 0.17.0 in the same day. The fold is worth more than the name, and the folded line already names the first four files and how many more. `RULES.md` records the reasoning.
* **`check` exits non-zero on a blocker or critical.** It previously always exited 0, whatever it found, so a CI job could not fail on a finding without parsing the output. The tool was advisory by default in exactly the place it matters most. A clean workspace still exits 0, and `info` never fails, so an advisory note about a console call will not break a pipeline.
* **The feature needs no flag.** `--exit-zero` restores the old always zero behaviour for anyone who wants one release of grace before their pipeline starts enforcing. `--exit-threshold=warning` catches more. Both are opt out, and the safe choice is the default.
* 6 tests. Two of them assert the negative that matters: that a real unwrap outside tests still fires, and still fires at warning severity.

## 0.17.0

Findings are filtered, not merely emitted. 185 lines for one repository became 42, and nothing was deleted to achieve it.

* **Identical findings fold into one line with a count and the first evidence.** A self scan of this repository produced 152 instances of the same `unwrap` sentence, which is one finding with a count of 152, not 152 findings. `--all` prints every one.
* **The summary line always counts every finding,** folded or not, so the headline is never flattered by the folding. `heides check` on this repository: `1 critical, 157 warning(s), 41 info` whether the output is 11 lines or 207.
* **Evidence and advice are printed in separate sections and never share a list.** A taint finding is a path through code, reproducible from a file and a line. A "function spans N lines" is a style opinion. The advice section is labelled `advice, unproven and unranked` so a reader cannot mistake one for the other.
* **`--no-advice` drops the advisory findings entirely,** for a gate that wants evidence and nothing else. The counts still describe everything, so hiding advice never makes a run look better than it was.
* **The MCP surface folds by default** and accepts `all: true`. An agent pays for every token it reads, and a wall of 152 identical lines is how it misses the one finding that mattered.
* **A real bug, caught by the folding tests on their first run:** the fold stored the count and the output index in the same field, so a count of 1 was used as an index and the second identical finding panicked. The tests existed precisely to catch this class, and they did.
* Folding is keyed on guard plus message, so two guards saying similar things stay separate, and it walks the input in order, so the output is byte identical across runs. There is a test for that, because the determinism suite requires it.

## 0.16.3

A correction to 0.16.2, not a feature. `--no-deps` shipped a hollow pass, and
that is worse than the flag's absence, and the fix had to land on both surfaces
or the release would have closed the hole for humans and left it open for
agents.

* **The MCP surface could not fail a security gate at all.** `harmony.check` and
  `harmony.report` accepted `offline`, but nothing corresponded to
  `--require-advisories`. An agent asking for an offline check received a
  normal-looking result with the posture in the text and no way to make the call
  fail, so an agent wiring `harmony.check` into a gate got the one door that
  stayed open. Both tools now take `require_advisories`, and when it holds and
  the advisory lookup did not run, the tool returns a JSON-RPC error rather than
  a result. `harmony.report` also carries `security_gate` and
  `security_posture` inside its JSON, so an agent can gate without parsing prose
  or making a second call.
* **`require_advisories` defaults to true on MCP and is unset on the CLI.** A
  human running `heides check` in a terminal sees the posture line and can
  choose. An agent may only read the result, so the safe path is the default one
  and a caller who wants speed opts out explicitly. This is a deliberate
  difference between the two surfaces, not an oversight.
* **A per-call argument no longer changes the process for the next caller.**
  `apply_offline` called `set_deps_enabled(false)`, which writes a process global
  and never restores it. Fine in a single-shot CLI, wrong in a server: one
  client passing `offline: true` silently disabled the advisory lookup for every
  later request from every client. A security setting changed by an unrelated
  argument is the same failure class as the rest of this release. Overrides are
  now scoped to one call through `with_scoped_deps`, which restores the previous
  value and restores it even when the closure panics.
* **Nesting is refused rather than handled.** A depth counter detects a nested
  scope before any state lock is taken and runs the inner call unscoped. The
  first draft held both locks across the closure and tested whether they were
  already set, which deadlocked rather than failed, and hung the test suite for
  a minute per test. A lock is never held across the call now.
* **4 tests.** One proves an override does not outlive its call, one proves a
  pre-existing CLI flag is restored rather than reset to the default, one proves
  a refused nested scope leaves the outer one intact, and one proves a panic
  inside a scope still releases it.
 `--no-deps` shipped a hollow pass, and that is worse than the flag's absence.

* **A skipped advisory lookup was indistinguishable from a clean result.** On a tree pinning `rustls 0.23.43`, the default run reported `0 blocker(s), 1 critical` with RUSTSEC-2026-0285. The same tree with `--no-deps` reported `0 blocker(s), 0 critical, 0 warning(s), 1 info` and exited `0`. The summary line was structurally identical to a genuinely clean workspace, the only clue was an info footnote, and the exit code said success. That is the same failure class as 0.15.2, in a different place.
* **The summary line now carries the security posture,** on the same line as the counts, so it cannot be skimmed past: `0 blocker(s), 0 critical, 0 warning(s), 1 info. ADVISORIES NOT CHECKED`. An unreachable registry says `ADVISORIES INCOMPLETE`, so a silent network failure cannot read as a pass either. And the clean-workspace message no longer prints alone when the advisory guard did not run: it says `no findings, but the advisory lookup did not run.`
* **`--require-advisories` makes a security gate fail rather than pass hollow.** If advisories were skipped or the registry was unreachable, the exit is non-zero. Wiring `--no-deps` into a required CI status check is now a red X instead of a silent hole, which is the difference between fixing the problem and documenting it.
* **The 0.16.2 changelog wording was wrong and is corrected above.** It grouped the known-CVE lookup with the "a newer version exists" reminder as two conveniences given up. Only one is a convenience. The security one is gone when the flag is set, and there is no cache to recover it until the offline advisory database in Tier 4.
* **What this does not fix,** stated plainly so it is not later mistaken for a resolution: the hole still exists. A summary line and an exit code make it impossible to miss and impossible to pass silently by accident. They do not make the vulnerability known. Only the offline advisory cache does that, and it is Tier 4. Until it lands, `--no-deps` is a speed flag and nothing else.
* The default, with no flags, remains the security gate. It was deliberately not made offline by default: a silent-offline security guard is the exact bug class the last three releases were spent closing, and slow is not a safety property.
* **An unreachable advisory service used to report every dependency as clean.** `osv_check` returned `Option<String>`, and `None` meant both "this version has no known vulnerability" and "the request failed". A network failure therefore produced a zero-critical run that read as a clean bill of health, in the one guard where that is worst. It is a tri-state now, `Found` / `Clean` / `Unreachable`, and an unreachable lookup says `it is NOT known to be clean` rather than staying silent. This is the more serious of the two defects found while writing the first, and it is a better example of the failure class: a failure that looks exactly like success.
* **The security half and the convenience half shared one health flag.** A dependency whose *latest version* could not be resolved set the same boolean that drove the advisory posture, so `--require-advisories` would have failed on any repository holding such a package. The flag would have become unusable, which is how people end up dropping it. `DepsHealth` now tracks `advisories_ok` and `versions_ok` separately: only the advisory half drives the posture, and a missed update reminder gets its own note saying advisory results are complete.
* **The advisory posture is a value, not a setting.** `DepsPolicy` is resolved at the boundary and passed down. The previous attempt scoped three process globals with a depth counter, which fixed the MCP leak but still shared state, and its own tests raced: three failed under the default parallel `cargo test` and passed single threaded. A value cannot leak and cannot race. `SCOPE_DEPTH` and the scoped globals are gone.
* **MCP is fail closed.** `require_advisories` defaults to true and an explicit `false` is refused rather than honoured, because a default the caller can remove is not a guarantee and an agent may only read the result.
* Verified with 4 consecutive parallel runs of the lib suite, 131 tests, 0 failures, 0 warnings, and on the release binary: the miswired gate exits 1, the fast gate exits 0, and the online security gate still reports RUSTSEC-2026-0285.

## 0.16.2

The dependency guard stops reaching for the network unless asked, which makes a claim the README already made true.

* **`--no-deps` and `HEIDES_OFFLINE=1` skip the registry lookups.** `check` was making one HTTP request per dependency, unasked, to query OSV and to look up the latest version. On this repository a full check took **217 seconds**; it now takes **2**. The flag wins over the environment, and both are documented in `heides --help`.
* **The offline path is not the empty path.** Manifest parsing and pinned version extraction are local, so an offline check still reads every pinned version: 94 across crates.io on this repository, reported as an info line naming the count and the ecosystems, so the work is visible rather than assumed.
* **A skipped dependency check is stated, never implied.** The coverage receipt gained a third state. "Could not reach the registry" and "skipped on request" are different facts, and collapsing them would recreate the exact failure the receipt exists to prevent: a partial run reported as a complete one.
* **`harmony.check` and `harmony.report` over MCP accept `offline: true`,** and `harmony.report` now carries the full receipt inside its JSON, so an agent receiving a clean result can see what was skipped without a second call. Previously the MCP tools ignored the setting and hit the network regardless.
* What `--no-deps` gives up, stated plainly. **The known-CVE lookup is the security half, not a convenience, and it is genuinely given up.** A skipped advisory lookup means a known vulnerability in a pinned version is not reported, and there is no cache to fall back on until Tier 4. The "a newer version exists" reminder is the convenience half. No local check is given up: taint, the spine, `staged`, `query`, `describe`, frameworks, scaffold, the edge and practice guards and the whole graph are pure local analysis and are unaffected.
* 5 tests. The accepted `HEIDES_OFFLINE` values are tested through a pure helper rather than by mutating process environment state, which is unsafe on this toolchain.

## 0.16.1

Every `check` now ends with a receipt saying what it actually looked at. On clean runs too.

* **A clean result and an unanalysable workspace printed the same words.** "no findings. the workspace is clean." was printed whether the guards had read every file or none of them, which is the 0.15.2 defect wearing a different hat. The receipt prints `analysed N of M indexed file(s)` and the languages present, so a partial run is visible instead of implied.
* **The receipt names the languages it could not fully cover,** and separates the two ways a language can be incomplete, because they are different gaps. `no taint rules for: rust (indexed, taint not scanned)` is a language with no flow rules. `taint scanned, no grammar: ruby (no symbols in the graph)` is a language the guards can analyse but the parser cannot extract symbols from. The README table already said this; the output now says it too.
* **Unreadable files and an unreachable dependency registry are reported,** not folded into a partial result presented as a complete one.
* 5 tests, verified on the release binary against a clean JavaScript workspace, a Rust-only workspace, a Ruby-only workspace and one with findings. Language coverage is read from the rule tables rather than hardcoded, so it cannot drift from what the guards do.

## 0.16.0

SSRF and NoSQL sink classes, and the last of Tier 0 shipped. The two classes with the highest yield in a modern app, and the two hardest to add honestly, because both produce false positives the moment they are not careful.

* **SSRF.** User controlled input reaching a server side fetch, so the server becomes the requester and the attacker chooses the destination. 7 languages: python, javascript and typescript, go, java, php, ruby, csharp. Covers `requests`, `httpx`, `urlopen`, `urllib.request.urlopen`, `socket.create_connection`, `fetch`, `axios`, `got`, `superagent`, node `http.get`, `http.Get`, `client.Do`, `new URL`, `openStream`, `openConnection`, `RestTemplate`, `HttpClient.send`, `curl_exec`, `fsockopen`, ruby `URI.open` and `Net::HTTP.get`, and the .NET `WebClient` and `HttpClient` shapes. A tainted fetch aimed at `169.254.169.254`, `metadata.google.internal`, or the Alibaba and ECS equivalents is reported as `a cloud metadata fetch sink`, because credential theft is what it is.
* **NoSQL injection.** Request data reaching a document query, where an attacker controlled key or operator changes the meaning of the query rather than only its value. 7 languages. `collection.find`, `findOne`, `findOneAndUpdate`, `updateOne`, `deleteOne`, `insertOne`, `aggregate`, `countDocuments`, `where`, pymongo and motor equivalents, the PHP driver names, the Go driver methods, `Document.parse`, `BsonDocument.Parse`, and `$where`.
* **A stricter gate for these two classes than SQL uses.** A source existing somewhere in a handler is not enough; the tainted value has to reach the sink line. A handler that reads `req.query.id` and then calls `fetch('https://api.internal/health')` stays silent, and `find({ published: true, page: 1 })` stays silent, because a literal query object is safe. A tainted name used as an object *key* is also not a use, which is what makes the literal case work.
* **A tainted address is never guessed.** A host passed in through a variable is reported as SSRF, not as cloud metadata, because the address is not on the line and the tool will not claim to know where it points.
* **TypeScript was never taint scanned.** `.ts` and `.tsx` mapped to `typescript` in the parser and the source and sink tables had no `typescript` rows, so every TypeScript file was skipped in silence. TypeScript now shares the JavaScript rows. This is a larger real-world gain than the new rules themselves, since most modern SSRF and NoSQL code is TypeScript.
* **Ruby could not taint at all,** for three separate reasons: no `rb` extension in `detect_language`, no source row, and a block detector that understood braces but not `def` and `end`. All three fixed. Ruby still has no grammar, so it contributes no symbols to the graph, and the README says so rather than implying parity.
* **Ruby's bare `open(` is exempt when the receiver is `File.` or `IO.`** Reading or writing a path is not request forgery, and mislabelling it would be worse than missing it.
* **The rule dialect's two silent traps are documented** at `concrete_patterns`: a `|` outside a group is kept as a literal character, and the only recognised escapes are `\b \s \. \( \) \$`, so a pattern containing `\[` matches the text `\[` and nothing else. Both were hit while writing these rules and both failed silently.
* 22 new tests, including the false-positive halves. A hardcoded URL, a literal query object, `items.find(`, a tainted key that is only an object key, and `File.open` must all stay silent, and each has a test that fails if it does not.

## 0.15.2

A false negative, found by running the release binary the way a user would.

* **The first check on a never indexed workspace reported nothing, and called the workspace clean.** `build_graph` stored every file path relative to the scan root but never recorded the root itself, so `file_path_of` returned a bare relative path that resolved against the current working directory. Every content read failed, so the taint, edge and practice guards had no files to look at and produced zero findings. On a fresh clone, `heides check` printed "0 blockers" over code that was full of them. The second run was correct, because the saved index restores the root from the database, which is exactly why this was not caught earlier. One line sets the root, and two tests pin it: one asserts a freshly built graph can read back every file it lists, the other asserts a first run over an unindexed tainted file reports it. Found while testing the SSRF and NoSQL sinks, when a fixture that reported findings on the second run reported nothing on the first.

## 0.15.1

A security patch, and the fix was found by the tool scanning itself.

* rustls 0.23.43 is bumped to 0.23.45 for RUSTSEC-2026-0285, TLS 1.3 handshake messages incorrectly accepted across encryption level boundaries. It arrives through `ureq`, the HTTP client used for the OSV advisory lookup, so any scan that reached a registry was running on the affected TLS stack. Reported by heides scanning its own workspace, and this release is the response.

## 0.15.0

Tier 0 of the growth roadmap shipped: the security claims the README already made now hold, and the roadmap itself records what is done and what is not.

* SQL injection detection closed for the drivers that were invisible. `db.run`, `stmt.run`, `knex.raw`, `db.exec`, `raw`, `literal`, `prepare`, `execSQL`, `queryRaw`, gorm `Raw`, EF `FromSqlRaw`, `ExecuteSqlRaw`, php `prepare` and `rawQuery`, and python `executescript` are sinks now. A planted `db.run("DELETE FROM users WHERE id = " + id)` reported zero findings before and reports critical now. Ambiguous names only count on a database-ish receiver, so `run(taskName)` in a task runner stays silent.
* `query search` reads file content. It answered "no symbol matches" for a file whose whole point was a SQL string, because the FTS table held one row per symbol. Literals and comments are indexed now, capped per file, with symbol hits still first. Index version 8, so an existing index rescans once.
* `plan` returns the evidence it was grounded on: symbol, file and line, capped at twelve. When no identifier in the plan exists in the spine it says the plan introduces new definitions, names existing functions to build on, and reports what the spine holds, instead of printing `feasible true` and implying it checked something.
* Framework-aware entrypoints. Express, Flask, Django and Go route registrations are recognised, so a handler is no longer listed as an uncalled root. Runs at describe time, so no index schema moves and reindexing stays as cheap as before.
* The taint report says `source on this line (line N)` when the value is read and used on one line. It used to print `source at line 0`, which reads as a bug in the tool rather than in the code under test. Both this and the ambiguous-evidence defect were found by running the release binary on a fixture, not by the suite.
* One version everywhere. The npm installer derives the binary tag from `package.json`, a test fails the build if they drift, a leading `v` in a pin is stripped instead of building a `vv0.14.4` tag that 404s, and npm honours `HEIDES_VERSION` so one pin works for the curl installer and npm. The npm README platform table now matches the installer: Linux arm64 and Android map to real assets, only musl errors.
* Documentation accuracy: the root README stopped pinning a two-year-old example version, and both READMEs point at `cargo test` instead of freezing a test count that moves with every change.
* 91 lib tests, and the battle, clean, determinism, hostile and path resolve suites all green on the release toolchain and in CI, clippy included.

## 0.14.4

* npm installer maps android-arm64 to the Android build, Termux reports android not linux so global installs failed without it.
* Terminal wordmark is figlet standard ASCII, phone safe on every font. README keeps the PNG banner.

## 0.14.3

* TTY only ANSI Shadow wordmark on the bare command and help screens, verified byte identical to the approved render, silent on pipes so agents and the dash free contract are unaffected.
* README shows the same wordmark art and keeps Compatibility prose grouped with every logo row at the very bottom.

## 0.14.2

* Collapsed two nested ifs into let chains per clippy, CI lint gate green.

## 0.14.1

* rustfmt exact line joins in the language aware file talk map, CI format gate green.

## 0.14.0

* Fixed the one line installer dying silently on Linux, a `set -e` plus trailing `&&` aborted detection before any download. Termux Android and proot installs work again.
* Release pipeline builds ARM again, `aarch64-unknown-linux-gnu` on native ARM runners plus `aarch64-linux-android` via NDK and cargo-ndk, so every tag ships the phone binary. The npm wrapper maps `linux-arm64` and detects Termux for the bionic build.
* CLI takes a workspace dir everywhere it matters, `query [kind] [name] [dir]`, `staged [patch] [dir]`, `plan [text] [dir]`, no more forced `cd`. Every command answers `--help`, `-h` and `help` with usage and exit 0 instead of treating them as paths, which previously created a junk `--help/.heides/` index. Empty args keep exit 1.
* `describe` file talk is language aware, same named symbols across languages no longer report phantom `app.js talks to app.py` edges. Web surface (html, css) still links to scripts.
* Battle suite holds 78 of 78 with the dash free output contract intact.

## 0.13.1

* Fixed a test-only race where the display override unit tests shared process-wide state across parallel test threads. The UI tests now serialize on a test lock, 70 of 70 green on repeated default parallel runs. Added the crates.io publish job to the release workflow and backfilled package metadata (homepage, readme, keywords, categories).

## 0.13.0

* Stored file paths now resolve against the scan root recorded in the index. A check run from inside the repo and one run from the directory that launched the scan report identical findings, closing the silent false clean found when heides checked its own code from a parent folder. Index version 7, stale indexes rescan on the next command. Regression covered by the cross working directory test.

## 0.12.0

* harmony.report joins the MCP tools. It runs the same guards as harmony.check and returns the verdict as structured JSON, one object per finding with guard, severity, message, file and line, plus severity counts and a clean flag, so an agent can gate on the verdict without parsing prose.

## 0.11.0

* mark_safe is now a python taint sink, the only framework sink in the engine. Django escapes template output unless a value is explicitly marked safe, so a qualifying source flowing into mark_safe is provable cross site scripting. Literal markup inside mark_safe stays silent, the clean corpus proves the idiomatic escaped render passes.
* Framework specific XSS shapes stay silent until grammars and a template context model exist, that boundary is stated in RULES.md so the claim never overreaches.

## 0.10.1

* severity tokens render in color on a real terminal, red blocker and critical, yellow warning, green info, plain on pipes and in logs
* scan, check and deps show a running pulse on stderr with an elapsed report when the command takes longer than a second
* watch mode prints live severity deltas after every reindex, local guards only so the loop never stalls on the registry
* the group flag clusters findings by guard with colored bucket counts
* long commands set the terminal title and ring the bell once they pass ten seconds
* the no color flag and the color always flag give every consumer control, NO_COLOR is honored

## 0.10.0

* the dependency guard now reads go.mod, requirements.txt, pyproject.toml, pom.xml, composer.lock and composer.json alongside cargo and npm manifests
* OSV vulnerability queries run on pinned versions only, range requirements still compare against the latest release
* latest version lookups are ecosystem aware, go modules via the proxy, pypi, maven central search and packagist

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
