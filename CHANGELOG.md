# Changelog

All notable changes to HEIDES are recorded here.

## 0.32.0

### Added
- `--max-bytes` on every command. The MCP surface capped tool results with
  `max_bytes`; the CLI had no ceiling at all, so `heides check` on a large repo
  could bury the one finding that mattered under pages of the ones that did not.
  Truncation lands on a line boundary and the run says it stopped.

## 0.31.0

### Fixed
- A name-keyed call count is no longer printed as a count of callers. Call
  edges record names, so `as_str` produced "146 callers" against a specific
  line while its edges belonged to definitions never resolved to one another.
  The count is now published as an upper bound with the other definitions
  named, and stays silent when the name is unique.
- Test detection recognises the conventions the languages actually use:
  RSpec `_spec.rb`, JUnit `TestUser.java`, C# `UserTests.cs`, Jest
  `user.test.ts`, Go, and symbols reached through a test module. These were
  read as production callers, so a fully tested file reported as untested.

### Changed
- `insight coverage` states what it checked when nothing is wrong. Silence on
  success was indistinguishable from a command that never ran.
- `doc.hotspot`'s bare `12` is now `HOTSPOT_FLOOR`, stated with the measurement
  behind it and pinned by a test that builds the boundary it decides.

## 0.30.0

**The blind spots, closed one at a time, each found by running rather than reading.**

Rust had no source row and no sink row anywhere in the taint tables.
`Command::new` fed from the environment, or `fs::read_to_string` fed from argv,
was invisible in the language this tool is written in, and the receipt said so
plainly: *rust: 44 file(s) indexed, no taint rule can fire on any of them.*
Five sources and eight sinks now, written without groups because the matcher
expands alternation inside a group and does not nest groups, so `env::(var|var_os)`
matched nothing while the table claimed coverage.

C#, Java, PHP and Ruby had no route reader at all, so route to table, auth risk
and taint from a request were all empty for them. Four bugs, all found by
running a fixture rather than by reading the code:

* The verb is not spelled in uppercase. `@GetMapping` and `[HttpGet]` matched
  nothing, because the reader looked for `GET`.
* `declared_name` answered the return type. `IActionResult` and `List<User>`
  are not method names.
* A Rails needle of `get ` silently missed every Laravel route, because Laravel
  writes `Route::get(` with a paren and no space.
* PHP was routed to the attribute reader alone, so every Laravel route was
  invisible while the language still looked covered, because Symfony shared the
  branch. PHP carries two dialects and needs both readers.

TypeScript was never blind: `scan_file` maps it onto the JavaScript rows. The
rows written under `typescript` were unreachable and are gone, with the reason
recorded where they were.

`insight coverage` asked only about the strict SSRF and NoSQL tables, so a
language with SQL and shell rules but no strict rows read as uncovered. It now
uses the same test the receipt does.

Two tests that enforced the blindness changed, because they asserted Rust is
unscanned and that was true. The invariant they protect, that a language with no
taint rules is always named, is kept and asserted against html, which still has
no rows, with a new test asserting Rust is covered.

456 tests pass. Six of them cover the four languages that previously had no
route reader at all, so this cannot rot back into silence.

## 0.29.0

**Four signals that need more than one fact.**

Every other guard here reads one signal and applies a rule. These read two
signals that were computed independently and report where they cannot both be
true, which is the cheap way to find a real defect.

`insight contradictions` compares them: a route whose handler no definition in
the workspace matches, a handler the dead root check also reports unreachable,
the most called function in a well documented file carrying no comment, a file
that nothing reaches and nothing calls out of. On this repository it finds 13
documentation hotspots and no route disagreement, which is the answer this
repository deserves.

**What a change would reach.**

`insight impact <symbol>` is the question an agent asks before every edit, and a
caller list answers it badly. It reports the transitive size, the files that move
with the change, the routes behind it, and whether any test reaches it: "four
callers" and "four callers and no test reaches it" are different answers.

**A finding that is new matters more than one that has always been there.**

`insight baseline save` records today's findings; `insight baseline` then reports
only the ones it has never seen. A finding key ignores its line number, so a file
that only moved down does not fill the baseline with noise.

**Clean is only clean where a rule exists.**

`insight coverage` says where it is not. `rust: 44 file(s) indexed, no taint rule
can fire on any of them` is a different statement from clean, and only one of the
two is worth acting on. An empty result and an unrun check are not the same
answer.

## 0.28.0

**A tool result should not be able to end the conversation.**

Every MCP result lands in a model's context in full. `harmony.check` on this
repository returned 1,232 tokens before, and a larger workspace would return
more, which is not a bigger bill but a way to lose the thread. `max_bytes` trims
the result to a budget the caller sets. The cut lands on a line boundary and says
how much was dropped, so a caller that hit the cap knows to narrow the question
rather than assume the answer was complete.

**The MCP surface stopped paying for style opinion.**

`harmony.check` returned evidence and advice together. On this repository that
is 1,206 tokens, of which 1,027 are advice: opinions about loose equality and
long functions that no agent can act on and no gate can fail on. The MCP default
is now evidence only, 179 tokens, an 85% cut with every blocker, critical and
warning intact. `advice: true` asks the rest back. The CLI keeps its full
receipt, because a person at a terminal is reading the whole thing on purpose.

**`describe --brief` drops the parts a reader cannot act on.**

Rule measurement, per language doc coverage and the undocumented symbol list are
a receipt for a person deciding whether to trust the gate. `--brief` keeps the
map and drops the commentary: 1,624 tokens to 1,279.

Measured on this repository, for an agent paying context on every call:
orientation is 169x smaller than reading the source, evidence-only checking is
85% smaller, and brief describing is 21% smaller.

## 0.27.0

**A type annotation was hiding every typed secret.**

The credential rules looked for the first `=` or `:` on a line and read the
value from there. In a typed declaration the annotation comes first, so the
search stopped on the type and never reached the value:

```rust
const GITHUB_TOKEN = "ghp_...";               // reported
const GITHUB_TOKEN: &str = "ghp_...";        // not reported
const API: string = "ghp_...";               // not reported
const std::string API = "ghp_...";           // not reported
```

Same credential, same file, one character apart. In Rust, TypeScript, C++ and
Java that is how a constant is written, so the guard was blind to the idiomatic
declaration of a hardcoded key. The fix finds the quoted literal first and walks
back to the operator, which also stops a `==` comparison or a `=>` match arm
being read as an assignment.

**`staged` judged a patch twice.**

A staged review is normally run after the change is already in the working
tree, because that is the point of one. heides read the working tree as the
pre-image and applied the hunks again, so every added line landed in the file
twice. The duplicate declaration rule then raised a *blocker* for each pair, at
a line number past the end of the file. Adding two functions to a four line
file produced four blockers, two of them pointing at lines five and six.

Applying a patch is now idempotent. A deletion is still applied, because a hunk
with nothing to add is a deletion rather than an already applied change, and
that distinction is what the battle suite caught on the first attempt.

A reviewed file also kept its trailing newline now. Dropping it made every
staged file differ from disk by a byte no hunk mentioned.

**`.tsx` is parsed as TSX.**

`.tsx` was parsed with the plain TypeScript grammar, so a JSX element opened
node kinds the walker could not name and the file yielded fewer symbols than the
same code under a `.ts` extension. The TSX grammar is now selected by extension.

## Unreleased

**A line comment was swallowing the rest of the file.**

`body_range` tracked a line comment with a flag that was set on `//` and never
cleared. From the first line comment inside a function body onward, every brace
in the file was read as being inside a comment, the braces never balanced, the
scan ran to end of file, and the function was reported as the rest of the file
long. On this repository `parse_sql` is 190 lines and was being reported as
3601. Everything downstream inherited it: the interprocedural taint summaries,
the API surface, the dead root check, and the long function guard, which is how
this surfaced at all. Thirty findings had grown into functions of 2578, 1969 and
1676 lines that no one had written.

The flag is now cleared at the start of every line, because a line comment ends
with the line.

**A Rust lifetime is not a character literal.**

The same reader treated every `'` as the start of a string. In Rust `&'a str` is
a lifetime, so the apostrophe opened a string that closed at the next apostrophe
somewhere in the file and hid every brace in between. An apostrophe is now read
as a quote only when the closing one is on the same line and near enough to be
one character or an escape.

**Rust routes are read now.**

`route_handlers` and `endpoints` dispatched to JavaScript, Python and Go, so a
Rust service had no route inventory at all: no route to table surface, no auth
risk, and no taint path from a request to a query. axum, actix-web and Rocket are
read now, and a Rust route reaches the dead root check.

**One body span rule, not two.** `practice.rs` counted braces a second time, on
its own and without string or comment awareness. It is gone; both callers read
the same span.

**The advisory guard is gone. heides is now local-only.**

The dependency guard asked one question, is this pinned version a known CVE.
That is a fact about the world rather than about the repository, and every way
of answering it inside this tool was a way of being wrong. Over the network, a
gate verdict depended on network conditions rather than on the tree: `check`
took 3242 ms with the guard and 117 ms without, on the same five file fixture.
From a cache, worse: the offline cache expired a clean answer after 24 hours,
so a CVE published that morning read as *no known vulnerability* until the entry
was re-fetched, and nothing in the output distinguished the two. A guard that
cannot tell *no vulnerability* from *has not heard of it yet* reports false
confidence, and false confidence is indistinguishable from a pass.

So it was removed rather than made opt-in. An opt-in default that is safe is
still a slow default, and a cache that is correct is still a cache.

* **Removed:** `deps.rs`, `osv_cache.rs`, `lockgraph.rs`, `lockparse.rs`, 4207
  lines. 26656 to 22449, 25 modules to 21, 21 MCP tools to 18.
* **Removed with them:** the `DepsState` enum, the security posture suffix on the
  summary line, `advisories_ran` in the verify verdict, `--no-deps`,
  `--require-advisories`, the `offline` and `require_advisories` arguments on
  `harmony.check` and `harmony.report`, and the `deps.check`, `deps.tree` and
  `deps.advisories` tools.
* **The removals refuse rather than vanish.** `heides deps` and the three tools
  explain that the capability moved and name
  [GRIM](https://pypi.org/project/grim-mcp/), which is public, published, and
  backed by a continuously updated feed. Neither refusal makes a vulnerability
  claim of its own. An agent holding one of these names in a plan learns where
  the answer went instead of concluding the tool is broken.
* **Unchanged and still the point:** taint flows, hardcoded credentials, edge
  cases, schema defects and config credentials. Each names a file and a line
  and reproduces from the tree alone, so the same commit produces the same
  verdict with the network off.
* **An indirect foreign key cycle is not a self reference.** The walk compared
  each edge's target against the table the walk began from rather than the table
  the edge is declared on, so `a.b_id -> b` plus `b.a_id -> a` was reported as
  two *self references* at `critical` severity in a schema that has none. It now
  distinguishes them, and 8 tests pin the distinction in both directions: a real
  self reference and a cascading one keep their own findings, a three table loop
  is indirect, and a diamond is still not a cycle.
* **Every `db` subcommand honours its directory.** The earlier fix covered
  `routes` and `schema` only, so `db tables`, `db orphans` and the rest still
  walked the current directory and printed tables belonging to unrelated
  projects. `root_offset` now covers all eleven subcommands by their own shape,
  and `tests/dbargs.rs` walks each one with and without a directory so a partial
  fix cannot pass again.

## 0.25.0

Heides stops talking to the network. This removes `deps`, the OSV cache, the
lock-file graph and transitive dependency resolution: 5,448 lines out, 1,104 in.

**Why.** Those features needed two long-lived registry tokens, and both expired
on the day we tried to publish. A scanner that stops working because a credential
rotated is a scanner with a credential-shaped failure mode, and it cannot run on
an airgapped machine or in a pipeline that forbids egress. Dependency advisories
belong to a tool that owns dependencies.

**What you lose.** `heides deps`, the advisory half of `heides verify`,
`--require-advisories`, and the transitive dependency graph. If you want known
CVEs in your lockfile, that is a different tool's job and it should be a
different tool.

**What stays.** Every guard, all twelve languages, the spine, the taint engine,
the database graph, the sanitizers, and the local file index. Nothing that
analysed your source code was removed.

* **`db` root offsets.** Every `db` subcommand takes the workspace root at a
  different argument position, and one fixed offset meant `db routes <dir>`
  stepped over the directory and walked the current one instead, printing "no
  routes recognised" for a project full of routes.
* **The Stripe guard was correct the whole time.** The guard matches `sk_live_`;
  the failing fixture built its prefix with `["sk","live",""].join("")`, which
  consumes the underscore and yields `sklive`. The fixture was wrong. Worth
  recording, because the natural reaction to a red test is to relax the rule,
  and that would have weakened a working check to accommodate a broken string.
* Verified: 430 tests, 25 suites, 0 failures. fmt, clippy and npm clean.
  36 of 36 end-to-end checks across 8 areas.

## 0.24.4

Six fixes and one command. Everything from 0.24.2 through 0.24.3 was committed but never published, so this is the first release that carries any of it.

* **Python docstrings are documentation again.** `doc_above` only collected comments *above* a declaration, and Python puts documentation inside the body, so every Python function in every codebase indexed as undocumented and `query definition` showed no docs for Python at all.
* **Single line docstrings do not swallow the rest of the file.** The check asked whether the text after the opening quote *starts* with a closing quote, which is never true, so every single line docstring scanned forward for a closing triple quote that was already behind it and reported the following source lines as prose. It read as correct because the test asserted `contains("Entry point")` and the corrupted string still contained it. The check now asks whether the remainder *ends* with the quote, and the multi line branch stops at a dedent so an unterminated docstring cannot absorb real code either.
* **`--no-advice` no longer deletes proven secrets.** It filtered on the guard name, so a committed `AKIA...` key went out with the "function spans N lines" opinions the flag exists to remove. A hardcoded credential is a fact about the value and is now judged from the message rather than from the family it happens to be emitted by.
* **A workspace root that does not exist is an error.** The walk over a missing directory yields zero files, so `check` printed a clean summary and exited 0 for a path that was never inspected, and `save` created the directory in order to put an empty index inside it. "There is nothing here" and "there is nothing at that path" are different answers and only the first is a pass.
* **`db routes <dir>` walked the wrong directory.** One fixed offset for the root meant the subcommand stepped over the directory and walked the current one instead, printing "no routes recognised" for a project full of routes. `routes` was also unreachable as a positional for the same reason.
* **An unrecognised flag is no longer a path.** `deps tree --help` walked a directory called `--help`. Commands whose arguments are free text are exempt, because `plan` and `scaffold` take an English objective that legitimately contains hyphenated words.
* **`heides confirm <package>`** is the CLI twin of the `web.confirm` MCP tool, which had none. It says it is reaching the network rather than printing an empty result that reads as "no such package".
* **A sanitizer table.** A value that has been escaped, quoted, bounded or parameterised stops being a finding, instead of every rule being written timid to stay precise.
* **Every command is documented,** and `tests/readme_commands.rs` fails if a command exists that the README does not document. The README claimed the server exposed eleven tools while it declares twenty one, and documented 7 of 16 commands.

## 0.24.3

Two ways to get the test-code scope wrong, both found by probing rather than reading, and one of them was hiding real findings on this repository.

* **A one line `mod tests` was never recognised.** The question "is this line in a test module" was asked after the braces on that line had been applied and the stack popped, so a module that opened and closed on the line being asked about was gone before it was seen. Dense, ordinary formatting, and the same shape as the one line C function fixed in 0.24.1.
* **The name test was a substring match,** so any module whose name merely contained `tests` was test code and everything inside it was silenced. A production `mod tests_support` is ordinary code. The name is now matched as a whole word.
* **The two fixes are not independent, which is the interesting part.** Tightening the name is only safe because the `cfg` attribute is now read from the line above, where rustfmt puts it. `#[cfg(test)] mod liveness` in `src/harmony.rs` was classified as *production*, because the attribute sits on line 966, the declaration on 967, and the old code only ever looked at the declaration's own line. It holds 14 `unwrap`s and not one of them says anything about the shipped binary. Fixing the name test without reading the attribute above would have traded a false positive for a false positive; with both, they are correctly silent.
* **`#[cfg(not(test))]` compiles an item when tests are *not* running,** so it is production code wearing a test attribute and is now treated as such. An ambiguous `cfg` expression resolves to production, because silencing a real finding is the worse error to make.
* **Verified differentially rather than by inspection.** A standalone harness ran the old and new algorithms side by side over every file in `src`: 23 lines differ, all in `harmony.rs`, all in one direction, none newly reported. One direction only is the point, because it means no new false negatives.
* Heides on Heides: 66 warnings to 52. The 14 that went quiet were the false positives described above.

## 0.24.2

Heides scanned Heides and did not like what it saw.

* **Heides on Heides reported 144 warnings and 126 of the 127 `unwrap` warnings were inside Heides' own test modules.** An `unwrap` in `#[cfg(test)]` code says nothing about the shipped binary. A scanner that files its own fixtures as production risk teaches people to ignore it, which is the failure this project is supposed to exist to prevent.
* **The cause was a bail point, not a misidentification.** `is_test_context` walked backwards from the finding and gave up at the first `}`. Inside `mod tests` the commonest brace in the file is the end of the *previous test function*, so the walk decided it had left test scope on nearly every line. It never got as far as looking for the module.
* **It now scans forward and tracks which modules are open at the line,** pushing and popping with brace depth. A module is open at a line if its braces opened before it and have not closed yet. That is unambiguous, and a sibling module later in the file cannot be mistaken for an enclosing one.
* **Two intermediate versions each broke one test, and that is why there are two tests.** One still treated a sibling `fn two() {` as a boundary. Fixing that reintroduced the pre-existing failure. The pair pins both directions: a sibling brace does not end the module, and code after the module is real code again.
* **Measured on the tool itself: 144 warnings to 66, `unwrap` 127 to 49.** All 49 remaining are production code that cannot panic: mutex locks, `last()` after an `is_empty` guard, a quote matched by `Some` directly above. The one critical is the deliberate SQL fixture at `testdata/first_run/app.js`.
* **Two limits are recorded rather than left to be rediscovered,** both pre-existing and neither introduced here: a `mod tests` written entirely on one line opens and closes together, so it is not recognised, which is the same shape as the one-line C function defect fixed in 0.24.1; and the `cfg(test)` check falls back to a substring test on the module name, so any production module whose name merely contains `tests` is treated as test code.

## 0.24.1

0.24.0 shipped a false negative in C and C++, and it was wider than one line of code.

* **The inline source gate was ruby only.** `strcpy(buf, getenv("NAME"))` reads a source and reaches a sink with nothing in between to bind a name, so the flow was only recognised where a name was captured. C and C++ now get the same gate as ruby. `strcpy` of a literal stays silent in both.
* **This was not limited to one line functions.** The reported case was a function written entirely on one line, where the braces open and close together and a block rule that only closes on a later line drops it. That part is fixed too. But the same shape in a normal multi-line function was also missed, because it failed the same gate for the same reason, and the reported fixture happened to be the one that was noticed.
* **Measured on real code before widening the gate:** 401 real C and C++ files report zero false criticals, which is why javascript and java are still excluded. An inline `req.query.x` reaching a sink is rarer there, and an unmeasured gate is how a scanner starts crying wolf.
* **The rule is stated as a measurement rather than a preference.** Ruby was measured across 536 files across rack, sinatra, redis-rb and faraday. C and C++ are measured now. Anything else has to earn the gate the same way.

## 0.24.0

C and C++ are indexed, Ruby is indexed, and the offline opt-out now actually opts out.

* **C and C++ are indexed, with the memory safety class they need.** Before this, a `main.c` containing `strcpy` indexed zero files, because there was no grammar. `strcpy` of a `getenv` value is now a critical finding and `strcpy` of a literal stays silent.
* **Ruby is indexed,** and a test roundtrip is no longer called a critical. Reporting a thing that is correct behaviour as critical is how a scanner teaches people to ignore it.
* **`--no-deps` and `HEIDES_OFFLINE` still made live requests.** The flags parsed correctly and `deps_enabled()` was correct and unit tested; nothing on the `deps` code path ever called it, which is exactly why every test for the flag passed while the command ignored it. An opt out that silently does nothing is worse than no opt out, because it is the control a privacy conscious user reaches for and then trusts. Found by running it rather than reading it: a cold cache with `HEIDES_OFFLINE=1` still returned a live advisory for a known vulnerable version.
* **The gate is at the single entry point `heides deps` calls,** and it states the skip rather than returning an empty result, because silence here reads as "no vulnerabilities". `advisories_ok` is false, since a run that checked nothing has not established there is nothing to find. A project with no manifests still reports no manifests found and keeps `advisories_ok` true, because nothing to check is not a failure of the check.
* **`DEPS_OVERRIDE` was one `Mutex<Option<bool>>` for the whole process,** so tests calling `set_deps_enabled` raced each other and the first version of the gate test failed by observing another test's value. The opt out is a parameter now, so it is testable without touching global state.
* **The memory safety sink class renders its article correctly.** The C rule hardcoded "a" where every other taint rule calls the helper, so it read "a unbounded copy sink".
* Verified live in three directions: `heides deps --no-deps .` skips with no lookup, `heides deps .` finds a live advisory, `heides deps <empty dir>` reports no manifests found.

## 0.23.0

The interprocedural budget did not bound the work, so the receipt it promised never fired. Three corrections, one of them mine.

* **The budget was declared between the initial sweep and the requeue loop,** so only requeues consumed it and the first pass over every active function was free. `HEIDES_INTERPROC_BUDGET=1` ran for 25s against 21s for the default budget on a 364 file corpus, and printed no truncation note at all, because nothing requeued. The bound bounded nothing on any repository that does not requeue, which is most of them.
* **A receipt that promises a bound and stays silent is worse than shipping none,** because a user cannot tell a pass that stopped from a pass that had nothing to do. Both loops now draw on one counter, checked before each step.
* **Express routes whose handler is written inline** are recognised, so `router.get('/x', (req, res) => ...)` no longer reads as an uncalled function.
* **The credential rules no longer flag heides own source.** `practice.rs` decides from the file and its context rather than from the name alone, which is why 0.19.1 had to de-entropy a fixture to make push protection happy. Fixing the rule was the right response and muting the test was the wrong one.
* **The interprocedural budget is verified through the CLI**, not only in a unit test, because the real corpus does no interprocedural work to bound. On a fixture that does seed, `HEIDES_INTERPROC_BUDGET=1` reports `interprocedural taint analysis stopped after 1 steps at a work budget of 1: cross function flows beyond this point were not followed` and the default stays silent on the same tree.
* **How it got in, since that is the part worth recording.** The three PRs were stacked on local `main`, so the budget commit was an ancestor of both other branches. Merging them by number pulled it in without passing review on its own. Stacked branches need the base checked, not the numbers.

## 0.22.0

The taint pass was 99% of a check, and it was one arithmetic mistake.

* **`taint::scan_file` fell from 123s to 9.3s on 364 real files.** Total check time went from 124s to 11s.
* **The cause was the pattern expander, and it was measured rather than guessed.** Three attempts to fix this were based on an estimated candidate count and all three were wrong. Read properly, the table asked for **35,582 substring searches on every line** of source: 27,588 of them javascript and 7,583 python, with every other language under 130. One javascript row, 31 alternation branches with three `\s*`, accounted for 27,500 on its own, because every `\s*` became five variants and they multiplied. At roughly 154ns per search, 1,665 lines is 4.7s, which is exactly what the instrument reported.
* **The whitespace run is narrowed from zero through four copies to zero or one**, which takes javascript to 1,806 candidates per line, 15x fewer.
* **That is a behaviour change and it is stated as one.** A call written with two or more whitespace characters between tokens, as in `db . find (`, is no longer matched by that row. Source overwhelmingly writes `db.find(`, and the wide run was paying an 8x multiplier for a construct that does not occur. The narrowed spacing is a security-relevant miss, not a formatting preference, and a future row that needs it must say so.
* **The prepared pattern cache took a mutex on every call.** `regex_hit` runs about seventy thousand times on a 49KB file and every one of them locked. The cache is filled once and never mutated, so a `OnceLock` over an immutable map is the correct shape. Worth 11.5% on its own.
* **The sink dedup was quadratic with an allocation inside its predicate**, walking every report with a `format!` per sink row per line. Now a `HashSet`.
* **A test pins the bound.** Any language exceeding 4,000 candidates per line fails the build, so a future rule row cannot quietly reintroduce a pathological one. The probe test reads the number so it never has to be estimated again.

## 0.21.0

The expensive layer was guessed at five times and was wrong every time. This release makes the guessing unnecessary, and removes 60% of the cost it identified.

* **`HEIDES_TIMING=1` reports where a check spends its time, per layer, as each layer completes.** Every counter accumulates and one line prints per layer. The flush is explicit and `emit_worst()` fires before the interprocedural pass, because a buffered line lost to SIGTERM is the case this exists for. An earlier draft printed one summary at the end, which meant a hang produced no output at all: the one run you most need data from was the one run that stayed silent.
* **The ranked worst-file list is the data, not a stream.** A cost spread over hundreds of files hides the one that costs everything.
* **`taint::scan_file` fell from 267s to 104s** on a 313 file corpus. The ranked list named the reason: 62 seconds in three files under a vendored directory, the largest being 634KB of generated algebra code. Vendored and generated code is no longer analysed by the taint pass, and all ten worst files are now first party code.
* **The trade, stated rather than hidden.** A vulnerability living only inside a dependency is invisible to the taint layer. `practice.rs` already made this trade, `deps` and the advisory guard cover third-party risk, and the coverage receipts report what was skipped so the reduction is visible rather than silent.
* **Vendored matching is on whole path segments, not substrings.** A substring rule eats first party code: `src/vendor-portal/client.js`, `src/distillation/index.js` and `app/distillery/rules.js` all contain a vendor word without being vendored, and each has a test asserting it is still scanned.
* **Two corpora disagreed about which layer dominates, and that turned out to be the finding.** On 364 real files from a large TypeScript project, taint is 99.1% of a check and interprocedural analysis is 0.2%. On a generated corpus interprocedural measured 33%. Both earlier numbers came from generated code, which is why neither could be trusted. The instrument is what settled it.
* **The vendored skip does not help every corpus.** It is 2.6x on the corpus it was measured on, which had vendored code. On a corpus without any, it changes nothing. Stated so the number is not read as general.
* **A byte-budget sweep** replaces a file-count sweep, because the cost tracks bytes rather than file count. The file-count sweep capped at 200 files and reported the expensive layer as free.

## 0.20.1

A false positive that only a real repository could find, and a guard pass that ran twice.

* **A call expression bound to a secret sounding name was reported as a hardcoded credential.** Running the published binary against llama.cpp produced this at `tools/ui/tests/unit/settings-private-fields.test.ts`:
  ```ts
  const apiKeyField = fields.find((field) => field?.key === SETTINGS_KEYS.API_KEY);
  ```
  reported as "a secret looking name holds a literal value, 61 chars". The rule read the whole right hand side as a value. This is the worst failure mode for a credential rule: a finding like it trains an agent to ignore the rule rather than act on it.
* **The fix is a literal check, and the distinction is subtle.** An earlier attempt disqualified on `=` and on `:`, which silently dropped a real Kubernetes Secret finding, because a Secret value is base64 with trailing `=` padding, and a real TypeScript credential. The question is not "does it contain a symbol" but "would it have to be evaluated": brackets, arrows, a leading dot, a leading dollar. A colon and an equals do not mean evaluation. Both positives are pinned by tests so the tightening cannot quietly drop them again.
* **`check` ran the entire guard pass twice.** `check` called `check_workspace_with_database`, which itself called `check_workspace_without_deps`, and the caller then filtered the code guards back out with a `retain`. The interprocedural taint pass therefore ran twice for every check, and it is the expensive layer. Measured on attrs, 56 python files: 675 seconds became 55. Twelve times, from one redundant pass, found by timing the layer rather than guessing at it.
* **llama.cpp at 706 source files still exceeds 240 seconds**, stated plainly in the commit that fixed it. One interprocedural pass over that many files is the remaining cost, and it is a real cost rather than the duplicate that was removed.

## 0.20.0

Every capability reachable by an agent, and one gap closed before it shipped.

* **The dead-code signal is no longer a list of functions the workspace cannot see.** `describe` reported uncalled roots, which is a false statement about plenty of live code: a method dispatched through a framework, a job handed to a queue, a test exercising a helper, a symbol exported for a consumer, a trait method called through its trait. Routes were handled and nothing else was. Each case now carries a reason, and a symbol whose source cannot be read is neither called dead nor called live.
* **Python dispatch by naming convention was the hole left in that fix.** Django views, Celery workers and Flask handlers are dispatched by name, so there is no call edge and no decorator to find. `handle_request`, `dispatch_event` and `task` were all reported dead, which is exactly the kind of finding an agent acts on by deleting working code. Found by probing the rule rather than reading it, because the original tests covered routes and exports and nothing dispatched by name.
* **The exemption is python and method only.** A JS or Go function called `get` really is usually dead, and exempting it everywhere would make the signal useless in every other language the scanner supports.
* **A python method is extracted as `function_definition`, not `method_definition`,** so the kind cannot tell a method from a module level function. Indentation does, and that is what the check uses.
* **8 tests.** Three for the convention cases, and one asserting the exemption does not leak into JavaScript or Go.


The release that makes Heides usable by an agent rather than only by a person at
a terminal. Everything here was reachable from a terminal before and is now
either a tool call or a machine-checkable verdict, and several of the new layers
found real defects in themselves the moment they were switched on.

* **`verify`: a machine-checkable definition of done.** Runs the workspace tests plus every guard and returns a boolean with reasons, `--json` for agents. This is the stopping condition an autonomous loop actually needs. Silence is never success, and a failing gate returns non-zero rather than printing an unhappy message. Six `SHELL_UNSAFE` rules ship with it, catching `shell=True`, `verify=False` and `rejectUnauthorized`, each with a benign twin asserting the safe form stays silent.
* **The database layer.** `.sql` and migration directories (SQL, Alembic, Goose, Flyway, Prisma) parse into a schema graph; seven ORMs and raw SQL resolve to tables with the read/write split preserved; concatenated query construction is a syntactic sink. Reports foreign key cycles with their path, missing indexes, tables with no primary key, sensitive columns, and N+1 query patterns. The first version reported a dropped `DROP TABLE` as a live table, which is the kind of defect that makes a tool untrustworthy rather than merely wrong.
* **The API surface graph.** `endpoint -> handler -> service -> table`, in one query, every hop grounded in a file and line. `heides db routes` lists what each endpoint reads and writes; `heides db touch POST /users` answers the single question an agent asks before changing a route. Recognises Express, Fastify, Flask, Django and Go net/http.
* **Configuration and secret indexing.** `.env`, `Dockerfile`, Compose, Terraform, Kubernetes and Helm manifests, and ini files. These were not merely unchecked, they were never read: a file with no extension returns no language, and `.env` and `Dockerfile` have none. A finding never carries the credential, on the wire or in the JSON form, because a report that echoes a secret has copied it into every log and transcript that reads the output.
* **Transitive dependency resolution.** Seven lockfile formats, with each package's depth and the path taken to reach it. A vulnerability four levels down is a different decision from one on a direct dependency, and the report now says which it is. Verified on Heides' own `Cargo.lock`: 94 packages, 90 reachable, a six-level path reported correctly.
* **An OSV advisory cache, so `--no-deps` is a real gate.** An offline run previously gave up on advisories entirely. The asymmetry is the safety property: a stale *vulnerability* is still reported, a stale *clean* is not, because only one of those errs in a direction a reader can correct.
* **MCP: 21 tools, up from 11.** Everything above is reachable as a tool call, not only as a subcommand. Every tool's arguments are validated against its declared schema before dispatch, because a wrong type silently coerced to an empty string answers as if it were a fact about the codebase.
* **The database index is persisted** at `.heides/db.json`, with migration drift detection, so a resuming agent can tell whether the schema it holds is still the schema on disk.

**Defects found and fixed while building the above**, each of which made a shipped feature report nothing rather than something wrong: the enclosing-function scan skipped the query's own line, so no one-line function body ever resolved; the verb `create` matched inside `createUser`; only callees were checked, so a handler querying directly was reported as touching nothing; `findmany({` sat in the batch-marker list, so every prisma read looked pre-batched; the config scan sat behind the database branch's early returns; and `check` and `verify` filtered the extra guards to `database.` only, so a repository with a live key in it reported clean.

### Credential shapes and weak crypto, from the same unreleased line

Four audit findings closed. Three of them had no test at all when they were written, so two were measurably wrong before this release.

* **Credentials are now matched by value shape, not only by variable name.** `AWS_ACCESS_KEY_ID`, `SLACK_TOKEN`, `HOOK_URL` and `KEY` all bind a real credential to a name containing no keyword, so the keyword match never fired. Thirteen shapes are recognised: AWS access and temporary key ids, GitHub PAT, OAuth and fine grained tokens, all four Slack token families, Slack webhook URLs, OpenAI project keys, Anthropic keys and PEM blocks. The report names which credential it found, so "possible secret" becomes "AWS access key id hardcoded in source".
* **Only the value is inspected, never the line.** The first version searched everything after the `=`, so a docstring reading "rotate your ghp_ token" fired, and so did a variable literally named `comment`. A shape must now sit inside an unbroken run of token characters with at least 16 characters after it, which keeps real keys and drops prose. An env read such as `AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]` stays silent: the key name appears inside the bracket expression, and reading a credential from the environment is the correct thing to do.
* **`pickle`, `marshal`, `yaml.load`, `hashlib.md5`, `hashlib.sha1` and insecure `random` are reported.** They are pattern rules rather than taint sinks on purpose: `pickle.loads` of an attacker controlled archive is exploitable whatever the source is, so tying it to a flow would leave it silent on exactly the archives that matter. Weak hash and non crypto randomness are defects on their own.
* **The safe twins are asserted, not assumed.** `hashlib.sha256`, `secrets`, `random.SystemRandom`, `yaml.safe_load` and `yaml.load(x, Loader=SafeLoader)` must all stay silent. The first version fired on the explicit `SafeLoader` form, which is the documented safe way to write it. Rows are python gated, so a doc comment mentioning `pickle.loads` is not a finding in a rust or typescript file.
* **Rust `unsafe` blocks and null pointer construction are reported**, both as warnings and never as blockers. `unsafe` is a promise the compiler cannot check, not a defect, so this is a review hint. `unsafe impl` and `unsafe trait` are marker signatures and stay silent.
* **8 tests, all of them measuring something that was previously wrong.** Value shapes fire on real keys, stay silent on prose and env reads, and stay silent when a prefix is embedded in a longer identifier. The safe twins stay silent. The python rows do not leak into other languages. `unsafe impl` and comments stay silent.

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
