# HEIDES

![HEIDES, the code nervous system](assets/banner.png)

## The code nervous system

HEIDES is a deterministic harness that gives AI coding agents what they do not have on their own: a persistent map of the code, warnings derived from that map, and a verdict before a patch lands. The agent suggests. HEIDES decides what is safe.

One binary. No cloud, no model, no account. It runs on a laptop, on a server, in CI, and on a phone running Termux.

```sh
heides scan                 # map the codebase once
heides check                # run every guard, exit non-zero on a blocker or critical
heides staged patch.diff    # judge a patch before it lands
heides mcp                  # expose it to any MCP client
```

`check` is a gate, not a report. It exits non-zero when it finds a blocker or a
critical, so CI fails on a real SQL injection without anyone parsing the output.
A clean workspace exits 0. `--exit-zero` restores the old always zero behaviour,
and `--exit-threshold=warning` makes it stricter.

### Every guard is local, and that is the whole design

heides reports only what it can prove from the files it read. Each finding names
a file and a line, and the same tree produces the same verdict on a laptop, in a
container, and on a phone with the network off. There is no cache to go stale and
no registry that can fail.

That used to not be true. heides carried a dependency guard that asked whether a
pinned version was a known CVE, and every way of answering it inside the tool
was a way of being wrong:

- Over the network, a gate verdict depended on network conditions rather than on
  the tree. `check` took 3242 ms with the guard and 117 ms without, on the same
  five file fixture.
- From a cache, worse. The offline cache expired a clean answer after 24 hours,
  so a CVE published that morning read as "no known vulnerability" until the
  entry was re-fetched. Nothing in the output distinguished the two.

A guard that cannot tell *no vulnerability* from *has not heard of it yet*
reports false confidence, and false confidence is indistinguishable from a pass.
So the guard was removed rather than made opt-in: an opt-in default that is safe
is still a slow default, and a cache that is correct is still a cache.

**Dependencies, secrets and exposure live in
[GRIM](https://pypi.org/project/grim-mcp/)**, which is public, published, and
backed by a continuously updated feed rather than by this repository's cache.
`heides deps` and the `deps.*` tools still exist and say exactly that, so an
agent holding one of those names learns where the answer went instead of
concluding the tool is broken.

What heides still proves locally is the part that matters for a change you are
about to make:

| | |
|---|---|
| Taint | user input reaching a SQL string, a shell, or a prompt |
| Secrets | committed credentials by value shape, in source and in config |
| Edge cases | the unwrap and index patterns that panic on the wrong input |
| Schema | foreign key cycles, missing primary keys, PII on a read path |
| Config | credentials in `.env`, Dockerfile, Terraform and manifests |

Every one of those is a fact about your repository rather than about the world,
which is why they belong in the same tool and the CVE question does not.

### Over MCP

`harmony.check` and `harmony.report` return findings with the guard, severity,
message, file and line. `harmony.report` carries `security_gate` and
`security_posture` so an agent can gate on the verdict without parsing prose,
and the coverage receipt travels inside the JSON, because an agent that receives
a clean result must be able to see how much was actually inspected without a
second call.

One lesson outlived the guard it was written for. An MCP server handles every
client in one process, so a setting that changes behaviour must be scoped to the
call that asked for it and never set on the process. An earlier version of
`harmony.check` set a process global and never restored it, so one client
passing an argument silently changed the security posture of every later request
from every client.

## Why it exists

An AI agent is powerful and blind. It can write a perfect function and still break three callers it never read, because it has no persistent map of the code. Linters and tests catch that after the change lands, and only on paths that happen to run. The classic failure: an agent changes a signature, the unexercised call sites break, the suite stays green, and production breaks at two in the morning.

HEIDES closes that gap at the moment that matters, before the write. It answers the questions no other tool answers at that instant. Who calls this function? Which imports does this file really use? Does this patch conflict with the graph? Is user input flowing into a SQL string, a shell, or a prompt?

## The Spine

![The Spine maps a codebase into one embedded SQLite file](assets/spine.png)

HEIDES walks the tree once and builds a persistent graph in one embedded SQLite file: files, symbols with their captured doc comments, call edges, import edges, and two FTS5 tables, one over names and docs, one over literals and comments. Every later question is an index lookup, so an agent asks the graph instead of reading files.

The spine is not a model and not a guess. `heides describe` reads the whole workspace manifest in one shot, including entrypoints, hubs and doc coverage per language. A function nobody calls in the workspace is not automatically dead code: Express, Flask, Django and Go route registrations are recognised, so a handler stops being reported as an uncalled root.

The cost contract is enforced on every push by the CI scale phase, not by a number frozen into this file: index time linear in files, queries on indexes, bounded memory, and analysis that never needs the network.

## Taint

![Taint traces user input into sinks, across function boundaries](assets/taint.png)

Taint is the part that finds real bugs. Sources are request data and environment reads per language. Flow is tracked block scoped, across function boundaries and across module level code, with a hop cap and silence past it. Sinks include SQL, SSRF, NoSQL, shell, filesystem, prompt, eval and Django's `mark_safe`.

SSRF and NoSQL use a stricter gate than SQL on purpose. A hardcoded health-check URL and a literal query object inside a request handler are both safe, so those rules require the tainted value to actually reach the sink line rather than merely a source existing somewhere in the handler:

```js
app.get('/health', async (req, res) => {
  const id = req.query.id;                              // a source is in scope here
  const r = await fetch('https://api.internal/health'); // ...and this must stay silent
});
```

A tainted fetch aimed at a cloud metadata address is reported as credential theft rather than as a generic SSRF, because that is what it is:

```
user controlled input reaches a cloud metadata fetch sink on this line. source at line 4
```

The report only claims what it can see. A tainted host passed in through a variable is reported as SSRF, because the address never appears on the line and the tool will not guess where it points.

The rule that matters most is restraint. `run`, `raw`, `literal` and `prepare` are ambiguous names, so they only count as SQL on a database-ish receiver:

```js
db.run("DELETE FROM users WHERE id = " + id)   // critical SQL finding
run(taskName)                                  // silence, a task runner is not a database
```

The same applies to a document query, where the method name alone is ambiguous but the receiver is not:

```js
UserModel.find(JSON.parse(req.query.filter))  // critical NoSQL finding
items.find(i => i.id === id)                  // silence, that is an array method
```

Both halves have a regression test, so the shortcut cannot come back.

### Languages

Taint and indexing are separate, and the table is honest about which is which.
Every row below was measured against the released binary, not inferred from the
grammar list.

| Language | Indexed with symbols | Taint scanned |
|---|---|---|
| JavaScript, TypeScript, TSX, Python, PHP, Go, Java, C# | yes | yes |
| C, C++ | yes | no |
| Ruby | yes | yes |
| HTML, CSS | yes | no |
| Rust | yes | no |

TypeScript was silently unscanned for taint until 0.16.0: the parser mapped `.ts` to `typescript` and the rule tables had no `typescript` rows, so every TypeScript file was skipped without a word. Ruby could not taint at all until this series, for three separate reasons: no `rb` extension, no source row, and a block detector that understood braces but not `def` and `end`. Rust is indexed but not taint scanned, so a shell or SQL sink in Rust code is not reported.

`.tsx` is parsed with the TSX grammar rather than the plain TypeScript one. The
two are not interchangeable: a JSX element opens node kinds that the plain
grammar cannot name, and the walk stopped there, so a component file yielded
fewer symbols than the same code with the `.ts` extension. C and C++ are
indexed with symbols and call edges, and are not taint scanned: a `sprintf` into
a fixed buffer feeding `system` produces nothing.


## The gate

![The pre-apply gate judges a diff before it lands](assets/gate.png)

`heides staged` is the part an agent loop actually uses. It judges the diff, not the file: signature widening and not just removal, callers and imports the patch breaks, taint the patch introduces, and the project's own tests when it has them. The verdict is structured, so an agent can gate on it without parsing prose, and it exits non-zero with a file and a line for every finding.

## Install

One line installer, downloads the prebuilt binary for linux, macos, windows and Termux Android.

```sh
curl -fsSL https://raw.githubusercontent.com/AbduljabbarBXR/heides/main/scripts/install.sh | bash
```

Pin a version with `HEIDES_VERSION`. It takes a bare version, and a leading `v` is stripped, so both `0.16.0` and `v0.16.0` work. The npm installer reads the same variable, so one pin covers both paths.

```sh
# any published tag, bare or with a leading v
HEIDES_VERSION=v0.16.0 curl -fsSL https://raw.githubusercontent.com/AbduljabbarBXR/heides/main/scripts/install.sh | bash
```

Or install from npm, no Rust toolchain needed:

```sh
npm install -g heides
```

If the binary is missing when you run `heides`, the launcher downloads it on the spot and says
so. This is not a fallback you should ever need: npm 11.16 and newer block dependency
lifecycle scripts by default, and on npm 11.17 the `--allow-scripts` flag aborts the install
outright, so the postinstall hook that fetches the binary never runs. Rather than tell you to
reinstall, which is the thing that just failed, the launcher runs the same installer the hook
would have. The platform table lives in `install.js`, so there is one copy of it.

Or with cargo:

```sh
cargo install heides
```

Or take a prebuilt binary for your platform from the releases page, or build from source
with `cargo build --release`.

Every channel is on the same version, and a test fails the build if the npm wrapper and the
binary ever drift apart.

## Quick start

```sh
heides scan                       # build the spine index
heides check                      # every guard, human readable
heides query callers send_order   # who calls it
heides query search refresh       # names, docs, literals and comments
heides describe                   # the workspace manifest in one shot
heides plan "add a health endpoint"   # is this plan grounded in what exists
heides staged patch.diff          # judge a patch before applying it
heides mcp                        # serve the eleven tools over stdio
```

A worked example, on a small Express service where two bugs are planted:

```sh
$ heides check
0 blocker(s), 3 critical, 0 warning(s), 1 info

[critical] user controlled input reaches a SQL sink ... at src/knexish.js:6
[critical] user controlled input reaches a SQL sink ... at src/knexish.js:7
[critical] user controlled input reaches a SQL sink ... at src/orders.js:9
[info] no dependency manifests found

$ heides query search users
2 hit(s)
SELECT * FROM users WHERE email = (literal) at src/knexish.js:5
DELETE FROM users WHERE id = (literal) at src/orders.js:9

$ heides plan "add a health endpoint"
feasible true
  no identifier in this plan exists in the spine. this plan introduces new definitions.
  existing functions to build on or replace: findUser, greet at src/clean.js:1
  spine holds 4 file(s) and 5 symbol(s). index version 8.
```

## Command reference

Every command, in one place. `heides <command> --help` prints the usage line for
any of them.

| Command | What it does |
|---|---|
| `scan` | Map the current codebase into the persistent index. The other commands read what this builds. |
| `status` | One line: files, symbols, call edges and imports held by the index. |
| `describe` | The workspace manifest: languages, counts, entrypoints, hubs, doc coverage, and which guards have a real corpus behind them. |
| `query` | `callers`, `imports`, `definition`, `calls`, `neighbors`, `search`. Who calls a symbol, where a definition lives, what it calls, free text search over names, signatures, docs, literals and comments. |
| `check` | Run every guard. The gate. Non-zero exit when a finding is a blocker or critical. |
| `staged` | Check a unified diff before applying it. |
| `verify` | Assertions a project can state about itself: its own tests plus every local guard, with a boolean to branch on. |
| `db` | `tables`, `columns`, `reads`, `writes`, `orphans`, `missingindex`, `policies`, `cycles`, `schema`, `routes`, `touch`. The database graph, read from the code. |
| `deps` | Removed. It used to ask whether a pinned version was a known CVE. It now refuses and points at [GRIM](https://pypi.org/project/grim-mcp/). |
| `config` | Scan manifests and config files for credentials and settings that matter. |
| `export` | Write the code map to a markdown file. The one command with no MCP twin, because it is a file export and the server has nothing to export to. |
| `confirm` | Ask crates.io and npm what a package name actually is, before you depend on it. The only command here that uses the network by choice. |
| `plan` | Evaluate a plan against the codebase and show the evidence it used. Takes free text. |
| `scaffold` | Generate a project from a plan and index it. Takes free text. |
| `changed-since` | Indexed files whose mtime is after a unix timestamp. The same answer as the `spine.changed_since` tool. |
| `watch` | Re-index and re-check on change. |
| `version` | Print the version. |
| `mcp` | Run the MCP server over stdio. |

## MCP tool reference

The server exposes twenty one tools over stdio, for any MCP client. Every one has
a command line twin except where noted.

* `spine.scan`. Map the current codebase into the persistent index. (`scan`)
* `spine.query`. Who calls a symbol, who imports a module, where a definition lives, what a function calls, or free text search over names, signatures, docs, literals and comments. (`query`)
* `spine.describe`. The workspace manifest in one call: languages, counts, entrypoints, hubs, doc coverage. (`describe`)
* `spine.neighbors`. Every side of a symbol: definition with its captured doc, its callers, its calls. (`query neighbors`)
* `spine.changed_since`. Indexed files touched after a unix timestamp. (`changed-since`)
* `harmony.check`. Run every guard, findings with evidence. (`check`)
* `harmony.report`. The same verdict as structured JSON with severity counts and a clean flag.
* `harmony.staged`. Check a unified diff before applying it. (`staged`)
* `harmony.verify`. The project's own tests plus every guard, as one boolean. (`verify`)
* `grounding.plan`. Evaluate a plan against the codebase, with the evidence it used. (`plan`)
* `grounding.scaffold`. Scaffold a new project from a plan and index it immediately. (`scaffold`)
The three `deps.*` tools were removed with the guard. Calling one returns an
error explaining that the capability moved to GRIM, rather than an unknown tool
error that would read as a broken server.
* `db.tables`, `db.columns`, `db.reads`, `db.writes`, `db.routes`, `db.schema`, `db.touch`. The database graph, read from the code. (`db <subcommand>`)
* `config.scan`. Credentials and settings in manifests and config files. (`config`)
* `web.confirm`. Confirm a fact against the package registries. (`confirm`)

`harmony.report` has no separate command because `check` prints the same verdict and
`export` writes the map out; splitting it again would be a second spelling of one
answer.

## Security model

* Deterministic by design. Every finding carries a file, a line, a reason and a rule id. No black boxes.
* Local by default. Nothing leaves the machine except the explicit web calls for dependency checks and grounding.
* No telemetry, no analytics, no account, no ports, no daemon protocol. One process on stdio.
* One static binary with no runtime dependencies.
* The MCP server reads raw bytes so binary input can never kill it, and caps message size.

## Use cases

* A guardrail for agentic coding sessions in the terminal.
* Pre-merge review for AI generated pull requests, in CI or over MCP.
* Onboarding an agent to an unfamiliar codebase without reading the whole tree.
* Security review of agent applications, especially prompt injection.
* Dependency hygiene for older projects.

## What is not done yet

Stated plainly, and tracked with citations and a resolution column in `ROADMAP.md`. Two things about this list are worth being explicit about. A gap listed here is a limit you can plan around; a silent no-op is not, and one shipped in 0.15.2, where a check on a never-indexed workspace reported a clean workspace. That specific defect is now pinned by two tests: one asserts a freshly built graph can read back every file it lists, the other asserts a first run over an unindexed tainted file reports it.

* No database layer yet. There is no `.sql` parsing, no schema graph, no way to ask which code touches a table. This is the largest known gap. Note this is a missing *database* layer, not a missing store: the spine is already one embedded SQLite file, so this extends an existing store rather than introducing one.
* No API surface graph, so nothing answers "what does `POST /users` end up writing to" in one call. This is the flagship item.
* Path traversal beyond the filesystem write sinks, and no command injection rule for framework-specific shell APIs.
* No open redirect, XXE, unsafe deserialization or crypto misuse rules.
* A handful of ecosystems are not read for dependencies: Ruby, .NET, Swift, Gradle, Dart, and no transitive resolution from lockfiles.
* Languages not indexed: SQL, shell, Kotlin, Swift, Scala, Dart, Dockerfile. C and C++ are indexed with symbols and call edges but carry no taint rows. Rust is indexed but not taint scanned.
* **There is no network in any guard.** Every finding is provable from the files. The one command that reaches the network is web confirmation inside `grounding.plan`, which is a deliberate lookup a caller asks for by name, not a guard that runs as part of `check`.
* `staged` validates conflicts only; it does not run taint over the post-patch tree, so a patch that introduces a flow is not yet caught by the gate.


## Reading the output

A check on this repository printed 185 lines, 152 of them the same sentence.
That is one finding with a count of 152, and printing it as 152 lines is how the
finding that mattered hides inside the wall.

```text
0 blocker(s), 1 critical, 157 warning(s), 41 info

[warning] unwrap can panic when the value is not present. handle the case
instead. x152 (edge.cases) at src/deps.rs:893

advice, unproven and unranked:
[info] diagnostic console call left in the code. x10 (best.practice) at npm/bin/heides.js:17
```

Three rules. Identical findings fold, and the count and the first file and line
are kept, so nothing is lost. `--all` prints every one. And evidence is never
mixed with advice: a taint finding is a path through code you can go and read,
a "function spans N lines" is a style opinion, and an agent cannot act on one the
way it acts on the other. The counts at the top always describe every finding, so
folding never flatters the result.

`--no-advice` drops the advisory section entirely, for a gate that wants evidence
and nothing else.

### What this costs an agent

heides is built to be read by a model, so what a call returns is a budget, not
just an answer. Measured on this repository:

| Call | Bytes | Tokens |
|---|---|---|
| reading every Rust file once | 1,105,462 | 276,365 |
| `describe` | 6,497 | 1,624 |
| `describe --brief` | 5,116 | 1,279 |
| `harmony.check` with advice (MCP) | 4,827 | 1,206 |
| `harmony.check` default (MCP) | 718 | 179 |

Orientation is 169x smaller than reading the source. Over MCP, `harmony.check`
returns **evidence only** and `advice: true` asks the style opinion back, because
an agent cannot act on it and a gate cannot fail on it. The CLI keeps the full
receipt: a person at a terminal is reading the whole thing on purpose.

Two flags keep a result from becoming the thing that ends the conversation:

* `--brief` on `describe` drops rule measurement, doc coverage and the
  undocumented symbol list: a receipt for a person judging the gate, not data an
  agent acts on.
* `max_bytes` on `harmony.check` trims the result to a budget you set. The cut
  lands on a line boundary and reports what was dropped, so a capped result is
  never mistaken for a complete one.

### `insight`

Where heides disagrees with itself, and what a change would reach.

```sh
heides insight contradictions   # signals that cannot both be true
heides insight impact <symbol>  # what editing this could reach
heides insight coverage         # where no rule can fire at all
heides insight baseline save    # record today's findings as known
heides insight baseline         # what is new since that baseline
```

`contradictions` compares signals computed independently, so a disagreement is
evidence rather than a guess: a route whose handler no definition matches, a
handler the dead root check also calls unreachable, the most called function in a
well documented file carrying no comment, a file nothing reaches and nothing
calls out of.

`impact` answers the question an agent asks before every edit. It reports the
transitive caller count, the files that move with the change, the routes behind
it, and whether any test reaches it, because "four callers" and "four callers and
no test reaches it" are different answers.

`coverage` says where a clean verdict means nothing. `rust: 44 file(s) indexed, no
taint rule can fire on any of them` is a different statement from clean, and only
one of the two is worth acting on.

`baseline` turns a wall of findings into a delta. A finding that is new matters
more than one that has always been there, and a finding key ignores its line
number so a file that only moved down does not fill the baseline with noise.

## The receipt

Every `check` ends by saying what it actually looked at, on clean runs too:

```text
analysed 12 of 12 indexed file(s)
languages: javascript, typescript, python
```

That is not decoration. A workspace with no findings and a workspace that was
never analysed printed exactly the same words, and a check that cannot say
which one it is cannot be trusted either way. The receipt also names the
languages it could not fully cover, and distinguishes the two ways a language
can be incomplete:

```text
languages: rust
no taint rules for: rust (indexed, taint not scanned)

languages: ruby
taint scanned, no grammar: ruby (no symbols in the graph)
```

The first is indexed but not scanned for flows. The second is scanned for flows
but contributes no symbols to the graph. Those are different gaps and pretending
otherwise is how a tool loses a user.

A run that could not read every indexed file, or that could not reach the
dependency registries, says so rather than reporting a partial result as a
complete one.

## Contributing

Read `CONTRIBUTING.md` before opening a pull request. `RULES.md` is the contract: every rule the harness runs is specified there with its exact trigger, severity and guarantee, so behaviour is reviewable rather than accidental.

## Development

```sh
cargo build --release
cargo test
```

The same gate runs in CI on every push and pull request: format, clippy with warnings denied, build, and the full suite, which includes a clean corpus gate that fails if a rule fires on idiomatic code, a hostility suite that feeds random bytes and brace storms to the parser, a scale phase that asserts the performance budget, and a determinism test that requires byte identical output and an identical index.

## License

MIT. See `LICENSE`.
