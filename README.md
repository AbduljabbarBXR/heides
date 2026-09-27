# HEIDES

![HEIDES, the code nervous system](assets/banner.png)

## The code nervous system

HEIDES is a deterministic harness that gives AI coding agents what they do not have on their own: a persistent map of the code, warnings derived from that map, and a verdict before a patch lands. The agent suggests. HEIDES decides what is safe.

One binary. No cloud, no model, no account. It runs on a laptop, on a server, in CI, and on a phone running Termux.

```sh
heides scan                 # map the codebase once
heides check                # run every guard
heides staged patch.diff    # judge a patch before it lands
heides mcp                  # expose it to any MCP client
```

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

Taint is the part that finds real bugs. Sources are request data and environment reads per language. Flow is tracked block scoped, across function boundaries and across module level code, with a hop cap and silence past it. Sinks include SQL, shell, filesystem, prompt, eval and Django's `mark_safe`.

The rule that matters most is restraint. `run`, `raw`, `literal` and `prepare` are ambiguous names, so they only count as SQL on a database-ish receiver:

```js
db.run("DELETE FROM users WHERE id = " + id)   // critical SQL finding
run(taskName)                                  // silence, a task runner is not a database
```

Both halves have a regression test, so the shortcut cannot come back.

## The gate

![The pre-apply gate judges a diff before it lands](assets/gate.png)

`heides staged` is the part an agent loop actually uses. It judges the diff, not the file: signature widening and not just removal, callers and imports the patch breaks, taint the patch introduces, and the project's own tests when it has them. The verdict is structured, so an agent can gate on it without parsing prose, and it exits non-zero with a file and a line for every finding.

## Install

One line installer, downloads the prebuilt binary for linux, macos, windows and Termux Android.

```sh
curl -fsSL https://raw.githubusercontent.com/AbduljabbarBXR/heides/main/scripts/install.sh | bash
```

Pin a version with `HEIDES_VERSION`. It takes a bare version such as `0.15.0`, a leading `v` is stripped, and the npm installer reads the same variable, so one pin covers both paths.

```sh
HEIDES_VERSION=0.15.0 curl -fsSL https://raw.githubusercontent.com/AbduljabbarBXR/heides/main/scripts/install.sh | bash
```

Or install from npm, no Rust toolchain needed:

```sh
npm install -g heides
```

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

## MCP tool reference

The server exposes eleven tools over stdio, for any MCP client.

* `spine.scan`. Map the current codebase into the persistent index.
* `spine.query`. Who calls a symbol, who imports a module, where a definition lives, what a function calls, or free text search over names, signatures, docs, literals and comments.
* `spine.describe`. The workspace manifest in one call: languages, counts, entrypoints, hubs, doc coverage.
* `spine.neighbors`. Every side of a symbol: definition with its captured doc, its callers, its calls.
* `harmony.check`. Run every guard, findings with evidence.
* `harmony.report`. The same verdict as structured JSON with severity counts and a clean flag.
* `harmony.staged`. Check a unified diff before applying it.
* `grounding.plan`. Evaluate a plan against the codebase, with the evidence it used.
* `grounding.scaffold`. Scaffold a new project from a plan and index it immediately.
* `deps.check`. Known vulnerabilities and outdated versions from the manifests.
* `web.confirm`. Confirm a fact against the package registries.

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

Stated plainly, and tracked with citations in `ROADMAP.md`.

* No database layer yet. There is no `.sql` parsing, no schema graph, no way to ask which code touches a table. This is the largest known gap.
* No NoSQL or SSRF sink classes. The sink list is SQL, shell, filesystem, prompt, eval and `mark_safe`.
* A handful of ecosystems are not read for dependencies: Ruby, .NET, Swift, Gradle, Dart, and no transitive resolution from lockfiles.
* Languages are the eight the grammars cover. C, C++, SQL, shell, Ruby, Kotlin, Swift, Scala, Dart and Dockerfile are not indexed.
* `deps` needs the network to reach OSV, and degrades gracefully when it cannot.
* No API surface graph, so nothing answers "what does `POST /users` end up writing to" in one call.

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
