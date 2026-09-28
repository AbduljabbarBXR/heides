# HEIDES Growth Roadmap

Goal: make HEIDES comprehensive for **any kind of app** while staying deterministic,
cheap and fast. Every change below preserves the existing performance contract:
single-pass indexing, embedded SQLite spine, no network required for analysis,
and bounded work per query.

This document is derived from a full audit of the 0.14.4 source tree. Every gap
listed was verified by reading the code and running the binary against a test
codebase with planted defects.

---

## 1. What already works (do not regress)

| Capability | Implementation | Why it matters |
|---|---|---|
| AST parsing, 8 languages | `parser.rs:9`, `language_for` at `parser.rs:36` | tree-sitter, so a new language is one grammar crate, not a rewrite |
| Persistent code graph | `spine.rs:213-253`, embedded `rusqlite` (bundled) | `files`, `symbols`, `calls`, `imports` + FTS5 in one file |
| Interprocedural taint | `interproc.rs`, `MAX_HOPS = 8` | proves flows across function boundaries with an evidence chain |
| Pre-apply diff guard | `staged.rs` | catches conflicts before a patch lands |
| Dependency CVE checks | `deps.rs`, OSV at `deps.rs:715` | graceful degradation when offline |
| MCP server | `server.rs`, protocol `2025-06-18` | agents consume the graph without reading source |
| Footprint | 15 MB stripped binary, ~6 MB peak RSS, sub-second on small repos | this is the contract to keep |

Preserve these invariants while extending:

- **Deterministic.** Same input, same output, forever.
- **Bounded.** Caps like `MAX_HOPS = 8` exist deliberately; deepen them with a budget, never remove them.
- **Silent rather than guessing.** `interproc.rs` deliberately stays quiet past the hop cap. Keep that discipline.
- **Cheap context.** The graph exists so an agent queries instead of reading files. Every new capability must be answerable from the spine.

---

## 2. Verified gaps

### 2.1 Database: not supported

Databases appear in exactly two places, and neither is understanding:

1. **As a taint sink regex** — JS SQL sink at `taint.rs:48` is
   `("javascript", r"\b(query|execute|exec)\s*\(", "SQL")`.
2. **As a dependency name** parsed from manifests (`go-sql-driver`, `sqlalchemy`).

There is no `.sql` parsing, no migration awareness, no schema graph, no ORM
mapping, and no way to ask which code touches a table.

**Root cause of a demonstrated miss:** a test repo with
`db.run("DELETE FROM users WHERE id = " + id)` reported **0 warnings** from
`check`. The sink pattern matches `query|execute|exec`, not `run`. Worse,
`taint.rs:527` asserts `run(` must *not* fire (added to stop shell false
positives). That rule also blinds SQL detection for `better-sqlite3`,
`node:sqlite`, and Knex, where `db.run` / `stmt.run` is the primary query API.

### 2.2 Sink and source coverage is thin

`SOURCES` had 14 entries and `SINKS` 21 when this was written. Missing classes,
with the state as of 0.16.0:

| Class | State |
|---|---|
| **NoSQL injection** (Mongo `find`/`aggregate`, Firestore) | shipped in 0.16.0, 7 languages, co-occurrence gated so `items.find(` stays silent |
| **SSRF** (`fetch`/`axios`/`requests` with attacker-controlled URL) | shipped in 0.16.0, 7 languages, plus a cloud-metadata class |
| **Path traversal** beyond the filesystem write sinks | open |
| **Command injection** via framework-specific APIs | open |
| **Open redirect, XXE, unsafe deserialization, crypto misuse** | open |
| **Sources**: GraphQL resolvers, WebSocket, message queues (Kafka/SQS/Rabbit), file uploads | open. `localStorage` and framework routing params were already present |

Two coverage defects were found while building the 0.16.0 sinks and are fixed,
because both meant whole languages were invisible rather than a rule being weak:

- **TypeScript was never taint scanned.** `parser.rs` mapped `.ts` and `.tsx` to
  `typescript`, and the source and sink tables had no `typescript` rows, so every
  TypeScript file was skipped in silence. `.ts` now maps to the JavaScript rows.
- **Ruby could not taint at all,** for three separate reasons: no `rb` extension
  in `detect_language`, no source row, and `function_blocks` which understood
  braces but not `def` and `end`. All three are fixed. Ruby still has no grammar,
  so it contributes no symbols to the graph.


### 2.3 Query and plan weaknesses

- `query search sql` returns `no symbol matches` — search matches symbol names
  only, not string literals or content.
- `plan` prints `feasible true / grounding received the plan` without the
  grounded symbol and file evidence it used.
- `describe` lists `uncalled roots` including `login`, which is an Express-style
  entrypoint. Entrypoints are not modeled, so handlers read as dead code.
- `staged` validates conflicts only; it does not run taint on the post-patch tree.

### 2.4 Packaging

- npm package version is `0.14.5` but `install.js:15` hardcodes
  `BIN_VERSION = "0.14.4"`. `heides --version` and the npm version disagree.
  **Resolved in 0.15.0:** `BIN_VERSION` is derived from `package.json`, a test
  fails the build if they drift, and `HEIDES_VERSION` covers both install paths.
  Kept here as the worked example of why a version split matters.

### 2.5 Dependency ecosystem

`deps.rs` parses Cargo, package.json, go.mod, requirements/pyproject, pom.xml,
composer. Missing: Ruby (Gemfile.lock), .NET (packages.lock), Swift
(Package.resolved), Gradle, Dart (pubspec), transitive resolution from lockfiles,
and offline OSV caching (it queries `api.osv.dev` live).

---

## 3. Roadmap

Ordered by value. Each tier lists the work and the performance safeguard.

### Tier 0 — make existing claims true (shipped in 0.15.0)

| Fix | Where | State |
|---|---|---|
| SQL sinks learn `run`, `raw`, `literal`, `prepare`, `execSQL`, gorm `Raw`, EF `FromSqlRaw`, php `prepare`, python `executescript`, plus receiver-scoped matching so a bare `run(` in a task runner stays silent | `taint.rs` | shipped, 6 regression tests |
| NoSQL and SSRF sink classes, with a stricter gate than SQL so a constant URL and a literal query object stay silent | `taint.rs` | shipped in 0.16.0, 7 languages each, 22 tests including the false-positive halves |
| One version across the binary and npm, `BIN_VERSION` derived from `package.json`, lock asserted in CI, `v` prefixes stripped, `HEIDES_VERSION` honoured by npm too | `install.js`, `scripts/install.sh` | shipped, `npm test` covers it |
| `query search` matches literals and comments, not only symbol names, index version 8 | `spine.rs` | shipped, 6 tests |
| `plan` returns grounded evidence with file and line, capped at 12, and says so when nothing exists | `grounding.rs` | shipped, 4 tests |
| Framework-aware entrypoints for Express, Flask, Django and Go so handlers stop being flagged dead | `frameworks.rs`, `describe` | shipped, 4 tests |
| Report the source honestly when the tainted value is read and used on one line | `taint.rs` | shipped, 1 test |

Two defects were found by running the release binary on a fixture rather than by
the suite, and both are fixed: evidence named only the first file when a symbol
existed in two, and the taint report printed `source at line 0` for the common
same-line shape.

### Tier 0b — trustworthiness, the part that matters in production

Feature work stopped here on purpose. Everything above this line adds detection.
Everything below it addresses the failure mode that is far more dangerous than a
missing rule: a guard that silently reports nothing.

| Fix | State |
|---|---|
| `check` on a never indexed workspace reported zero findings and called the workspace clean. `build_graph` stored relative paths but never the root, so every content read failed and the taint, edge and practice guards received nothing | shipped in 0.15.2, 2 regression tests |
| Every guard has a liveness test: plant a known-bad input, assert it fires, and assert a known-good input stays silent | shipped. `harmony.rs` liveness module, 5 tests running the real index-then-check pipeline on files on disk. The positive tests were proven to fail by reintroducing the 0.15.2 defect |
| `check` reports what it analysed: files, languages, and what it skipped and why, so silence is never mistaken for a clean repo. Prints on every run, clean included, because a receipt you only see when something is wrong is a warning and not a receipt | shipped. `harmony::Coverage`, 5 tests, verified on the release binary across a clean, a Rust-only, a Ruby-only and a findings workspace |
| `--no-deps` and `HEIDES_OFFLINE` so `check` stops doing per-dependency HTTP nobody asked for | shipped in 0.16.2, 217s to 2s on this repo, still reads all 94 pinned versions offline, honoured by `harmony.check` and `harmony.report` over MCP. Corrected in 0.16.3: the summary line carries the posture, `--require-advisories` exits non-zero when advisories did not run, the posture is a value rather than a process global, MCP is fail closed, an unreachable advisory service no longer reports dependencies as clean, and advisory coverage is tracked separately from the update reminder so a missed reminder cannot fail a security gate |
| Findings are filtered, not merely emitted: collapse by message, provable separated from advisory, `--all` to expand, MCP defaults collapsed | shipped in 0.17.0. 185 lines to 42 on this repo, the summary line still counts everything, `--no-advice` drops the advisory section, MCP folds unless asked not to |
| The `unwrap` rule is a substring match, not a proof, which contradicts the contract in `RULES.md`. Make it provable: skip `#[cfg(test)]` and `tests/`, report the enclosing function | not started |
| Decide whether unprovable style advice may speak in the same voice as a proven hazard | shipped in 0.17.0. Advice is a separate section labelled `advice, unproven and unranked`, and `--no-advice` removes it |

**The general rule this section exists to enforce:** heides must be fully useful
with the network unplugged, and any check that wants the network must say so up
front and be skippable. A clean result and an unanalysable repository must never
print the same words.

### Tier 1 — the database layer (highest value)

"Any kind of app" almost always means "app plus database." This is the largest
single gap.

**New spine tables**, following the existing schema style:

```sql
CREATE TABLE IF NOT EXISTS db_schemas    (id INTEGER PRIMARY KEY, db TEXT, name TEXT);
CREATE TABLE IF NOT EXISTS db_tables     (id INTEGER PRIMARY KEY, schema_id INTEGER, name TEXT, kind TEXT);
CREATE TABLE IF NOT EXISTS db_columns    (id INTEGER PRIMARY KEY, table_id INTEGER, name TEXT,
                                          type TEXT, pk INTEGER, fk_table_id INTEGER, fk_col TEXT);
CREATE TABLE IF NOT EXISTS db_indexes    (id INTEGER PRIMARY KEY, table_id INTEGER, name TEXT,
                                          cols TEXT /* json */, unique INTEGER);
CREATE TABLE IF NOT EXISTS db_migrations (file TEXT, version TEXT, sha TEXT);
CREATE TABLE IF NOT EXISTS db_calls      (symbol_id INTEGER, table TEXT,
                                          op TEXT /* read|write */, via TEXT, line INTEGER);
CREATE INDEX IF NOT EXISTS idx_db_calls_table ON db_calls(table);
CREATE INDEX IF NOT EXISTS idx_db_columns_fk  ON db_columns(fk_table_id);
```

Deliverables:

1. **Parse `.sql` and migration dirs** (prisma/migrations, db/migrate, alembic,
   goose, flyway, liquibase) into the schema graph.
2. **ORM call-site to table resolution.** Map `prisma.user.findMany()`,
   `User.objects.filter()`, `db.First<User>()`, GORM, ActiveRecord into
   `db_calls`.
3. **New query kinds**: `query tables`, `query columns <t>`, `query reads <t>`,
   `query writes <t>`, `query orphans` (tables and columns nothing touches),
   `query missingindex` (FK without an index), N+1 candidates (per-row query in
   a call loop).
4. **Concatenated query construction as a syntactic sink.** `"SELECT ... " + id`
   is detectable from syntax alone, with no source/sink match. This catches the
   class the current `check` misses entirely.
5. **Sensitive-column taint.** Flag PII and credential columns reaching logs or
   responses.

Performance safeguard: schema parsing is a separate pass from code indexing,
written to its own tables, so re-indexing code never re-parses migrations and
`watch` stays cheap. All new queries are indexed B-tree or FTS5 lookups, never
full scans.

### Tier 2 — language coverage for any stack

Add tree-sitter grammars, in value order: **C/C++, SQL, shell/bash, Ruby,
Kotlin, Swift, Scala, Dart, YAML/JSON config, Dockerfile.**

Because `parser.rs` is already tree-sitter, each language needs a grammar crate
and a symbol/edge extractor; the spine and query layer are language-agnostic.
C/C++, SQL and shell together cover embedded, infrastructure and the database
layer. Config and Dockerfile become first-class indexed artifacts so an agent
can reason about the whole deployable unit, not just source.

### Tier 3 — app-shape awareness

- **API surface graph**: `endpoint -> handler -> service -> db_table`. This is
  the flagship capability: it answers "what does `POST /users` end up writing
  to?" in one query instead of an agent reading a dozen files. Built from the
  Tier 1 `db_calls` table plus route detection in the framework classifiers.
- **Config and secret indexing**: `.env`, Dockerfile, Terraform, Kubernetes
  manifests, with hardcoded-credential detection reaching a sink.
- **Dead-code signal refinement**: with entrypoints and routes modeled, the
  `uncalled roots` list becomes trustworthy enough to act on automatically.

### Tier 4 — ecosystem and the agent loop

- **deps.rs**: Ruby, .NET, Swift, Gradle, Dart manifests; transitive resolution
  from lockfiles; cached OSV database so vulnerability checks work fully offline
  and stay fast on repeat runs.
- **`verify` command**: run tests plus all guards and return a machine-checkable
  definition of done. This is what an autonomous loop needs as a stopping
  condition.
- **`staged` runs taint on the post-patch tree**, not only conflict detection.
- **MCP**: expose the new query kinds as tools, and add a `changed-since` tool
  so an agent resumes work without re-reading the graph (token efficiency).

---

## 4. Sequencing

Tier 0 first — it is days of work and it makes the security claims that are
already documented actually hold. Then Tier 1, because the database layer is
both the largest gap and the highest value, and it unlocks Tier 3's API surface
graph. Tiers 2 and 3 follow naturally since the tree-sitter and SQLite plumbing
already exist.

The single highest-leverage change is **Tier 1 item 4: detect concatenated query
strings syntactically.** It is deterministic, needs no source/sink matching, and
it closes the injection class that `check` currently misses.

---

## 5. Performance budget

Every capability above must fit this contract, measured on a mid-size repo:

- index time: linear in files, single pass, no quadratic re-analysis
- query time: indexed lookup, never a workspace scan
- memory: bounded, no full AST retention between passes
- binary: stay near current size; grammars are shared object additions, not
  duplicated pipelines
- offline by default: analysis never requires the network; `deps` degrades
  gracefully and caches when it can reach OSV

If a feature cannot meet the budget, it ships behind a flag and off the default
path, or it does not ship.
