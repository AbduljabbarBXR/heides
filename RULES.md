# HEIDES rule specification

This file is the contract of every rule the harness runs. Each rule lists its exact trigger, its severity and its guarantee. A rule reports only what it can prove from the code itself. No finding without proof, no window guesses, no style opinions dressed as findings. If a rule cannot prove a fact it stays silent.

Severity levels. A blocker stops an agent patch from applying. A critical finding is a real hazard in the workspace. A warning is a probable hazard. An info is a note that needs human judgment. The clean corpus gate asserts zero findings on idiomatic code in all eight languages, so any rule that fires on clean code fails the build.

## security.taint

Two layers prove flows, intra procedural and interprocedural. The intra layer traces inside one function block at a time. A variable assigned from a source line is tainted for the rest of that block. A sink line reports critical when it uses a tainted variable, or when a qualifying source exists earlier in the same block at the same or deeper indent within the last 60 lines. Sources are the standard user entry points per language, request parameters, form values, headers, cookies, query strings, environment variables, storage reads. Operator input, command line arguments such as sys.argv and os.Args, is not a source class at all, a CLI tool is run by its operator, the attacker in the threat model is remote. Sinks are SQL execution, shell and system execution, file system writes, dynamic code evaluation, prompt construction. All data sink findings report critical. The reported source line is 0 when the trace is indirect, meaning the source exists in the block but the sink does not name the tainted variable itself.

The interprocedural layer proves flows across function boundaries with the same discipline. Every function gets a static summary. Which parameters reach which sinks inside its body, which parameters flow into its return value, and whether a source read reaches a return, the source wrapper case. A fixpoint over the call graph then propagates parameter taint from callers to callees, argument position to parameter position, and return taint back into the caller variables. A report fires only at an end sink and carries the full chain, source line, every function the value passed through, and the call lines, so each finding reads like a sentence of evidence.

Interprocedural limits, stated so the claim never overreaches. Positional arguments only, named arguments are not modeled. Whole variable granularity, a tainted value stays tainted through its name but per field splitting is not modeled. Only callees resolvable to exactly one definition in the scanned workspace propagate, library and framework calls stop the flow silently. Provenance chains cap at eight hops, deeper flows stay silent rather than guess. When a sink parameter is already tainted, the first proven path wins and later paths to the same parameter are not reported again. Each of these limits is a false negative boundary, never a source of wrong findings. Module level code is analyzed as its own scope per file, so a source read at the top level reaching a sink line or flowing into a function call at the top level is reported with the same evidence chain as a function flow.

- SQL sink reach. Trigger, a qualifying source feeds a query execution call such as executeQuery, query, mysqli_query, db Query, ExecuteScalar, sqlite execute. Message shape, user controlled input reaches a {sink} sink on this line. source at line {n}.
- Shell sink reach. Trigger, a qualifying source feeds system, shell exec, Process Start, Runtime exec, os system. Same message shape.
- File sink reach. Trigger, a qualifying source feeds file write calls such as file put contents, fs writeFile, File WriteAllText, os Create. Same message shape.
- Eval sink reach. Trigger, a qualifying source feeds eval or Function construction. Same message shape.
- Prompt injection. Trigger, a line that constructs a prompt, system message or model input uses a variable tainted from user input. This rule models AI system files first class. Message shape, user input reaches a prompt construction on this line (prompt injection risk). source at line {n}.

## edge.cases

Boundary mistakes in changed code. Every rule is exact.

- Unwrap on a possibly absent value. Severity warning. Trigger, a line contains .unwrap() on an Option or Result expression. Guarantee, the call site is named. Message, unwrap can panic when the value is not present. handle the case instead.
- Panic macro. Severity info. Trigger, a line contains panic!(). Guarantee, the call site is named. Message, panic macro present. make sure this path is truly unreachable.
- Unparsed JSON. Severity warning. Trigger, a JSON.parse call whose enclosing block has no try and no catch. Guarantee, the enclosing block is scanned exactly, not a fixed window. Message, JSON.parse can throw on bad input. wrap it in try or validate first.
- Unguarded storage read. Severity warning. Trigger, a localStorage or sessionStorage getItem value is used in the same block and none of the uses is guarded by a null check, fallback operator or conditional. Guarantee, the whole enclosing block is scanned for a guard. Message, storage reads can return null and the value is used without a guard.
- Missing radix. Severity info. Trigger, a parseInt call with no second argument. Message, parseInt without a radix can misread strings. pass a radix.
- Loose equality. Severity info. Trigger, a == or != comparison between values. Guarantee, no style claim, only coercion risk is named. Message, loose equality can coerce types. prefer strict equality.
- Mutable default argument. Severity warning. Trigger, a python function signature has a list, dict or set literal as a default. Message, mutable default arguments are evaluated once and can leak state.
- Bare except. Severity warning. Trigger, a python except clause with no exception type. Message, bare except swallows every error including interrupts. name the exception.
- File handle without context manager. Severity warning. Trigger, a python file is opened and the enclosing block has no with statement. Guarantee, the enclosing block is scanned exactly. Message, file handle is opened outside a with block and may leak.

## best.practice

- Unfinished work marker. Severity info. Trigger, a comment or string contains todo, fixme or hack. Message, unfinished work marker left in the code.
- Debug output. Severity warning. Trigger, a javascript or typescript line contains console.log or debugger outside a script context. Message, debug output left in the code.
- Debug macro. Severity warning. Trigger, a rust line contains dbg!. Message, debug macro left in the code.
- Module level print. Severity info. Trigger, a python module that defines functions prints at column zero outside the main guard. Scripts and main guarded blocks are legitimate. Message, print statement found at module level in a library module. remove before shipping.
- Hardcoded secret. Severity critical. Trigger, an assignment binds a long literal to a name that looks like a key, password, token or secret. Message, possible secret or credential hardcoded in source.
- Overlong function. Severity info. Trigger, a function body spans more than 80 lines. Guarantee, the body length is counted exactly from the real braces or python indentation, never estimated from the distance to the next function. Message, function {name} spans {n} lines. consider splitting it.

## dependency

Manifest based checks over Cargo.toml, Cargo.lock and package.json.

- Known vulnerability. Severity critical. Trigger, a pinned dependency version is reported vulnerable by the OSV database. Guarantee, the report names the package and the advisory. Message, {package} {version} has a known vulnerability: {advisory}.
- Update outside the declared range. Severity warning. Trigger, the latest stable version of a dependency falls outside the range the manifest declares. Guarantee, ranges are evaluated with real semver semantics for caret, tilde, wildcard and exact forms. serde = "1" is inside range when the latest is 1.0.228, so it is never reported. Message, latest {version} falls outside the declared range {range} for {package}. edit the manifest to upgrade.
- No manifests. Severity info. Trigger, no manifest file exists in the workspace. Message, no dependency manifests found (Cargo.toml, Cargo.lock, package.json).
- No pinned dependencies. Severity info. Trigger, a manifest declares no pinned versions. Message, no pinned dependencies to check.
- Network unavailable. Severity info. Trigger, the registries could not be reached. Message, network was unavailable for the dependency check. results are partial.

## staged.apply

A unified diff is checked against the spine graph before anything touches disk. The patch is applied in memory, the affected files are reparsed, and the proposed graph is diffed against the current one. A caller file the patch itself rewrites is judged on its proposed content, so a patch that renames a function and updates every caller in one move passes clean.

- Deleted file with live callers. Severity blocker. Trigger, a patch deletes a file whose symbols are still called from any file the patch does not rewrite, or from a rewritten file whose proposed content still calls them. Message, file {file} is deleted but {symbol} is still called from {n} call site(s).
- Removed function still called. Severity blocker. Trigger, a patch removes a function and a surviving call site remains, either in a file the patch does not touch or in a rewritten file that still calls it. Message, function {name} is removed by the patch but still called at {file}.
- Removed function with no callers. Severity warning. Trigger, a patch removes a function that has no recorded callers. Message, function {name} is removed by the patch and has no recorded callers.
- Duplicate definition. Severity blocker. Trigger, the new content of one file declares the same name twice with the same signature. Cross file collisions stay silent, modules, classes and route handlers routinely export the same method name as other files, and overloads differ in signature. Message, {file} declares {name} more than once in the same file.
- Signature change. Severity blocker when a stale call remains in a file the patch does not touch, warning when the patch rewrote the callers or none are recorded. Trigger, the normalized signature of a kept function differs after the patch. Argument compatibility of rewritten calls cannot be proven without type checking, so they surface as a warning, never a false blocker. Message, signature of {name} changed ({n} caller(s) may break: {caller}).

## grounding.plan and scaffold

Plan evaluation reads the spine graph and answers feasibility questions with evidence. Scaffold writes a new project tree from a plan and indexes it immediately. Neither runs the code guards above; the workspace check does that after the scaffold lands.

## Determinism guarantee

Two fresh scans of the same tree print byte identical output and write a byte identical index. The determinism test enforces this on every run. Parallel parsing merges results in file order, so no thread can race the outcome.
