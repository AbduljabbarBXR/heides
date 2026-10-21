# HEIDES rule specification

This file is the contract of every rule the harness runs. Each rule lists its exact trigger, its severity and its guarantee. A rule reports only what it can prove from the code itself. No finding without proof, no window guesses, no style opinions dressed as findings. If a rule cannot prove a fact it stays silent.

Severity levels. A blocker stops an agent patch from applying. A critical finding is a real hazard in the workspace. A warning is a probable hazard. An info is a note that needs human judgment. The clean corpus gate asserts zero findings on idiomatic code in all eight languages, so any rule that fires on clean code fails the build.

## security.taint

Two layers prove flows, intra procedural and interprocedural. The intra layer traces inside one function block at a time. A variable assigned from a source line is tainted for the rest of that block. A sink line reports critical when it uses a tainted variable, or when a qualifying source exists earlier in the same block at the same or deeper indent within the last 60 lines. Sources are the standard user entry points per language, request parameters, form values, headers, cookies, query strings, environment variables, storage reads. Operator input, command line arguments such as sys.argv and os.Args, is not a source class at all, a CLI tool is run by its operator, the attacker in the threat model is remote. Sinks are SQL execution, shell and system execution, file system writes, dynamic code evaluation, prompt construction. All data sink findings report critical. The reported source line is 0 when the trace is indirect, meaning the source exists in the block but the sink does not name the tainted variable itself.

The interprocedural layer proves flows across function boundaries with the same discipline. Every function gets a static summary. Which parameters reach which sinks inside its body, which parameters flow into its return value, and whether a source read reaches a return, the source wrapper case. A fixpoint over the call graph then propagates parameter taint from callers to callees, argument position to parameter position, and return taint back into the caller variables. A report fires only at an end sink and carries the full chain, source line, every function the value passed through, and the call lines, so each finding reads like a sentence of evidence.

Interprocedural limits, stated so the claim never overreaches. Positional arguments only, named arguments are not modeled. Whole variable granularity, a tainted value stays tainted through its name but per field splitting is not modeled. Only callees resolvable to exactly one definition in the scanned workspace propagate, library and framework calls stop the flow silently. Provenance chains cap at eight hops, deeper flows stay silent rather than guess. When a sink parameter is already tainted, the first proven path wins and later paths to the same parameter are not reported again. Each of these limits is a false negative boundary, never a source of wrong findings. Module level code is analyzed as its own scope per file, so a source read at the top level reaching a sink line or flowing into a function call at the top level is reported with the same evidence chain as a function flow.

- SQL sink reach. Trigger, a qualifying source feeds a query execution call such as executeQuery, query, mysqli_query, db Query, ExecuteScalar, sqlite execute. Message shape, user controlled input reaches a {sink} sink at {callee}. source at line {n}.
- Shell sink reach. Trigger, a qualifying source feeds system, shell exec, Process Start, Runtime exec, os system. Same message shape.
- One call, one class. The class of a sink is a property of the call, not of the line. A line that holds one call is classified by the most specific rule that matches that call, so `db.exec(cmd)` is a SQL sink and a bare `exec(cmd)` is a shell sink, and neither line reports the other. A line that holds two calls reports one class per call. The {callee} in the message is the receiver qualified name of the call, so a reader can go and look at the exact expression.
- Cross site scripting sink. Trigger, a qualifying source feeds innerHTML, outerHTML, document write, insertAdjacentHTML, dangerouslySetInnerHTML, render_template_string, Markup, or a Flutter WebView loadUrl, loadHtmlString or loadData. Message shape, user controlled input reaches a XSS sink at {callee}. source at line {n}.
- Deserialization sink. Trigger, a qualifying source feeds pickle load, yaml load, marshal load, unserialize, Marshal load, ObjectInputStream or readObject. Message shape, user controlled input reaches a deserialization sink at {callee}. source at line {n}.
- Platform channel sink. Trigger, a qualifying source reaches a Dart invokeMethod, which hands a message to the host, where the host can do things the Dart side cannot see. Message shape, user controlled input reaches a platform channel sink at {callee}. source at line {n}.
- Dart sources. The Dart rows are the standard library, stdin readLineSync and readLine, Platform environment, the body of an inbound request, a Flutter text field, and a value out of a parsed request URL. A Dart function parameter counts as untrusted input for the classes where that matters, because in a Dart service the parameter usually is the request data and nothing else in the language says so. The filesystem class is deliberately excluded, because `File(path)` with a path argument is ordinary code.
- Dart shell execution. `Process.run` passes an argument list to the program, so it is not a shell and nothing can be injected through it. The shell sinks are `runInShell`, and `run` or `start` with `runInShell: true` on the same line.
- File sink reach. Trigger, a qualifying source feeds file write calls such as file put contents, fs writeFile, File WriteAllText, os Create. Same message shape.
- Eval sink reach. Trigger, a qualifying source feeds eval or Function construction. Same message shape.
- Prompt injection. Trigger, a line that constructs a prompt, system message or model input uses a variable tainted from user input. This rule models AI system files first class. Message shape, user input reaches a prompt construction on this line (prompt injection risk). source at line {n}.
- Marked safe output. Severity critical. Trigger, a qualifying source feeds a python mark_safe call. Django escapes template output unless a value is explicitly marked safe, so tainted content reaching mark_safe renders unescaped, provable cross site scripting. mark_safe is the only framework sink in the engine, every other framework specific XSS shape stays silent until grammars and a template context model exist. Message shape, user controlled input reaches a mark_safe sink. Literal content inside mark_safe never fires.

## edge.cases

Boundary mistakes in changed code. Every rule is exact.

- Unwrap on a possibly absent value. Severity warning. Trigger, a line outside test code contains .unwrap() on an Option or Result expression. Test code means a #[cfg(test)] module, or a tests/, benches/ or examples/ path, where an unwrap is an assertion rather than shipped behaviour. Guarantee, the call site and its enclosing function are named. Limitation, this is a syntactic match and not a proof: heides does not have type information, so it cannot tell whether the value is genuinely fallible. It reports the pattern, and the reader judges it. Message, unwrap can panic when the value is not present in NAME. handle the case instead.
- Panic macro. Severity info. Trigger, a line outside test code contains panic!(). Guarantee, the call site and its enclosing function are named. Message, panic macro present in NAME. make sure this path is truly unreachable.
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
- Diagnostic console calls. Severity info. Trigger, a javascript or typescript line contains console.debug, console.info, console.warn or console.error outside a script context. Message, diagnostic console call left in the code. warn and error are sometimes deliberate production logging, so they stay visible without being treated as dirt.
- Alert dialog. Severity info. Trigger, a javascript or typescript line contains alert( outside a script context. Message, alert dialog call left in the code, remove before shipping.
- Debug macro. Severity warning. Trigger, a rust line contains dbg!. Message, debug macro left in the code.
- Module level print. Severity info. Trigger, a python module that defines functions prints at column zero outside the main guard. Scripts and main guarded blocks are legitimate. Message, print statement found at module level in a library module. remove before shipping.
- Hardcoded secret. Severity critical. Trigger, an assignment binds a long literal to a name that looks like a key, password, token or secret. Message, possible secret or credential hardcoded in source.
- Overlong function. Severity info. Trigger, a function body spans more than 80 lines. Guarantee, the body length is counted exactly from the real braces or python indentation, never estimated from the distance to the next function. Message, function {name} spans {n} lines. consider splitting it.

HTML web surface rules, on html files only.

- Javascript URL. Severity critical. Trigger, a link href or script src attribute value starts with javascript: and the attribute sits inside a tag on the same line, prose examples outside tags never fire. Guarantee, the hazard is proven from the file alone, a browser executing that URL runs page script. Message, javascript URL in an html attribute executes script from the page, replace it with a safe destination.
- Missing content security policy on a form page. Severity info. Trigger, an html file contains a form element and no meta tag that mentions content-security-policy anywhere in the file. Pages whose CSP arrives in a server header stay quiet at the human judgment level. Message, page renders a form without a content security policy meta tag, add one or confirm the server sends the header.

## dependency

The dependency guard was removed in 0.25.0, and this section is here so the
absence is not mistaken for an oversight.

A guard that cannot tell *no vulnerability* from *has not heard of it yet*
reports false confidence, and false confidence is indistinguishable from a
pass. Every way of answering the question inside this tool was a way of being
wrong: over the network the verdict depended on network conditions, and from a
cache a clean answer expired after a day, so a CVE published that morning read
as clean until the entry was fetched again. The guard could not name the
advisory it matched, and it reported advisories against versions that were
already fixed.

CVEs, secrets and exposure live in GRIM, which is backed by a continuously
updated feed rather than by this repository's cache. `heides deps` and the
`deps.*` tools still exist and refuse with a pointer to it, so an agent holding
one of those names learns where the answer went instead of concluding the tool
is broken.

## workspace policy

The policy is what a project uses to say what it does and does not want
scanned. It is applied at the walk, so an excluded path produces no finding at
all rather than a finding that is hidden later, and the coverage receipt says
how many files were excluded so the exclusion is visible rather than a gap.

- Path rules. `.heidesignore` holds gitignore style rules. A rule with no slash matches any path component, so `tests` excludes `tests/a.py` and `src/tests/a.py`. A rule with a slash is matched from the workspace root, with `**` standing for any number of segments. A `!` rule re-includes. `.heides/config.json` holds the same thing in an `ignore` array, plus an `exclude` array and an `include` array. An include list is an allow list: a path that matches nothing in it is not scanned, so a typo narrows the scan instead of silently widening it.
- Severity overrides. `severity_overrides` maps a rule id to a severity. A rule id matches exactly, or as a family when the key ends with a dot, so `security` covers `security.taint`. The rule still fires. Only the label changes.
- Language toggles. `languages` is the list of languages to scan, `disabled_languages` the list to skip. A language that is switched off is not parsed at all, so it produces no finding and no coverage.
- Size limit. `max_file_bytes` skips files over the limit. The default is one megabyte.
- Inline suppression. `// heides-ignore security.taint the reason` silences one rule on one line, `// heides-ignore-file security.taint` silences it for the file, and `until 2026-12-31` expires the suppression. An expired suppression suppresses nothing. A suppression written inside a string literal is not a suppression, and the marker has to start a comment.
- Baseline. `heides baseline` records the findings a project has accepted in `.heides/baseline`. `heides check --baseline` fails only on findings that are not in it, and `heides check --new-only` prints only those. A known finding is still reported and still counted. It only stops failing the build. The key is the rule, the file and the message with the line references removed, so a finding that moved down the file is still the known finding.

## staged.apply

A unified diff is checked against the spine graph before anything touches disk. The patch is applied in memory, the affected files are reparsed, and the proposed graph is diffed against the current one. A caller file the patch itself rewrites is judged on its proposed content, so a patch that renames a function and updates every caller in one move passes clean.

- Deleted file with live callers. Severity blocker. Trigger, a patch deletes a file whose symbols are still called from any file the patch does not rewrite, or from a rewritten file whose proposed content still calls them. Message, file {file} is deleted but {symbol} is still called from {n} call site(s).
- Removed function still called. Severity blocker. Trigger, a patch removes a function and a surviving call site remains, either in a file the patch does not touch or in a rewritten file that still calls it. Message, function {name} is removed by the patch but still called at {file}.
- Removed function with no callers. Severity warning. Trigger, a patch removes a function that has no recorded callers. Message, function {name} is removed by the patch and has no recorded callers.
- Duplicate definition. Severity blocker. Trigger, the new content of one file declares the same name twice with the same signature. Cross file collisions stay silent, modules, classes and route handlers routinely export the same method name as other files, and overloads differ in signature. Message, {file} declares {name} more than once in the same file.
- Signature change. Severity blocker when a stale call remains in a file the patch does not touch, warning when the patch rewrote the callers or none are recorded. Trigger, the normalized signature of a kept function differs after the patch. Argument compatibility of rewritten calls cannot be proven without type checking, so they surface as a warning, never a false blocker. Message, signature of {name} changed ({n} caller(s) may break: {caller}).

## grounding.plan and scaffold

Plan evaluation reads the spine graph and answers feasibility questions with evidence. Scaffold writes a new project tree from a plan and indexes it immediately. Neither runs the code guards above; the workspace check does that after the scaffold lands.

- The verdict is false unless the plan is grounded. It used to be true for any plan at all, including one that named two symbols the workspace does not contain and one that named nothing the spine knows about. An agent that reads `feasible true` stops checking, so the answer has to be the one that keeps it looking.
- The status says which of `feasible`, `unverified` and `unknown` applies. `unverified` means the plan names real code and code it cannot find. `unknown` means the plan names nothing the spine knows about, so there is nothing to say about it either way.
- The blockers say what is missing, by name.
- The scaffold refuses a stack it cannot generate, and says which stacks exist. It used to read one keyword and write a Node app for every request, so a request for a Flutter app produced a JavaScript file and an empty requirements file. An agent that asked for a Flutter app and got a Node app would not know it had been given something else.

## Determinism guarantee

Two fresh scans of the same tree print byte identical output and write a byte identical index. The determinism test enforces this on every run. Parallel parsing merges results in file order, so no thread can race the outcome.
