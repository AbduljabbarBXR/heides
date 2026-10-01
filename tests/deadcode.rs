// Dead-code signal refinement tests.
//
// `describe` reports uncalled roots: a function nothing in the workspace calls.
// That is weak on its own, because plenty of functions are called by something
// the workspace cannot see, and calling those dead is a false statement about
// live code. The route case was handled and nothing else was: a method
// dispatched through a base class, a job handed to a queue, a test exercising a
// helper, a symbol exported for a consumer, a trait method called through its
// trait.
//
// Every positive here has a benign twin. A rule that cannot fail safely is not
// something to act on, because an agent following a false "dead" deletes working
// code.

use std::fs;
use std::path::{Path, PathBuf};

use heides::deadcode;

fn fixture(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("heides-dead-{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(dir: &Path, rel: &str, body: &str) {
    let p = dir.join(rel);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(p, body).unwrap();
}

fn graph_of(dir: &Path) -> heides::spine::CodeGraph {
    heides::indexer::build_graph(dir).0
}

fn reported(dir: &Path) -> Vec<String> {
    let g = graph_of(dir);
    deadcode::dead_roots(&g, dir)
        .into_iter()
        .map(|r| r.name)
        .collect()
}

// ------------------------------------------------------------- the true dead

#[test]
fn a_plain_unused_function_is_reported() {
    let dir = fixture("plain");
    write(
        &dir,
        "a.js",
        "export function caller() { return usedElsewhere(); }\n\
         function usedElsewhere() { return 1; }\n\
         function genuinelyUnused() { return 2; }\n",
    );
    let got = reported(&dir);
    assert!(
        got.contains(&"genuinelyUnused".to_string()),
        "a function nothing references is dead: {got:?}"
    );
    assert!(
        !got.contains(&"usedElsewhere".to_string()),
        "a called function is not dead: {got:?}"
    );
}

// ---------------------------------------------------------- the false claims

#[test]
fn a_route_handler_is_not_dead() {
    let dir = fixture("route");
    write(
        &dir,
        "routes.js",
        "router.post('/users', createUser);\n\
         function createUser(req) { return insert(req.body); }\n\
         function insert(x) { return x; }\n",
    );
    let got = reported(&dir);
    assert!(
        !got.contains(&"createUser".to_string()),
        "the framework calls it: {got:?}"
    );
}

#[test]
fn an_exported_javascript_symbol_is_not_dead() {
    // A library's whole point is that its consumer is outside the workspace.
    let dir = fixture("exported");
    write(
        &dir,
        "lib.js",
        "export function publicHelper() {\n  return 1;\n}\n\
         function notExported() {\n  return 2;\n}\n",
    );
    let got = reported(&dir);
    assert!(
        !got.contains(&"publicHelper".to_string()),
        "it is exported: {got:?}"
    );
    assert!(
        got.contains(&"notExported".to_string()),
        "a private function nothing calls is dead: {got:?}"
    );
}

#[test]
fn a_go_exported_function_is_not_dead() {
    // Go capitalises for a reason, and `main` is the program.
    let dir = fixture("goexport");
    write(
        &dir,
        "a.go",
        "package main\n\n\
         func main() { helper() }\n\
         func helper() int { return 1 }\n\
         func Unused() int { return 2 }\n\
         func neverCalled() int { return 3 }\n",
    );
    let got = reported(&dir);
    assert!(
        !got.contains(&"main".to_string()),
        "main is the program: {got:?}"
    );
    assert!(
        !got.contains(&"Unused".to_string()),
        "a capitalised name is package surface: {got:?}"
    );
    assert!(
        got.contains(&"neverCalled".to_string()),
        "an unexported function nothing calls is dead: {got:?}"
    );
}

#[test]
fn a_method_overriding_a_base_is_not_dead() {
    // A method is called through the base type, so no call edge names it.
    let dir = fixture("override");
    write(
        &dir,
        "a.java",
        "class Base {\n    abstract void handle();\n}\n\
         class Child extends Base {\n    void handle() { doWork(); }\n\
         void doWork() { }\n}\n",
    );
    let got = reported(&dir);
    assert!(
        !got.contains(&"handle".to_string()),
        "an override is dispatched through its base: {got:?}"
    );
}

#[test]
fn a_function_inside_a_test_file_is_not_dead() {
    // A test is an entrypoint by definition, so nothing inside one is dead, even
    // a helper it never calls.
    let dir = fixture("testfile");
    write(
        &dir,
        "suite.test.js",
        "function neverCalledInsideATest() {\n  return 1;\n}\n\
         test('works', () => { expect(1).toBe(1); });\n",
    );
    let got = reported(&dir);
    assert!(
        got.is_empty(),
        "a test file is an entrypoint, so nothing in it is dead: {got:?}"
    );
}

#[test]
fn a_helper_a_test_reaches_is_not_dead() {
    let dir = fixture("testreaches");
    write(
        &dir,
        "helper.js",
        "function usedByATest() {\n  return 1;\n}\n",
    );
    write(
        &dir,
        "suite.test.js",
        "import { usedByATest } from './helper.js';\n\
         test('works', () => { usedByATest(); });\n",
    );
    let got = reported(&dir);
    assert!(
        !got.contains(&"usedByATest".to_string()),
        "the test calls it, so there is a real edge: {got:?}"
    );
}

#[test]
fn a_decorated_python_function_is_not_dead() {
    // A decorator registers the function; nothing in the workspace calls it.
    let dir = fixture("decorated");
    write(
        &dir,
        "api.py",
        "def plain():\n    return 1\n\n\
         @app.route('/thing', methods=['GET'])\n\
         def thing():\n    return 2\n",
    );
    let got = reported(&dir);
    assert!(
        !got.contains(&"thing".to_string()),
        "a decorator registers it: {got:?}"
    );
    assert!(
        got.contains(&"plain".to_string()),
        "an undecorated function nothing calls is dead: {got:?}"
    );
}

#[test]
fn a_python_dunder_is_not_dead() {
    // `__init__` and `__repr__` are called by the runtime.
    let dir = fixture("dunder");
    write(
        &dir,
        "m.py",
        "class C:\n    def __init__(self):\n        self.x = 1\n    def __repr__(self):\n        return 'c'\n",
    );
    let got = reported(&dir);
    for name in ["__init__", "__repr__"] {
        assert!(
            !got.contains(&name.to_string()),
            "{name} is called by the runtime: {got:?}"
        );
    }
}

#[test]
fn a_named_function_passed_to_a_registration_is_not_dead() {
    // The shape with no call edge at all: a function handed over as a value.
    let dir = fixture("callback");
    write(
        &dir,
        "jobs.js",
        "queue.process('send', sendJob);\n\
         function sendJob(data) { return 1; }\n\
         function logJob(data) { return 2; }\n",
    );
    let got = reported(&dir);
    assert!(
        !got.contains(&"sendJob".to_string()),
        "a named function passed to a registration is dispatched: {got:?}"
    );
    assert!(
        got.contains(&"logJob".to_string()),
        "a function defined but never registered is still dead: {got:?}"
    );
}

#[test]
fn a_rust_trait_method_is_not_dead() {
    // A trait method is called through the trait, not by name.
    let dir = fixture("trait");
    write(
        &dir,
        "a.rs",
        "pub trait Shape {\n    fn area(&self) -> f64;\n}\n",
    );
    let got = reported(&dir);
    assert!(
        !got.contains(&"area".to_string()),
        "a trait method is dispatched through the trait: {got:?}"
    );
}

// ------------------------------------------------------------------ reporting

#[test]
fn every_report_carries_a_reason_and_a_location() {
    // A dead-code list with no reason is a list an agent cannot act on, and a
    // reason is the exact condition the roadmap sets for trusting this signal.
    let dir = fixture("reason");
    write(
        &dir,
        "a.js",
        "function used() { return 1; }\nfunction unused() { return 2; }\n",
    );
    let g = graph_of(&dir);
    let out = deadcode::dead_roots(&g, &dir);
    let hit = out.iter().find(|r| r.name == "unused").expect("reported");
    assert!(!hit.file.is_empty(), "needs a file: {hit:?}");
    assert!(hit.line > 0, "needs a line: {hit:?}");
    assert!(!hit.reason.is_empty(), "needs a reason: {hit:?}");
}

#[test]
fn a_workspace_with_nothing_dead_says_so() {
    let dir = fixture("clean");
    write(
        &dir,
        "a.js",
        "export function a() { return b(); }\nexport function b() { return 1; }\n",
    );
    let g = graph_of(&dir);
    assert!(
        deadcode::dead_roots(&g, &dir).is_empty(),
        "everything is reachable"
    );
    let summary = deadcode::summarise(&g, &dir);
    assert!(
        summary.contains("no dead roots"),
        "a clean result must be stated, not implied: {summary}"
    );
}

#[test]
fn the_report_is_stable_and_in_source_order() {
    // A list that reorders between runs is a list an agent cannot diff.
    let dir = fixture("stable");
    write(
        &dir,
        "a.js",
        "export function used() { return 1; }\n\
         function deadOne() {\n  return 2;\n}\n\
         function deadTwo() {\n  return 3;\n}\n\
         function deadThree() {\n  return 4;\n}\n",
    );
    let g = graph_of(&dir);
    let names = |gs: &heides::spine::CodeGraph| -> Vec<String> {
        deadcode::dead_roots(gs, &dir)
            .into_iter()
            .map(|r| r.name)
            .collect()
    };
    let first = names(&g);
    let second = names(&g);
    assert_eq!(first, second, "deterministic across runs");
    // Every dead function is present, and in source order.
    for expected in ["deadOne", "deadTwo", "deadThree"] {
        assert!(
            first.contains(&expected.to_string()),
            "{expected} is dead and must be listed: {first:?}"
        );
    }
    let at = |n: &str| first.iter().position(|x| x == n).expect("listed");
    assert!(
        at("deadOne") < at("deadTwo") && at("deadTwo") < at("deadThree"),
        "in source order: {first:?}"
    );
}
