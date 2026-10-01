// Framework dispatch by naming convention, which no call edge records.
//
// Django and Flask dispatch views, Celery and RQ dispatch workers, and none of
// it appears in the call graph or as a decorator. These shapes were reported as
// dead roots, which is a false statement about live code: an agent that trusts
// the dead list deletes a working handler. Found by probing the rule, not by
// reading it, because the original tests covered routes and exports but nothing
// dispatched by name.

use std::fs;
use std::path::{Path, PathBuf};

use heides::deadcode;

fn fixture(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("heides_dcconv_{name}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("fixture dir");
    dir
}

fn write(dir: &Path, rel: &str, body: &str) {
    let path = dir.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("parent");
    }
    fs::write(path, body).expect("write fixture");
}

fn reported(dir: &Path) -> Vec<String> {
    let graph = heides::indexer::build_graph(&dir).0;
    deadcode::dead_roots(&graph, &dir)
        .into_iter()
        .map(|r| r.name)
        .collect()
}

#[test]
fn a_django_style_handler_is_not_dead() {
    let dir = fixture("django");
    write(
        &dir,
        "app.py",
        "class Handler:\n    def handle_request(self, request):\n        return request\n\n    def dispatch_event(self, event):\n        return event\n",
    );
    let got = reported(&dir);
    assert!(
        !got.contains(&"handle_request".to_string()),
        "a handle_ method is dispatched by convention: {got:?}"
    );
    assert!(
        !got.contains(&"dispatch_event".to_string()),
        "a dispatch_ method is dispatched by convention: {got:?}"
    );
}

#[test]
fn a_celery_task_method_is_not_dead() {
    let dir = fixture("celery");
    write(
        &dir,
        "worker.py",
        "class Worker:\n    def task(self, payload):\n        return payload\n",
    );
    let got = reported(&dir);
    assert!(
        !got.contains(&"task".to_string()),
        "a method named task is a queue worker entrypoint: {got:?}"
    );
}

/// The exemption is python and method only, on purpose. A JS or Go function
/// called `get` really is usually dead, and exempting it everywhere would make
/// the signal useless in every language the scanner supports.
#[test]
fn the_convention_exemption_does_not_leak_to_other_languages() {
    let dir = fixture("leak");
    write(&dir, "lib.js", "function get_thing() { return 1; }\n");
    write(&dir, "svc.go", "package svc\n\nfunc get_thing() {}\n");
    let got = reported(&dir);
    assert!(
        got.contains(&"get_thing".to_string()),
        "a plain function named get_thing is dead, not a framework handler: {got:?}"
    );
}
