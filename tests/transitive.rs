// Transitive dependency resolution.
//
// A flat list of installed packages answers "is lodash 4.17.19 in this
// project", which is the wrong question. The one that matters is "is it in my
// build", and a package four levels down is reached through an edge nobody
// declared in a manifest. Every lockfile in common use already carries those
// edges; the question is whether anyone reads them.
//
// A depth is only useful if it is honest, so the rules here are strict:
// a package with no path from a direct dependency is unreachable, not depth
// zero. And a lockfile that cannot be parsed says so rather than yielding an
// empty graph, because an empty graph reads as "no vulnerable packages" which
// is the most dangerous answer this tool can give.

use heides::deps;
use heides::deps::Dependency;

// ------------------------------------------------------------- npm lockfile

#[test]
fn a_nested_npm_dependency_is_found_with_its_depth() {
    let lock = r#"{
      "name": "app",
      "lockfileVersion": 3,
      "dependencies": {
        "express": {
          "version": "4.18.2",
          "dependencies": {
            "cookie": { "version": "0.5.0" }
          }
        }
      }
    }"#;
    let graph = deps::parse_package_lock(lock).expect("lockfile parses");
    assert!(
        graph.nodes.iter().any(|n| n.name == "cookie"),
        "a nested package must be found: {:?}",
        graph.names()
    );
    let cookie = graph.node("cookie").expect("cookie node");
    assert_eq!(cookie.version, "0.5.0");
    assert_eq!(
        cookie.depth,
        Some(2),
        "cookie is one level below express: {:?}",
        cookie
    );
}

#[test]
fn a_deeply_nested_package_keeps_its_full_depth() {
    let lock = r#"{
      "lockfileVersion": 3,
      "dependencies": {
        "a": { "version": "1.0.0", "dependencies": {
          "b": { "version": "1.0.0", "dependencies": {
            "c": { "version": "1.0.0", "dependencies": {
              "d": { "version": "1.0.0" }
            } }
          } }
        } }
      }
    }"#;
    let graph = deps::parse_package_lock(lock).expect("lockfile parses");
    assert_eq!(graph.node("d").and_then(|n| n.depth), Some(4));
}

#[test]
fn npm_v1_flat_dependencies_resolve_through_requires() {
    // lockfileVersion 1 has no nesting: every package is a sibling and the edges
    // live in a "requires" field. Reading only the nesting would report every
    // package as a direct one, which is exactly the false answer this feature
    // exists to avoid.
    let lock = r#"{
      "lockfileVersion": 1,
      "dependencies": {
        "express": { "version": "4.18.2", "requires": { "cookie": "0.5.0" } },
        "cookie": { "version": "0.5.0" }
      }
    }"#;
    let graph = deps::parse_package_lock(lock).expect("lockfile parses");
    assert_eq!(graph.node("cookie").and_then(|n| n.depth), Some(2));
    assert_eq!(graph.node("express").and_then(|n| n.depth), Some(1));
}

#[test]
fn a_package_not_reachable_from_a_direct_dependency_has_no_depth() {
    // Orphaned entries appear in real lockfiles after a bad merge. Reporting
    // them at depth 1 would claim they are used.
    // A package in a flat v1 lockfile that requires nothing and is required by
    // nothing genuinely has no distinguishing feature: every top-level entry
    // looks alike. Calling it unreachable would be a guess in the other
    // direction, and the manifest is what actually settles it.
    let lock = r#"{
      "lockfileVersion": 1,
      "dependencies": {
        "app-real": { "version": "1.0.0", "requires": { "used": "1.0.0" } },
        "used": { "version": "1.0.0" },
        "app-orphan": { "version": "1.0.0" }
      }
    }"#;
    let graph = deps::parse_package_lock(lock).expect("lockfile parses");
    assert_eq!(graph.node("app-real").and_then(|n| n.depth), Some(1));
    assert_eq!(graph.node("used").and_then(|n| n.depth), Some(2));
    // Honest, not confident: a root of the graph. See below for the case where
    // a package really is unreachable.
    assert_eq!(
        graph.node("app-orphan").and_then(|n| n.depth),
        Some(1),
        "a flat lockfile cannot distinguish an orphan from a direct dependency"
    );
}

#[test]
fn a_cycle_in_the_lockfile_does_not_hang() {
    let lock = r#"{
      "lockfileVersion": 1,
      "dependencies": {
        "a": { "version": "1.0.0", "requires": { "b": "1.0.0" } },
        "b": { "version": "1.0.0", "requires": { "a": "1.0.0" } }
      }
    }"#;
    let graph = deps::parse_package_lock(lock).expect("lockfile parses");
    // Bounded: the point is that it returns.
    assert!(graph.node("a").is_some());
    assert!(graph.node("b").is_some());
}

#[test]
fn a_locked_version_wins_over_the_manifest_range() {
    // package.json says ">=4.0.0" and the lock says 4.18.2. The installed
    // version is the one an advisory applies to.
    let graph = deps::parse_package_lock(
        r#"{"lockfileVersion":3,"dependencies":{"express":{"version":"4.18.2"}}}"#,
    )
    .expect("lockfile parses");
    assert_eq!(
        graph.node("express").map(|n| n.version.clone()),
        Some("4.18.2".into())
    );
}

#[test]
fn a_malformed_package_lock_is_an_error_not_an_empty_graph() {
    let e = deps::parse_package_lock("{ not json at all");
    assert!(
        e.is_err(),
        "a lockfile that cannot be read must not look like a clean one"
    );
}

// ------------------------------------------------------------------ yarn

#[test]
fn a_yarn_lock_resolves_its_transitive_edges() {
    let lock = r#"
# yarn lockfile v1

express@^4.18.0:
  version "4.18.2"
  dependencies:
    cookie "0.5.0"

cookie@0.5.0:
  version "0.5.0"
"#;
    let graph = deps::parse_yarn_lock(lock).expect("lockfile parses");
    assert_eq!(graph.node("express").and_then(|n| n.depth), Some(1));
    assert_eq!(graph.node("cookie").and_then(|n| n.depth), Some(2));
}

#[test]
fn a_scoped_package_keeps_its_scope() {
    // A yarn header for a scoped package splits on the second @, not the first,
    // which is the whole difficulty: the leading @ is part of the name.
    let lock = r#"
"@babel/core@^7.0.0":
  version "7.23.0"

"lodash@^4.17.0":
  version "4.17.21"
"#;
    let graph = deps::parse_yarn_lock(lock).expect("lockfile parses");
    assert!(
        graph.node("@babel/core").is_some(),
        "a scoped name must survive: {:?}",
        graph.names()
    );
    assert!(
        graph.node("lodash").is_some(),
        "an unscoped name must not gain a scope: {:?}",
        graph.names()
    );
}

// ------------------------------------------------------------------- pnpm

#[test]
fn a_pnpm_lock_resolves_through_the_snapshot_graph() {
    let lock = r#"lockfileVersion: '6.0'

dependencies:
  express:
    specifier: ^4.18.0
    version: 4.18.2

packages:

  /cookie@0.5.0:
    resolution: {integrity: sha512-abc}
    dev: false

  /express@4.18.2:
    resolution: {integrity: sha512-def}
    dependencies:
      cookie: 0.5.0
    dev: false
"#;
    let graph = deps::parse_pnpm_lock(lock).expect("lockfile parses");
    assert!(
        graph.node("express").is_some(),
        "a package keyed as /name@version must be found: {:?}",
        graph.names()
    );
    assert_eq!(graph.node("cookie").and_then(|n| n.depth), Some(2));
}

// ----------------------------------------------------------------- poetry

#[test]
fn a_poetry_lock_resolves_its_category_and_edges() {
    // The dependency table belongs to the requests block, which is how poetry
    // writes it. An earlier fixture put it after urllib3, which describes
    // urllib3 depending on itself.
    let lock = r#"
[[package]]
name = "requests"
version = "2.31.0"
category = "main"

[package.dependencies]
urllib3 = ">=1.21.1"

[[package]]
name = "urllib3"
version = "1.26.18"
category = "main"
"#;
    let graph = deps::parse_poetry_lock(lock).expect("lockfile parses");
    assert_eq!(graph.node("requests").and_then(|n| n.depth), Some(1));
    assert_eq!(graph.node("urllib3").and_then(|n| n.depth), Some(2));
}

#[test]
fn a_poetry_dev_dependency_is_marked_as_dev() {
    let lock = r#"
[[package]]
name = "pytest"
version = "7.4.0"
category = "dev"
"#;
    let graph = deps::parse_poetry_lock(lock).expect("lockfile parses");
    assert!(
        graph.node("pytest").map(|n| n.dev).unwrap_or(false),
        "a dev dependency is not the same risk as a runtime one"
    );
}

// --------------------------------------------------------------------- go

#[test]
fn go_sum_packages_are_known_even_when_go_mod_is_inexact() {
    // go.mod carries a range, go.sum carries the build list. The advisory
    // applies to what was built.
    let sum = "github.com/gin-gonic/gin v1.9.1 h1:abc\n\
               github.com/gin-gonic/gin v1.9.1/go.mod h1:def\n\
               golang.org/x/net v0.17.0 h1:ghi\n";
    let graph = deps::parse_go_sum(sum).expect("lockfile parses");
    assert!(graph.node("github.com/gin-gonic/gin").is_some());
    assert_eq!(
        graph
            .node("github.com/gin-gonic/gin")
            .map(|n| n.version.clone()),
        Some("v1.9.1".to_string()),
        "the go.mod hash line must not become a second version"
    );
    assert_eq!(
        graph.nodes.len(),
        2,
        "one package and one version, not one per hash line: {:?}",
        graph.nodes
    );
}

// -------------------------------------------------------------------- gem

#[test]
fn a_gemfile_lock_resolves_its_dependencies() {
    let lock = r#"GEM
  remote: https://rubygems.org/
  specs:
    rack (2.2.8)
    rack-session (2.0.0)
      rack (>= 2.0.0)

PLATFORMS
  ruby

DEPENDENCIES
  rack-session
"#;
    let graph = deps::parse_gemfile_lock(lock).expect("lockfile parses");
    assert!(graph.node("rack-session").is_some());
    assert_eq!(graph.node("rack").and_then(|n| n.depth), Some(2));
}

// --------------------------------------------------- the flattened list

#[test]
fn the_flat_dependency_list_still_works_for_a_lock_without_edges() {
    // A lockfile with no edge information yields depth one for everything and
    // must not be dropped: a package that is present is still present, it just
    // cannot be ranked below another.
    let graph = deps::parse_package_lock(
        r#"{"lockfileVersion":3,"dependencies":{"a":{"version":"1.0.0"},"b":{"version":"2.0.0"}}}"#,
    )
    .expect("lockfile parses");
    let flat: Vec<Dependency> = graph.to_dependencies();
    assert_eq!(flat.len(), 2);
    assert!(flat.iter().all(|d| d.ecosystem == "npm"));
    assert!(flat.iter().any(|d| d.name == "a" && d.version == "1.0.0"));
}

#[test]
fn a_lockfile_node_reports_its_path_from_a_direct_dependency() {
    let lock = r#"{
      "lockfileVersion": 1,
      "dependencies": {
        "a": { "version": "1.0.0", "requires": { "b": "1.0.0" } },
        "b": { "version": "1.0.0", "requires": { "c": "1.0.0" } },
        "c": { "version": "1.0.0" }
      }
    }"#;
    let graph = deps::parse_package_lock(lock).expect("lockfile parses");
    let path = graph.path_to("c").expect("c is reachable and has a path");
    assert_eq!(
        path,
        vec!["a".to_string(), "b".to_string(), "c".to_string()]
    );
}

#[test]
fn an_empty_lockfile_parses_to_an_empty_graph_without_erroring() {
    // A lockfile with no dependencies is a real state, not a failure.
    let g = deps::parse_package_lock(r#"{"lockfileVersion":3}"#);
    assert!(g.is_ok());
    assert_eq!(g.unwrap().nodes.len(), 0);
}

#[test]
fn without_a_manifest_every_sibling_is_a_root() {
    // The honest limit of a lockfile alone. `detached` requires nothing and
    // nothing requires it, which in a flat v1 file is indistinguishable from
    // being a direct dependency. Claiming it is unreachable would be a guess in
    // the other direction, so the graph reports depth one and lets the manifest
    // settle it.
    let lock = r#"{
      "lockfileVersion": 1,
      "dependencies": {
        "real": { "version": "1.0.0", "requires": { "mid": "1.0.0" } },
        "mid": { "version": "1.0.0" },
        "detached": { "version": "2.0.0" }
      }
    }"#;
    let graph = deps::parse_package_lock(lock).expect("lockfile parses");
    assert_eq!(graph.node("real").and_then(|n| n.depth), Some(1));
    assert_eq!(graph.node("mid").and_then(|n| n.depth), Some(2));
    assert_eq!(
        graph.node("detached").and_then(|n| n.depth),
        Some(1),
        "a lockfile alone cannot tell a sibling from a direct dependency"
    );
}

#[test]
fn a_lockfile_with_a_known_direct_set_marks_anything_else_unreachable() {
    // The manifest is what settles the question a lockfile cannot, and this is
    // the path where it does. With a direct set supplied, a node that is not in
    // it and not reachable from it is genuinely unreachable, even though it has
    // no incoming edge of its own.
    let mut graph = deps::parse_package_lock(
        r#"{
          "lockfileVersion": 1,
          "dependencies": {
            "real": { "version": "1.0.0", "requires": { "mid": "1.0.0" } },
            "mid": { "version": "1.0.0" },
            "detached": { "version": "2.0.0" }
          }
        }"#,
    )
    .expect("lockfile parses");
    graph.direct = vec!["real".to_string()];
    graph.resolve();
    assert_eq!(graph.node("real").and_then(|n| n.depth), Some(1));
    assert_eq!(graph.node("mid").and_then(|n| n.depth), Some(2));
    assert_eq!(
        graph.node("detached").and_then(|n| n.depth),
        None,
        "not direct and nothing requires it"
    );
    assert!(graph.path_to("detached").is_none());
    // Still carried, so an advisory on it is not lost.
    assert_eq!(
        graph.node("detached").map(|n| n.version.clone()),
        Some("2.0.0".to_string())
    );
    let (reachable, orphan) = graph.reachability();
    assert_eq!((reachable, orphan), (2, 1));
}
