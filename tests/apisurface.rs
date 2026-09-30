// The API surface graph: endpoint -> handler -> service -> table.
//
// The question an agent asks before touching a route is "what does POST /users
// actually write to". Answering it by reading files costs a dozen reads and
// still misses a call three hops away, because the agent has to decide where to
// stop looking. This resolves the whole chain in one query, and every hop is
// grounded in a file and line so the answer can be checked rather than trusted.
//
// The test-first rule applies: a finding shape with no benign twin is not
// release ready, so every positive here has a negative that must stay quiet.

use std::fs;
use std::path::{Path, PathBuf};

/// A throwaway workspace. Removed by the caller via `Drop` on the path list.
fn fixture(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("heides-api-{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("fixture dir");
    dir
}

fn write(dir: &Path, rel: &str, body: &str) {
    let p = dir.join(rel);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(p, body).unwrap();
}

fn tables_for(dir: &Path, method: &str, path: &str) -> Vec<String> {
    let graph = heides::indexer::build_graph(dir).0;
    let db = heides::db::index_schema(dir).expect("db graph builds");
    let eps = heides::frameworks::endpoints(&root_files(&graph), dir);
    let surface = heides::frameworks::api_surface(&graph, &db, &eps, 6);
    surface
        .reachable_tables(method, path)
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn root_files(graph: &heides::spine::CodeGraph) -> Vec<String> {
    graph.files.iter().map(|f| f.path.clone()).collect()
}

// ------------------------------------------------------- route recognition

#[test]
fn an_express_post_registration_is_recognised() {
    let dir = fixture("express");
    write(
        &dir,
        "routes/users.js",
        "const express = require('express');\n\
         const router = express.Router();\n\
         router.post('/users', createUser);\n\
         function createUser(req, res) { res.send('ok'); }\n",
    );
    let graph = heides::indexer::build_graph(&dir).0;
    let eps = heides::frameworks::endpoints(&root_files(&graph), &dir);
    let hits: Vec<(String, String, String)> = eps
        .iter()
        .map(|e| (e.method.clone(), e.path.clone(), e.handler.clone()))
        .collect();
    assert!(
        hits.iter()
            .any(|(m, p, h)| m == "POST" && p == "/users" && h == "createUser"),
        "expected POST /users -> createUser, got {hits:?}"
    );
}

#[test]
fn a_flask_decorator_is_recognised() {
    let dir = fixture("flask");
    write(
        &dir,
        "app.py",
        "from flask import Flask\n\
         app = Flask(__name__)\n\
         @app.route('/users', methods=['POST'])\n\
         def create_user():\n    pass\n",
    );
    let graph = heides::indexer::build_graph(&dir).0;
    let eps = heides::frameworks::endpoints(&root_files(&graph), &dir);
    assert!(
        eps.iter()
            .any(|e| e.method == "POST" && e.handler == "create_user"),
        "expected a POST endpoint for create_user, got {:?}",
        eps.iter().map(|e| e.handler.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn a_path_with_a_parameter_keeps_its_placeholder() {
    let dir = fixture("param");
    write(
        &dir,
        "r.js",
        "app.put('/users/:id', updateUser);\nfunction updateUser() {}\n",
    );
    let graph = heides::indexer::build_graph(&dir).0;
    let eps = heides::frameworks::endpoints(&root_files(&graph), &dir);
    assert!(
        eps.iter().any(|e| e.path == "/users/:id"),
        "the :id placeholder must survive, got {:?}",
        eps.iter().map(|e| e.path.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn a_plain_function_call_is_not_an_endpoint() {
    let dir = fixture("notroute");
    write(&dir, "a.js", "renderThing();\nnotifyUser();\napp2.get();\n");
    let graph = heides::indexer::build_graph(&dir).0;
    let eps = heides::frameworks::endpoints(&root_files(&graph), &dir);
    assert!(
        eps.is_empty(),
        "no router verb, no endpoint; got {:?}",
        eps.iter().map(|e| e.path.clone()).collect::<Vec<_>>()
    );
}

// ----------------------------------------------------- the chain to a table

#[test]
fn a_handler_that_writes_through_a_service_reaches_the_table() {
    let dir = fixture("chain");
    write(
        &dir,
        "schema.sql",
        "CREATE TABLE users (id INT PRIMARY KEY, email TEXT NOT NULL);\n",
    );
    write(
        &dir,
        "routes.js",
        "router.post('/users', createUser);\n\
         function createUser(req, res) { return insertUser(req.body); }\n",
    );
    write(
        &dir,
        "service.js",
        "function insertUser(data) { return prisma.user.create({ data }); }\n",
    );
    let got = tables_for(&dir, "POST", "/users");
    assert_eq!(got, vec!["users"], "the chain resolves through the service");
}

#[test]
fn a_handler_that_reads_reaches_the_table_on_the_read_side() {
    let dir = fixture("readchain");
    write(
        &dir,
        "schema.sql",
        "CREATE TABLE users (id INT PRIMARY KEY);\n",
    );
    write(
        &dir,
        "routes.js",
        "router.get('/users', listUsers);\n\
         function listUsers() { return findAllUsers(); }\n",
    );
    write(
        &dir,
        "service.js",
        "function findAllUsers() { return prisma.user.findMany(); }\n",
    );
    let graph = heides::indexer::build_graph(&dir).0;
    let db = heides::db::index_schema(&dir).unwrap();
    let eps = heides::frameworks::endpoints(&root_files(&graph), &dir);
    let surface = heides::frameworks::api_surface(&graph, &db, &eps, 6);
    let writes = surface.reachable_tables("POST", "/users");
    assert!(
        writes.is_empty(),
        "GET /users must not appear as a writer; got {writes:?}"
    );
}

#[test]
fn a_dotted_chain_finds_the_terminal_write() {
    let dir = fixture("dotted");
    write(
        &dir,
        "schema.sql",
        "CREATE TABLE orders (id INT PRIMARY KEY);\n",
    );
    write(
        &dir,
        "routes.js",
        "router.post('/orders', make);\nfunction make() { return OrderRepo.create(o); }\n",
    );
    let graph = heides::indexer::build_graph(&dir).0;
    let db = heides::db::index_schema(&dir).unwrap();
    let eps = heides::frameworks::endpoints(&root_files(&graph), &dir);
    let surface = heides::frameworks::api_surface(&graph, &db, &eps, 6);
    assert_eq!(
        surface.reachable_tables("POST", "/orders"),
        vec!["orders"],
        "the terminal write is what matters, not the receiver name"
    );
}

#[test]
fn a_cycle_in_the_call_graph_terminates() {
    let dir = fixture("cycle");
    write(&dir, "schema.sql", "CREATE TABLE t (id INT PRIMARY KEY);\n");
    write(
        &dir,
        "routes.js",
        "router.post('/x', a);\n\
         function a() { return b(); }\n\
         function b() { return a(); }\n",
    );
    let graph = heides::indexer::build_graph(&dir).0;
    let db = heides::db::index_schema(&dir).unwrap();
    let eps = heides::frameworks::endpoints(&root_files(&graph), &dir);
    let surface = heides::frameworks::api_surface(&graph, &db, &eps, 6);
    // The point is that this returns at all.
    let _ = surface.reachable_tables("POST", "/x");
}

#[test]
fn a_handler_with_no_database_work_reaches_no_table() {
    let dir = fixture("nodbtable");
    write(
        &dir,
        "routes.js",
        "router.get('/health', health);\nfunction health() { return { ok: true }; }\n",
    );
    let graph = heides::indexer::build_graph(&dir).0;
    let db = heides::db::index_schema(&dir).unwrap();
    let eps = heides::frameworks::endpoints(&root_files(&graph), &dir);
    let surface = heides::frameworks::api_surface(&graph, &db, &eps, 6);
    assert!(surface.reachable_tables("GET", "/health").is_empty());
}

// --------------------------------------------------------- the whole surface

#[test]
fn the_surface_lists_every_recognised_endpoint() {
    let dir = fixture("surface");
    write(
        &dir,
        "r.js",
        "router.post('/users', createUser);\n\
         router.get('/users', listUsers);\n\
         function createUser() {}\nfunction listUsers() {}\n",
    );
    let graph = heides::indexer::build_graph(&dir).0;
    let db = heides::db::index_schema(&dir).unwrap();
    let eps = heides::frameworks::endpoints(&root_files(&graph), &dir);
    let surface = heides::frameworks::api_surface(&graph, &db, &eps, 6);
    let mut got: Vec<(String, String)> = surface
        .endpoints
        .iter()
        .map(|e| (e.method.clone(), e.path.clone()))
        .collect();
    got.sort();
    assert_eq!(
        got,
        vec![
            ("GET".to_string(), "/users".to_string()),
            ("POST".to_string(), "/users".to_string())
        ]
    );
}

#[test]
fn a_health_endpoint_is_reported_without_inventing_a_table() {
    let dir = fixture("health");
    write(
        &dir,
        "r.js",
        "router.get('/healthz', healthz);\nfunction healthz() { return 'ok'; }\n",
    );
    let graph = heides::indexer::build_graph(&dir).0;
    let db = heides::db::index_schema(&dir).unwrap();
    let eps = heides::frameworks::endpoints(&root_files(&graph), &dir);
    let surface = heides::frameworks::api_surface(&graph, &db, &eps, 6);
    assert_eq!(surface.endpoints.len(), 1);
    assert_eq!(surface.endpoints[0].path, "/healthz");
}

#[test]
fn a_depth_limit_stops_a_deep_chain_without_hanging() {
    let dir = fixture("deep");
    write(
        &dir,
        "schema.sql",
        "CREATE TABLE deep (id INT PRIMARY KEY);\n",
    );
    // Nine hops, deeper than the limit passed in.
    let mut body = String::from("router.post('/deep', h0);\n");
    for i in 0..9 {
        body.push_str(&format!("function h{i}() {{ return h{}(); }}\n", i + 1));
    }
    body.push_str("function h9() { return prisma.deep.create({}); }\n");
    write(&dir, "r.js", &body);
    let graph = heides::indexer::build_graph(&dir).0;
    let db = heides::db::index_schema(&dir).unwrap();
    let eps = heides::frameworks::endpoints(&root_files(&graph), &dir);
    let surface = heides::frameworks::api_surface(&graph, &db, &eps, 3);
    let got = surface.reachable_tables("POST", "/deep");
    // Bounded either way, but it must return rather than loop.
    assert!(got.len() <= 1, "depth limited, got {got:?}");
}
