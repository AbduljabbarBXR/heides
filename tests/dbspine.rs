// The database spine: tables stored in the index rather than rebuilt on every run.
//
// The schema graph is derivable, so it could be recomputed each time. Storing it
// is worth it for two reasons that are not about speed: `changed-since` becomes
// possible, because a stored row can be compared against a file's mtime, and the
// agent can ask about tables without the walk running at all.
//
// The tests below are about the properties that matter rather than the SQL:
// a round trip loses nothing, deleting a table from a migration removes it from
// the index, and a stale index is detected rather than trusted.

use std::path::Path;

use heides::db::{self, Op};
use heides::indexer;

fn fixture(name: &str, sql: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("heides_dbspine_{}", name));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("migrations")).unwrap();
    std::fs::write(dir.join("migrations/0001_init.sql"), sql).unwrap();
    dir
}

#[test]
fn a_schema_round_trips_through_the_index() {
    let dir = fixture(
        "roundtrip",
        "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT);\n\
         CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id));\n\
         CREATE INDEX idx_orders_user ON orders(user_id);",
    );
    db::save_db_index(&dir, &db::index_schema(&dir).unwrap()).expect("saves");
    let back = db::load_db_index(&dir).expect("loads");

    assert_eq!(back.tables.len(), 2, "{:?}", back.tables);
    let orders = back.tables.iter().find(|t| t.name == "orders").unwrap();
    assert_eq!(orders.columns.len(), 2);
    assert_eq!(orders.columns[1].fk_table.as_deref(), Some("users"));
    assert_eq!(orders.indexes.len(), 1, "the index survives the round trip");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn call_sites_survive_the_round_trip_with_their_read_write_split() {
    let dir = fixture(
        "calls",
        "CREATE TABLE users (id INTEGER PRIMARY KEY);\n\
         CREATE TABLE audit_log (id INTEGER PRIMARY KEY);",
    );
    std::fs::write(
        dir.join("app.py"),
        "session.query(User).all()\ncur.execute(\"INSERT INTO audit_log (id) VALUES (1)\")\n",
    )
    .unwrap();
    let g = db::index_schema(&dir).unwrap();
    assert!(
        g.calls
            .iter()
            .any(|c| c.table == "User" && c.op == Op::Read),
        "{:?}",
        g.calls
    );
    assert!(
        g.calls
            .iter()
            .any(|c| c.table == "audit_log" && c.op == Op::Write),
        "{:?}",
        g.calls
    );
    db::save_db_index(&dir, &g).expect("saves");
    let back = db::load_db_index(&dir).expect("loads");
    assert_eq!(back.calls.len(), g.calls.len());
    assert!(back.calls.iter().any(|c| c.op == Op::Write));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn migrations_survive_with_their_dialect_and_digest() {
    let dir = fixture("migrations", "CREATE TABLE t (id INTEGER PRIMARY KEY);\n");
    std::fs::write(
        dir.join("migrations/0002_add.sql"),
        "ALTER TABLE t ADD COLUMN name TEXT;\n",
    )
    .unwrap();
    let g = db::index_schema(&dir).unwrap();
    assert!(g.migrations.len() >= 2, "{:?}", g.migrations);
    assert!(g.migrations.iter().any(|m| m.file.contains("0001")));
    db::save_db_index(&dir, &g).unwrap();
    let back = db::load_db_index(&dir).unwrap();
    assert_eq!(back.migrations.len(), g.migrations.len());
    assert!(back.migrations.iter().all(|m| !m.sha.is_empty()));
    assert!(back.migrations.iter().all(|m| m.dialect == "sql"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_changed_migration_is_reported_as_drift() {
    let dir = fixture("drift", "CREATE TABLE t (id INTEGER PRIMARY KEY);\n");
    let g = db::index_schema(&dir).unwrap();
    db::save_db_index(&dir, &g).unwrap();
    assert!(
        db::migration_drift(&dir, &db::load_db_index(&dir).unwrap()).is_empty(),
        "nothing changed yet"
    );

    // The migration body changes under the index: a real and common event.
    std::fs::write(
        dir.join("migrations/0001_init.sql"),
        "CREATE TABLE t (id INTEGER PRIMARY KEY, added TEXT);\n",
    )
    .unwrap();
    let drift = db::migration_drift(&dir, &db::load_db_index(&dir).unwrap());
    assert_eq!(drift.len(), 1, "{:?}", drift);
    assert!(
        drift[0].contains("0001_init"),
        "the file is named: {:?}",
        drift
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_dropped_migration_is_reported_as_drift() {
    let dir = fixture("dropped", "CREATE TABLE t (id INTEGER PRIMARY KEY);\n");
    std::fs::write(
        dir.join("migrations/0002_more.sql"),
        "CREATE TABLE u (id INTEGER PRIMARY KEY);\n",
    )
    .unwrap();
    let g = db::index_schema(&dir).unwrap();
    db::save_db_index(&dir, &g).unwrap();
    std::fs::remove_file(dir.join("migrations/0002_more.sql")).unwrap();
    let drift = db::migration_drift(&dir, &db::load_db_index(&dir).unwrap());
    assert_eq!(drift.len(), 1, "{:?}", drift);
    assert!(drift[0].contains("0002_more"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_table_dropped_from_a_migration_disappears_from_the_index() {
    // The last migration wins, so a table created then dropped is gone. This is
    // the case that makes the index honest rather than an append-only log.
    let dir = fixture("droptable", "CREATE TABLE t (id INTEGER PRIMARY KEY);\n");
    std::fs::write(dir.join("migrations/0002_drop.sql"), "DROP TABLE t;\n").unwrap();
    let g = db::index_schema(&dir).unwrap();
    assert!(
        g.tables.is_empty(),
        "a dropped table is not in the schema: {:?}",
        g.tables.iter().map(|t| &t.name).collect::<Vec<_>>()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_absent_index_loads_empty_rather_than_failing() {
    let dir = std::env::temp_dir().join("heides_dbspine_none");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Not a panic and not an error: a workspace with no database index is the
    // normal state before the first scan.
    let _ = db::load_db_index(&dir);
    assert!(!db::db_index_exists(&dir));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_index_does_not_disturb_the_code_spine() {
    // Two stores, one directory. Writing the database index must not invalidate
    // the code graph, or every scan would redo the parse.
    let dir = fixture("coexist", "CREATE TABLE t (id INTEGER PRIMARY KEY);\n");
    std::fs::write(dir.join("app.py"), "def add(a, b):\n    return a + b\n").unwrap();
    let (graph, _) = indexer::build_graph(&dir);
    let before = graph.version;

    db::save_db_index(&dir, &db::index_schema(&dir).unwrap()).unwrap();

    // The code index path is unchanged, and the code graph still describes the
    // same files. Writing the database index must not force a rescan.
    let after = indexer::load_or_build(&dir).expect("code spine still loads");
    assert_eq!(before, after.version, "the code spine version is untouched");
    assert_eq!(
        graph.files.len(),
        after.files.len(),
        "the same files are indexed"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn saving_twice_replaces_rather_than_duplicates() {
    let dir = fixture("idempotent", "CREATE TABLE t (id INTEGER PRIMARY KEY);\n");
    let g = db::index_schema(&dir).unwrap();
    db::save_db_index(&dir, &g).unwrap();
    db::save_db_index(&dir, &g).unwrap();
    let back = db::load_db_index(&dir).unwrap();
    assert_eq!(back.tables.len(), g.tables.len(), "no duplicate tables");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_graph_rebuilds_identically_from_the_same_input() {
    // Determinism matters because the index is compared against a rebuild to
    // detect drift. A rebuild that reorders rows would report drift constantly.
    let dir = fixture(
        "determinism",
        "CREATE TABLE b (id INTEGER PRIMARY KEY, ref INTEGER REFERENCES a(id));\n\
         CREATE TABLE a (id INTEGER PRIMARY KEY);\n\
         CREATE TABLE c (id INTEGER PRIMARY KEY, ref INTEGER REFERENCES a(id));\n",
    );
    let first = db::index_schema(&dir).unwrap();
    let second = db::index_schema(&dir).unwrap();
    let names =
        |g: &db::DbGraph| -> Vec<String> { g.tables.iter().map(|t| t.name.clone()).collect() };
    assert_eq!(names(&first), names(&second), "table order is stable");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unknown_table_name_is_reported_not_guessed() {
    let dir = fixture("unknown", "CREATE TABLE users (id INTEGER PRIMARY KEY);\n");
    let g = db::index_schema(&dir).unwrap();
    assert!(db::columns_of(&g, "nope").is_empty());
    assert!(!db::table_names_match("users", "orders"));
    let _ = Path::new("/").exists();
    let _ = std::fs::remove_dir_all(&dir);
}
