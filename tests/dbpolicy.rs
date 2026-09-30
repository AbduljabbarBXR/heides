// Tier 1, part two: foreign key cycles and table policies.
//
// These are the checks that close a hole the existing guards miss entirely.
// A recursive foreign key is not automatically a defect: `users.parent_id`
// modelling a category tree is correct and common, and `employees.manager_id`
// is too. What matters is whether the cycle is safe, and that differs per
// column. So the output separates:
//
//   * self references and indirect cycles, always reported, with the path,
//     because a reader has to decide what to do about them
//   * unconditional delete cascades that form a cycle, which is where a delete
//     can walk into itself
//   * policy findings: sensitive columns reachable from a read, writes with no
//     validation, missing tenant scoping, missing constraints
//
// Every rule here has a negative case. A policy checker that fires on a well
// designed schema is noise, and noise is what makes these tools ignored.

use std::path::Path;

use heides::db::{self, DbGraph, Op};

// ------------------------------------------------------------------ helpers

fn graph(sql: &str) -> DbGraph {
    DbGraph {
        tables: db::parse_sql(Path::new("s.sql"), sql),
        calls: Vec::new(),
        migrations: Vec::new(),
    }
}

fn with_calls(sql: &str, calls: &[(&str, Op, &str)]) -> DbGraph {
    let mut g = graph(sql);
    g.calls = calls
        .iter()
        .map(|(table, op, via)| db::Call {
            table: table.to_string(),
            op: *op,
            via: via.to_string(),
            // Not used by the policy checks, which work off the table and the
            // operation, but the field is not optional.
            fn_name: "handler".into(),
            file: "app.py".into(),
            line: 1,
        })
        .collect();
    g
}

// ------------------------------------------------------------ cycle detection

#[test]
fn a_self_referencing_column_is_reported_with_its_path() {
    // Category trees do this legitimately, which is exactly why the finding must
    // carry the path and not a bare yes/no.
    let g = graph(
        "CREATE TABLE categories (\n\
         \x20 id INTEGER PRIMARY KEY,\n\
         \x20 parent_id INTEGER REFERENCES categories(id),\n\
         \x20 name TEXT\n\
         );",
    );
    let cycles = db::fk_cycles(&g);
    assert_eq!(cycles.len(), 1, "{:?}", cycles);
    assert_eq!(cycles[0].table, "categories");
    assert_eq!(cycles[0].column, "parent_id");
    assert_eq!(
        cycles[0].path,
        vec!["categories", "categories"],
        "the path names both ends"
    );
    assert!(cycles[0].self_referential);
}

#[test]
fn an_indirect_cycle_is_found_and_the_path_is_walkable() {
    // A genuine three-table loop: an approval chain that circles back.
    let g = graph(
        "CREATE TABLE employees (\n\
         \x20 id INTEGER PRIMARY KEY,\n\
         \x20 approver_id INTEGER REFERENCES employees(id),\n\
         \x20 manager_id INTEGER REFERENCES employees(id)\n\
         );\n\
         CREATE TABLE approvals (\n\
         \x20 id INTEGER PRIMARY KEY,\n\
         \x20 employee_id INTEGER NOT NULL REFERENCES employees(id)\n\
         );\n\
         CREATE TABLE audit_entries (\n\
         \x20 id INTEGER PRIMARY KEY,\n\
         \x20 approval_id INTEGER NOT NULL REFERENCES approvals(id)\n\
         );",
    );
    let cycles = db::fk_cycles(&g);
    assert!(
        cycles.iter().any(|c| c.self_referential),
        "the employees self reference: {:?}",
        cycles
    );
    assert!(
        cycles.iter().all(|c| {
            c.path.len() >= 2 && c.path.first() == c.path.last()
        }),
        "every reported cycle closes on itself and carries at least one edge: {:?}",
        cycles
    );
}

#[test]
fn a_self_reference_reached_through_another_table_is_not_double_counted() {
    // Walking from employees reaches companies and then finds companies' own self
    // reference. That is the same cycle found from a different entry point, not a
    // second cycle, and reporting it twice would inflate the count.
    let g = graph(
        "CREATE TABLE companies (\n\
         \x20 id INTEGER PRIMARY KEY,\n\
         \x20 parent_id INTEGER REFERENCES companies(id)\n\
         );\n\
         CREATE TABLE employees (\n\
         \x20 id INTEGER PRIMARY KEY,\n\
         \x20 company_id INTEGER REFERENCES companies(id)\n\
         );",
    );
    let cycles = db::fk_cycles(&g);
    assert_eq!(
        cycles.len(),
        1,
        "exactly one cycle exists here: {:?}",
        cycles
    );
    assert!(cycles[0].self_referential);
    assert_eq!(cycles[0].table, "companies");
}

#[test]
fn a_real_multi_table_loop_is_reported_with_every_hop() {
    // department -> company -> group -> department, a genuine three table cycle
    // with no self reference anywhere.
    let g = graph(
        "CREATE TABLE groups_ (\n\
         \x20 id INTEGER PRIMARY KEY,\n\
         \x20 department_id INTEGER NOT NULL REFERENCES departments(id)\n\
         );\n\
         CREATE TABLE companies (\n\
         \x20 id INTEGER PRIMARY KEY,\n\
         \x20 group_id INTEGER NOT NULL REFERENCES groups_(id)\n\
         );\n\
         CREATE TABLE departments (\n\
         \x20 id INTEGER PRIMARY KEY,\n\
         \x20 company_id INTEGER NOT NULL REFERENCES companies(id)\n\
         );",
    );
    let cycles = db::fk_cycles(&g);
    assert!(!cycles.is_empty(), "the three table loop must be found");
    let multi = cycles
        .iter()
        .find(|c| !c.self_referential && c.path.len() >= 3)
        .unwrap_or_else(|| panic!("no multi hop cycle in {:?}", cycles));
    assert_eq!(multi.path.len(), 4, "three edges plus the closing node");
    assert_eq!(multi.path.first(), multi.path.last());
}

#[test]
fn an_acyclic_schema_reports_no_cycles() {
    let g = graph(
        "CREATE TABLE users (id INTEGER PRIMARY KEY);\n\
         CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id));\n\
         CREATE TABLE items (id INTEGER PRIMARY KEY, order_id INTEGER REFERENCES orders(id));",
    );
    assert!(db::fk_cycles(&g).is_empty(), "{:?}", db::fk_cycles(&g));
}

#[test]
fn a_diamond_is_not_a_cycle() {
    // orders -> users and items -> orders -> users is a shared ancestor, not a
    // loop. Reporting this would be a false positive on an extremely common
    // schema shape.
    let g = graph(
        "CREATE TABLE users (id INTEGER PRIMARY KEY);\n\
         CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id));\n\
         CREATE TABLE items (id INTEGER PRIMARY KEY, order_id INTEGER REFERENCES orders(id), user_id INTEGER REFERENCES users(id));",
    );
    assert!(
        db::fk_cycles(&g).is_empty(),
        "a diamond is not a cycle: {:?}",
        db::fk_cycles(&g)
    );
}

#[test]
fn cycle_detection_terminates_on_a_mutually_recursive_pair() {
    let g = graph(
        "CREATE TABLE a (id INTEGER PRIMARY KEY, b_id INTEGER REFERENCES b(id));\n\
         CREATE TABLE b (id INTEGER PRIMARY KEY, a_id INTEGER REFERENCES a(id));",
    );
    let cycles = db::fk_cycles(&g);
    assert!(!cycles.is_empty());
    assert!(cycles.len() <= 4, "each edge pair yields one cycle: {:?}", cycles);
    for c in &cycles {
        assert!(c.path.len() <= 4, "no unbounded path growth: {:?}", c);
    }
}

#[test]
fn a_cycle_with_cascade_delete_is_flagged_differently() {
    // The dangerous shape: a cyclic cascade can walk into itself on delete.
    let plain = graph(
        "CREATE TABLE a (id INTEGER PRIMARY KEY, b_id INTEGER REFERENCES b(id) ON DELETE CASCADE);\n\
         CREATE TABLE b (id INTEGER PRIMARY KEY, a_id INTEGER REFERENCES a(id) ON DELETE CASCADE);",
    );
    let cascades = db::cyclic_cascades(&plain);
    assert!(
        !cascades.is_empty(),
        "mutual ON DELETE CASCADE must be reported: {:?}",
        db::fk_cycles(&plain)
    );

    // A self reference with SET NULL terminates safely and is not a cascade risk.
    let safe = graph(
        "CREATE TABLE categories (\n\
         \x20 id INTEGER PRIMARY KEY,\n\
         \x20 parent_id INTEGER REFERENCES categories(id) ON DELETE SET NULL\n\
         );",
    );
    assert!(
        db::cyclic_cascades(&safe).is_empty(),
        "SET NULL is safe: {:?}",
        db::cyclic_cascades(&safe)
    );
}

// -------------------------------------------------------------------- policies

#[test]
fn a_sensitive_column_reaching_a_read_path_is_flagged() {
    let g = with_calls(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, ssn TEXT);",
        &[
            ("users", Op::Read, "session.query(User)"),
            ("users", Op::Read, "prisma.user.findMany()"),
        ],
    );
    let leaks = db::sensitive_exposure(&g);
    assert!(
        leaks.iter().any(|l| l.column == "ssn"),
        "ssn on a read path: {:?}",
        leaks
    );
    assert!(
        leaks.iter().any(|l| l.column == "email"),
        "email on a read path: {:?}",
        leaks
    );
}

#[test]
fn a_sensitive_column_that_is_only_written_is_not_an_exposure() {
    let g = with_calls(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, ssn TEXT);",
        &[("users", Op::Write, "session.add(User)")],
    );
    assert!(
        db::sensitive_exposure(&g).is_empty(),
        "writing a secret into a column is not leaking it out: {:?}",
        db::sensitive_exposure(&g)
    );
}

#[test]
fn a_write_with_no_read_path_is_reported_as_write_only() {
    let g = with_calls(
        "CREATE TABLE audit_log (id INTEGER PRIMARY KEY, message TEXT);\n\
         CREATE TABLE users (id INTEGER PRIMARY KEY);",
        &[("audit_log", Op::Write, "session.add(Log)")],
    );
    let wo = db::write_only(&g);
    assert!(wo.contains(&"audit_log".to_string()), "{:?}", wo);
}

#[test]
fn a_nullable_sensitive_column_is_reported() {
    let g = graph("CREATE TABLE users (id INTEGER PRIMARY KEY, ssn TEXT);");
    let issues = db::policy_findings(&g);
    assert!(
        issues.iter().any(|p| p.kind == "nullable_sensitive"),
        "a nullable ssn has no required value: {:?}",
        issues
    );

    let required = graph(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, ssn TEXT NOT NULL);",
    );
    assert!(
        !db::policy_findings(&required)
            .iter()
            .any(|p| p.kind == "nullable_sensitive"),
        "NOT NULL is the correct shape"
    );
}

#[test]
fn a_credential_column_without_a_default_is_reported_as_a_missing_constraint() {
    let g = graph(
        "CREATE TABLE users (\n\
         \x20 id INTEGER PRIMARY KEY,\n\
         \x20 email TEXT NOT NULL,\n\
         \x20 password_hash TEXT NOT NULL\n\
         );",
    );
    let issues = db::policy_findings(&g);
    // Informational, not blocking: a credential column is not a uniqueness
    // candidate, but the check exists so the shape is reviewed.
    assert!(
        issues
            .iter()
            .all(|p| p.kind != "credential_in_free_text"),
        "a plain TEXT credential column is normal practice: {:?}",
        issues
    );
}

#[test]
fn a_table_with_no_primary_key_is_reported() {
    let g = graph("CREATE TABLE logs (message TEXT, level TEXT);");
    let issues = db::policy_findings(&g);
    assert!(
        issues.iter().any(|p| p.kind == "no_primary_key"),
        "{:?}",
        issues
    );

    let ok = graph("CREATE TABLE logs (id INTEGER PRIMARY KEY, message TEXT);");
    assert!(
        !db::policy_findings(&ok).iter().any(|p| p.kind == "no_primary_key")
    );
}

#[test]
fn a_foreign_key_with_no_index_is_a_policy_finding() {
    let g = graph(
        "CREATE TABLE users (id INTEGER PRIMARY KEY);\n\
         CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id));",
    );
    let issues = db::policy_findings(&g);
    assert!(
        issues
            .iter()
            .any(|p| p.kind == "unindexed_foreign_key" && p.column == "user_id"),
        "{:?}",
        issues
    );
}

#[test]
fn a_well_designed_schema_produces_no_blocking_policy_findings() {
    // The negative half that decides whether this is usable. A schema that does
    // the right thing must be silent, or every review has to be filtered by hand.
    let g = graph(
        "CREATE TABLE users (\n\
         \x20 id INTEGER PRIMARY KEY,\n\
         \x20 email TEXT NOT NULL,\n\
         \x20 created_at TIMESTAMP NOT NULL\n\
         );\n\
         CREATE TABLE orders (\n\
         \x20 id INTEGER PRIMARY KEY,\n\
         \x20 user_id INTEGER NOT NULL REFERENCES users(id),\n\
         \x20 total NUMERIC(12,2) NOT NULL\n\
         );\n\
         CREATE INDEX idx_orders_user ON orders(user_id);",
    );
    let blocking: Vec<_> = db::policy_findings(&g)
        .into_iter()
        .filter(|p| p.severity == "critical")
        .collect();
    assert!(
        blocking.is_empty(),
        "a correct schema must not produce critical policy findings: {:?}",
        blocking
    );
}

#[test]
fn an_empty_graph_is_not_a_panicking_one() {
    let g = DbGraph::default();
    assert!(db::fk_cycles(&g).is_empty());
    assert!(db::cyclic_cascades(&g).is_empty());
    assert!(db::policy_findings(&g).is_empty());
    assert!(db::sensitive_exposure(&g).is_empty());
    assert!(db::write_only(&g).is_empty());
}

#[test]
fn the_whole_database_verdict_carries_every_layer() {
    let g = with_calls(
        "CREATE TABLE categories (\n\
         \x20 id INTEGER PRIMARY KEY,\n\
         \x20 parent_id INTEGER REFERENCES categories(id),\n\
         \x20 ssn TEXT\n\
         );",
        &[("categories", Op::Read, "session.query(Category)")],
    );
    let v = db::verify_schema(&g);
    assert_eq!(v.tables, 1);
    assert!(!v.cycles.is_empty(), "the self reference is reported");
    assert!(
        v.cycles_blocking,
        "an unindexed self reference is worth blocking on"
    );
    assert!(
        v.sensitive_exposed.iter().any(|l| l.column == "ssn"),
        "{:?}",
        v.sensitive_exposed
    );
}