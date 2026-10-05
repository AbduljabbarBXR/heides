// An indirect foreign key cycle is not a self reference, and reporting it as
// one was a critical severity false claim.
//
// `walk_for_cycles` compared each edge's target against `start`, the table the
// walk began from, rather than against the table the edge is declared on. For
// `a.b_id -> b` and `b.a_id -> a` the walk from `a` returns to `a`, so every
// edge on the loop matched `start` and each was reported as "a self reference
// with no index" at critical severity. That schema contains no self reference
// anywhere.
//
// The two are different defects with different fixes. An unindexed self
// reference is a hierarchy walk scanning every level of a tree; an indirect
// cycle is usually a modelling error. Merging them hides one behind the other,
// and the self reference label then steals the severity a real one deserves.
//
// `tests/dbpolicy.rs` already covers genuine self references, multi-table loops
// and diamonds, so this file pins only the distinction the fix restored.

use std::path::Path;

use heides::db::{self, DbGraph};

fn graph(sql: &str) -> DbGraph {
    DbGraph {
        tables: db::parse_sql(Path::new("s.sql"), sql),
        calls: Vec::new(),
        migrations: Vec::new(),
    }
}

const INDIRECT_PAIR: &str = "CREATE TABLE a (id INTEGER PRIMARY KEY, b_id INTEGER REFERENCES b(id));\n\
     CREATE TABLE b (id INTEGER PRIMARY KEY, a_id INTEGER REFERENCES a(id));";

const INDIRECT_TRIPLE: &str = "CREATE TABLE a (id INTEGER PRIMARY KEY, b_id INTEGER REFERENCES b(id));\n\
     CREATE TABLE b (id INTEGER PRIMARY KEY, c_id INTEGER REFERENCES c(id));\n\
     CREATE TABLE c (id INTEGER PRIMARY KEY, a_id INTEGER REFERENCES a(id));";

const REAL_SELF_REF: &str = "CREATE TABLE employees (\n\
     \x20 id INTEGER PRIMARY KEY,\n\
     \x20 manager_id INTEGER REFERENCES employees(id)\n\
     );";

#[test]
fn an_indirect_two_table_cycle_is_not_called_a_self_reference() {
    let g = graph(INDIRECT_PAIR);
    let cycles = db::fk_cycles(&g);
    assert!(
        !cycles.is_empty(),
        "the schema really is cyclic, so a cycle must be reported: {:?}",
        cycles
    );
    for c in &cycles {
        assert!(
            !c.self_referential,
            "a -> b -> a is an indirect cycle, not a self reference, but {:?} claims otherwise",
            c
        );
    }
}

#[test]
fn an_indirect_three_table_cycle_is_not_called_a_self_reference() {
    let g = graph(INDIRECT_TRIPLE);
    let cycles = db::fk_cycles(&g);
    assert!(!cycles.is_empty(), "the loop must be found: {:?}", cycles);
    for c in &cycles {
        assert!(
            !c.self_referential,
            "a -> b -> c -> a is indirect, but {:?} claims a self reference",
            c
        );
    }
}

#[test]
fn a_genuine_self_reference_still_gets_its_own_finding() {
    // The fix must not disable the rule it corrected. A category tree or an
    // org chart is a legitimate self reference and keeps its own label.
    let g = graph(REAL_SELF_REF);
    let cycles = db::fk_cycles(&g);
    let self_refs: Vec<_> = cycles.iter().filter(|c| c.self_referential).collect();
    assert!(
        !self_refs.is_empty(),
        "a real self reference must still be reported, got {:?}",
        cycles
    );
    assert_eq!(self_refs[0].table, "employees");
    assert_eq!(self_refs[0].column, "manager_id");
}

#[test]
fn an_unindexed_indirect_cycle_earns_no_self_reference_finding() {
    // The policy layer is where the wrong label became a `critical`. With no
    // index on either referencing column, an indirect cycle must not produce an
    // "unindexed self reference".
    let g = graph(INDIRECT_PAIR);
    let findings = db::policy_findings(&g);
    let mislabelled: Vec<_> = findings
        .iter()
        .filter(|f| f.message.contains("self reference"))
        .collect();
    assert!(
        mislabelled.is_empty(),
        "an indirect cycle must not produce a self reference finding: {:?}",
        mislabelled
    );
}

#[test]
fn an_unindexed_real_self_reference_still_earns_its_critical() {
    let g = graph(REAL_SELF_REF);
    let findings = db::policy_findings(&g);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == "unindexed_self_reference" && f.severity == "critical"),
        "an unindexed self reference is still a full table scan per level: {:?}",
        findings
    );
}

#[test]
fn a_cascading_self_reference_is_still_in_the_cascade_subset() {
    // `ON DELETE CASCADE` on a self reference deletes a whole subtree in one
    // statement. That is the dangerous subset the cascade rule looks for, and
    // it must survive the fix.
    let g = graph(
        "CREATE TABLE employees (\n\
         \x20 id INTEGER PRIMARY KEY,\n\
         \x20 manager_id INTEGER REFERENCES employees(id) ON DELETE CASCADE\n\
         );",
    );
    let cascades = db::cyclic_cascades(&g);
    assert!(
        !cascades.is_empty(),
        "a cascading self reference must be in the cascade subset: {:?}",
        db::fk_cycles(&g)
    );
}

#[test]
fn a_diamond_is_still_not_a_cycle() {
    // Shared ancestor, no loop. Kept here because the fix touched the walk's
    // bookkeeping and a diamond is the case that would regress first.
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
fn a_chain_longer_than_the_depth_bound_terminates() {
    // The walk carries a visited set and a hard depth bound. This asserts it
    // returns at all on a chain far longer than either.
    let mut sql = String::new();
    for i in 0..40 {
        sql.push_str(&format!(
            "CREATE TABLE t{i} (id INTEGER PRIMARY KEY, next_id INTEGER REFERENCES t{}(id));\n",
            i + 1
        ));
    }
    sql.push_str("CREATE TABLE t40 (id INTEGER PRIMARY KEY);");
    let g = graph(&sql);
    let cycles = db::fk_cycles(&g);
    // A pure chain has no loop, so the correct answer is none. What matters is
    // that the call returns.
    assert!(cycles.is_empty(), "a chain is not a cycle: {:?}", cycles);
}
