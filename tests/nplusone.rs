// N+1 candidate detection.
//
// The pattern: a query executed inside a loop. One query becomes N queries at
// runtime, which is the single most common performance defect in an ORM codebase
// and the one an agent is least likely to notice when reading a diff, because the
// loop looks harmless and the cost only shows up under load.
//
// Detection is syntactic and therefore approximate. It reports *candidates*, not
// proven defects, and it is bounded to the cases where the shape is unambiguous:
//
//   * a query call as the body of a for/while loop
//   * a query call inside a list or set comprehension that iterates a collection
//   * `await` over a sequence of ids where each iteration queries
//
// It deliberately does NOT fire on:
//   * a query in a loop over a literal range with no collection, since that is
//     often an intentional batch
//   * a batch query using `whereIn`, `IN (...)` or `bulk_create`, which is the
//     correct spelling
//   * a query outside any loop

use std::path::Path;

use heides::db;

#[test]
fn a_query_inside_a_for_loop_is_a_candidate() {
    let sql = "for u in users:\n    session.query(Order).filter(Order.user_id == u.id).all()\n";
    let found = db::n_plus_one_candidates(Path::new("app.py"), sql);
    assert_eq!(found.len(), 1, "{:?}", found);
    assert_eq!(found[0].table, "Order");
    assert!(found[0].line >= 1);
    assert!(
        found[0].reason.contains("loop"),
        "the reason must say why: {:?}",
        found[0]
    );
}

#[test]
fn a_query_inside_a_comprehension_is_a_candidate() {
    let sql = "rows = [session.query(Order).filter_by(user_id=u.id).all() for u in users]\n";
    let found = db::n_plus_one_candidates(Path::new("app.py"), sql);
    assert_eq!(found.len(), 1, "{:?}", found);
}

#[test]
fn an_await_inside_a_for_of_is_a_candidate() {
    let sql = "for const u of users {\n  const o = await prisma.order.findMany({ where: { userId: u.id } });\n}\n";
    let found = db::n_plus_one_candidates(Path::new("r.ts"), sql);
    assert_eq!(found.len(), 1, "{:?}", found);
    assert_eq!(found[0].table, "order");
}

#[test]
fn a_query_outside_any_loop_is_not_a_candidate() {
    let sql = "session.query(User).filter(User.active == True).all()\n";
    assert!(
        db::n_plus_one_candidates(Path::new("app.py"), sql).is_empty(),
        "a single query is not N+1"
    );
}

#[test]
fn a_bulk_query_is_not_a_candidate() {
    // The correct spelling of the same intent. Reporting it would make the tool
    // useless on well written code.
    for sql in [
        "session.query(Order).filter(Order.user_id.in_(ids)).all()\n",
        "db.Where(\"user_id IN (?)\", ids).Find(&orders)\n",
        "await prisma.order.findMany({ where: { userId: { in: ids } } });\n",
        "User.objects.filter(id__in=ids)\n",
    ] {
        assert!(
            db::n_plus_one_candidates(Path::new("app.py"), sql).is_empty(),
            "a bulk query is correct code: {:?}",
            sql
        );
    }
}

#[test]
fn a_bulk_create_is_not_a_candidate() {
    let sql = "for u in users:\n    User.objects.bulk_create([u])\n";
    assert!(
        db::n_plus_one_candidates(Path::new("app.py"), sql).is_empty(),
        "bulk_create is the batch spelling"
    );
}

#[test]
fn nested_loops_report_once_per_query_line() {
    let sql =
        "for a in as:\n  for b in bs:\n    session.query(Order).filter_by(a=a.id, b=b.id).all()\n";
    let found = db::n_plus_one_candidates(Path::new("app.py"), sql);
    assert_eq!(found.len(), 1, "one query line, one candidate: {:?}", found);
}

#[test]
fn a_query_before_and_inside_a_loop_reports_only_the_loop() {
    let sql = "total = session.query(Order).count()\nfor u in users:\n    session.query(Order).filter_by(user_id=u.id).all()\n";
    let found = db::n_plus_one_candidates(Path::new("app.py"), sql);
    assert_eq!(found.len(), 1, "{:?}", found);
    assert!(
        found[0].line >= 3,
        "the loop line, not the earlier one: {:?}",
        found
    );
}

#[test]
fn an_empty_loop_body_is_not_a_candidate() {
    assert!(db::n_plus_one_candidates(Path::new("m.py"), "for u in users:\n    pass\n").is_empty());
}

#[test]
fn a_loop_with_no_query_is_not_a_candidate() {
    let sql = "for u in users:\n    print(u.name)\n";
    assert!(db::n_plus_one_candidates(Path::new("m.py"), sql).is_empty());
}

#[test]
fn detection_never_panics_on_hostile_input() {
    let hostile: Vec<String> = vec![
        "for".to_string(),
        "for x in".to_string(),
        "for x in y:\n".to_string(),
        format!("for x in y:\n{}", "session.query(".repeat(500)),
        format!("{}{{", "for x in y:".repeat(2000)),
    ];
    for junk in &hostile {
        let _ = db::n_plus_one_candidates(Path::new("m.py"), junk);
    }
}

#[test]
fn the_candidate_carries_a_suggested_fix() {
    let sql = "for u in users:\n    session.query(Order).filter_by(user_id=u.id).all()\n";
    let found = db::n_plus_one_candidates(Path::new("app.py"), sql);
    assert!(
        found[0].suggestion.contains("in") || found[0].suggestion.contains("fetch"),
        "the fix must name the batch spelling: {:?}",
        found[0]
    );
}
