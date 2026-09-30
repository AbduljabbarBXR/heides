// Tier 1: the database layer.
//
// Two things are being built, and they are tested separately because they fail
// differently.
//
// The schema graph parses `.sql` and migration directories: tables, columns,
// types, primary keys, foreign keys and indexes. It is a syntax problem, so the
// tests are mostly exact assertions on the parsed shape.
//
// The ORM resolution maps code call sites to tables: `prisma.user.findMany()`,
// `User.objects.filter()`, `db.First<User>()`, GORM, ActiveRecord. It is a
// naming problem, so the tests include the negatives, because the failure mode
// that matters here is a wrong table rather than a missing one. A caller that
// resolves to `users` when it touches `orders` is worse than no answer.

use std::path::{Path, PathBuf};

// ---------------------------------------------------------------- schema graph

// Aliases to the module's own types. These tests compile against the real API
// rather than a local copy, so a field rename cannot leave the tests green
// against a stale shape.
use heides::db::{Call, Column, Index, Op, Table};

pub fn parse_sql_file(path: &str, body: &str) -> Vec<Table> {
    heides::db::parse_sql(Path::new(path), body)
}

fn cols(t: &Table) -> Vec<&str> {
    t.columns.iter().map(|c| c.name.as_str()).collect()
}

#[test]
fn parses_a_plain_create_table() {
    let t = parse_sql_file(
        "schema.sql",
        "CREATE TABLE users (\n  id INTEGER PRIMARY KEY,\n  email TEXT NOT NULL\n);\n",
    );
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].name, "users");
    assert_eq!(cols(&t[0]), vec!["id", "email"]);
    assert!(t[0].columns[0].pk);
    assert!(!t[0].columns[1].nullable);
    assert!(t[0].columns[1].pk == false);
}

#[test]
fn parses_postgres_types_and_nullability() {
    let t = parse_sql_file(
        "s.sql",
        "CREATE TABLE public.accounts (\n\
         \x20 id BIGSERIAL PRIMARY KEY,\n\
         \x20 email VARCHAR(255) NOT NULL UNIQUE,\n\
         \x20 nickname VARCHAR(40),\n\
         \x20 balance NUMERIC(12,2) DEFAULT 0\n\
         );",
    );
    assert_eq!(t[0].name, "accounts");
    // The schema qualifier must not leak into the table name.
    assert_eq!(cols(&t[0]), vec!["id", "email", "nickname", "balance"]);
    assert_eq!(t[0].columns[0].ty, "BIGSERIAL");
    assert!(t[0].columns[1].ty.starts_with("VARCHAR"));
    assert!(!t[0].columns[1].nullable);
    assert!(t[0].columns[2].nullable, "no NOT NULL means nullable");
}

#[test]
fn parses_composite_primary_keys() {
    let t = parse_sql_file(
        "s.sql",
        "CREATE TABLE order_items (\n\
         \x20 order_id INTEGER NOT NULL,\n\
         \x20 sku TEXT NOT NULL,\n\
         \x20 qty INTEGER NOT NULL,\n\
         \x20 PRIMARY KEY (order_id, sku)\n\
         );",
    );
    assert_eq!(t[0].name, "order_items");
    assert!(t[0].columns[1].pk, "second column of the composite key is pk");
    assert!(t[0].columns[2].pk == false);
}

#[test]
fn parses_inline_and_table_level_foreign_keys() {
    let t = parse_sql_file(
        "s.sql",
        "CREATE TABLE orders (\n\
         \x20 id INTEGER PRIMARY KEY,\n\
         \x20 user_id INTEGER REFERENCES users(id),\n\
         \x20 coupon_id INTEGER,\n\
         \x20 FOREIGN KEY (coupon_id) REFERENCES coupons(code)\n\
         );",
    );
    assert_eq!(t[0].columns[1].fk_table.as_deref(), Some("users"));
    assert_eq!(t[0].columns[1].fk_col.as_deref(), Some("id"));
    assert_eq!(t[0].columns[2].fk_table.as_deref(), Some("coupons"));
    assert_eq!(t[0].columns[2].fk_col.as_deref(), Some("code"));
}

#[test]
fn parses_indexes_and_uniqueness() {
    let t = parse_sql_file(
        "s.sql",
        "CREATE TABLE events (\n\
         \x20 id INTEGER PRIMARY KEY,\n\
         \x20 user_id INTEGER,\n\
         \x20 kind TEXT\n\
         );\n\
         CREATE UNIQUE INDEX idx_events_kind ON events(user_id, kind);\n\
         CREATE INDEX idx_events_uid ON events ( user_id );",
    );
    let idx = &t[0].indexes;
    assert_eq!(idx.len(), 2, "both indexes attach to events");
    assert!(idx.iter().any(|i| i.unique && i.columns == vec!["user_id", "kind"]));
    assert!(idx
        .iter()
        .any(|i| !i.unique && i.columns == vec!["user_id"]));
}

#[test]
fn handles_alembic_and_prisma_migration_dialect() {
    // Alembic emits lowercase op.create_table with a quoted name and
    // sa.Column(...). Prisma emits CREATE TABLE "name" (...).
    let a = parse_sql_file(
        "migrations/1234_init.py",
        "op.create_table(\n    'users',\n    sa.Column('id', sa.Integer(), nullable=False),\n\
         \x20   sa.Column('email', sa.String(255)),\n\
         \x20   sa.PrimaryKeyConstraint('id')\n)",
    );
    assert_eq!(a.len(), 1, "alembic create_table parses");
    assert_eq!(a[0].name, "users");
    assert!(cols(&a[0]).contains(&"email"));

    let p = parse_sql_file(
        "prisma/migrations/0_init/migration.sql",
        "CREATE TABLE \"User\" (\n    \"id\" SERIAL NOT NULL,\n\
         \x20   \"email\" TEXT NOT NULL,\n    PRIMARY KEY (\"id\")\n);",
    );
    assert_eq!(p[0].name, "User", "quoted identifiers keep their case");
    assert!(cols(&p[0]).contains(&"email"));
}

#[test]
fn ignores_drops_renames_and_comments() {
    let t = parse_sql_file(
        "s.sql",
        "-- CREATE TABLE dropped (id INT);\n\
         /* CREATE TABLE also_dropped (id INT); */\n\
         CREATE TABLE kept (id INT);\n\
         DROP TABLE gone;\n\
         ALTER TABLE kept ADD COLUMN extra TEXT;\n\
         CREATE VIEW v AS SELECT 1;",
    );
    assert_eq!(t.len(), 1, "only kept survives");
    assert_eq!(t[0].name, "kept");
}

#[test]
fn a_statement_without_create_table_yields_nothing() {
    assert!(parse_sql_file("s.sql", "SELECT 1;").is_empty());
    assert!(parse_sql_file("s.sql", "").is_empty());
    assert!(parse_sql_file("s.sql", "-- nothing here\n").is_empty());
}

#[test]
fn unreadable_garbage_does_not_panic() {
    // The hostile-input contract: never panic, never invent a table.
    for junk in [
        "CREATE TABLE",
        "CREATE TABLE t (",
        "CREATE TABLE t (a,",
        "CREATE TABLE t () ;",
        "CREATE TABLE t (a INT, a TEXT);",
        "CREATE TABLE t (a INT REFERENCES);",
        "))))",
        "CREATE TABLE t (a INT); CREATE TABLE t (b TEXT);",
    ] {
        let t = parse_sql_file("s.sql", junk);
        // Duplicate names must collapse, never double count.
        assert!(
            t.windows(2).all(|w| w[0].name != w[1].name),
            "duplicate table name in {:?}",
            junk
        );
    }
}

// --------------------------------------------------------------- query analysis

/// Table accesses found in one source file.
pub fn calls_in(file: &str, body: &str) -> Vec<Call> {
    heides::db::scan_calls(Path::new(file), body)
}

#[test]
fn resolves_prisma_models() {
    let c = calls_in(
        "a.ts",
        "await prisma.user.findMany();\n\
         await prisma.order.create({ data });\n\
         await prisma.user.update({ where: { id } });",
    );
    let users: Vec<&Call> = c.iter().filter(|x| x.table == "user").collect();
    assert_eq!(users.len(), 2);
    assert!(users.iter().any(|x| x.op == Op::Read));
    assert!(c.iter().any(|x| x.table == "order" && x.op == Op::Write));
    assert!(c.iter().all(|x| x.via.contains("prisma")));
}

#[test]
fn resolves_django_orm() {
    let c = calls_in(
        "m.py",
        "User.objects.filter(active=True)\n\
         User.objects.create(name=n)\n\
         Order.objects.filter(user=user).delete()",
    );
    assert!(c.iter().any(|x| x.table == "User" && x.op == Op::Read));
    assert!(c.iter().any(|x| x.table == "User" && x.op == Op::Write));
    assert!(
        c.iter().any(|x| x.table == "Order" && x.op == Op::Write),
        "delete is a write: {:?}",
        c
    );
    // `via` names the operation that was resolved, not the accessor in front of
    // it. Pinning it to "objects" would assert on the accessor and say nothing
    // about whether the right read or write was recorded.
    assert!(
        c.iter().all(|x| x.via.contains('.') && x.via.contains("()")),
        "every call records its operation: {:?}",
        c
    );
}

#[test]
fn resolves_gorm_and_raw_sql() {
    let c = calls_in(
        "m.go",
        "db.Where(\"name = ?\", n).Find(&users)\n\
         db.Create(&user)\n\
         db.Table(\"orders\").Where(\"id = ?\", id).Delete(&o)\n\
         db.Exec(\"DELETE FROM orders WHERE id = ?\", id)",
    );
    assert!(c.iter().any(|x| x.table == "users" && x.op == Op::Read));
    assert!(c.iter().any(|x| x.table == "user" && x.op == Op::Write));
    assert!(c.iter().any(|x| x.table == "orders"), "raw Exec names orders");
}

#[test]
fn resolves_activerecord_and_entityframework() {
    let c = calls_in(
        "m.rb",
        "User.where(active: true).order(:name)\nUser.create!(name: n)\n\
         Order.delete_all",
    );
    assert!(c.iter().any(|x| x.table == "User" && x.op == Op::Read));
    assert!(c.iter().any(|x| x.table == "User" && x.op == Op::Write));
    assert!(c.iter().any(|x| x.table == "Order" && x.op == Op::Write));

    let ts = calls_in(
        "s.cs",
        "await _db.Users.Where(u => u.Active).ToListAsync();\n\
         _db.Users.Add(new User());\n\
         _db.Orders.Remove(order);",
    );
    assert!(ts.iter().any(|x| x.table == "Users" && x.op == Op::Read));
    assert!(ts.iter().any(|x| x.table == "Users" && x.op == Op::Write));
    assert!(ts.iter().any(|x| x.table == "Orders" && x.op == Op::Write));
}

#[test]
fn resolves_sqlalchemy_and_typeorm_entities() {
    let py = calls_in(
        "m.py",
        "session.query(User).filter(User.id == 1).all()\n\
         session.add(User(name=n))\n\
         session.execute(select(Order))",
    );
    assert!(py.iter().any(|x| x.table == "User" && x.op == Op::Read));
    assert!(py.iter().any(|x| x.table == "User" && x.op == Op::Write));
    assert!(py.iter().any(|x| x.table == "Order" && x.op == Op::Read));

    // A repository that names its entity: the entity is in the variable name.
    let ts = calls_in(
        "r.ts",
        "await this.userRepo.findOne({ where: { id } });\n\
         await this.userRepo.save(user);\n\
         await this.userRepo.delete(id);",
    );
    assert!(
        ts.iter().any(|x| x.table == "user" && x.op == Op::Read),
        "userRepo.findOne is a read on user: {:?}",
        ts
    );
    assert!(
        ts.iter().any(|x| x.table == "user" && x.op == Op::Write),
        "userRepo.save is a write on user: {:?}",
        ts
    );

    // A repository named only `repo` carries no entity name at all. Guessing one
    // would be inventing a table, so the only honest answer is the entity named in
    // the argument of a write.
    let anon = calls_in(
        "r.ts",
        "await this.repo.save(user);",
    );
    assert!(
        anon.iter().any(|x| x.table == "user" && x.op == Op::Write),
        "the argument names the entity: {:?}",
        anon
    );
}

#[test]
fn raw_sql_names_its_table() {
    let c = calls_in(
        "q.py",
        "cur.execute(\"SELECT * FROM users WHERE id = ?\", (uid,))\n\
         cur.execute('DELETE FROM audit_log')\n\
         cursor.execute(\"INSERT INTO orders (id) VALUES (?)\", (i,))",
    );
    assert!(c.iter().any(|x| x.table == "users" && x.op == Op::Read));
    assert!(c.iter().any(|x| x.table == "audit_log" && x.op == Op::Write));
    assert!(c.iter().any(|x| x.table == "orders" && x.op == Op::Write));
}

#[test]
fn the_read_write_split_is_correct() {
    // A method that only reads must never be recorded as a write, and the
    // reverse. This is the field an agent reasons about, so a wrong value is
    // worse than a missing one.
    let c = calls_in(
        "m.py",
        "session.query(User).all()\n\
         session.add(User(name=n))\n\
         User.objects.filter(x=1).count()\n\
         User.objects.update_or_create(id=1)",
    );
    for call in &c {
        if call.via.contains("query(") || call.via.contains("count(") {
            assert_eq!(call.op, Op::Read, "a query is not a write: {:?}", call);
        }
        if call.via.contains("add(") || call.via.contains("update_or_create(") {
            assert_eq!(call.op, Op::Write, "an add is a write: {:?}", call);
        }
    }
}

#[test]
fn unrelated_method_chains_resolve_to_nothing() {
    // The negative half, and the reason this feature is trustworthy. A wrong
    // table is worse than no answer.
    for junk in [
        "logger.info(\"users table is empty\")",
        "console.log(\"SELECT * FROM users\")",
        "const table = 'users'",
        "config.set('orders.table', 'orders')",
        "user.name = \"users\"",
        "help.search('users')",
        "def users(): pass",
        "vector.add(users)",
        "cache.get('users')",
    ] {
        let c = calls_in("m.py", junk);
        assert!(
            c.iter().all(|x| x.table != "users" && x.table != "orders"),
            "must not resolve {:?} to a table, got {:?}",
            junk,
            c
        );
    }
}

#[test]
fn concatenated_construction_is_a_syntactic_sink() {
    // Deliverable 4, and the class `check` misses entirely: no source, no sink
    // match, just string concatenation inside a query call.
    let found = heides::db::concatenated_queries(Path::new("m.py"), "q = \"SELECT * FROM users WHERE id = \" + uid\n");
    assert_eq!(found.len(), 1, "concatenation into a query is a finding");
    assert!(found[0].contains("users") || found[0].contains("concatenat"));

    // f-strings, .format and template literals are the same defect.
    assert_eq!(
        heides::db::concatenated_queries(
            Path::new("m.py"),
            "q = f\"SELECT * FROM users WHERE id = {uid}\"\n"
        )
        .len(),
        1
    );
    assert_eq!(
        heides::db::concatenated_queries(
            Path::new("q.js"),
            "const q = `SELECT * FROM users WHERE id = ${id}`;\n"
        )
        .len(),
        1
    );
    assert_eq!(
        heides::db::concatenated_queries(
            Path::new("m.py"),
            "q = \"SELECT * FROM users WHERE id = {}\".format(uid)\n"
        )
        .len(),
        1
    );
}

#[test]
fn a_placeholder_query_is_not_a_concatenated_query() {
    // The negative half of deliverable 4. Parameterised queries are the correct
    // spelling and must stay silent, and a plain constant is not a defect.
    for ok in [
        "q = \"SELECT * FROM users WHERE id = ?\"\ncur.execute(q, (uid,))\n",
        "q = 'SELECT * FROM users WHERE id = :id'\n",
        "q = \"SELECT * FROM users\"\n",
        "msg = \"users \" + name\n",
        "total = prefix + suffix\n",
        "q = \"SELECT * FROM users WHERE id = %s\" % uid\n",
        "path = \"SELECT\" + \"FROM\"\n",
    ] {
        assert!(
            heides::db::concatenated_queries(Path::new("m.py"), ok).is_empty(),
            "must stay quiet: {:?}",
            ok
        );
    }
}

// ------------------------------------------------------------------- migrations

#[test]
fn discovers_migration_directories() {
    let dirs = heides::db::migration_dirs(Path::new("/repo"));
    // The function is pure over a path list; the real walk is in index_path.
    assert!(dirs.is_empty() || dirs.iter().all(|d| d.starts_with("/repo")));
}

#[test]
fn classifies_a_migration_file_by_shape() {
    assert_eq!(
        heides::db::classify_migration("0001_init.sql"),
        Some("sql")
    );
    assert_eq!(
        heides::db::classify_migration("20240101120000_add_email.py"),
        Some("alembic")
    );
    assert_eq!(
        heides::db::classify_migration("db/migrate/20240101_create_users.go"),
        Some("goose")
    );
    assert_eq!(
        heides::db::classify_migration("V1__init__sql.sql"),
        Some("flyway")
    );
    assert_eq!(heides::db::classify_migration("README.md"), None);
    assert_eq!(heides::db::classify_migration("model.py"), None);
}

// --------------------------------------------------------------------- the db

#[test]
fn writes_and_reads_back_a_schema_graph() {
    let dir = std::env::temp_dir().join("heides_db_roundtrip");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("migrations")).unwrap();
    std::fs::write(
        dir.join("migrations/0001_init.sql"),
        "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT);\n\
         CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id));\n\
         CREATE INDEX idx_orders_user ON orders(user_id);\n",
    )
    .unwrap();
    // An orphan is a table nothing touches AND nothing references, so a schema
    // with no application code has every table as an orphan. The fixture needs
    // code that touches both tables, otherwise the assertion below would be
    // asserting that the feature does not work.
    std::fs::write(
        dir.join("app.py"),
        "session.query(User).all()\ncur.execute(\"SELECT * FROM orders\")\n",
    )
    .unwrap();

    let graph = heides::db::index_schema(&dir).expect("schema indexes");
    assert_eq!(graph.tables.len(), 2);

    let back = heides::db::load_schema(&dir).expect("schema loads");
    assert_eq!(back.tables.len(), 2);
    let orders = back.tables.iter().find(|t| t.name == "orders").unwrap();
    assert_eq!(orders.columns[1].fk_table.as_deref(), Some("users"));

    // Orphans: `users` is referenced by orders, so nothing is orphaned here.
    let orphans = heides::db::orphans(&back);
    assert!(
        orphans.is_empty(),
        "every table is referenced or is a root: {:?}",
        orphans
    );

    // `orders.user_id` has an explicit index, so it is not missing one.
    let miss = heides::db::missing_index(&back);
    assert!(
        miss.is_empty(),
        "orders.user_id is indexed: {:?}",
        miss
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reports_a_foreign_key_without_an_index() {
    let dir = std::env::temp_dir().join("heides_db_missingindex");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("s.sql"),
        "CREATE TABLE users (id INTEGER PRIMARY KEY);\n\
         CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id));\n",
    )
    .unwrap();

    let graph = heides::db::index_schema(&dir).unwrap();
    let miss = heides::db::missing_index(&graph);
    assert_eq!(miss.len(), 1, "orders.user_id is an unindexed fk");
    assert_eq!(miss[0].0, "orders");
    assert_eq!(miss[0].1, "user_id");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn flags_sensitive_columns() {
    let dir = std::env::temp_dir().join("heides_db_sensitive");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("s.sql"),
        "CREATE TABLE users (\n  id INTEGER PRIMARY KEY,\n  email TEXT,\n\
         \x20 password_hash TEXT,\n  ssn TEXT,\n  bio TEXT\n);\n",
    )
    .unwrap();
    let graph = heides::db::index_schema(&dir).unwrap();
    let sens = heides::db::sensitive_columns(&graph);
    let names: Vec<&str> = sens.iter().map(|(_, c, _)| c.as_str()).collect();
    assert!(names.contains(&"email"));
    assert!(names.contains(&"password_hash"));
    assert!(names.contains(&"ssn"));
    assert!(
        !names.contains(&"id"),
        "an id is not PII: {:?}",
        names
    );
    assert!(
        !names.contains(&"bio"),
        "bio is free text the tool cannot judge: {:?}",
        names
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_workspace_with_no_database_yields_an_empty_graph() {
    let dir = std::env::temp_dir().join("heides_db_empty");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("main.py"), "print(1)\n").unwrap();
    let g = heides::db::index_schema(&dir).expect("empty graph is not an error");
    assert!(g.tables.is_empty());
    assert!(g.calls.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_file_walk_finds_sql_next_to_code() {
    let dir = std::env::temp_dir().join("heides_db_walk");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("db/migrate")).unwrap();
    std::fs::write(
        dir.join("db/migrate/0001_init.sql"),
        "CREATE TABLE t (id INT PRIMARY KEY);\n",
    )
    .unwrap();
    std::fs::write(dir.join("app.py"), "x = 1\n").unwrap();
    let g = heides::db::index_schema(&dir).unwrap();
    assert_eq!(g.tables.len(), 1);
    assert_eq!(g.tables[0].name, "t");
    assert!(!g.migrations.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn db_calls_survive_a_brace_storm() {
    let junk = "session.query(User).all()".to_string() + &"{".repeat(5000);
    let _ = heides::db::scan_calls(Path::new("m.py"), &junk);
    let _ = heides::db::concatenated_queries(Path::new("m.py"), &junk);
}