// The OSV advisory cache.
//
// An offline run used to give up on advisories entirely, which made `--no-deps`
// honest but nearly useless: it could say the versions were pinned and nothing
// else. A cache makes it a real gate again, because the answer to "is this
// version vulnerable" is stable for a day and does not need the network on every
// run.
//
// The rule that matters is what the cache is allowed to say. A cached answer is
// only an answer if you know how old it is, so a hit, a stale entry, and a miss
// are three different states and none of them is silently clean. The asymmetry
// below is the safety-critical part: a stale *vulnerability* is always still
// reported, while a stale *clean* is not, because the two err in opposite
// directions and only one of them can be corrected by the reader.

use std::path::Path;

use heides::osv_cache::{self, Answer, CachePolicy, Entry};

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A cache entry stamped `age_secs` in the past.
fn entry(vuln: Option<&str>, age_secs: u64) -> Entry {
    Entry {
        vuln: vuln.map(|s| s.to_string()),
        fetched_at: now().saturating_sub(age_secs),
    }
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("heides-osv-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A policy with everything on and a one hour clean window, so the tests do not
/// depend on the default TTL.
fn policy() -> CachePolicy {
    CachePolicy {
        enabled: true,
        allow_offline: true,
        clean_ttl_secs: 3600,
    }
}

// ------------------------------------------------------------- the key shape

#[test]
fn a_key_is_derived_from_the_ecosystem_package_and_version() {
    let p = osv_cache::entry_path(Path::new("/c"), "npm", "express", "4.18.2");
    assert!(p.starts_with(Path::new("/c")), "{p:?}");
    let s = p.to_string_lossy().to_string();
    assert!(s.contains("npm"), "the ecosystem must be in the key: {s}");
    assert!(s.contains("express"), "{s}");
    assert!(s.contains("4.18.2"), "the version must be in the key: {s}");
}

#[test]
fn a_key_survives_a_name_that_is_not_a_path() {
    // A scoped npm package and a go module path both contain characters that
    // would be a separator. `../../etc` is a valid package name string, so a
    // cache keyed on the raw name would write outside the cache directory.
    let p = osv_cache::entry_path(Path::new("/c"), "npm", "@scope/pkg", "1.0.0");
    assert!(p.starts_with(Path::new("/c")), "must stay under the cache: {p:?}");

    let g = osv_cache::entry_path(Path::new("/c"), "go", "../../etc/passwd", "v1.0.0");
    assert!(
        g.starts_with(Path::new("/c")),
        "a traversal must not escape: {g:?}"
    );
    // And two different traversals must not collapse onto one key.
    let h = osv_cache::entry_path(Path::new("/c"), "go", "../etc/shadow", "v1.0.0");
    assert_ne!(g, h, "distinct names must not collide: {g:?} vs {h:?}");
    assert!(h.starts_with(Path::new("/c")), "{h:?}");
}

#[test]
fn two_versions_of_one_package_do_not_collide() {
    let a = osv_cache::entry_path(Path::new("/c"), "npm", "express", "4.17.0");
    let b = osv_cache::entry_path(Path::new("/c"), "npm", "express", "4.18.2");
    assert_ne!(a, b, "a cache keyed without the version is a wrong answer");
}

#[test]
fn two_ecosystems_with_one_name_do_not_collide() {
    let a = osv_cache::entry_path(Path::new("/c"), "npm", "utils", "1.0.0");
    let b = osv_cache::entry_path(Path::new("/c"), "pypi", "utils", "1.0.0");
    assert_ne!(a, b);
}

// ------------------------------------------------------------- store and read

#[test]
fn a_stored_clean_answer_reads_back_clean() {
    let dir = scratch("cleanclean");
    osv_cache::store(&dir, "npm", "express", "4.18.2", None);
    let e = osv_cache::load(&dir, "npm", "express", "4.18.2").expect("entry exists");
    assert_eq!(e.vuln, None);
}

#[test]
fn a_stored_advisory_reads_back_as_one() {
    let dir = scratch("vuln");
    osv_cache::store(
        &dir,
        "npm",
        "lodash",
        "4.17.19",
        Some("GHSA-x5rq-j2xg-h7qm"),
    );
    let e = osv_cache::load(&dir, "npm", "lodash", "4.17.19").expect("entry exists");
    assert_eq!(e.vuln.as_deref(), Some("GHSA-x5rq-j2xg-h7qm"));
}

#[test]
fn a_missing_entry_is_none_rather_than_an_error() {
    // A miss is the normal state on a first run, not a failure.
    let dir = scratch("miss");
    assert!(osv_cache::load(&dir, "npm", "nothing", "1.0.0").is_none());
}

#[test]
fn storing_twice_replaces_rather_than_appending() {
    let dir = scratch("replace");
    osv_cache::store(&dir, "npm", "x", "1.0.0", Some("FIRST"));
    osv_cache::store(&dir, "npm", "x", "1.0.0", Some("SECOND"));
    let e = osv_cache::load(&dir, "npm", "x", "1.0.0").unwrap();
    assert_eq!(e.vuln.as_deref(), Some("SECOND"));
}

#[test]
fn a_corrupt_entry_is_a_miss_and_not_a_panic() {
    // A truncated file from an interrupted write must not take the run down, and
    // must not be read as a clean answer.
    let dir = scratch("corrupt");
    let p = osv_cache::entry_path(&dir, "npm", "broken", "1.0.0");
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, "{not json").unwrap();
    assert!(osv_cache::load(&dir, "npm", "broken", "1.0.0").is_none());
}

// ---------------------------------------------------------------- freshness

#[test]
fn a_clean_entry_inside_the_ttl_is_usable() {
    let now = 1_000_000u64;
    let e = Entry {
        vuln: None,
        fetched_at: now - 60,
    };
    assert!(
        osv_cache::usable(&e, now, 3600),
        "fresh is usable, and the default policy must agree"
    );
}

#[test]
fn a_clean_entry_past_the_ttl_is_not_usable() {
    let now = 1_000_000u64;
    let e = Entry {
        vuln: None,
        fetched_at: now - 7200,
    };
    assert!(
        !osv_cache::usable(&e, now, 3600),
        "a stale clean answer is not a clean answer"
    );
}

#[test]
fn a_vulnerable_entry_is_usable_at_any_age() {
    // The asymmetry. A finding does not expire, because dropping it hides a real
    // problem and the cost of a stale finding is a wasted look.
    let now = 1_000_000u64;
    let e = Entry {
        vuln: Some("GHSA-old".to_string()),
        fetched_at: now - 999_999,
    };
    assert!(
        osv_cache::usable(&e, now, 1),
        "a vulnerability must never expire"
    );
}

#[test]
fn an_entry_stamped_in_the_future_is_refused() {
    // A wrong clock or a tampered file. Refusing is the only safe reading, since
    // computing a negative age would call it fresh.
    let now = 1_000_000u64;
    let e = Entry {
        vuln: None,
        fetched_at: now + 5000,
    };
    assert!(!osv_cache::usable(&e, now, 999_999), "future stamp refused");
}

// ------------------------------------------------------------------ consult

#[test]
fn a_fresh_cached_clean_is_reported_as_cached_clean() {
    // The caller has to be able to tell a cached clean from a live one, because
    // only one of them is current.
    let dir = scratch("consultclean");
    osv_cache::store(&dir, "npm", "express", "4.18.2", None);
    match osv_cache::consult(policy(), Some(&dir), "npm", "express", "4.18.2") {
        Some(Answer::Clean {
            cached: true,
            age_secs,
        }) => assert!(
            age_secs.map(|a| a < 300).unwrap_or(false),
            "a just written entry is seconds old, got {age_secs:?}"
        ),
        other => panic!("expected a cached clean, got {other:?}"),
    }
}

#[test]
fn a_cached_advisory_is_reported_as_found_and_marked_cached() {
    let dir = scratch("consultvuln");
    osv_cache::store(
        &dir,
        "npm",
        "lodash",
        "4.17.19",
        Some("GHSA-x5rq-j2xg-h7qm"),
    );
    match osv_cache::consult(policy(), Some(&dir), "npm", "lodash", "4.17.19") {
        Some(Answer::Found {
            detail,
            cached: true,
            ..
        }) => assert_eq!(detail, "GHSA-x5rq-j2xg-h7qm"),
        other => panic!("expected a found, got {other:?}"),
    }
}

#[test]
fn a_miss_is_none_and_never_a_clean() {
    // The single most important case. A miss that reads as clean would make the
    // gate green on a project nobody checked. `None` means "the cache has
    // nothing", which the caller turns into NotChecked.
    let dir = scratch("consultmiss");
    assert_eq!(
        osv_cache::consult(policy(), Some(&dir), "npm", "never-seen", "1.0.0"),
        None,
        "a miss must be None so the caller can tell it from a clean"
    );
}

#[test]
fn a_stale_clean_becomes_not_checked_rather_than_clean() {
    // The branch that must never fall through to Clean, so it is its own state.
    let dir = scratch("staleclean");
    osv_cache::write_at(&dir, "npm", "old", "1.0.0", &entry(None, 10 * 24 * 3600));
    match osv_cache::consult(policy(), Some(&dir), "npm", "old", "1.0.0") {
        Some(Answer::NotChecked { cached_stale: true }) => {}
        other => panic!("a ten day old clean must not pass as clean, got {other:?}"),
    }
}

#[test]
fn a_stale_advisory_is_still_reported() {
    // The other half of the asymmetry, pinned so the asymmetry cannot be
    // "simplified" into a single rule later.
    let dir = scratch("stalevuln");
    osv_cache::write_at(
        &dir,
        "npm",
        "old",
        "1.0.0",
        &entry(Some("GHSA-stale"), 10 * 24 * 3600),
    );
    match osv_cache::consult(policy(), Some(&dir), "npm", "old", "1.0.0") {
        Some(Answer::Found { detail, .. }) => assert_eq!(detail, "GHSA-stale"),
        other => panic!("a stale advisory is still an advisory, got {other:?}"),
    }
}

#[test]
fn no_cache_directory_at_all_is_a_miss() {
    assert_eq!(
        osv_cache::consult(policy(), None, "npm", "x", "1.0.0"),
        None
    );
}

#[test]
fn a_disabled_policy_never_reads_the_cache() {
    // A caller that turned the cache off must not be answered from it, or turning
    // it off does nothing.
    let dir = scratch("disabled");
    osv_cache::store(
        &dir,
        "npm",
        "express",
        "4.18.2",
        Some("GHSA-x5rq-j2xg-h7qm"),
    );
    let off = CachePolicy {
        enabled: false,
        ..Default::default()
    };
    assert_eq!(
        osv_cache::consult(off, Some(&dir), "npm", "express", "4.18.2"),
        None
    );
}

// ----------------------------------------------------------------- reporting

#[test]
fn a_human_age_reads_as_a_duration() {
    assert_eq!(osv_cache::human_age(30), "30s");
    assert!(osv_cache::human_age(90).contains('m'), "{}", osv_cache::human_age(90));
    assert!(
        osv_cache::human_age(7200).contains('h'),
        "{}",
        osv_cache::human_age(7200)
    );
}

#[test]
fn a_cache_health_line_names_the_counts() {
    let mut h = osv_cache::CacheHealth::default();
    h.note_hit(Some(120));
    h.note_hit(Some(60));
    h.note_miss();
    h.note_stale();
    assert_eq!(h.hits, 2);
    assert_eq!(h.misses, 1);
    assert_eq!(h.stale, 1);
    // The oldest relied-on age is what tells a reader how much weight a clean
    // result carries, so it has to be tracked rather than left at zero.
    assert_eq!(h.oldest_used_secs, 120);
}
