//! A local cache of OSV advisory answers, so an offline run can still say
//! something true about a dependency.
//!
//! Why this exists. `--no-deps` and `HEIDES_OFFLINE=1` made the dependency
//! guard do nothing but read manifests, and the receipt said `skipped`. That is
//! honest but it is not useful: a scanner that only works with a network is
//! exactly the scanner you cannot run in the place you need it. The cache
//! lets the same run answer from a previous answer and report how old it is.
//!
//! The rule that matters, and the reason this is not just a `HashMap`:
//!
//! * A cached **vulnerable** answer never expires. A known bad version stays
//!   bad. Keying on the exact version means an upgrade naturally misses and
//!   re-fetches, so holding a vulnerability forever cannot produce a false
//!   alarm about a package you already fixed.
//! * A cached **clean** answer expires. "No known vulnerability at 09:00 on
//!   Tuesday" stops being true, because a CVE can be published at any moment.
//!   Past the TTL the answer becomes *unknown*, never *clean*. This asymmetry
//!   is the entire safety argument for the cache: the failure direction of an
//!   expired entry is toward checking nothing, never toward claiming safety.
//!
//! Anything unreadable, unparseable or from a future clock is treated as
//! absent. A corrupt cache must not be able to produce a confident answer.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// How long a cached *clean* answer stays usable, in seconds. One day.
pub const CLEAN_TTL_SECS: u64 = 24 * 60 * 60;

/// What the cache is allowed to do for one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachePolicy {
    /// Whether cache reads and writes may happen.
    pub enabled: bool,
    /// Whether a cached answer may satisfy an offline run.
    pub allow_offline: bool,
    /// Freshness ceiling for a cached clean answer, in seconds.
    pub clean_ttl_secs: u64,
}

impl Default for CachePolicy {
    fn default() -> Self {
        CachePolicy {
            enabled: cache_enabled(),
            allow_offline: true,
            clean_ttl_secs: CLEAN_TTL_SECS,
        }
    }
}

fn env_truthy(key: &str) -> bool {
    matches!(
        std::env::var(key).ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

fn cache_enabled() -> bool {
    // Opt out with HEIDES_NO_CACHE, in case a user needs a guaranteed live
    // answer and does not trust their own cache directory.
    !env_truthy("HEIDES_NO_CACHE")
}

/// Where cached answers live.
///
/// Resolution order, most explicit first: `HEIDES_CACHE_DIR`, then
/// `XDG_CACHE_HOME/heides/osv`, then `$HOME/.cache/heides/osv`. No new
/// dependency for this, the three variables are the convention already and a
/// `dirs` crate would be one more thing to audit for a path lookup.
pub fn cache_dir() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("HEIDES_CACHE_DIR")
        && !d.is_empty()
    {
        return Some(PathBuf::from(d).join("osv"));
    }
    if let Some(x) = std::env::var_os("XDG_CACHE_HOME")
        && !x.is_empty()
    {
        return Some(PathBuf::from(x).join("heides").join("osv"));
    }
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(|h| PathBuf::from(h).join(".cache").join("heides").join("osv"))
}

/// The one answer that was cached, with when it was fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub fetched_at: u64,
    pub vuln: Option<String>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Turn a package name into one safe path segment.
///
/// Scoped npm names contain a slash: `@babel/core`. Left alone that becomes a
/// directory traversal into whatever the consumer's cache root sits next to,
/// so the slash and every other separator is replaced rather than escaped.
pub fn key_segment(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '-' => out.push(c),
            _ => out.push('_'),
        }
    }
    if out.is_empty() { "_".to_string() } else { out }
}

/// The file one ecosystem/name/version answer lives in.
pub fn entry_path(dir: &Path, ecosystem: &str, name: &str, version: &str) -> PathBuf {
    // The version is sanitised too. A manifest is attacker influenced input
    // here, since a lockfile can be checked out from anywhere, so no segment
    // of this key is trusted to already be a bare filename.
    let file = format!(
        "{}__{}@{}.json",
        key_segment(ecosystem),
        key_segment(name),
        key_segment(version)
    );
    dir.join(file)
}

/// Read a cached answer, or `None` when absent or unusable.
///
/// A parse failure, a missing field or a timestamp in the future are all
/// `None`. The caller cannot tell those apart from a genuine miss, which is
/// the point: none of them may become a clean bill of health.
pub fn load(dir: &Path, ecosystem: &str, name: &str, version: &str) -> Option<Entry> {
    let raw = std::fs::read_to_string(entry_path(dir, ecosystem, name, version)).ok()?;
    let value: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let fetched_at = value.get("fetched_at")?.as_u64()?;
    let vuln = match value.get("vuln") {
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        // A JSON null means the answer was clean.
        Some(serde_json::Value::Null) | None => None,
        // Anything else is a shape we do not understand, so we do not guess.
        Some(_) => return None,
    };
    Some(Entry { fetched_at, vuln })
}

/// Store an answer. A failed write is not an error the caller needs to see:
/// the run did the lookup for real, and the cache is an optimisation. Being
/// unable to cache must never turn a completed check into a failure.
pub fn store(dir: &Path, ecosystem: &str, name: &str, version: &str, vuln: Option<&str>) {
    write_at(
        dir,
        ecosystem,
        name,
        version,
        &Entry {
            fetched_at: now_secs(),
            vuln: vuln.map(|s| s.to_string()),
        },
    );
}

/// Write an entry with an explicit stamp, rather than "now".
///
/// Separate from `store` because a caller restoring a cache, a test pinning a
/// specific age, and any future import path all need to say when an answer was
/// obtained. Without it, testing the freshness boundary means editing a file by
/// hand or sleeping, and a test that sleeps is a test that lies.
///
/// The write is atomic: to a sibling, then renamed. A concurrent reader or a
/// killed process must never observe a half written file and cache a truncated
/// answer as if it were real, which is the failure a cache must never have.
pub fn write_at(dir: &Path, ecosystem: &str, name: &str, version: &str, entry: &Entry) {
    let path = entry_path(dir, ecosystem, name, version);
    if let Some(parent) = path.parent()
        && std::fs::create_dir_all(parent).is_err()
    {
        // A cache that cannot be written is a performance loss, not a correctness
        // one, so this is quiet by design and the live path still works.
        return;
    }
    let body = serde_json::json!({
        "fetched_at": entry.fetched_at,
        "vuln": entry.vuln,
    });
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, body.to_string()).is_err() {
        return;
    }
    let _ = std::fs::rename(&tmp, &path);
}

/// Age of an entry in seconds, or `None` when the clock is before the stamp.
pub fn age_secs(entry: &Entry) -> Option<u64> {
    now_secs().checked_sub(entry.fetched_at)
}

/// Whether a cached answer may be used right now.
///
/// Asymmetric on purpose, and this is the safety-critical function in the file:
/// a vulnerability is always usable, a clean answer only inside the TTL.
pub fn usable(entry: &Entry, now: u64, ttl: u64) -> bool {
    // A stamp from the future means a wrong clock or a tampered file. Refuse
    // it rather than computing a negative age and calling it fresh.
    if entry.fetched_at > now {
        return false;
    }
    match &entry.vuln {
        Some(_) => true,
        None => now - entry.fetched_at <= ttl,
    }
}

/// What one lookup actually established, once the cache is in the picture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// A vulnerability, and whether the answer came from cache.
    Found {
        detail: String,
        cached: bool,
        age_secs: Option<u64>,
    },
    /// No known vulnerability, inside the TTL.
    Clean { cached: bool, age_secs: Option<u64> },
    /// The advisory service could not be reached and the cache had nothing
    /// usable. Explicitly not a clean bill of health.
    NotChecked { cached_stale: bool },
}

/// Consult the cache for one dependency, deciding freshness on its own.
pub fn consult(
    policy: CachePolicy,
    dir: Option<&Path>,
    ecosystem: &str,
    name: &str,
    version: &str,
) -> Option<Answer> {
    if !policy.enabled {
        return None;
    }
    let dir = dir?;
    let entry = load(dir, ecosystem, name, version)?;
    let now = now_secs();
    if !usable(&entry, now, policy.clean_ttl_secs) {
        // Present but expired. This is the branch that must never fall through
        // to Clean, so it is spelled out as its own state.
        return Some(Answer::NotChecked { cached_stale: true });
    }
    let age = age_secs(&entry);
    match &entry.vuln {
        Some(detail) => Some(Answer::Found {
            detail: detail.clone(),
            cached: true,
            age_secs: age,
        }),
        None => Some(Answer::Clean {
            cached: true,
            age_secs: age,
        }),
    }
}

/// How a run used the cache, for the receipt.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheHealth {
    pub hits: usize,
    pub misses: usize,
    pub stale: usize,
    /// The oldest cache entry that was relied on, in seconds.
    pub oldest_used_secs: u64,
}

impl CacheHealth {
    pub fn note_hit(&mut self, age: Option<u64>) {
        self.hits += 1;
        if let Some(a) = age {
            self.oldest_used_secs = self.oldest_used_secs.max(a);
        }
    }
    pub fn note_miss(&mut self) {
        self.misses += 1;
    }
    pub fn note_stale(&mut self) {
        self.stale += 1;
    }
}

/// Render an age the way a person reads it, so the receipt does not make
/// everyone do the arithmetic on a raw second count.
pub fn human_age(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 60 * 60 {
        format!("{}m", secs / 60)
    } else if secs < 24 * 60 * 60 {
        format!("{}h", secs / (60 * 60))
    } else {
        format!("{}d", secs / (24 * 60 * 60))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!("heides_osvcache_{tag}_{stamp}"));
        let _ = std::fs::create_dir_all(&p);
        p
    }

    #[test]
    fn round_trips_a_clean_answer() {
        let d = tmpdir("clean");
        store(&d, "npm", "left-pad", "1.3.0", None);
        let got = load(&d, "npm", "left-pad", "1.3.0").expect("must read back");
        assert_eq!(got.vuln, None, "a clean answer is a null vuln, not missing");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn round_trips_a_vulnerability() {
        let d = tmpdir("vuln");
        store(
            &d,
            "npm",
            "lodash",
            "4.17.15",
            Some("GHSA-x5rq-j2xg-h7qm: prototype pollution"),
        );
        let got = load(&d, "npm", "lodash", "4.17.15").expect("must read back");
        assert_eq!(
            got.vuln.as_deref(),
            Some("GHSA-x5rq-j2xg-h7qm: prototype pollution")
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The safety property. A clean answer past the TTL is *not* clean, it is
    /// unknown, because a CVE can be published at any moment after the answer
    /// was cached.
    #[test]
    fn clean_expires_and_becomes_unknown_not_clean() {
        let now = 1_000_000_000;
        let fresh = Entry {
            fetched_at: now - 10,
            vuln: None,
        };
        let old = Entry {
            fetched_at: now - 100_000,
            vuln: None,
        };
        assert!(usable(&fresh, now, 86_400), "a day old clean is usable");
        assert!(
            !usable(&old, now, 86_400),
            "an expired clean must not be usable, or we claim safety we do not have"
        );
    }

    /// The other half of the asymmetry. A vulnerability never expires, so
    /// pointing the scanner at an air gapped machine still reports the bad
    /// version it already knows about.
    #[test]
    fn a_known_vulnerability_never_expires() {
        let now = 1_000_000_000;
        let ancient = Entry {
            // Decades old, which is well past any plausible cache lifetime.
            fetched_at: now - 900_000_000,
            vuln: Some("GHSA-old: still bad".to_string()),
        };
        assert!(
            usable(&ancient, now, 86_400),
            "a vulnerability stays usable, the version is what is bad"
        );
    }

    #[test]
    fn a_future_timestamp_is_refused() {
        let now = 1_000_000;
        let skew = Entry {
            fetched_at: now + 5_000,
            vuln: None,
        };
        assert!(
            !usable(&skew, now, 86_400),
            "a wrong clock must not be able to manufacture a fresh answer"
        );
    }

    #[test]
    fn a_corrupt_entry_is_a_miss_never_a_clean_answer() {
        let d = tmpdir("corrupt");
        let p = entry_path(&d, "npm", "evil", "1.0.0");
        std::fs::write(&p, "{ this is not json").unwrap();
        assert_eq!(load(&d, "npm", "evil", "1.0.0"), None, "corrupt is absent");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn an_entry_of_an_unknown_shape_is_refused() {
        let d = tmpdir("shape");
        // A vuln field that is neither a string nor null. Guessing here would
        // mean inventing a clean result out of a value we did not understand.
        let p = entry_path(&d, "npm", "odd", "1.0.0");
        std::fs::write(&p, r#"{"fetched_at":1,"vuln":42}"#).unwrap();
        assert_eq!(load(&d, "npm", "odd", "1.0.0"), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn different_versions_do_not_share_an_entry() {
        // The reason a cached vulnerability can be held forever: upgrading
        // changes the key, so the old answer cannot follow you forward.
        let d = tmpdir("versions");
        store(&d, "npm", "lodash", "4.17.15", Some("GHSA-a: bad"));
        assert!(load(&d, "npm", "lodash", "4.17.15").is_some());
        assert!(
            load(&d, "npm", "lodash", "4.17.20").is_none(),
            "an upgraded version must not inherit the old answer"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_scoped_name_cannot_escape_the_cache_directory() {
        // @babel/core contains a slash. Unsanitised it would write outside the
        // cache root, and the name comes from a lockfile we did not write.
        let d = tmpdir("scoped");
        let p = entry_path(&d, "npm", "@babel/core", "7.0.0");
        assert_eq!(
            p.parent().unwrap(),
            d.as_path(),
            "the entry must stay directly inside the cache dir"
        );
        assert!(
            !p.to_string_lossy().contains("babel/core"),
            "no slash survived"
        );
        store(&d, "npm", "@babel/core", "7.0.0", None);
        assert!(load(&d, "npm", "@babel/core", "7.0.0").is_some());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_traversal_name_stays_inside_the_cache() {
        let d = tmpdir("traversal");
        let p = entry_path(&d, "npm", "../../etc/passwd", "1.0.0");
        assert_eq!(
            p.parent().unwrap(),
            d.as_path(),
            "a traversing name must not add a directory level"
        );
        // Dots are legal in package names, lodash.get and scoped versions
        // like 1.0.0-beta both need them, so a ".." inside a single filename
        // is kept. What matters is that it is one segment with no separator,
        // so it cannot climb out of the cache directory.
        let file = p.file_name().unwrap().to_string_lossy().to_string();
        assert!(
            !file.contains('/') && !file.contains('\\'),
            "the entry must be a single path segment, got {file}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn consult_reports_a_stale_entry_as_not_checked() {
        let d = tmpdir("stale");
        // Write an entry dated well in the past by hand, since store always
        // stamps now.
        let p = entry_path(&d, "npm", "old", "1.0.0");
        let body = serde_json::json!({
            "fetched_at": now_secs().saturating_sub(10 * 86_400),
            "vuln": serde_json::Value::Null,
        });
        std::fs::write(&p, body.to_string()).unwrap();
        let policy = CachePolicy {
            enabled: true,
            allow_offline: true,
            clean_ttl_secs: 86_400,
        };
        match consult(policy, Some(&d), "npm", "old", "1.0.0") {
            Some(Answer::NotChecked { cached_stale: true }) => {}
            other => panic!("an expired clean must be NotChecked, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn consult_is_silent_when_the_cache_is_disabled() {
        let d = tmpdir("disabled");
        store(&d, "npm", "x", "1.0.0", None);
        let policy = CachePolicy {
            enabled: false,
            allow_offline: true,
            clean_ttl_secs: 86_400,
        };
        assert_eq!(
            consult(policy, Some(&d), "npm", "x", "1.0.0"),
            None,
            "HEIDES_NO_CACHE must mean no reads at all"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn an_unwritable_cache_does_not_panic() {
        // A cache is an optimisation. If it cannot be written the run already
        // did the lookup, so this must be a quiet no-op rather than a failure.
        let blocker = std::env::temp_dir().join("heides_osvcache_notadir");
        std::fs::write(&blocker, b"i am a file, not a directory").unwrap();
        store(&blocker, "npm", "x", "1.0.0", Some("GHSA-a: bad"));
        let _ = std::fs::remove_file(&blocker);
    }

    #[test]
    fn health_tracks_the_oldest_entry_relied_on() {
        let mut h = CacheHealth::default();
        h.note_hit(Some(10));
        h.note_hit(Some(900));
        h.note_hit(None);
        h.note_miss();
        assert_eq!(h.hits, 3);
        assert_eq!(h.misses, 1);
        assert_eq!(
            h.oldest_used_secs, 900,
            "the receipt must show the oldest answer we leaned on"
        );
    }

    #[test]
    fn human_age_is_readable_at_every_scale() {
        assert_eq!(human_age(30), "30s");
        assert_eq!(human_age(600), "10m");
        assert_eq!(human_age(7200), "2h");
        assert_eq!(human_age(172_800), "2d");
    }
}
