use std::{
    collections::HashSet,
    fmt::Write as _,
    io::Read,
    path::PathBuf,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

const MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Category {
    Disposable,
    DisposableReview,
    FreeSubdomain,
    ReferrerSpam,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u8,
    sources: Vec<Source>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    id: String,
    category: Category,
    license: String,
    license_text: String,
    license_sha256: String,
    url: String,
    revision: String,
    updated_at_unix: u64,
    fetched_at_unix: u64,
    expires_at_unix: u64,
    domains: HashSet<String>,
    allowlist: HashSet<String>,
}

pub struct DomainData {
    sources: Vec<Source>,
    reason: Option<&'static str>,
}

#[derive(Serialize)]
pub struct DomainCheck {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    #[serde(flatten)]
    facts: Option<Facts>,
}

#[derive(Serialize)]
struct Facts {
    disposable: Fact,
    free_subdomain: Fact,
    spam: Fact,
}

#[derive(Serialize)]
struct Fact {
    value: Option<bool>,
    status: &'static str,
    scope: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    sources: Vec<SourceStatus>,
}

#[derive(Serialize)]
struct SourceStatus {
    id: String,
    status: &'static str,
    license: String,
    license_sha256: String,
    url: String,
    revision: String,
    updated_at_unix: u64,
    fetched_at_unix: u64,
    expires_at_unix: u64,
}

impl DomainData {
    pub fn unavailable(reason: &'static str) -> Self {
        Self {
            sources: Vec::new(),
            reason: Some(reason),
        }
    }

    fn load(bytes: Option<&[u8]>) -> Self {
        match bytes {
            None => Self::unavailable("data_unavailable"),
            Some(bytes) => Self::parse(bytes).unwrap_or_else(|_| Self::unavailable("invalid_data")),
        }
    }

    fn write_metrics(&self, out: &mut String) {
        let _ = writeln!(
            out,
            "# HELP openfingerprint_domain_data_loaded Whether a valid domain snapshot is loaded.\n# TYPE openfingerprint_domain_data_loaded gauge\nopenfingerprint_domain_data_loaded {}",
            u8::from(self.reason.is_none())
        );
        for (name, help, value) in [
            (
                "source_expiry_timestamp_seconds",
                "When each loaded source stops being used.",
                (|s: &Source| s.expires_at_unix) as fn(&Source) -> u64,
            ),
            (
                "source_fetched_timestamp_seconds",
                "When each loaded source was fetched or reviewed.",
                |s| s.fetched_at_unix,
            ),
            (
                "source_entries",
                "Listed domains in each loaded source.",
                |s| s.domains.len() as u64,
            ),
        ] {
            let _ = writeln!(
                out,
                "# HELP openfingerprint_domain_data_{name} {help}\n# TYPE openfingerprint_domain_data_{name} gauge"
            );
            for s in &self.sources {
                let _ = writeln!(
                    out,
                    "openfingerprint_domain_data_{name}{{source=\"{}\"}} {}",
                    s.id,
                    value(s)
                );
            }
        }
    }

    fn parse(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() > MAX_BYTES {
            return Err(());
        }
        let snapshot: Snapshot = serde_json::from_slice(bytes).map_err(|_| ())?;
        if snapshot.version != 1 || snapshot.sources.len() > 16 {
            return Err(());
        }
        let mut ids = HashSet::new();
        for s in &snapshot.sources {
            if s.id.is_empty()
                || s.id.len() > 64
                || !s
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                || !ids.insert(&s.id)
                || !["CC0-1.0", "MIT", "BSD-3-Clause", "LicenseRef-Public-Domain"]
                    .contains(&s.license.as_str())
                || s.license_text.is_empty()
                || s.license_text.len() > 16384
                || crate::check::sha256(&s.license_text) != s.license_sha256
                || s.url.len() > 512
                || !s.url.starts_with("https://")
                || s.url
                    .chars()
                    .any(|c| c.is_whitespace() || matches!(c, '?' | '#' | '@'))
                || s.revision.is_empty()
                || s.revision.len() > 128
                || !s
                    .revision
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
                || s.updated_at_unix > s.fetched_at_unix.saturating_add(300)
                || !s
                    .expires_at_unix
                    .checked_sub(s.fetched_at_unix)
                    .is_some_and(|n| n > 0 && n <= 30 * 86400)
                || s.domains.is_empty()
                || (s.category == Category::DisposableReview && !s.allowlist.is_empty())
                || s.domains.len() + s.allowlist.len() > 100000
                || s.domains.iter().chain(&s.allowlist).any(|d| {
                    !crate::check::domain(d)
                        || d.ends_with('.')
                        || *d != d.to_ascii_lowercase()
                        || (s.category == Category::FreeSubdomain
                            && psl::suffix(d.as_bytes()).is_some_and(|suffix| {
                                suffix.as_bytes() == d.as_bytes()
                                    && suffix.typ() == Some(psl::Type::Icann)
                            }))
                })
            {
                return Err(());
            }
        }
        Ok(Self {
            sources: snapshot.sources,
            reason: None,
        })
    }

    pub fn check(&self, value: serde_json::Value, mx: Option<serde_json::Value>) -> DomainCheck {
        let invalid = |reason| DomainCheck {
            status: "invalid_input",
            reason: Some(reason),
            facts: None,
        };
        let normalize = |s: &str| s.strip_suffix('.').unwrap_or(s).to_ascii_lowercase();
        let Some(value) = value.as_str().filter(|s| crate::check::domain(s)) else {
            return invalid("invalid_domain");
        };
        let mx = match mx {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(serde_json::Value::Array(hosts))
                if (1..=10).contains(&hosts.len())
                    && hosts
                        .iter()
                        .all(|h| h.as_str().is_some_and(crate::check::domain)) =>
            {
                hosts
                    .iter()
                    .filter_map(|h| h.as_str().map(normalize))
                    .collect()
            }
            Some(_) => return invalid("invalid_mx"),
        };
        self.check_at(&normalize(value), &mx, now())
    }

    fn check_at(&self, domain: &str, mx: &[String], now: u64) -> DomainCheck {
        let facts = Facts {
            disposable: self.mx_fact(
                self.fact(domain, now, Category::Disposable, "disposable_domain"),
                domain,
                mx,
                now,
            ),
            free_subdomain: self.fact(
                domain,
                now,
                Category::FreeSubdomain,
                "free_subdomain_namespace",
            ),
            spam: self.fact(domain, now, Category::ReferrerSpam, "referrer_spam"),
        };
        let items = [&facts.disposable, &facts.free_subdomain, &facts.spam];
        let status = if items.iter().all(|f| f.status == "unknown") {
            "unknown"
        } else if items.iter().any(|f| {
            matches!(f.status, "unknown" | "partial" | "conflict")
                || f.sources
                    .iter()
                    .any(|s| matches!(s.status, "stale" | "future_data"))
        }) {
            "partial"
        } else {
            "ok"
        };
        DomainCheck {
            status,
            reason: self.reason,
            facts: Some(facts),
        }
    }

    fn mx_fact(&self, fact: Fact, domain: &str, mx: &[String], now: u64) -> Fact {
        if fact.status != "not_listed" {
            return fact;
        }
        let suffix = format!(".{domain}");
        let hosts: Vec<_> = mx
            .iter()
            .filter(|h| *h != domain && !h.ends_with(&suffix))
            .map(|h| self.fact(h, now, Category::Disposable, "disposable_domain"))
            .collect();
        let blocked = mx
            .iter()
            .flat_map(|h| {
                std::iter::successors(Some(h.as_str()), |s| s.split_once('.').map(|(_, r)| r))
            })
            .any(|c| {
                let f = self.fact(c, now, Category::Disposable, "disposable_domain");
                f.value == Some(false) || f.status == "conflict"
            });
        if blocked {
            return fact;
        }
        match hosts.into_iter().find(|h| h.value == Some(true)) {
            Some(host) => Fact {
                status: "mx_listed",
                ..host
            },
            None => fact,
        }
    }

    fn fact(&self, domain: &str, now: u64, category: Category, scope: &'static str) -> Fact {
        let mut yes = false;
        let mut no = None;
        let mut disputed = false;
        let mut unavailable = false;
        let sources: Vec<_> = self
            .sources
            .iter()
            .filter(|s| {
                s.category == category
                    || (category == Category::Disposable
                        && s.category == Category::DisposableReview)
            })
            .map(|s| {
                // An overdue review must not restore a disputed positive classification.
                if s.category == Category::DisposableReview && s.domains.contains(domain) {
                    disputed = true;
                }
                let status = if s.fetched_at_unix > now.saturating_add(300) {
                    unavailable = true;
                    "future_data"
                } else if s.expires_at_unix <= now {
                    unavailable = true;
                    "stale"
                } else {
                    s.lookup(domain)
                };
                if status == "listed" {
                    yes = true;
                }
                if matches!(status, "allowlisted" | "provider_domain") {
                    no = Some(status);
                }
                SourceStatus {
                    id: s.id.clone(),
                    status,
                    license: s.license.clone(),
                    license_sha256: s.license_sha256.clone(),
                    url: s.url.clone(),
                    revision: s.revision.clone(),
                    updated_at_unix: s.updated_at_unix,
                    fetched_at_unix: s.fetched_at_unix,
                    expires_at_unix: s.expires_at_unix,
                }
            })
            .collect();
        let (value, status, reason) = if disputed {
            (None, "conflict", Some("review_required"))
        } else if yes && no.is_some() {
            (None, "conflict", Some("conflicting_sources"))
        } else if yes {
            (Some(true), "listed", None)
        } else if let Some(status) = no {
            (Some(false), status, None)
        } else if sources.is_empty() {
            (
                None,
                "unknown",
                Some(self.reason.unwrap_or("not_configured")),
            )
        } else if sources
            .iter()
            .all(|s| matches!(s.status, "stale" | "future_data"))
        {
            (None, "unknown", Some("no_fresh_data"))
        } else if unavailable {
            (None, "partial", Some("incomplete_data"))
        } else {
            (None, "not_listed", None)
        };
        Fact {
            value,
            status,
            scope,
            reason,
            sources,
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn read(path: &PathBuf) -> Option<Vec<u8>> {
    let mut data = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take((MAX_BYTES + 1) as u64).read_to_end(&mut data))
        .ok()?;
    Some(data)
}

/// The loaded snapshot, swapped atomically when the override file changes and parses.
pub struct DomainStore {
    path: Option<PathBuf>,
    current: RwLock<Arc<DomainData>>,
    seen: Mutex<Option<Vec<u8>>>,
    loaded_at: AtomicU64,
    failures: AtomicU64,
}

impl DomainStore {
    pub fn new(data: DomainData) -> Self {
        let loaded = data.reason.is_none();
        Self {
            path: None,
            current: RwLock::new(Arc::new(data)),
            seen: Mutex::new(None),
            loaded_at: AtomicU64::new(if loaded { now() } else { 0 }),
            failures: AtomicU64::new(0),
        }
    }

    pub fn from_env() -> Self {
        let Some(path) = std::env::var_os("OPENFINGERPRINT_DOMAIN_DATA").map(PathBuf::from) else {
            return Self::new(DomainData::load(Some(include_bytes!(
                "../data/domains.json"
            ))));
        };
        let bytes = read(&path);
        let digest = bytes.as_deref().map(sha256);
        let store = Self {
            path: Some(path),
            ..Self::new(DomainData::load(bytes.as_deref()))
        };
        *store.seen.lock().unwrap() = digest;
        store
    }

    pub fn reloads(&self) -> bool {
        self.path.is_some()
    }

    pub fn current(&self) -> Arc<DomainData> {
        self.current.read().unwrap().clone()
    }

    /// Re-reads the override file. A changed file replaces the snapshot only if it
    /// parses; otherwise the last valid snapshot stays until its sources expire.
    pub fn reload(&self) {
        let Some(path) = &self.path else { return };
        let bytes = read(path);
        let digest = bytes.as_deref().map(sha256);
        {
            let mut seen = self.seen.lock().unwrap();
            if *seen == digest {
                return;
            }
            seen.clone_from(&digest);
        }
        let data = DomainData::load(bytes.as_deref());
        let mut current = self.current.write().unwrap();
        if data.reason.is_none() {
            *current = Arc::new(data);
            self.loaded_at.store(now(), Ordering::Relaxed);
        } else {
            self.failures.fetch_add(1, Ordering::Relaxed);
            if current.reason.is_some() {
                *current = Arc::new(data);
            }
        }
    }

    pub fn metrics(&self) -> String {
        let mut out = String::new();
        self.current().write_metrics(&mut out);
        let _ = writeln!(
            out,
            "# HELP openfingerprint_domain_data_loaded_timestamp_seconds When the current snapshot was loaded.\n# TYPE openfingerprint_domain_data_loaded_timestamp_seconds gauge\nopenfingerprint_domain_data_loaded_timestamp_seconds {}\n# HELP openfingerprint_domain_data_reload_failures_total Changed snapshot files that could not be read or parsed.\n# TYPE openfingerprint_domain_data_reload_failures_total counter\nopenfingerprint_domain_data_reload_failures_total {}",
            self.loaded_at.load(Ordering::Relaxed),
            self.failures.load(Ordering::Relaxed)
        );
        out
    }
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .to_vec()
}

impl Source {
    fn lookup(&self, domain: &str) -> &'static str {
        if self.category == Category::DisposableReview {
            return if self.domains.contains(domain) {
                "disputed"
            } else {
                "not_listed"
            };
        }
        let boundary = psl::suffix_str(domain).unwrap_or(domain).len();
        for candidate in
            std::iter::successors(Some(domain), |s| s.split_once('.').map(|(_, rest)| rest))
        {
            if self.category != Category::FreeSubdomain && candidate.len() <= boundary {
                return if self.domains.contains(candidate) {
                    "public_suffix_excluded"
                } else {
                    "not_listed"
                };
            }
            if self.allowlist.contains(candidate) {
                return "allowlisted";
            }
            if self.domains.contains(candidate) {
                return if self.category == Category::FreeSubdomain && candidate == domain {
                    "provider_domain"
                } else {
                    "listed"
                };
            }
        }
        "not_listed"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn source(category: &str, domains: &[&str]) -> serde_json::Value {
        serde_json::json!({"id":category,"category":category,"license":"CC0-1.0","license_text":"fixture","license_sha256":crate::check::sha256("fixture"),"url":"https://example.test/source","revision":"fixture1","updated_at_unix":1000,"fetched_at_unix":1000,"expires_at_unix":2000,"domains":domains,"allowlist":[]})
    }
    fn data(sources: Vec<serde_json::Value>) -> DomainData {
        DomainData::parse(
            &serde_json::to_vec(&serde_json::json!({"version":1,"sources":sources})).unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn classifications_are_independent_and_missing_is_not_false() {
        let d = data(vec![
            source("disposable", &["mail.example"]),
            source("free_subdomain", &["is-a.dev"]),
            source("referrer_spam", &["spam.example"]),
        ]);
        let r = d.check_at("mail.example", &[], 1500).facts.unwrap();
        assert_eq!(r.disposable.value, Some(true));
        assert_eq!(r.free_subdomain.value, None);
        assert_eq!(r.spam.value, None);
        assert_eq!(r.spam.scope, "referrer_spam");
        assert_eq!(r.spam.status, "not_listed");
        let r = d.check_at("spam.example", &[], 1500).facts.unwrap();
        assert_eq!(r.spam.value, Some(true));
        assert_eq!(r.disposable.value, None);
        let r = d.check_at("tenant.is-a.dev", &[], 1500).facts.unwrap();
        assert_eq!(r.free_subdomain.value, Some(true));
        let r = d.check_at("is-a.dev", &[], 1500).facts.unwrap();
        assert_eq!(r.free_subdomain.value, Some(false));
        assert_eq!(r.free_subdomain.status, "provider_domain");
    }
    #[test]
    fn matches_labels_without_promoting_tenants_or_public_suffixes() {
        let d = data(vec![
            source(
                "disposable",
                &[
                    "mail.example",
                    "bad.github.io",
                    "co.uk",
                    "bar.ck",
                    "city.kawasaki.jp",
                ],
            ),
            source("referrer_spam", &["github.io", "bad.example"]),
        ]);
        assert_eq!(
            d.check_at("child.mail.example", &[], 1500)
                .facts
                .unwrap()
                .disposable
                .value,
            Some(true)
        );
        for input in [
            "notmail.example",
            "example",
            "good.github.io",
            "github.io",
            "co.uk",
            "innocent.co.uk",
            "foo.bar.ck",
        ] {
            let r = d.check_at(input, &[], 1500).facts.unwrap();
            assert_eq!(r.disposable.value, None);
            assert_eq!(r.spam.value, None);
        }
        assert_eq!(
            d.check_at("bad.github.io", &[], 1500)
                .facts
                .unwrap()
                .disposable
                .value,
            Some(true)
        );
        assert_eq!(
            d.check_at("example", &[], 1500).facts.unwrap().spam.value,
            None
        );
    }
    #[test]
    fn suffix_exceptions_keep_the_original_query_boundary() {
        let d = data(vec![source("disposable", &["kawasaki.jp"])]);
        assert_eq!(
            d.check_at("city.kawasaki.jp", &[], 1500)
                .facts
                .unwrap()
                .disposable
                .value,
            None
        );
        let d = data(vec![source("disposable", &["city.kawasaki.jp"])]);
        assert_eq!(
            d.check_at("child.city.kawasaki.jp", &[], 1500)
                .facts
                .unwrap()
                .disposable
                .value,
            Some(true)
        );
    }

    #[test]
    fn specific_allowlists_and_conflicting_sources_are_explicit() {
        let mut s = source("disposable", &["mail.example", "bad.good.mail.example"]);
        s["allowlist"] = serde_json::json!(["good.mail.example"]);
        let d = data(vec![s.clone()]);
        assert_eq!(
            d.check_at("good.mail.example", &[], 1500)
                .facts
                .unwrap()
                .disposable
                .value,
            Some(false)
        );
        assert_eq!(
            d.check_at("child.good.mail.example", &[], 1500)
                .facts
                .unwrap()
                .disposable
                .value,
            Some(false)
        );
        assert_eq!(
            d.check_at("bad.good.mail.example", &[], 1500)
                .facts
                .unwrap()
                .disposable
                .value,
            Some(true)
        );
        let mut other = source("disposable", &["good.mail.example"]);
        other["id"] = serde_json::json!("other");
        let d = data(vec![s, other]);
        let r = d
            .check_at("good.mail.example", &[], 1500)
            .facts
            .unwrap()
            .disposable;
        assert_eq!(r.value, None);
        assert_eq!(r.status, "conflict");
    }
    #[test]
    fn reviewed_disputes_are_exact_unknowns_and_do_not_expire_into_accusations() {
        let d = data(vec![
            source("disposable", &["mail.example"]),
            source("disposable_review", &["mail.example", "vip.mail.example"]),
        ]);
        for input in ["mail.example", "vip.mail.example"] {
            let result = d.check_at(input, &[], 1500);
            assert_eq!(result.status, "partial");
            let fact = result.facts.unwrap().disposable;
            assert_eq!(fact.value, None);
            assert_eq!(fact.status, "conflict");
            assert_eq!(fact.reason, Some("review_required"));
            assert_eq!(fact.sources[1].status, "disputed");
        }
        assert_eq!(
            d.check_at("child.mail.example", &[], 1500)
                .facts
                .unwrap()
                .disposable
                .value,
            Some(true)
        );
        let mut review = source("disposable_review", &["mail.example"]);
        review["expires_at_unix"] = serde_json::json!(1400);
        let d = data(vec![source("disposable", &["mail.example"]), review]);
        let fact = d
            .check_at("mail.example", &[], 1500)
            .facts
            .unwrap()
            .disposable;
        assert_eq!(fact.value, None);
        assert_eq!(fact.status, "conflict");
        assert_eq!(fact.sources[1].status, "stale");
    }

    #[test]
    fn mx_hosts_on_listed_providers_infer_disposable_conservatively() {
        let mut s = source("disposable", &["temp.example", "mail.example", "co.uk"]);
        s["allowlist"] = serde_json::json!(["good.temp.example"]);
        let d = data(vec![s, source("disposable_review", &["mail.example"])]);
        let mx = |hosts: &[&str]| hosts.iter().map(|h| h.to_string()).collect::<Vec<_>>();
        let fact = |domain, hosts: &[&str], now| {
            d.check_at(domain, &mx(hosts), now)
                .facts
                .unwrap()
                .disposable
        };
        let r = fact("new.test", &["mx1.temp.example"], 1500);
        assert_eq!((r.value, r.status), (Some(true), "mx_listed"));
        assert_eq!(r.sources[0].status, "listed");
        for hosts in [
            &[][..],
            &["aspmx.l.google.com"],
            &["mx.new.test"],
            &["new.test"],
            &["mx1.temp.example", "good.temp.example"],
            &["mx1.temp.example", "mx.mail.example"],
            &["mx.mail.example"],
            &["mx.innocent.co.uk"],
        ] {
            let r = fact("new.test", hosts, 1500);
            assert_eq!((r.value, r.status), (None, "not_listed"), "{hosts:?}");
        }
        assert_eq!(fact("new.test", &["mx1.temp.example"], 2500).value, None);
        let r = fact("temp.example", &["aspmx.l.google.com"], 1500);
        assert_eq!((r.value, r.status), (Some(true), "listed"));
        let r = fact("good.temp.example", &["mx1.temp.example"], 1500);
        assert_eq!((r.value, r.status), (Some(false), "allowlisted"));
        let r = fact("mail.example", &["mx1.temp.example"], 1500);
        assert_eq!((r.value, r.status), (None, "conflict"));
        for invalid in [
            serde_json::json!([]),
            serde_json::json!("mx.temp.example"),
            serde_json::json!(["bad host"]),
            serde_json::json!(vec!["mx.temp.example"; 11]),
        ] {
            let r = d.check(serde_json::json!("new.test"), Some(invalid));
            assert_eq!((r.status, r.reason), ("invalid_input", Some("invalid_mx")));
        }
    }

    #[test]
    fn future_dated_disputes_remain_pending_not_clean_or_positive() {
        let mut review = source("disposable_review", &["mail.example"]);
        review["fetched_at_unix"] = serde_json::json!(2500);
        review["expires_at_unix"] = serde_json::json!(3500);
        let d = data(vec![source("disposable", &["mail.example"]), review]);
        let fact = d
            .check_at("mail.example", &[], 1500)
            .facts
            .unwrap()
            .disposable;
        assert_eq!(fact.value, None);
        assert_eq!(fact.reason, Some("review_required"));
        assert_eq!(fact.sources[1].status, "future_data");
    }

    #[test]
    fn expiry_future_clock_and_missing_sources_stay_unknown() {
        let d = data(vec![source("disposable", &["mail.example"])]);
        for now in [0, 2000, 3000] {
            let r = d
                .check_at("mail.example", &[], now)
                .facts
                .unwrap()
                .disposable;
            assert_eq!(r.value, None);
            assert_eq!(r.status, "unknown");
        }
        let r = DomainData::unavailable("invalid_data").check_at("mail.example", &[], 1500);
        assert_eq!(r.status, "unknown");
        assert_eq!(r.facts.unwrap().disposable.reason, Some("invalid_data"));
    }
    #[test]
    fn partial_freshness_never_reuses_expired_matches() {
        let mut stale = source("disposable", &["mail.example"]);
        stale["id"] = serde_json::json!("stale");
        stale["expires_at_unix"] = serde_json::json!(1400);
        let d = data(vec![source("disposable", &["other.example"]), stale]);
        let r = d.check_at("mail.example", &[], 1500);
        assert_eq!(r.status, "partial");
        let f = r.facts.unwrap().disposable;
        assert_eq!(f.value, None);
        assert_eq!(f.status, "partial");
        assert_eq!(f.reason, Some("incomplete_data"));
    }

    #[test]
    fn invalid_snapshots_fail_closed_without_disabling_the_verifier() {
        for field in ["license", "license_sha256", "url", "revision"] {
            let mut s = source("disposable", &["mail.example"]);
            s[field] = serde_json::json!("invalid value");
            assert!(
                DomainData::parse(
                    &serde_json::to_vec(&serde_json::json!({"version":1,"sources":[s]})).unwrap()
                )
                .is_err()
            );
        }
        for domain in [
            "com",
            "https://example.test",
            "bad..example",
            "UPPER.example",
        ] {
            let s = source("disposable", &[domain]);
            assert!(
                DomainData::parse(
                    &serde_json::to_vec(&serde_json::json!({"version":1,"sources":[s]})).unwrap()
                )
                .is_err()
            );
        }
        let s = source("free_subdomain", &["co.uk"]);
        assert!(
            DomainData::parse(
                &serde_json::to_vec(&serde_json::json!({"version":1,"sources":[s]})).unwrap()
            )
            .is_err()
        );
        let mut review = source("disposable_review", &["mail.example"]);
        review["allowlist"] = serde_json::json!(["mail.example"]);
        assert!(
            DomainData::parse(
                &serde_json::to_vec(&serde_json::json!({"version":1,"sources":[review]})).unwrap()
            )
            .is_err()
        );
        assert!(DomainData::parse(&vec![b' '; MAX_BYTES + 1]).is_err());
        assert!(DomainData::parse(b"{}").is_err());
        let s = source("disposable", &["mail.example"]);
        assert!(
            DomainData::parse(
                &serde_json::to_vec(&serde_json::json!({"version":1,"sources":[s,s]})).unwrap()
            )
            .is_err()
        );
    }
    #[test]
    fn bundled_snapshot_is_valid_and_contains_only_open_sources() {
        let raw: serde_json::Value =
            serde_json::from_slice(include_bytes!("../data/domains.json")).unwrap();
        for source in raw["sources"].as_array().unwrap() {
            let one = serde_json::json!({"version":1,"sources":[source]});
            assert!(
                DomainData::parse(&serde_json::to_vec(&one).unwrap()).is_ok(),
                "invalid bundled source category: {}",
                source["category"]
            );
        }
        let d = DomainData::parse(include_bytes!("../data/domains.json")).unwrap();
        assert_eq!(d.sources.len(), 7);
        let at = d.sources[0].fetched_at_unix;
        let r = d.check_at("sharklasers.com", &[], at).facts.unwrap();
        assert_eq!(r.disposable.value, Some(true));
        assert_eq!(r.spam.scope, "referrer_spam");
        assert_eq!(
            d.sources
                .iter()
                .find(|s| s.id == "fakefilter_recent")
                .unwrap()
                .license,
            "BSD-3-Clause"
        );
        for name in ["21cn.com", "vip.21cn.com"] {
            let result = d.check_at(name, &[], at).facts.unwrap().disposable;
            assert_eq!(result.value, None);
            assert_eq!(result.reason, Some("review_required"));
        }
        assert_eq!(
            d.check_at("tenant.duckdns.org", &[], at)
                .facts
                .unwrap()
                .free_subdomain
                .value,
            Some(true)
        );
    }

    #[test]
    fn reload_swaps_valid_snapshots_and_keeps_the_last_good_one() {
        let path = std::env::temp_dir().join(format!(
            "openfingerprint-reload-{}-{}.json",
            std::process::id(),
            now()
        ));
        let snapshot = |domain: &str| {
            serde_json::to_vec(
                &serde_json::json!({"version":1,"sources":[source("disposable", &[domain])]}),
            )
            .unwrap()
        };
        let listed = |store: &DomainStore, domain| {
            store
                .current()
                .check_at(domain, &[], 1500)
                .facts
                .map(|f| f.disposable.value)
        };
        let store = DomainStore {
            path: Some(path.clone()),
            ..DomainStore::new(DomainData::load(read(&path).as_deref()))
        };
        assert_eq!(store.current().reason, Some("data_unavailable"));
        store.reload();
        assert_eq!(store.failures.load(Ordering::Relaxed), 0);
        std::fs::write(&path, snapshot("first.example")).unwrap();
        store.reload();
        assert_eq!(listed(&store, "first.example"), Some(Some(true)));
        std::fs::write(&path, b"{}").unwrap();
        store.reload();
        store.reload();
        assert_eq!(store.failures.load(Ordering::Relaxed), 1);
        assert_eq!(listed(&store, "first.example"), Some(Some(true)));
        std::fs::write(&path, snapshot("second.example")).unwrap();
        store.reload();
        assert_eq!(listed(&store, "first.example"), Some(None));
        assert_eq!(listed(&store, "second.example"), Some(Some(true)));
        std::fs::remove_file(&path).unwrap();
        store.reload();
        assert_eq!(store.failures.load(Ordering::Relaxed), 2);
        assert_eq!(listed(&store, "second.example"), Some(Some(true)));
        let metrics = store.metrics();
        for line in [
            "openfingerprint_domain_data_loaded 1",
            "openfingerprint_domain_data_source_expiry_timestamp_seconds{source=\"disposable\"} 2000",
            "openfingerprint_domain_data_source_entries{source=\"disposable\"} 1",
            "openfingerprint_domain_data_reload_failures_total 2",
        ] {
            assert!(metrics.lines().any(|l| l == line), "{line}");
        }
        assert!(
            DomainStore::new(DomainData::unavailable("invalid_data"))
                .metrics()
                .lines()
                .any(|l| l == "openfingerprint_domain_data_loaded 0")
        );
    }
}
