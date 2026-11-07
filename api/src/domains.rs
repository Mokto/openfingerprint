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
    PublicMailbox,
    Relay,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    mx_lookup: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mx_providers: Option<Vec<crate::providers::Provider>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    registration: Option<crate::rdap::Registration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    spf: Option<crate::mailauth::Spf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dmarc: Option<crate::mailauth::Dmarc>,
}

impl DomainCheck {
    pub fn with_registration(self, registration: crate::rdap::Registration) -> Self {
        Self {
            registration: Some(registration),
            ..self
        }
    }

    pub fn with_mail_auth(self, spf: crate::mailauth::Spf, dmarc: crate::mailauth::Dmarc) -> Self {
        Self {
            spf: Some(spf),
            dmarc: Some(dmarc),
            ..self
        }
    }
}

#[derive(Serialize)]
struct Facts {
    disposable: Fact,
    free_subdomain: Fact,
    spam: Fact,
    public_mailbox: Fact,
    relay: Fact,
    did_you_mean: Option<String>,
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
                        || (matches!(
                            s.category,
                            Category::FreeSubdomain | Category::PublicMailbox | Category::Relay
                        ) && psl::suffix(d.as_bytes()).is_some_and(|suffix| {
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

    #[cfg(test)]
    pub fn check(&self, value: serde_json::Value) -> DomainCheck {
        match Self::input(value) {
            Err(invalid) => *invalid,
            Ok(domain) => self.check_with(&domain, &[], "not_needed"),
        }
    }

    /// Validates and normalizes a domain input.
    pub fn input(value: serde_json::Value) -> Result<String, Box<DomainCheck>> {
        match value.as_str().filter(|s| crate::check::domain(s)) {
            Some(s) => Ok(s.strip_suffix('.').unwrap_or(s).to_ascii_lowercase()),
            None => Err(Box::new(DomainCheck {
                status: "invalid_input",
                reason: Some("invalid_domain"),
                facts: None,
                mx_lookup: None,
                mx_providers: None,
                registration: None,
                spf: None,
                dmarc: None,
            })),
        }
    }

    /// Tenants of a listed free-subdomain namespace: the registered domain belongs to its operator.
    pub fn hosted_tenant(&self, domain: &str) -> bool {
        self.fact(
            domain,
            now(),
            Category::FreeSubdomain,
            "free_subdomain_namespace",
        )
        .value
            == Some(true)
    }

    pub fn check_with(&self, domain: &str, mx: &[String], mx_lookup: &'static str) -> DomainCheck {
        DomainCheck {
            mx_lookup: Some(mx_lookup),
            mx_providers: (mx_lookup == "resolved").then(|| crate::providers::detect(mx)),
            ..self.check_at(domain, mx, now())
        }
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
            public_mailbox: self.consumer_fact(
                self.fact(domain, now, Category::PublicMailbox, "public_mailbox"),
                mx,
            ),
            relay: self.fact(domain, now, Category::Relay, "email_relay"),
            did_you_mean: None,
        };
        let facts = Facts {
            did_you_mean: (facts.public_mailbox.status == "not_listed")
                .then(|| self.suggestion(domain, now))
                .flatten(),
            ..facts
        };
        let items = [
            &facts.disposable,
            &facts.free_subdomain,
            &facts.spam,
            &facts.public_mailbox,
            &facts.relay,
        ];
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
            mx_lookup: None,
            mx_providers: None,
            registration: None,
            spf: None,
            dmarc: None,
        }
    }

    /// A likely-intended public mailbox domain one edit away, in the suffix or after the first
    /// letter of the name, for names of five letters or more. Shorter names and first-letter edits
    /// mostly hit real sites (web.dev, pcloud.com in the Tranco top 20k), and swapping one
    /// two-letter country code for another usually names the same brand's regional domain
    /// (posteo.dk, hotmail.pt). Ambiguity suggests nothing.
    fn suggestion(&self, domain: &str, now: u64) -> Option<String> {
        let (name, suffix) = split(domain)?;
        let mut hits = self
            .sources
            .iter()
            .filter(|s| {
                s.category == Category::PublicMailbox
                    && s.fetched_at_unix <= now.saturating_add(300)
                    && s.expires_at_unix > now
            })
            .flat_map(|s| &s.domains)
            .filter(|target| {
                split(target).is_some_and(|(n, sfx)| {
                    n.len() >= 5
                        && ((n == name
                            && one_edit(suffix, sfx)
                            && !(suffix.len() == 2 && sfx.len() == 2))
                            || (sfx == suffix && n[..1] == name[..1] && one_edit(name, n)))
                })
            });
        let hit = hits.next()?;
        hits.next().is_none().then(|| hit.clone())
    }

    /// An otherwise unlisted domain whose mail goes only to a provider's consumer infrastructure.
    fn consumer_fact(&self, fact: Fact, mx: &[String]) -> Fact {
        match crate::providers::consumer(mx) {
            Some(_) if fact.status == "not_listed" => Fact {
                value: Some(true),
                status: "mx_listed",
                ..fact
            },
            _ => fact,
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

/// A registered domain as (name, public suffix); None for subdomains and bare suffixes.
fn split(d: &str) -> Option<(&str, &str)> {
    let suffix = psl::suffix_str(d)?;
    let name = d.strip_suffix(suffix)?.strip_suffix('.')?;
    (!name.contains('.')).then_some((name, suffix))
}

/// Exactly one substitution, insertion, deletion or adjacent transposition apart.
fn one_edit(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let prefix = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let (a, b) = (&a[prefix..], &b[prefix..]);
    match a.len() as isize - b.len() as isize {
        0 => {
            !a.is_empty()
                && (a[1..] == b[1..]
                    || (a.len() >= 2 && a[0] == b[1] && a[1] == b[0] && a[2..] == b[2..]))
        }
        1 => a[1..] == *b,
        -1 => b[1..] == *a,
        _ => false,
    }
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .to_vec()
}

impl Source {
    fn lookup(&self, domain: &str) -> &'static str {
        if self.category == Category::PublicMailbox {
            return if self.domains.contains(domain) {
                "listed"
            } else {
                "not_listed"
            };
        }
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
    fn one_edit_covers_typos_but_not_identity_or_two_edits() {
        for (a, b) in [
            ("gmial", "gmail"),
            ("gmai", "gmail"),
            ("gmaill", "gmail"),
            ("gnail", "gmail"),
            ("con", "com"),
            ("co", "com"),
            ("ocm", "com"),
        ] {
            assert!(one_edit(a, b) && one_edit(b, a), "{a} {b}");
        }
        for (a, b) in [
            ("gmail", "gmail"),
            ("gamli", "gmail"),
            ("de", "com"),
            ("", "ab"),
            ("ab", "ba "),
        ] {
            assert!(!one_edit(a, b), "{a} {b}");
        }
    }

    #[test]
    fn public_mailboxes_are_exact_relays_cover_subdomains_and_typos_suggest_once() {
        let d = data(vec![
            source(
                "public_mailbox",
                &[
                    "gmail.com",
                    "hotmail.com",
                    "hotmail.co.uk",
                    "gmx.de",
                    "gmx.net",
                    "live.com",
                    "me.com",
                ],
            ),
            source("relay", &["mozmail.com"]),
        ]);
        let check = |name: &str| serde_json::to_value(d.check_at(name, &[], 1500)).unwrap();
        assert_eq!(check("gmail.com")["public_mailbox"]["status"], "listed");
        assert_eq!(
            check("mail.gmail.com")["public_mailbox"]["status"],
            "not_listed"
        );
        assert_eq!(check("x.mozmail.com")["relay"]["value"], true);
        assert_eq!(check("gmail.com")["relay"]["status"], "not_listed");
        for (typo, want) in [
            ("gmial.com", Some("gmail.com")),
            ("gmail.con", Some("gmail.com")),
            ("gmail.co", Some("gmail.com")),
            ("hotmial.co.uk", Some("hotmail.co.uk")),
            ("live.co", None),
            ("gmx.dk", None),
            ("hotmail.pt", None),
            ("fmail.com", None),
            ("cloud.com", None),
            ("gmail.com", None),
            ("gmx.ne", None),
            ("gnx.de", None),
            ("mc.com", None),
            ("mail.gmial.com", None),
            ("co.uk", None),
            ("hotmail.org.uk", None),
        ] {
            assert_eq!(check(typo)["did_you_mean"].as_str(), want, "{typo}");
        }
        assert_eq!(
            serde_json::to_value(d.check_at("gmial.com", &[], 2500)).unwrap()["did_you_mean"],
            serde_json::Value::Null,
            "stale lists suggest nothing"
        );
    }

    /// `OPENFINGERPRINT_TYPO_EVAL=<one domain per line> cargo test typo_eval -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn typo_eval() {
        let list: Vec<String> = serde_json::from_str::<serde_json::Value>(include_str!(
            "../data/reviewed-public-mailboxes.json"
        ))
        .unwrap()["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["domain"].as_str().unwrap().to_owned())
            .collect();
        let d = data(vec![source(
            "public_mailbox",
            &list.iter().map(String::as_str).collect::<Vec<_>>(),
        )]);
        let names =
            std::fs::read_to_string(std::env::var("OPENFINGERPRINT_TYPO_EVAL").unwrap()).unwrap();
        let mut total = 0;
        for name in names
            .lines()
            .map(str::trim)
            .filter(|n| crate::check::domain(n))
        {
            total += 1;
            if let Some(hit) =
                serde_json::to_value(d.check_at(name, &[], 1500)).unwrap()["did_you_mean"].as_str()
            {
                println!("SUGGEST {name} -> {hit}");
            }
        }
        println!("checked {total}");
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
        assert_eq!(d.sources.len(), 9);
        let at = d.sources.iter().map(|s| s.fetched_at_unix).max().unwrap();
        assert!(d.sources.iter().all(|s| s.expires_at_unix > at));
        let r = d.check_at("sharklasers.com", &[], at).facts.unwrap();
        assert_eq!(r.disposable.value, Some(true));
        let gmail = d.check_at("gmail.com", &[], at).facts.unwrap();
        assert_eq!(
            (
                gmail.public_mailbox.value,
                gmail.disposable.value,
                gmail.relay.status
            ),
            (Some(true), None, "not_listed")
        );
        assert_eq!(
            d.check_at("x.mozmail.com", &[], at)
                .facts
                .unwrap()
                .relay
                .value,
            Some(true)
        );
        assert_eq!(
            d.check_at("gmial.com", &[], at)
                .facts
                .unwrap()
                .did_you_mean
                .as_deref(),
            Some("gmail.com")
        );
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
