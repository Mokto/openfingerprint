use std::{
    collections::HashMap,
    fmt::Write as _,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::sync::Semaphore;

use axum::{
    body::Bytes,
    http::{Request, header},
};
use http_body_util::{BodyExt, Empty, Limited};
use hyper_rustls::HttpsConnector;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use serde::Serialize;

const TIMEOUT: Duration = Duration::from_secs(2);
const MAX_BODY: usize = 256 * 1024;
// Concurrent requests per registry server; the rest wait inside the same two-second budget.
// Bursts beyond this were throttled (HTTP 429) or timed out in testing.
const RDAP_PARALLEL: usize = 4;
const WHOIS_PARALLEL: usize = 2;
const RESULTS: [&str; 5] = [
    "found",
    "no_date",
    "not_found",
    "unavailable",
    "unsupported_tld",
];

#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all(serialize = "camelCase"))]
pub struct Registration {
    pub(crate) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    registered_at_unix: Option<u64>,
}

impl Registration {
    pub fn found(registered_at_unix: u64) -> Self {
        Self {
            status: "found",
            registered_at_unix: Some(registered_at_unix),
        }
    }

    pub fn status(status: &'static str) -> Self {
        Self {
            status,
            registered_at_unix: None,
        }
    }
}

// One GET to the registry from the bundled IANA bootstrap, following at most one redirect to the
// same domain path, or one WHOIS query for TLDs without RDAP. No retries. Through the cache, each
// registered domain reaches its registry at most once per TTL while Redis is up.
pub struct Rdap {
    client: Client<HttpsConnector<HttpConnector>, Empty<Bytes>>,
    servers: HashMap<String, String>,
    whois: HashMap<String, String>,
    limits: HashMap<String, Arc<Semaphore>>,
    counts: [AtomicU64; 5],
    whois_counts: [AtomicU64; 5],
    cache: crate::cache::Cache,
}

impl Rdap {
    pub fn from_env(redis: redis::Client) -> Result<Self, &'static str> {
        let cache = crate::cache::Cache::new(redis);
        let whois = match std::env::var("OPENFINGERPRINT_WHOIS_SERVERS") {
            Ok(path) => {
                std::fs::read(path).map_err(|_| "Unreadable OPENFINGERPRINT_WHOIS_SERVERS")?
            }
            Err(_) => include_bytes!("../data/whois-servers.json").to_vec(),
        };
        let whois = crate::whois::servers(&whois).ok_or("Invalid WHOIS server list")?;
        let rdap = match std::env::var("OPENFINGERPRINT_RDAP_BOOTSTRAP") {
            Ok(path) => Self::new(
                &std::fs::read(path).map_err(|_| "Unreadable OPENFINGERPRINT_RDAP_BOOTSTRAP")?,
                true,
                cache,
            ),
            Err(_) => Self::new(include_bytes!("../data/rdap-dns.json"), false, cache),
        }?;
        Ok(rdap.with_whois(whois))
    }

    pub fn with_whois(self, whois: HashMap<String, String>) -> Self {
        let mut limits = self.limits;
        for server in whois.values() {
            limits
                .entry(server.clone())
                .or_insert_with(|| Arc::new(Semaphore::new(WHOIS_PARALLEL)));
        }
        Self {
            whois,
            limits,
            ..self
        }
    }

    /// `allow_http` exists for local test servers; the bundled bootstrap uses HTTPS only.
    pub fn new(
        bootstrap: &[u8],
        allow_http: bool,
        cache: crate::cache::Cache,
    ) -> Result<Self, &'static str> {
        let servers = parse_bootstrap(bootstrap, allow_http).ok_or("Invalid RDAP bootstrap")?;
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();
        let limits = servers
            .values()
            .map(|base| (base.clone(), Arc::new(Semaphore::new(RDAP_PARALLEL))))
            .collect();
        Ok(Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
            servers,
            whois: HashMap::new(),
            limits,
            counts: Default::default(),
            whois_counts: Default::default(),
            cache,
        })
    }

    /// `domain` must already be a validated, lower-case hostname without a trailing dot.
    pub async fn lookup(&self, domain: &str) -> Registration {
        let Some((registrable, tld)) = registrable(domain) else {
            return Registration::status("not_applicable");
        };
        let (server, counts) = match (self.servers.get(tld), self.whois.get(tld)) {
            (Some(base), _) => (base, &self.counts),
            (None, Some(host)) => (host, &self.whois_counts),
            (None, None) => {
                self.counts[4].fetch_add(1, Ordering::Relaxed);
                return Registration::status("unsupported_tld");
            }
        };
        // Hashed so a cache dump does not list checked domains in clear text.
        let key = format!(
            "openfingerprint:rdap:v2:{}",
            crate::check::sha256(registrable)
        );
        if let Some(cached) = self.cache.get(&key).await.and_then(|v| decode(&v)) {
            return cached;
        }
        let rdap = self.servers.contains_key(tld);
        let request = async {
            // Includes the wait for a per-registry slot: a throttled registry queues callers.
            let _timer = crate::metrics::start(if rdap {
                crate::metrics::Step::RdapFetch
            } else {
                crate::metrics::Step::WhoisFetch
            });
            let _permit = self.limits.get(server)?.acquire().await.ok()?;
            Some(if rdap {
                self.fetch(&format!("{server}domain/{registrable}")).await
            } else {
                crate::whois::query(server, registrable).await
            })
        };
        let result = tokio::time::timeout(TIMEOUT, request)
            .await
            .ok()
            .flatten()
            .unwrap_or(Registration::status("unavailable"));
        if let Some(i) = RESULTS.iter().position(|s| *s == result.status) {
            counts[i].fetch_add(1, Ordering::Relaxed);
        }
        if let Some((value, ttl)) = encode(&result) {
            self.cache.set(&key, &value, ttl).await;
        }
        result
    }

    async fn fetch(&self, url: &str) -> Registration {
        let unavailable = Registration::status("unavailable");
        let mut target = url.to_owned();
        let mut response = None;
        for _ in 0..2 {
            let Ok(request) = Request::get(&target)
                .header(header::ACCEPT, "application/rdap+json")
                .body(Empty::new())
            else {
                return unavailable;
            };
            let Ok(r) = self.client.request(request).await else {
                return unavailable;
            };
            if !r.status().is_redirection() {
                response = Some(r);
                break;
            }
            // Registries may refer to a sub-registry (.ua): one hop, to HTTPS, same domain path.
            let next = r
                .headers()
                .get(header::LOCATION)
                .and_then(|l| l.to_str().ok());
            match next.filter(|n| target == url && referral(url, n)) {
                Some(next) => target = next.to_owned(),
                None => return unavailable,
            }
        }
        let Some(response) = response else {
            return unavailable;
        };
        match response.status().as_u16() {
            200 => {}
            404 => return Registration::status("not_found"),
            _ => return unavailable,
        }
        match Limited::new(response.into_body(), MAX_BODY).collect().await {
            Ok(body) => parse_domain(&body.to_bytes(), &target),
            Err(_) => unavailable,
        }
    }

    pub fn metrics(&self) -> String {
        let mut out = self.cache.metrics();
        out.push_str(
            "# HELP openfingerprint_rdap_lookups_total RDAP registration lookups by outcome.\n# TYPE openfingerprint_rdap_lookups_total counter\n",
        );
        for (result, count) in RESULTS.iter().zip(&self.counts) {
            let _ = writeln!(
                out,
                "openfingerprint_rdap_lookups_total{{result=\"{result}\"}} {}",
                count.load(Ordering::Relaxed)
            );
        }
        out.push_str(
            "# HELP openfingerprint_whois_lookups_total WHOIS registration lookups for TLDs without RDAP, by outcome.\n# TYPE openfingerprint_whois_lookups_total counter\n",
        );
        for (result, count) in RESULTS[..4].iter().zip(&self.whois_counts) {
            let _ = writeln!(
                out,
                "openfingerprint_whois_lookups_total{{result=\"{result}\"}} {}",
                count.load(Ordering::Relaxed)
            );
        }
        out
    }
}

/// Cached answers: registration dates change only when a domain is re-registered; a domain
/// that is not registered yet may be soon. Unavailable answers are never cached.
fn encode(r: &Registration) -> Option<(String, u64)> {
    match (r.status, r.registered_at_unix) {
        ("found", Some(at)) => Some((format!("found:{at}"), 86400)),
        ("no_date", _) => Some(("no_date".into(), 86400)),
        ("not_found", _) => Some(("not_found".into(), 3600)),
        _ => None,
    }
}

fn decode(value: &str) -> Option<Registration> {
    match value {
        "no_date" => Some(Registration::status("no_date")),
        "not_found" => Some(Registration::status("not_found")),
        _ => Some(Registration {
            status: "found",
            registered_at_unix: Some(value.strip_prefix("found:")?.parse().ok()?),
        }),
    }
}

/// An absolute HTTPS URL on a DNS name whose path still ends in `/domain/<queried name>`.
fn referral(from: &str, to: &str) -> bool {
    let Some(rest) = to.strip_prefix("https://") else {
        return false;
    };
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let queried = from.rsplit('/').next().unwrap_or_default();
    crate::check::domain(host)
        && host.parse::<std::net::IpAddr>().is_err()
        && !to.contains(['?', '#', '@'])
        && path
            .strip_suffix(queried)
            .is_some_and(|p| p.ends_with("domain/"))
}

fn parse_bootstrap(bytes: &[u8], allow_http: bool) -> Option<HashMap<String, String>> {
    #[derive(serde::Deserialize)]
    struct Bootstrap {
        services: Vec<(Vec<String>, Vec<String>)>,
    }
    let bootstrap: Bootstrap = serde_json::from_slice(bytes).ok()?;
    let mut servers = HashMap::new();
    for (tlds, urls) in bootstrap.services {
        let Some(url) = urls
            .iter()
            .find(|u| u.starts_with("https://") || (allow_http && u.starts_with("http://")))
        else {
            continue;
        };
        let url = if url.ends_with('/') {
            url.clone()
        } else {
            format!("{url}/")
        };
        for tld in tlds {
            servers.insert(tld.to_ascii_lowercase(), url.clone());
        }
    }
    (!servers.is_empty()).then_some(servers)
}

/// The domain registered under its ICANN public suffix, and its TLD. `None` for tenants of
/// private namespaces (their registrable domain belongs to the namespace operator) and for
/// public suffixes themselves.
fn registrable(domain: &str) -> Option<(&str, &str)> {
    let own = psl::suffix(domain.as_bytes())?;
    if own.typ() == Some(psl::Type::Private) && own.as_bytes().len() < domain.len() {
        return None;
    }
    let starts: Vec<usize> = std::iter::once(0)
        .chain(domain.match_indices('.').map(|(i, _)| i + 1))
        .collect();
    let last = *starts.last()?;
    let public = starts
        .iter()
        .position(|&start| {
            let candidate = &domain[start..];
            psl::suffix(candidate.as_bytes()).is_some_and(|s| {
                s.as_bytes() == candidate.as_bytes() && s.typ() != Some(psl::Type::Private)
            })
        })
        .unwrap_or(starts.len() - 1);
    Some((
        &domain[*starts.get(public.checked_sub(1)?)?..],
        &domain[last..],
    ))
}

fn parse_domain(body: &[u8], url: &str) -> Registration {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Registration::status("unavailable");
    };
    let queried = url.rsplit('/').next().unwrap_or_default();
    if value["objectClassName"] != "domain"
        || value["ldhName"]
            .as_str()
            .is_some_and(|name| !name.trim_end_matches('.').eq_ignore_ascii_case(queried))
    {
        return Registration::status("unavailable");
    }
    let registered = value["events"].as_array().and_then(|events| {
        events
            .iter()
            .find(|e| e["eventAction"] == "registration")
            .and_then(|e| unix(e["eventDate"].as_str()?))
    });
    match registered {
        Some(at) => Registration {
            status: "found",
            registered_at_unix: Some(at),
        },
        None => Registration::status("no_date"),
    }
}

/// RFC 3339 date-time to Unix seconds.
fn unix(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| {
        s.get(r)
            .filter(|t| t.bytes().all(|c| c.is_ascii_digit()))?
            .parse::<i64>()
            .ok()
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, se) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let mut rest = &s[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        rest = &fraction[digits..];
    }
    let offset = match rest.as_bytes() {
        [b'Z' | b'z'] => 0,
        [sign @ (b'+' | b'-'), _, _, b':', _, _] => {
            let hours = num(s.len() - 5..s.len() - 3)?;
            let minutes = num(s.len() - 2..s.len())?;
            if hours > 23 || minutes > 59 {
                return None;
            }
            let minutes = hours * 60 + minutes;
            if *sign == b'-' { -minutes } else { minutes }
        }
        _ => return None,
    };
    let month_days = match mo {
        2 if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => return None,
    };
    if !(1..=month_days).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    u64::try_from(days(y, mo, d) * 86400 + h * 3600 + mi * 60 + se - offset * 60).ok()
}

/// Days from 1970-01-01 to a proleptic Gregorian date.
pub fn days(y: i64, mo: i64, d: i64) -> i64 {
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((mo + 9) % 12) + 2) / 5 + d - 1;
    era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rfc3339_instants() {
        for (input, expected) in [
            ("1970-01-01T00:00:00Z", Some(0)),
            ("1995-08-14T04:00:00Z", Some(808372800)),
            ("2014-03-20T12:59:17.0Z", Some(1395320357)),
            ("2024-02-29T23:59:59.123456z", Some(1709251199)),
            ("2026-11-06T22:00:00+01:00", Some(1793998800)),
            ("2026-11-06T20:30:00-00:30", Some(1793998800)),
            ("2026-11-06 21:00:00Z", None),
            ("2026-13-06T21:00:00Z", None),
            ("2026-00-06T21:00:00Z", None),
            ("2026-02-00T00:00:00Z", None),
            ("2026-02-31T00:00:00Z", None),
            ("2026-04-31T00:00:00Z", None),
            ("2026-02-29T00:00:00Z", None),
            ("1900-02-29T00:00:00Z", None),
            ("2000-02-29T00:00:00Z", Some(951782400)),
            ("2100-02-29T00:00:00Z", None),
            ("2026-01-10T00:00:00+24:00", None),
            ("2026-01-10T00:00:00-24:00", None),
            ("2026-01-10T00:00:00+00:60", None),
            ("2026-01-10T00:00:00-00:99", None),
            ("2026-11-06T21:00:00", None),
            ("2026-11-06T21:00:00.Z", None),
            ("2026-11-06T21:00:00+0100", None),
            ("+026-11-06T21:00:00Z", None),
            ("1969-12-31T23:59:59Z", None),
            ("", None),
        ] {
            assert_eq!(unix(input), expected, "{input}");
        }
    }

    #[test]
    fn queries_the_icann_registrable_domain() {
        for (domain, expected) in [
            ("mail.example.com", Some(("example.com", "com"))),
            ("example.com", Some(("example.com", "com"))),
            ("a.b.bbc.co.uk", Some(("bbc.co.uk", "uk"))),
            ("github.io", Some(("github.io", "io"))),
            ("new.example", Some(("new.example", "example"))),
            ("tenant.github.io", None),
            ("co.uk", None),
        ] {
            assert_eq!(registrable(domain), expected, "{domain}");
        }
    }

    #[test]
    fn reads_only_the_registration_event_of_the_queried_domain() {
        let url = "https://rdap.example/domain/example.com";
        let body = |name: &str, events: &str| {
            format!(r#"{{"objectClassName":"domain","ldhName":"{name}","events":{events}}}"#)
        };
        let events = r#"[{"eventAction":"expiration","eventDate":"2030-01-01T00:00:00Z"},{"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"}]"#;
        assert_eq!(
            parse_domain(body("EXAMPLE.COM.", events).as_bytes(), url),
            Registration {
                status: "found",
                registered_at_unix: Some(808372800)
            }
        );
        for (input, status) in [
            (body("example.com", "[]"), "no_date"),
            (
                body(
                    "example.com",
                    r#"[{"eventAction":"registration","eventDate":"redacted"}]"#,
                ),
                "no_date",
            ),
            (
                body(
                    "example.com",
                    r#"[{"eventAction":"registration","eventDate":"2026-02-31T00:00:00Z"}]"#,
                ),
                "no_date",
            ),
            (body("other.com", events), "unavailable"),
            (
                r#"{"objectClassName":"entity","events":[]}"#.into(),
                "unavailable",
            ),
            ("not json".into(), "unavailable"),
        ] {
            assert_eq!(parse_domain(input.as_bytes(), url).status, status);
        }
    }

    #[test]
    fn bootstrap_maps_tlds_to_https_servers() {
        let bootstrap = br#"{"services":[[["COM","net"],["https://rdap.verisign.example/v1"]],[["plain"],["http://rdap.plain.example/"]]]}"#;
        let servers = parse_bootstrap(bootstrap, false).unwrap();
        assert_eq!(servers["com"], "https://rdap.verisign.example/v1/");
        assert_eq!(servers["net"], "https://rdap.verisign.example/v1/");
        assert!(!servers.contains_key("plain"));
        assert!(
            parse_bootstrap(bootstrap, true)
                .unwrap()
                .contains_key("plain")
        );
        assert!(parse_bootstrap(b"{}", false).is_none());
        let bundled = parse_bootstrap(include_bytes!("../data/rdap-dns.json"), false).unwrap();
        assert!(bundled.len() > 1000 && bundled.values().all(|u| u.starts_with("https://")));
    }

    #[tokio::test]
    async fn fetches_bounded_responses_without_following_unsafe_redirects() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let bootstrap = format!(r#"{{"services":[[["test"],["http://{addr}/rdap"]]]}}"#);
        // A Redis that refuses connections: every lookup falls back to the registry.
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let down = closed.local_addr().unwrap().to_string();
        drop(closed);
        let rdap = Rdap::new(
            bootstrap.as_bytes(),
            true,
            crate::cache::Cache::new(crate::cache::tests::client_for(&down)),
        )
        .unwrap();
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let served = requests.clone();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                served.fetch_add(1, Ordering::Relaxed);
                let mut buf = [0; 2048];
                let n = stream.read(&mut buf).await.unwrap();
                let request = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
                let path = request
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_owned();
                assert!(request.contains("accept: application/rdap+json"));
                let (status, body) = match path.as_str() {
                    "/rdap/domain/found.test" => ("200 OK", r#"{"objectClassName":"domain","ldhName":"found.test","events":[{"eventAction":"registration","eventDate":"2026-11-01T00:00:00Z"}]}"#.to_owned()),
                    "/rdap/domain/huge.test" => ("200 OK", format!(r#"{{"objectClassName":"domain","pad":"{}"}}"#, "x".repeat(MAX_BODY))),
                    "/rdap/domain/moved.test" => ("302 Found", String::new()),
                    "/rdap/domain/broken.test" => ("503 Service Unavailable", String::new()),
                    _ => ("404 Not Found", String::new()),
                };
                let _ = stream
                    .write_all(format!("HTTP/1.1 {status}\r\nLocation: http://{addr}/rdap/domain/found.test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())
                    .await;
            }
        });
        let found = rdap.lookup("mail.found.test").await;
        assert_eq!(found.registered_at_unix, Some(1793491200));
        for (domain, status) in [
            ("missing.test", "not_found"),
            ("huge.test", "unavailable"),
            ("moved.test", "unavailable"),
            ("broken.test", "unavailable"),
            ("example.zz", "unsupported_tld"),
        ] {
            assert_eq!(rdap.lookup(domain).await.status, status, "{domain}");
        }
        let metrics = rdap.metrics();
        assert!(metrics.contains("result=\"found\"} 1"));
        assert!(metrics.contains("result=\"unavailable\"} 3"));

        let (redis, store) = crate::cache::tests::fake_redis(None).await;
        let cached = Rdap::new(
            bootstrap.as_bytes(),
            true,
            crate::cache::Cache::new(crate::cache::tests::client_for(&redis)),
        )
        .unwrap();
        let legacy_key = format!(
            "openfingerprint:rdap:v1:{}",
            crate::check::sha256("found.test")
        );
        store
            .lock()
            .unwrap()
            .insert(legacy_key.clone(), ("found:42".into(), "86400".into()));
        let before = requests.load(Ordering::Relaxed);
        for domain in [
            "found.test",
            "www.found.test",
            "missing.test",
            "missing.test",
            "broken.test",
            "broken.test",
        ] {
            cached.lookup(domain).await;
        }
        assert_eq!(cached.lookup("found.test").await, found);
        assert_eq!(
            requests.load(Ordering::Relaxed) - before,
            4,
            "found and missing once, unavailable every time"
        );
        let mut store = store.lock().unwrap();
        assert_eq!(
            store.remove(&legacy_key),
            Some(("found:42".into(), "86400".into()))
        );
        assert_eq!(store.len(), 2);
        assert!(
            store
                .keys()
                .all(|k| k.starts_with("openfingerprint:rdap:v2:") && !k.contains("test"))
        );
        let ttls: std::collections::BTreeSet<_> = store
            .values()
            .map(|(v, ttl)| (v.clone(), ttl.clone()))
            .collect();
        assert_eq!(
            ttls,
            [
                ("found:1793491200".into(), "86400".into()),
                ("not_found".into(), "3600".into())
            ]
            .into()
        );
    }

    #[test]
    fn follows_only_https_referrals_for_the_same_domain() {
        let from = "https://rdap.hostmaster.ua/domain/mailbox.in.ua";
        assert!(referral(from, "https://rdap.sunic.ua/domain/mailbox.in.ua"));
        for bad in [
            "http://rdap.sunic.ua/domain/mailbox.in.ua",
            "https://rdap.sunic.ua/domain/other.in.ua",
            "https://rdap.sunic.ua/entity/mailbox.in.ua",
            "https://10.0.0.1/domain/mailbox.in.ua",
            "https://user@rdap.sunic.ua/domain/mailbox.in.ua",
            "https://rdap.sunic.ua/domain/mailbox.in.ua?x=1",
            "/domain/mailbox.in.ua",
        ] {
            assert!(!referral(from, bad), "{bad}");
        }
    }

    #[tokio::test]
    async fn tlds_without_rdap_use_their_whois_server_and_count_separately() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut q = vec![0; 256];
                let n = s.read(&mut q).await.unwrap();
                let reply = if &q[..n] == b"old.wtest\r\n" {
                    "Domain Name: old.wtest\r\nCreated: 2001-02-03\r\n"
                } else {
                    "Domain not found.\r\n"
                };
                let _ = s.write_all(reply.as_bytes()).await;
            }
        });
        let rdap = Rdap::new(
            br#"{"services":[[["test"],["https://rdap.invalid/"]]]}"#,
            false,
            crate::cache::Cache::new(crate::cache::tests::client_for("127.0.0.1:1")),
        )
        .unwrap()
        .with_whois([("wtest".to_owned(), addr)].into());
        assert_eq!(
            rdap.lookup("mail.old.wtest").await,
            Registration::found(u64::try_from(days(2001, 2, 3) * 86400).unwrap())
        );
        assert_eq!(rdap.lookup("new.wtest").await.status, "not_found");
        assert_eq!(rdap.lookup("x.nowhois").await.status, "unsupported_tld");
        let metrics = rdap.metrics();
        assert!(metrics.contains("openfingerprint_whois_lookups_total{result=\"found\"} 1"));
        assert!(metrics.contains("openfingerprint_whois_lookups_total{result=\"not_found\"} 1"));
        assert!(metrics.contains("openfingerprint_rdap_lookups_total{result=\"found\"} 0"));
    }

    #[test]
    fn cached_answers_round_trip() {
        for r in [
            Registration {
                status: "found",
                registered_at_unix: Some(808372800),
            },
            Registration::status("no_date"),
            Registration::status("not_found"),
        ] {
            assert_eq!(decode(&encode(&r).unwrap().0), Some(r));
        }
        assert_eq!(encode(&Registration::status("unavailable")), None);
        assert_eq!(decode("found:soon"), None);
        assert_eq!(decode("garbage"), None);
    }
}
