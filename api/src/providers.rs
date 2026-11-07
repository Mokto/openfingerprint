use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Table {
    #[allow(dead_code)]
    license: String,
    #[allow(dead_code)]
    reviewed_at_unix: u64,
    providers: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    slug: String,
    #[serde(rename = "type")]
    kind: String,
    suffixes: Vec<String>,
    #[allow(dead_code)]
    evidence_urls: Vec<String>,
    /// Hosts that serve only the provider's shared consumer mailboxes, minus `business` hosts.
    #[serde(default)]
    consumer: Vec<String>,
    #[serde(default)]
    business: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    consumer_evidence: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Provider {
    slug: &'static str,
    #[serde(rename = "type")]
    kind: &'static str,
}

static PROVIDERS: LazyLock<Vec<(&'static str, Provider)>> = LazyLock::new(|| {
    let table: Table = serde_json::from_str(include_str!("../data/mx-providers.json"))
        .expect("bundled MX provider table is validated by tests");
    table
        .providers
        .into_iter()
        .flat_map(|e| {
            let provider = Provider {
                slug: e.slug.leak(),
                kind: e.kind.leak(),
            };
            e.suffixes
                .into_iter()
                .map(move |s| (&*s.leak(), provider.clone()))
        })
        .collect()
});

static CONSUMER: LazyLock<Vec<Entry>> = LazyLock::new(|| {
    let table: Table = serde_json::from_str(include_str!("../data/mx-providers.json"))
        .expect("bundled MX provider table is validated by tests");
    table
        .providers
        .into_iter()
        .filter(|e| !e.consumer.is_empty())
        .collect()
});

fn under(host: &str, suffix: &str) -> bool {
    host == suffix
        || host
            .strip_suffix(suffix)
            .is_some_and(|rest| rest.ends_with('.'))
}

/// The provider whose shared consumer mail infrastructure receives all of these MX hosts. Such a
/// domain's addresses belong to unrelated people, like the provider's own consumer domains.
pub fn consumer(hosts: &[String]) -> Option<&'static str> {
    let slug_of = |host: &String| {
        CONSUMER.iter().find_map(|e| {
            (e.consumer.iter().any(|s| under(host, s))
                && !e.business.iter().any(|s| under(host, s)))
            .then_some(e.slug.as_str())
        })
    };
    let first = slug_of(hosts.first()?)?;
    hosts
        .iter()
        .all(|h| slug_of(h) == Some(first))
        .then_some(first)
}

/// Services that run the domain's MX hosts, in MX preference order and without duplicates. An
/// empty list means self-hosted or unrecognised mail routing, not a missing provider.
pub fn detect(hosts: &[String]) -> Vec<Provider> {
    let mut found: Vec<Provider> = Vec::new();
    for host in hosts {
        let hit = PROVIDERS.iter().find(|(suffix, _)| under(host, suffix));
        if let Some((_, provider)) = hit
            && !found.contains(provider)
        {
            found.push(provider.clone());
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_table_is_valid_and_unambiguous() {
        let table: Table = serde_json::from_str(include_str!("../data/mx-providers.json")).unwrap();
        assert_eq!(table.license, "CC0-1.0");
        let mut slugs = std::collections::HashSet::new();
        let mut suffixes = std::collections::HashSet::new();
        for e in &table.providers {
            assert!(slugs.insert(e.slug.as_str()), "duplicate {}", e.slug);
            assert!(e.slug.bytes().all(|b| b.is_ascii_lowercase()));
            assert!(["mailbox", "forwarding", "gateway", "inbound"].contains(&e.kind.as_str()));
            assert!(
                !e.evidence_urls.is_empty()
                    && e.evidence_urls.iter().all(|u| u.starts_with("https://"))
            );
            for s in &e.suffixes {
                assert!(
                    crate::check::domain(s) && *s == s.to_ascii_lowercase(),
                    "{s}"
                );
                assert!(suffixes.insert(s.as_str()), "duplicate suffix {s}");
            }
        }
        for a in &suffixes {
            assert!(
                !suffixes
                    .iter()
                    .any(|b| b != a && b.ends_with(&format!(".{a}"))),
                "{a} nests another suffix"
            );
        }
        assert!(PROVIDERS.len() == suffixes.len());
        for e in &table.providers {
            for s in e.consumer.iter().chain(&e.business) {
                assert!(
                    e.suffixes.iter().any(|own| under(s, own)),
                    "{s} is outside {}'s own suffixes",
                    e.slug
                );
            }
            assert_eq!(
                e.consumer.is_empty(),
                e.consumer_evidence.is_empty(),
                "{}",
                e.slug
            );
        }
    }

    #[test]
    fn consumer_infrastructure_needs_every_mx_host_and_skips_business_hosts() {
        let hosts = |h: &[&str]| h.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            consumer(&hosts(&["hotmail-com.olc.protection.outlook.com"])),
            Some("microsoft")
        );
        assert_eq!(
            consumer(&hosts(&["mx-rogers.mail.am0.yahoodns.net"])),
            Some("yahoo")
        );
        assert_eq!(
            consumer(&hosts(&["mx00.mail.com", "mx01.mail.com"])),
            Some("mailcom")
        );
        assert_eq!(consumer(&hosts(&["mx00.emig.gmx.net"])), Some("gmx"));
        for not in [
            &["example-com.mail.protection.outlook.com"][..],
            &["mx-biz.mail.am0.yahoodns.net"],
            &["mta5.am0.yahoodns.net", "mx.example.com"],
            &["mx00.mail.com", "mta5.am0.yahoodns.net"],
            &["hotmail-nl.b-v1.mx.microsoft"],
            &[],
        ] {
            assert_eq!(consumer(&hosts(not)), None, "{not:?}");
        }
    }

    #[test]
    fn matches_whole_labels_in_preference_order_once() {
        let hosts = |h: &[&str]| h.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let slugs = |h: &[&str]| {
            detect(&hosts(h))
                .into_iter()
                .map(|p| p.slug)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            slugs(&[
                "eu-smtp-inbound-1.mimecast.com",
                "example-com.mail.protection.outlook.com",
                "eu-smtp-inbound-2.mimecast.com"
            ]),
            ["mimecast", "microsoft"]
        );
        assert_eq!(
            slugs(&[
                "aspmx.l.google.com",
                "alt1.aspmx.l.google.com",
                "aspmx2.googlemail.com"
            ]),
            ["google"]
        );
        assert_eq!(slugs(&["hotmail-nl.b-v1.mx.microsoft"]), ["microsoft"]);
        assert_eq!(
            slugs(&[
                "notgoogle.com",
                "google.com.evil.example",
                "mail.example.com"
            ]),
            Vec::<&str>::new()
        );
        assert_eq!(
            detect(&hosts(&["route1.mx.cloudflare.net"])),
            [Provider {
                slug: "cloudflare",
                kind: "forwarding"
            }]
        );
    }
}
