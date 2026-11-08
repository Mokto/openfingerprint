use serde::Serialize;

use crate::mx::{Lookup, Resolver};

/// Whether the domain publishes exactly one SPF policy (RFC 7208 4.5).
#[derive(Debug, PartialEq, Serialize)]
pub struct Spf {
    status: &'static str,
    /// What the record says about senders it does not list: its `all` term (RFC 7208 5.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<&'static str>,
}

/// The DMARC policy that applies to mail from the domain (RFC 7489 6.6.3).
#[derive(Debug, PartialEq, Serialize)]
pub struct Dmarc {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<&'static str>,
    /// Found at the organisational domain rather than at the domain itself.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    inherited: bool,
}

impl Spf {
    pub fn status(status: &'static str) -> Self {
        Self {
            status,
            policy: None,
        }
    }
}

impl Dmarc {
    pub fn status(status: &'static str) -> Self {
        Self {
            status,
            policy: None,
            inherited: false,
        }
    }
}

/// `domain` must be a validated, lower-case hostname that is not a public suffix.
pub async fn check(dns: &Resolver, domain: &str) -> (Spf, Dmarc) {
    let organisation = psl::domain_str(domain).filter(|org| *org != domain);
    let own = format!("_dmarc.{domain}");
    let inherited = async {
        match organisation {
            Some(org) => Some(dns.txt(&format!("_dmarc.{org}")).await),
            None => None,
        }
    };
    let (spf, own, inherited) = tokio::join!(dns.txt(domain), dns.txt(&own), inherited);
    (spf_of(spf), dmarc_of(own, inherited))
}

fn spf_of(lookup: Lookup) -> Spf {
    match lookup {
        Lookup::Hosts(records) => {
            let mut found = records.iter().filter(|r| tag_value(r, "v=spf1", ' '));
            match (found.next(), found.next()) {
                (None, _) => Spf::status("none"),
                (Some(record), None) => Spf {
                    status: "found",
                    policy: spf_policy(record),
                },
                _ => Spf::status("multiple"),
            }
        }
        Lookup::NoRecords => Spf::status("none"),
        Lookup::NoDomain => Spf::status("no_domain"),
        Lookup::Unavailable => Spf::status("unavailable"),
    }
}

/// The first `all` mechanism ends evaluation, so later terms never apply.
fn spf_policy(record: &str) -> Option<&'static str> {
    record.split_ascii_whitespace().skip(1).find_map(|term| {
        let term = term.to_ascii_lowercase();
        match term.strip_suffix("all")? {
            "-" => Some("fail"),
            "~" => Some("softfail"),
            "" | "?" => Some("neutral"),
            "+" => Some("pass"),
            _ => None,
        }
    })
}

fn dmarc_of(own: Lookup, organisation: Option<Lookup>) -> Dmarc {
    let record = |lookup: &Lookup| -> Option<Option<String>> {
        match lookup {
            Lookup::Hosts(records) => {
                let found: Vec<_> = records
                    .iter()
                    .filter(|r| tag_value(r, "v=dmarc1", ';'))
                    .collect();
                Some((found.len() == 1).then(|| found[0].clone()))
            }
            Lookup::NoRecords | Lookup::NoDomain => Some(None),
            Lookup::Unavailable => None,
        }
    };
    let (text, inherited) = match (record(&own), organisation.as_ref().map(record)) {
        (None, _) | (Some(None), Some(None)) => return Dmarc::status("unavailable"),
        (Some(Some(text)), _) => (text, false),
        (Some(None), Some(Some(Some(text)))) => (text, true),
        (Some(None), _) => return Dmarc::status("none"),
    };
    let tag = |name: &str| {
        text.split(';').find_map(|part| {
            let (k, v) = part.split_once('=')?;
            k.trim()
                .eq_ignore_ascii_case(name)
                .then(|| v.trim().to_ascii_lowercase())
        })
    };
    let policy = if inherited {
        tag("sp").or_else(|| tag("p"))
    } else {
        tag("p")
    };
    match policy.as_deref() {
        Some("none") => Dmarc {
            status: "found",
            policy: Some("none"),
            inherited,
        },
        Some("quarantine") => Dmarc {
            status: "found",
            policy: Some("quarantine"),
            inherited,
        },
        Some("reject") => Dmarc {
            status: "found",
            policy: Some("reject"),
            inherited,
        },
        _ => Dmarc {
            status: "invalid",
            policy: None,
            inherited,
        },
    }
}

/// The record starts with `version` (any case), followed by `separator`, whitespace or its end.
fn tag_value(record: &str, version: &str, separator: char) -> bool {
    record
        .get(..version.len())
        .is_some_and(|v| v.eq_ignore_ascii_case(version))
        && record[version.len()..]
            .chars()
            .next()
            .is_none_or(|c| c == separator || c.is_ascii_whitespace())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn txt(records: &[&str]) -> Lookup {
        Lookup::Hosts(records.iter().map(|r| r.to_string()).collect())
    }

    #[test]
    fn spf_needs_exactly_one_versioned_policy() {
        for (lookup, want) in [
            (
                txt(&[
                    "v=spf1 include:_spf.example -all",
                    "google-site-verification=x",
                ]),
                "found",
            ),
            (txt(&["V=SPF1"]), "found"),
            (txt(&["v=spf1 -all", "v=spf1 ~all"]), "multiple"),
            (
                txt(&["v=spf10 -all", "spf1", "verification=v=spf1"]),
                "none",
            ),
            (Lookup::NoRecords, "none"),
            (Lookup::NoDomain, "no_domain"),
            (Lookup::Unavailable, "unavailable"),
        ] {
            assert_eq!(spf_of(lookup).status, want);
        }
    }

    #[test]
    fn spf_policy_is_the_first_all_term() {
        for (record, want) in [
            ("v=spf1 include:_spf.example -all", Some("fail")),
            ("v=spf1 mx ~all", Some("softfail")),
            ("v=spf1 ?all", Some("neutral")),
            ("v=spf1 all", Some("neutral")),
            ("v=spf1 +all", Some("pass")),
            ("V=SPF1 a -ALL", Some("fail")),
            ("v=spf1 -all ~all", Some("fail")),
            ("v=spf1 redirect=_spf.example", None),
            ("v=spf1 include:small.example", None),
            ("v=spf1 include:overall.example", None),
            ("v=spf1", None),
        ] {
            assert_eq!(spf_policy(record), want, "{record}");
        }
        assert_eq!(spf_of(txt(&["v=spf1 -all"])).policy, Some("fail"));
        assert_eq!(spf_of(txt(&["v=spf1 -all", "v=spf1 ~all"])).policy, None);
    }

    #[test]
    fn dmarc_reads_the_policy_and_falls_back_to_the_organisational_domain() {
        let own = dmarc_of(txt(&["v=DMARC1; p=Reject; rua=mailto:d@example.com"]), None);
        assert_eq!(
            (own.status, own.policy, own.inherited),
            ("found", Some("reject"), false)
        );
        let sub = dmarc_of(
            Lookup::NoDomain,
            Some(txt(&["v=DMARC1; p=reject; sp=quarantine"])),
        );
        assert_eq!(
            (sub.status, sub.policy, sub.inherited),
            ("found", Some("quarantine"), true)
        );
        let no_sp = dmarc_of(txt(&["unrelated"]), Some(txt(&["v=DMARC1;p=none"])));
        assert_eq!((no_sp.policy, no_sp.inherited), (Some("none"), true));
        for (own, org, want) in [
            (txt(&["v=DMARC1; p=maybe"]), None, "invalid"),
            (txt(&["v=DMARC1"]), None, "invalid"),
            (
                txt(&["v=DMARC1; p=none", "v=DMARC1; p=reject"]),
                Some(Lookup::NoDomain),
                "none",
            ),
            (Lookup::NoDomain, None, "none"),
            (Lookup::NoRecords, Some(Lookup::NoDomain), "none"),
            (
                Lookup::Unavailable,
                Some(txt(&["v=DMARC1; p=reject"])),
                "unavailable",
            ),
            (Lookup::NoDomain, Some(Lookup::Unavailable), "unavailable"),
        ] {
            assert_eq!(dmarc_of(own, org).status, want);
        }
    }
}
