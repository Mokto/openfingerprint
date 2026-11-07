use std::collections::HashMap;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::rdap::Registration;

const MAX_BODY: usize = 64 * 1024;

/// TLD to WHOIS server (`host` or `host:port`), for TLDs without RDAP.
pub fn servers(bytes: &[u8]) -> Option<HashMap<String, String>> {
    #[derive(serde::Deserialize)]
    struct File {
        servers: HashMap<String, String>,
    }
    let file: File = serde_json::from_slice(bytes).ok()?;
    file.servers
        .into_iter()
        .map(|(tld, server)| {
            let host = server.rsplit_once(':').map_or(server.as_str(), |(h, p)| {
                if p.parse::<u16>().is_ok() { h } else { "" }
            });
            (crate::check::domain(host) || host.parse::<std::net::IpAddr>().is_ok())
                .then_some((tld.to_ascii_lowercase(), server.clone()))
        })
        .collect::<Option<HashMap<_, _>>>()
        .filter(|s| !s.is_empty())
}

/// One plain query on port 43 (or the configured port); the caller bounds the time.
pub async fn query(server: &str, domain: &str) -> Registration {
    let addr = if server.contains(':') {
        server.to_owned()
    } else {
        format!("{server}:43")
    };
    let Ok(mut stream) = tokio::net::TcpStream::connect(addr).await else {
        return Registration::status("unavailable");
    };
    // JPRS answers in Japanese unless asked for English with `/e`.
    let suffix = if server == "whois.jprs.jp" { "/e" } else { "" };
    if stream
        .write_all(format!("{domain}{suffix}\r\n").as_bytes())
        .await
        .is_err()
    {
        return Registration::status("unavailable");
    }
    let mut body = Vec::new();
    match (&mut stream)
        .take(MAX_BODY as u64 + 1)
        .read_to_end(&mut body)
        .await
    {
        Ok(_) if body.len() <= MAX_BODY => parse(&String::from_utf8_lossy(&body), domain),
        _ => Registration::status("unavailable"),
    }
}

const CREATED: [&str; 13] = [
    "creation date",
    "created",
    "created on",
    "created date",
    "domain created",
    "registered",
    "registered on",
    "registration date",
    "registration time",
    "domain registration date",
    "record created",
    "domain record activated",
    "first registration date",
];
const NOT_FOUND: [&str; 11] = [
    "no data found",
    "domain not found",
    "no entries found",
    "no match",
    "not found",
    "no matching record",
    "object_not_found",
    "has not been registered",
    "does not exist",
    "status: free",
    "status: available",
];

/// Free-text WHOIS is not a standard: a date counts only from a known creation key in an
/// unambiguous format, and an unrecognised answer (rate limits, notices) is `unavailable`.
pub fn parse(text: &str, domain: &str) -> Registration {
    let tld = domain.rsplit('.').next().unwrap_or_default();
    let lines: Vec<(String, &str)> = text
        .lines()
        .filter_map(|line| {
            let (key, value) = match line.trim_start().strip_prefix('[') {
                Some(bracketed) => bracketed.split_once(']')?,
                None => line.split_once(':')?,
            };
            Some((
                key.trim().trim_end_matches('.').trim().to_ascii_lowercase(),
                value.trim(),
            ))
        })
        .collect();
    let free = lines.iter().any(|(k, v)| {
        k == "status" && ["free", "available"].contains(&v.to_ascii_lowercase().as_str())
    });
    if free {
        return Registration::status("not_found");
    }
    if let Some(at) = lines
        .iter()
        .filter(|(k, _)| CREATED.contains(&k.as_str()))
        .find_map(|(_, v)| date(v, tld))
    {
        return Registration::found(at);
    }
    let names_domain = lines.iter().any(|(k, v)| {
        matches!(k.as_str(), "domain" | "domain name" | "domain_name")
            && v.trim_end_matches('.').eq_ignore_ascii_case(domain)
    });
    if names_domain {
        return Registration::status("no_date");
    }
    let lower = text.to_ascii_lowercase();
    if NOT_FOUND.iter().any(|p| lower.contains(p)) {
        Registration::status("not_found")
    } else {
        Registration::status("unavailable")
    }
}

/// A registration day at 00:00 UTC (WHOIS times and zones vary, the day is what matters).
fn date(value: &str, tld: &str) -> Option<u64> {
    let digits = |s: &str| {
        s.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| s.parse::<i64>().ok())?
    };
    let month = |s: &str| {
        [
            "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
        ]
        .iter()
        .position(|m| s.eq_ignore_ascii_case(m))
        .map(|i| i as i64 + 1)
    };
    let first = value.split([' ', 'T']).next()?;
    let words: Vec<&str> = value.split_whitespace().collect();
    let (y, m, d) = if let [y, m, d] = first.split('-').collect::<Vec<_>>()[..]
        && y.len() == 4
    {
        (digits(y)?, digits(m)?, digits(d)?)
    } else if first.len() == 8 && digits(first).is_some() {
        (
            digits(&first[..4])?,
            digits(&first[4..6])?,
            digits(&first[6..])?,
        )
    } else if let [d, m, y] = first.split('.').collect::<Vec<_>>()[..] {
        (digits(y)?, digits(m)?, digits(d)?)
    } else if let [d, m, y] = first.split('-').collect::<Vec<_>>()[..] {
        (digits(y)?, month(m)?, digits(d)?)
    } else if let [y, m, d] = first.split('/').collect::<Vec<_>>()[..]
        && y.len() == 4
    {
        (digits(y)?, digits(m)?, digits(d)?)
    } else if let [d, m, y] = first.split('/').collect::<Vec<_>>()[..]
        && tld == "pt"
    {
        (digits(y)?, digits(m)?, digits(d)?)
    } else if let [_, m, d, y] = words[..] {
        (digits(y)?, month(m)?, digits(d)?)
    } else {
        return None;
    };
    let max_day = match m {
        2 if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1..=12 => 31,
        _ => return None,
    };
    let at = crate::rdap::days(y, m, d) * 86400;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    ((1985..=9999).contains(&y) && (1..=max_day).contains(&d) && at <= now + 86400)
        .then(|| u64::try_from(at).ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day(y: i64, m: i64, d: i64) -> Registration {
        Registration::found(u64::try_from(crate::rdap::days(y, m, d) * 86400).unwrap())
    }

    #[test]
    fn reads_creation_dates_in_unambiguous_formats_only() {
        for (text, domain, want) in [
            (
                "Domain Name: a.us\nCreation Date: 2002-04-18T15:16:22Z\n",
                "a.us",
                day(2002, 4, 18),
            ),
            (
                "Domain:             a.it\nCreated:            2000-03-09 00:00:00\n",
                "a.it",
                day(2000, 3, 9),
            ),
            (
                "domain:        A.RU\ncreated:       2004-02-13T21:00:00Z\n",
                "a.ru",
                day(2004, 2, 13),
            ),
            (
                "Domain: a.pt\nCreation Date: 30/10/2002 00:00:00\n",
                "a.pt",
                day(2002, 10, 30),
            ),
            (
                "domain: a.se\ncreated: 2002-11-06\n",
                "a.se",
                day(2002, 11, 6),
            ),
            (
                "Domain created: 2007-04-21 03:53:02 (GMT+0:00)\n",
                "a.kz",
                day(2007, 4, 21),
            ),
            (
                "registered:     19990310 00:00:00\n",
                "a.at",
                day(1999, 3, 10),
            ),
            ("Registered:\tThu Mar 12 1998\n", "a.be", day(1998, 3, 12)),
            (
                "Registration date: 05.06.2008 12:00:00\n",
                "a.rs",
                day(2008, 6, 5),
            ),
            (
                "Domain record activated:    03-Mar-2000\n",
                "a.edu",
                day(2000, 3, 3),
            ),
            (
                "Domain Information: [ドメイン情報]\n[Domain Name]  A.JP\n[Created on]  2004/07/30\n",
                "a.jp",
                day(2004, 7, 30),
            ),
        ] {
            assert_eq!(parse(text, domain), want, "{text}");
        }
    }

    #[test]
    fn missing_ambiguous_or_unrecognised_answers_never_become_dates() {
        assert_eq!(
            parse("Domain: a.de\nStatus: connect\n", "a.de").status,
            "no_date"
        );
        assert_eq!(
            parse(
                "Domain: a.tn\nCreation date: 05-06-2008 12:00:00 GMT+1\n",
                "a.tn"
            )
            .status,
            "no_date"
        );
        assert_eq!(
            parse("Domain: a.sm\nRegistration date: 05/06/2008\n", "a.sm").status,
            "no_date"
        );
        assert_eq!(
            parse("Domain Name: a.us\nCreation Date: 2999-01-01\n", "a.us").status,
            "no_date"
        );
        assert_eq!(
            parse("Domain Name: a.us\nCreation Date: 2002-02-30\n", "a.us").status,
            "no_date"
        );
        for free in [
            "No Data Found\n",
            "Domain not found.\n",
            "Domain: a.it\nStatus:             AVAILABLE\n",
            "Domain: a.de\nStatus: free\n",
            "a.pt - No Match\n",
        ] {
            assert_eq!(parse(free, "a.it").status, "not_found", "{free}");
        }
        assert_eq!(
            parse("[Domain Name]  A.JP\n[Status]  Active\n", "a.jp").status,
            "no_date"
        );
        for odd in [
            "",
            "Query rate limit exceeded. Try again later.\n",
            "Requests of this client are not permitted.\n",
            "Domain Name: other.us\n",
        ] {
            assert_eq!(parse(odd, "a.us").status, "unavailable", "{odd}");
        }
    }

    #[test]
    fn server_files_accept_hostnames_and_explicit_ports_only() {
        let ok = servers(br#"{"servers":{"US":"whois.nic.us","test":"127.0.0.1:4343"}}"#).unwrap();
        assert_eq!(
            (ok["us"].as_str(), ok["test"].as_str()),
            ("whois.nic.us", "127.0.0.1:4343")
        );
        for bad in [
            &br#"{"servers":{}}"#[..],
            br#"{"servers":{"us":"whois nic"}}"#,
            br#"{"servers":{"us":"host:port"}}"#,
            b"[]",
        ] {
            assert!(servers(bad).is_none());
        }
        assert!(
            servers(include_bytes!("../data/whois-servers.json"))
                .is_some_and(|s| s.len() >= 50 && !s.contains_key("com"))
        );
    }

    #[tokio::test]
    async fn queries_over_tcp_with_a_size_limit() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut q = vec![0; 256];
                let n = s.read(&mut q).await.unwrap();
                let reply = match std::str::from_utf8(&q[..n]).unwrap() {
                    "found.test\r\n" => {
                        "Domain Name: found.test\r\nCreation Date: 2020-01-02T00:00:00Z\r\n"
                            .to_owned()
                    }
                    "huge.test\r\n" => "x".repeat(MAX_BODY + 1),
                    _ => "No match\r\n".to_owned(),
                };
                let _ = s.write_all(reply.as_bytes()).await;
            }
        });
        assert_eq!(query(&addr, "found.test").await, day(2020, 1, 2));
        assert_eq!(query(&addr, "huge.test").await.status, "unavailable");
        assert_eq!(query(&addr, "missing.test").await.status, "not_found");
        assert_eq!(
            query("127.0.0.1:1", "found.test").await.status,
            "unavailable"
        );
    }
}
