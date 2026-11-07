use std::{
    fmt::Write as _,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

const TIMEOUT: Duration = Duration::from_secs(2);
// Resent once if unanswered; this fits inside the RDAP lookup that runs alongside.
const RETRANSMIT: Duration = Duration::from_secs(1);
const RESULTS: [&str; 4] = ["resolved", "no_records", "no_domain", "unavailable"];

#[derive(Debug, PartialEq)]
pub enum Lookup {
    Hosts(Vec<String>),
    NoRecords,
    NoDomain,
    Unavailable,
}

impl Lookup {
    pub fn status(&self) -> &'static str {
        RESULTS[self.index()]
    }
    fn index(&self) -> usize {
        match self {
            Lookup::Hosts(_) => 0,
            Lookup::NoRecords => 1,
            Lookup::NoDomain => 2,
            Lookup::Unavailable => 3,
        }
    }
}

// ponytail: one UDP query to one nameserver, resent once after a second, with no cache or TCP
// fallback; a truncated answer is reported as unavailable. Add TCP if MX sets exceed 1232 bytes.
pub struct Resolver {
    server: SocketAddr,
    counts: [AtomicU64; 4],
}

impl Resolver {
    pub fn from_env() -> Result<Self, &'static str> {
        let value = std::env::var("OPENFINGERPRINT_DNS").unwrap_or_else(|_| "system".into());
        let resolv_conf = std::fs::read_to_string("/etc/resolv.conf").ok();
        Self::new(&value, resolv_conf.as_deref())
    }

    pub fn new(value: &str, resolv_conf: Option<&str>) -> Result<Self, &'static str> {
        let server = if value == "system" {
            resolv_conf
                .and_then(|conf| {
                    conf.lines().find_map(|line| {
                        let mut words = line.split_whitespace();
                        (words.next() == Some("nameserver"))
                            .then(|| words.next()?.parse::<IpAddr>().ok())
                            .flatten()
                    })
                })
                .map(|ip| SocketAddr::new(ip, 53))
        } else if let Ok(ip) = value.parse::<IpAddr>() {
            Some(SocketAddr::new(ip, 53))
        } else {
            value
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
        };
        server
            .map(|server| Self {
                server,
                counts: Default::default(),
            })
            .ok_or("No DNS server: set OPENFINGERPRINT_DNS to system, an IP, IP:port or host:port")
    }

    /// `domain` must already be a validated, lower-case hostname without a trailing dot.
    pub async fn mx(&self, domain: &str) -> Lookup {
        let result = tokio::time::timeout(TIMEOUT, self.query(domain))
            .await
            .unwrap_or(Lookup::Unavailable);
        self.counts[result.index()].fetch_add(1, Ordering::Relaxed);
        result
    }

    async fn query(&self, domain: &str) -> Lookup {
        let mut id = [0; 2];
        if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut id).is_err() {
            return Lookup::Unavailable;
        }
        let query = encode(u16::from_be_bytes(id), domain);
        let bind = SocketAddr::new(
            if self.server.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            },
            0,
        );
        let Ok(socket) = tokio::net::UdpSocket::bind(bind).await else {
            return Lookup::Unavailable;
        };
        if socket.connect(self.server).await.is_err() || socket.send(&query).await.is_err() {
            return Lookup::Unavailable;
        }
        let mut buf = [0; 1232];
        let mut resend_at = Some(tokio::time::Instant::now() + RETRANSMIT);
        loop {
            let received = match resend_at {
                Some(at) => match tokio::time::timeout_at(at, socket.recv(&mut buf)).await {
                    Ok(received) => received,
                    Err(_) => {
                        resend_at = None;
                        if socket.send(&query).await.is_err() {
                            return Lookup::Unavailable;
                        }
                        continue;
                    }
                },
                None => socket.recv(&mut buf).await,
            };
            let Ok(n) = received else {
                return Lookup::Unavailable;
            };
            if let Some(result) = parse(&buf[..n], &query) {
                return result;
            }
        }
    }

    pub fn metrics(&self) -> String {
        let mut out = String::from(
            "# HELP openfingerprint_mx_lookups_total MX lookups by outcome.\n# TYPE openfingerprint_mx_lookups_total counter\n",
        );
        for (result, count) in RESULTS.iter().zip(&self.counts) {
            let _ = writeln!(
                out,
                "openfingerprint_mx_lookups_total{{result=\"{result}\"}} {}",
                count.load(Ordering::Relaxed)
            );
        }
        out
    }
}

const OPT: [u8; 11] = [0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0];

fn encode(id: u16, domain: &str) -> Vec<u8> {
    let mut query = id.to_be_bytes().to_vec();
    query.extend_from_slice(&[0x01, 0, 0, 1, 0, 0, 0, 0, 0, 1]);
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 15, 0, 1]);
    query.extend_from_slice(&OPT);
    query
}

/// `None` means the packet is not an answer to `query` and is ignored.
fn parse(msg: &[u8], query: &[u8]) -> Option<Lookup> {
    let question = &query[12..query.len() - OPT.len()];
    let header = msg.get(..12)?;
    let end = 12 + question.len();
    if header[..2] != query[..2]
        || header[2] & 0x80 == 0
        || header[4..6] != [0, 1]
        || !msg.get(12..end)?.eq_ignore_ascii_case(question)
    {
        return None;
    }
    Some(answers(msg, end).unwrap_or(Lookup::Unavailable))
}

fn answers(msg: &[u8], mut pos: usize) -> Option<Lookup> {
    if msg[2] & 0x7a != 0 {
        return None;
    }
    match msg[3] & 0x0f {
        0 => {}
        3 => return Some(Lookup::NoDomain),
        _ => return None,
    }
    let mut hosts: Vec<(u16, String)> = Vec::new();
    for _ in 0..u16::from_be_bytes([msg[6], msg[7]]) {
        pos = name(msg, pos)?.1;
        let fixed = msg.get(pos..pos + 10)?;
        let data = pos + 10;
        pos = data + usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        let rdata = msg.get(data..pos)?;
        if fixed[..4] == [0, 15, 0, 1] {
            let preference = u16::from_be_bytes([*rdata.first()?, *rdata.get(1)?]);
            let (host, end) = name(msg, data + 2)?;
            if end != pos {
                return None;
            }
            // Cloudflare publishes MX targets such as `_dc-mx.<hash>.<domain>` that accept mail.
            if crate::check::domain(&host.replace('_', "u"))
                && !hosts.iter().any(|(_, h)| *h == host)
            {
                hosts.push((preference, host));
            }
        }
    }
    hosts.sort_by_key(|(preference, _)| *preference);
    hosts.truncate(10);
    Some(if hosts.is_empty() {
        Lookup::NoRecords
    } else {
        Lookup::Hosts(hosts.into_iter().map(|(_, h)| h).collect())
    })
}

/// Returns the lower-cased name and the offset just past it in the record being read.
fn name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut end = None;
    for _ in 0..128 {
        let len = *msg.get(pos)?;
        match len & 0xc0 {
            0 if len == 0 => return Some((out, end.unwrap_or(pos + 1))),
            0 => {
                let label = msg.get(pos + 1..pos + 1 + usize::from(len))?;
                if !label.is_ascii() || out.len() + label.len() >= 254 {
                    return None;
                }
                if !out.is_empty() {
                    out.push('.');
                }
                out.extend(label.iter().map(|b| b.to_ascii_lowercase() as char));
                pos += 1 + usize::from(len);
            }
            0xc0 => {
                let target = usize::from(u16::from_be_bytes([len & 0x3f, *msg.get(pos + 1)?]));
                end.get_or_insert(pos + 2);
                // Only backward pointers: rules out loops.
                if target >= pos {
                    return None;
                }
                pos = target;
            }
            _ => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.').filter(|l| !l.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn reply(query: &[u8], flags: [u8; 2], records: &[(u16, &str)]) -> Vec<u8> {
        let question = &query[12..query.len() - OPT.len()];
        let mut msg = query[..2].to_vec();
        msg.extend_from_slice(&flags);
        msg.extend_from_slice(&[0, 1, 0, records.len() as u8, 0, 0, 0, 0]);
        msg.extend_from_slice(question);
        for (preference, host) in records {
            let data = [&preference.to_be_bytes()[..], &labels(host)].concat();
            msg.extend_from_slice(&[0xc0, 12, 0, 15, 0, 1, 0, 0, 0, 60]);
            msg.extend_from_slice(&(data.len() as u16).to_be_bytes());
            msg.extend_from_slice(&data);
        }
        msg
    }

    #[test]
    fn encodes_a_recursive_mx_question_with_edns() {
        let query = encode(0xabcd, "mail.example");
        let mut expected = vec![0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1];
        expected.extend_from_slice(b"\x04mail\x07example\x00\x00\x0f\x00\x01");
        expected.extend_from_slice(&OPT);
        assert_eq!(query, expected);
    }

    #[test]
    fn parses_answers_conservatively() {
        let query = encode(7, "new.example");
        let ok = [0x81, 0x80];
        let parsed = parse(
            &reply(
                &query,
                ok,
                &[
                    (20, "MX2.Temp.Example."),
                    (10, "mx1.temp.example"),
                    (30, "mx1.temp.example"),
                ],
            ),
            &query,
        );
        assert_eq!(
            parsed,
            Some(Lookup::Hosts(vec![
                "mx1.temp.example".into(),
                "mx2.temp.example".into()
            ]))
        );
        assert_eq!(
            parse(&reply(&query, ok, &[]), &query),
            Some(Lookup::NoRecords)
        );
        assert_eq!(
            parse(&reply(&query, ok, &[(0, ".")]), &query),
            Some(Lookup::NoRecords)
        );
        assert_eq!(
            parse(&reply(&query, [0x81, 0x83], &[]), &query),
            Some(Lookup::NoDomain)
        );
        for flags in [[0x81, 0x82], [0x81, 0x85], [0x83, 0x80], [0x89, 0x80]] {
            assert_eq!(
                parse(&reply(&query, flags, &[]), &query),
                Some(Lookup::Unavailable)
            );
        }
        let many: Vec<_> = (0..12)
            .map(|i| (i, format!("mx{i}.temp.example")))
            .collect();
        let many: Vec<_> = many.iter().map(|(p, h)| (*p, h.as_str())).collect();
        let Some(Lookup::Hosts(hosts)) = parse(&reply(&query, ok, &many), &query) else {
            panic!("expected hosts");
        };
        assert_eq!((hosts.len(), hosts[0].as_str()), (10, "mx0.temp.example"));
        assert_eq!(
            parse(
                &reply(&query, ok, &[(10, "_dc-mx.95642e8dce05.temp.example")]),
                &query
            ),
            Some(Lookup::Hosts(vec![
                "_dc-mx.95642e8dce05.temp.example".into()
            ]))
        );
        assert_eq!(
            parse(&reply(&query, ok, &[(10, "bad host.temp.example")]), &query),
            Some(Lookup::NoRecords)
        );

        let mut other_id = reply(&query, ok, &[(10, "mx.temp.example")]);
        other_id[1] ^= 1;
        let mut not_reply = reply(&query, ok, &[]);
        not_reply[2] &= 0x7f;
        let other_question = reply(&encode(7, "other.example"), ok, &[]);
        for ignored in [other_id, not_reply, other_question, query.clone(), vec![]] {
            assert_eq!(parse(&ignored, &query), None);
        }

        let valid = reply(&query, ok, &[(10, "mx.temp.example")]);
        for cut in 12..valid.len() {
            assert!(matches!(
                parse(&valid[..cut], &query),
                None | Some(Lookup::Unavailable)
            ));
        }
        let pointer_at = valid.len() - labels("mx.temp.example").len();
        for (pointer, expected) in [
            ([0xc0, 12], Lookup::Hosts(vec!["new.example".into()])),
            ([0xc0, 0xff], Lookup::Unavailable),
            ([0xc0, pointer_at as u8], Lookup::Unavailable),
            ([0x80, 0x00], Lookup::Unavailable),
        ] {
            let mut compressed = valid.clone();
            compressed.truncate(pointer_at);
            compressed.extend_from_slice(&pointer);
            let len = compressed.len() - (pointer_at - 2);
            compressed[pointer_at - 4..pointer_at - 2].copy_from_slice(&(len as u16).to_be_bytes());
            assert_eq!(parse(&compressed, &query), Some(expected));
        }
        let rng = ring::rand::SystemRandom::new();
        for _ in 0..20000 {
            let mut noise = [0u8; 96];
            ring::rand::SecureRandom::fill(&rng, &mut noise).unwrap();
            let mut fuzzed = valid.clone();
            let at = usize::from(noise[0]) % fuzzed.len().saturating_sub(12) + 12;
            fuzzed.splice(
                at..,
                noise[1..usize::from(noise[1]) % 95 + 1].iter().copied(),
            );
            let _ = parse(&fuzzed, &query);
        }
    }

    #[test]
    fn configures_one_nameserver() {
        let conf = "search svc.cluster.local\nnameserverx 10.0.0.1\nnameserver fe80::1%eth0\nnameserver 10.43.0.10\nnameserver 10.43.0.11";
        let server = |value, conf| Resolver::new(value, conf).map(|r| r.server.to_string());
        assert_eq!(server("system", Some(conf)), Ok("10.43.0.10:53".into()));
        assert_eq!(server("192.0.2.53", None), Ok("192.0.2.53:53".into()));
        assert_eq!(
            server("[2001:db8::53]:5353", None),
            Ok("[2001:db8::53]:5353".into())
        );
        assert_eq!(server("127.0.0.1:5353", None), Ok("127.0.0.1:5353".into()));
        for invalid in ["", "system", "not a server", "192.0.2.53:99999"] {
            assert!(
                server(invalid, Some("nameserver bogus")).is_err(),
                "{invalid}"
            );
        }
    }

    #[tokio::test]
    async fn ignores_foreign_packets_and_bounds_silent_servers() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = Resolver::new(&server.local_addr().unwrap().to_string(), None).unwrap();
        let answer = async {
            let mut buf = [0; 512];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            let query = buf[..n].to_vec();
            let mut spoofed = reply(&query, [0x81, 0x80], &[(10, "mx.temp.example")]);
            spoofed[0] ^= 0xff;
            server.send_to(&spoofed, peer).await.unwrap();
            server
                .send_to(&reply(&query, [0x81, 0x80], &[]), peer)
                .await
                .unwrap();
            std::future::pending::<()>().await;
        };
        let lookups = async {
            let first = resolver.mx("new.example").await;
            let started = std::time::Instant::now();
            let second = resolver.mx("silent.example").await;
            (first, second, started.elapsed())
        };
        let (first, second, elapsed) = tokio::select! {
            r = lookups => r,
            _ = answer => unreachable!(),
        };
        assert_eq!((first, second), (Lookup::NoRecords, Lookup::Unavailable));
        assert!(elapsed >= TIMEOUT && elapsed < TIMEOUT * 2);
        let metrics = resolver.metrics();
        assert!(metrics.contains("result=\"no_records\"} 1"));
        assert!(metrics.contains("result=\"unavailable\"} 1"));
    }

    #[tokio::test]
    async fn resends_once_when_the_first_query_is_lost() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = Resolver::new(&server.local_addr().unwrap().to_string(), None).unwrap();
        let answer = async {
            let mut buf = [0; 512];
            server.recv_from(&mut buf).await.unwrap();
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            server
                .send_to(
                    &reply(&buf[..n], [0x81, 0x80], &[(10, "mx.temp.example")]),
                    peer,
                )
                .await
                .unwrap();
            std::future::pending::<()>().await;
        };
        let started = std::time::Instant::now();
        let result = tokio::select! {
            r = resolver.mx("lossy.example") => r,
            _ = answer => unreachable!(),
        };
        assert_eq!(result, Lookup::Hosts(vec!["mx.temp.example".into()]));
        assert!(started.elapsed() >= RETRANSMIT && started.elapsed() < TIMEOUT);
    }
}
