//! JA4 TLS client fingerprints (https://github.com/FoxIO-LLC/ja4, BSD 3-Clause) from the
//! ClientHello a browser sends to the identify listener, and which TLS stack they belong to.

use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Client {
    Chromium,
    Firefox,
    /// Safari and every iOS browser, which must use Apple's networking.
    Apple,
    Curl,
    Python,
    Go,
    Node,
}

/// JA4 `b_c` parts (cipher and extension hashes) measured against the identify listener
/// in November 2026. Matching ignores the `a` part, which changes with SNI and ALPN. A
/// fingerprint not listed here is unknown, never a mismatch: other browser versions,
/// enterprise TLS inspection and unmeasured libraries all land there.
const KNOWN: &[(&str, Client)] = &[
    // Google Chrome 157 (macOS); Playwright Chromium 158 headless shell.
    ("8daaf6152771_cb7bf5808d99", Client::Chromium),
    ("8daaf6152771_806a8c22fdea", Client::Chromium),
    // Playwright Firefox 159.
    ("8daaf6152771_3cbfd9057e0d", Client::Firefox),
    // Playwright WebKit 27.2 on macOS, which uses Apple's networking stack.
    ("a09f3c656075_7f0f34a4126d", Client::Apple),
    // curl 8.7 (macOS, LibreSSL); curl 8.23 (Linux, OpenSSL 3.5).
    ("0d8feac7bc37_7395dae3b2f3", Client::Curl),
    ("1d37bd780c83_882d495ac381", Client::Curl),
    // Python 3.9 urllib and requests 2.32 (macOS, LibreSSL); Python 3.12 urllib and
    // requests (Linux, OpenSSL 3).
    ("10ed599f3404_67a080e8974e", Client::Python),
    ("d943125447b4_aaf95bb78ec9", Client::Python),
    ("ab0a1bf427ad_ecd0401ec68b", Client::Python),
    ("ab0a1bf427ad_8537cf56674e", Client::Python),
    // Go 1.27 net/http.
    ("f57a46bbacb6_f50d94e863eb", Client::Go),
    // Node.js 24 fetch and https; Node.js 22 fetch.
    ("b262b3658495_e44827223d20", Client::Node),
    ("b262b3658495_8e6e362c5eac", Client::Node),
];

pub fn client(ja4: &str) -> Option<Client> {
    let (_, parts) = ja4.split_once('_')?;
    KNOWN
        .iter()
        .find(|(known, _)| *known == parts)
        .map(|(_, c)| *c)
}

/// The TLS stack a browser's user agent implies, or `None` for anything else.
pub fn claimed(user_agent: &str) -> Option<Client> {
    let has = |s: &str| user_agent.contains(s);
    if has("iPhone") || has("iPad") || has("iPod") {
        Some(Client::Apple)
    } else if has("Firefox/") {
        Some(Client::Firefox)
    } else if has("Chrome/") || has("Chromium/") || has("Edg/") {
        Some(Client::Chromium)
    } else if has("Macintosh") && has("Version/") && has("Safari/") {
        Some(Client::Apple)
    } else {
        None
    }
}

fn grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }
    fn u8(&mut self) -> Option<usize> {
        Some(self.take(1)?[0] as usize)
    }
    fn u16(&mut self) -> Option<usize> {
        let b = self.take(2)?;
        Some(usize::from(u16::from_be_bytes([b[0], b[1]])))
    }
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()?;
        self.take(n)
    }
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()?;
        self.take(n)
    }
}

fn u16s(bytes: &[u8]) -> impl Iterator<Item = u16> + '_ {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_be_bytes(*b))
        .filter(|v| !grease(*v))
}

fn truncated_hash(list: &[String]) -> String {
    if list.is_empty() {
        return "000000000000".into();
    }
    crate::check::sha256(&list.join(","))[..12].into()
}

/// JA4 of a TLS record holding a complete ClientHello, or `None` for anything else.
pub fn ja4(record: &[u8]) -> Option<String> {
    let mut record = Reader(record);
    if record.u8()? != 0x16 {
        return None;
    }
    record.take(2)?;
    let mut handshake = Reader(record.vec16()?);
    if handshake.u8()? != 0x01 {
        return None;
    }
    let length = handshake.take(3)?;
    let length = (length[0] as usize) << 16 | (length[1] as usize) << 8 | length[2] as usize;
    let mut hello = Reader(handshake.take(length)?);
    let legacy_version = hello.u16()? as u16;
    hello.take(32)?;
    hello.vec8()?;
    let ciphers: Vec<u16> = u16s(hello.vec16()?).collect();
    hello.vec8()?;
    let mut extensions = Vec::new();
    let (mut sni, mut alpn, mut versions, mut signatures) = (false, None, Vec::new(), Vec::new());
    if !hello.0.is_empty() {
        let mut list = Reader(hello.vec16()?);
        while !list.0.is_empty() {
            let kind = list.u16()? as u16;
            let mut data = Reader(list.vec16()?);
            if grease(kind) {
                continue;
            }
            extensions.push(kind);
            match kind {
                0x0000 => sni = true,
                0x0010 => alpn = Reader(data.vec16()?).vec8().map(<[u8]>::to_vec),
                0x002b => versions = u16s(data.vec8()?).collect(),
                0x000d => signatures = u16s(data.vec16()?).collect(),
                _ => {}
            }
        }
    }
    let version = versions.iter().copied().max().unwrap_or(legacy_version);
    let version = match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    };
    let alpn = match alpn.as_deref() {
        None | Some([]) => "00".to_owned(),
        Some(value) => {
            let (first, last) = (value[0], value[value.len() - 1]);
            if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
                format!("{}{}", first as char, last as char)
            } else {
                let hex: String = value.iter().map(|b| format!("{b:02x}")).collect();
                format!("{}{}", &hex[..1], &hex[hex.len() - 1..])
            }
        }
    };
    let hex = |v: &u16| format!("{v:04x}");
    let mut sorted_ciphers: Vec<String> = ciphers.iter().map(hex).collect();
    sorted_ciphers.sort();
    let mut sorted_extensions: Vec<String> = extensions
        .iter()
        .filter(|e| **e != 0x0000 && **e != 0x0010)
        .map(hex)
        .collect();
    sorted_extensions.sort();
    let extension_hash = if sorted_extensions.is_empty() {
        "000000000000".into()
    } else if signatures.is_empty() {
        truncated_hash(&sorted_extensions)
    } else {
        let signatures: Vec<String> = signatures.iter().map(hex).collect();
        crate::check::sha256(&format!(
            "{}_{}",
            sorted_extensions.join(","),
            signatures.join(",")
        ))[..12]
            .into()
    };
    Some(format!(
        "t{version}{}{:02}{:02}{alpn}_{}_{extension_hash}",
        if sni { 'd' } else { 'i' },
        ciphers.len().min(99),
        extensions.len().min(99),
        truncated_hash(&sorted_ciphers),
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A TLS record with a ClientHello built from the given parts.
    pub(crate) fn hello(ciphers: &[u16], extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend([0u8; 32]);
        body.push(0);
        body.extend(((ciphers.len() * 2) as u16).to_be_bytes());
        for c in ciphers {
            body.extend(c.to_be_bytes());
        }
        body.extend([1, 0]);
        let mut list = Vec::new();
        for (kind, data) in extensions {
            list.extend(kind.to_be_bytes());
            list.extend((data.len() as u16).to_be_bytes());
            list.extend(data);
        }
        body.extend((list.len() as u16).to_be_bytes());
        body.extend(list);
        let mut handshake = vec![0x01];
        handshake.extend(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend(body);
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend((handshake.len() as u16).to_be_bytes());
        record.extend(handshake);
        record
    }

    fn list16(values: &[u16]) -> Vec<u8> {
        let mut out = ((values.len() * 2) as u16).to_be_bytes().to_vec();
        for v in values {
            out.extend(v.to_be_bytes());
        }
        out
    }

    /// The worked example of the JA4 specification, with GREASE values sprinkled in.
    pub(crate) fn spec_example() -> Vec<u8> {
        let ciphers = [
            0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
            0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ];
        let mut versions = vec![4u8];
        versions.extend([0x3a, 0x3a, 0x03, 0x04]);
        let alpn = {
            let mut entries = vec![2, b'h', b'2', 8];
            entries.extend(b"http/1.1");
            let mut out = (entries.len() as u16).to_be_bytes().to_vec();
            out.extend(entries);
            out
        };
        let extensions = [
            (0x2a2a, vec![]),
            (0x001b, vec![]),
            (0x0000, vec![]),
            (0x0033, vec![]),
            (0x0010, alpn),
            (0x4469, vec![]),
            (0x0017, vec![]),
            (0x002d, vec![]),
            (
                0x000d,
                list16(&[
                    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
                ]),
            ),
            (0x0005, vec![]),
            (0x0023, vec![]),
            (0x0012, vec![]),
            (0x002b, versions),
            (0xff01, vec![]),
            (0x000b, vec![]),
            (0x000a, vec![]),
            (0x0015, vec![]),
        ];
        hello(&ciphers, &extensions)
    }

    #[test]
    fn computes_the_specification_example() {
        assert_eq!(
            ja4(&spec_example()).as_deref(),
            Some("t13d1516h2_8daaf6152771_e5627efa2ab1")
        );
    }

    #[test]
    fn handles_missing_parts_and_rejects_other_bytes() {
        let bare = ja4(&hello(&[0x1301], &[])).unwrap();
        assert!(bare.starts_with("t12i010000_"), "{bare}");
        assert!(bare.ends_with("_000000000000"), "{bare}");
        let odd_alpn = {
            let mut out = 3u16.to_be_bytes().to_vec();
            out.extend([2, 0x30, 0xab]);
            out
        };
        let alpn = ja4(&hello(&[0x1301], &[(0x0010, odd_alpn)])).unwrap();
        assert!(alpn.starts_with("t12i01013b_"), "{alpn}");
        for bad in [
            vec![],
            vec![0x17, 3, 3, 0, 0],
            spec_example()[..40].to_vec(),
            b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        ] {
            assert_eq!(ja4(&bad), None);
        }
    }

    #[test]
    fn the_reference_table_holds_well_formed_unique_fingerprints() {
        let mut seen = std::collections::HashSet::new();
        for (parts, known) in KNOWN {
            assert!(seen.insert(*parts), "{parts} listed twice");
            let (b, c) = parts.split_once('_').unwrap();
            assert!(
                [b, c]
                    .iter()
                    .all(|h| h.len() == 12 && h.bytes().all(|x| x.is_ascii_hexdigit()))
            );
            assert_eq!(client(&format!("t13d1516h2_{parts}")), Some(*known));
        }
        assert_eq!(client("t13d1516h2_8daaf6152771_000000000000"), None);
        assert_eq!(client("garbage"), None);
    }

    #[test]
    fn user_agents_imply_their_tls_stack() {
        for (ua, client) in [
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0",
                Some(Client::Chromium),
            ),
            (
                "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
                Some(Client::Firefox),
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
                Some(Client::Apple),
            ),
            (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/140.0.0.0 Mobile/15E148 Safari/604.1",
                Some(Client::Apple),
            ),
            ("python-requests/2.32.3", None),
        ] {
            assert_eq!(claimed(ua), client, "{ua}");
        }
    }
}
