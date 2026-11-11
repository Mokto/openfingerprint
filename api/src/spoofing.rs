use std::{
    collections::BTreeSet,
    fmt::Write,
    sync::atomic::{AtomicU64, Ordering},
};

use serde::Serialize;
use serde_json::Value;

const PROBES: [&str; 4] = [
    "user_agent_mismatch",
    "client_hints_mismatch",
    "language_mismatch",
    "tls_mismatch",
];
const HEADERS: [&str; 5] = [
    "userAgent",
    "acceptLanguage",
    "secChUa",
    "secChUaMobile",
    "secChUaPlatform",
];
const HEADER_LIMIT: usize = 1024;

const STATUSES: [&str; 3] = ["detected", "unknown", "not_detected"];
static STATUS_COUNTS: [AtomicU64; STATUSES.len()] = [const { AtomicU64::new(0) }; STATUSES.len()];
static INDICATOR_COUNTS: [AtomicU64; PROBES.len()] = [const { AtomicU64::new(0) }; PROBES.len()];

/// Counts of evaluations, by verdict and by indicator. Nothing identifies a visitor.
pub fn metrics() -> String {
    let mut out = String::from(
        "# HELP openfingerprint_spoofing_checks_total Evidence compared with the request that posted it, by verdict.\n# TYPE openfingerprint_spoofing_checks_total counter\n",
    );
    for (status, count) in STATUSES.iter().zip(&STATUS_COUNTS) {
        let _ = writeln!(
            out,
            "openfingerprint_spoofing_checks_total{{status=\"{status}\"}} {}",
            count.load(Ordering::Relaxed)
        );
    }
    out.push_str(
        "# HELP openfingerprint_spoofing_indicators_total Evaluations in which each comparison found a mismatch.\n# TYPE openfingerprint_spoofing_indicators_total counter\n",
    );
    for (indicator, count) in PROBES.iter().zip(&INDICATOR_COUNTS) {
        let _ = writeln!(
            out,
            "openfingerprint_spoofing_indicators_total{{indicator=\"{indicator}\"}} {}",
            count.load(Ordering::Relaxed)
        );
    }
    out
}

fn record(result: &Check) {
    if let Some(i) = STATUSES.iter().position(|s| *s == result.status) {
        STATUS_COUNTS[i].fetch_add(1, Ordering::Relaxed);
    }
    for indicator in &result.indicators {
        if let Some(i) = PROBES.iter().position(|name| name == indicator) {
            INDICATOR_COUNTS[i].fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all(serialize = "camelCase"))]
pub struct Check {
    status: &'static str,
    rule_version: u8,
    source: &'static str,
    indicators: Vec<&'static str>,
    unavailable_probes: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}
impl Check {
    pub(crate) fn rejected(&self) -> bool {
        self.status == "invalid_input"
    }
}

#[derive(PartialEq, Debug)]
struct ClientHints {
    brands: BTreeSet<(String, String)>,
    mobile: bool,
    platform: String,
}

struct Evidence {
    user_agent: Option<String>,
    language: Option<String>,
    client_hints: Option<ClientHints>,
}

/// Compares what the browser reported in its evidence (`evidence`, when it has the
/// `spoofing` part) with the headers of the request that posted it and with the TLS stack
/// its ClientHello came from (`tls`: the JA4, `Some(None)` when none could be read; `None`
/// leaves the `tls_mismatch` probe out).
pub fn check(evidence: Option<&Value>, headers: &Value, tls: Option<Option<&str>>) -> Check {
    let mut result = Check {
        status: "invalid_input",
        rule_version: 1,
        source: "client_reported_vs_request_headers",
        indicators: Vec::new(),
        unavailable_probes: Vec::new(),
        reason: Some("invalid_headers"),
    };
    let Some(headers) = headers.as_object().filter(|h| {
        h.iter().all(|(key, value)| {
            HEADERS.contains(&key.as_str())
                && (value.is_null() || value.as_str().is_some_and(|v| v.len() <= HEADER_LIMIT))
        })
    }) else {
        return result;
    };
    let header = |name: &str| headers.get(name).and_then(Value::as_str);
    let evidence = match evidence.map(parse) {
        Some(Some(evidence)) => Some(evidence),
        Some(None) => {
            result.reason = Some("invalid_spoofing");
            return result;
        }
        None => None,
    };
    let observations = match &evidence {
        Some(evidence) => [
            evidence
                .user_agent
                .as_deref()
                .zip(header("userAgent"))
                .map(|(claimed, sent)| claimed != sent),
            client_hints_mismatch(
                evidence.client_hints.as_ref(),
                [
                    header("secChUa"),
                    header("secChUaMobile"),
                    header("secChUaPlatform"),
                ],
            ),
            evidence
                .language
                .as_deref()
                .and_then(primary)
                .zip(header("acceptLanguage").and_then(first_language))
                .map(|(claimed, sent)| claimed != sent),
        ],
        None => [None; 3],
    };
    let tls_mismatch = tls.map(|ja4| {
        let observed = crate::tls::client(ja4?)?;
        let user_agent = evidence
            .as_ref()
            .and_then(|e| e.user_agent.as_deref())
            .or(header("userAgent"))?;
        Some(observed != crate::tls::claimed(user_agent)?)
    });
    let observations = observations.into_iter().chain([tls_mismatch.flatten()]);
    for (observed, name) in observations.zip(PROBES) {
        if name == "tls_mismatch" && tls.is_none() {
            continue;
        }
        match observed {
            Some(true) => result.indicators.push(name),
            None => result.unavailable_probes.push(name),
            Some(false) => {}
        }
    }
    result.status = if !result.indicators.is_empty() {
        "detected"
    } else if !result.unavailable_probes.is_empty() {
        "unknown"
    } else {
        "not_detected"
    };
    result.reason = None;
    record(&result);
    result
}

/// Both sides without client hints (Firefox, Safari) agree; one side without them is
/// unknown, since proxies and callers may drop the headers.
fn client_hints_mismatch(claimed: Option<&ClientHints>, sent: [Option<&str>; 3]) -> Option<bool> {
    match (claimed, sent) {
        (None, [None, None, None]) => Some(false),
        (Some(claimed), [Some(brands), Some(mobile), Some(platform)]) => {
            let sent = ClientHints {
                brands: brand_list(brands)?,
                mobile: match mobile.trim() {
                    "?1" => true,
                    "?0" => false,
                    _ => return None,
                },
                platform: match sf_string(platform.trim())? {
                    (platform, "") => platform,
                    _ => return None,
                },
            };
            Some(*claimed != sent)
        }
        _ => None,
    }
}

/// The primary language subtag, lowercased: `en-US` and `en` agree, as WebKit reports
/// `ja` while sending `Accept-Language: ja-JP`.
fn primary(tag: &str) -> Option<String> {
    let primary = tag.trim().split(['-', '_']).next()?.to_ascii_lowercase();
    (!primary.is_empty() && primary != "*").then_some(primary)
}

fn first_language(header: &str) -> Option<String> {
    primary(header.split(',').next()?.split(';').next()?)
}

/// An RFC 8941 string at the start of `input`, and what follows it.
fn sf_string(input: &str) -> Option<(String, &str)> {
    let body = input.strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = body.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => out.push(
                chars
                    .next()
                    .map(|(_, c)| c)
                    .filter(|c| matches!(c, '"' | '\\'))?,
            ),
            '"' => return Some((out, &body[i + 1..])),
            c if c.is_ascii() && !c.is_ascii_control() => out.push(c),
            _ => return None,
        }
    }
    None
}

/// `Sec-CH-UA`: a list of `"Brand";v="version"` items.
fn brand_list(header: &str) -> Option<BTreeSet<(String, String)>> {
    let mut brands = BTreeSet::new();
    let mut rest = header.trim();
    loop {
        let (brand, after) = sf_string(rest)?;
        let after = after.strip_prefix(';')?.trim_start_matches(' ');
        let (version, after) = sf_string(after.strip_prefix("v=")?)?;
        brands.insert((brand, version));
        rest = after.trim_start();
        if rest.is_empty() {
            return Some(brands);
        }
        rest = rest.strip_prefix(',')?.trim_start();
    }
}

fn parse(value: &Value) -> Option<Evidence> {
    let fields = value.as_object()?;
    let text = |key: &str, limit: usize| match fields.get(key) {
        None | Some(Value::Null) => Some(None),
        Some(Value::String(s)) if !s.is_empty() && s.len() <= limit => Some(Some(s.clone())),
        _ => None,
    };
    if fields.get("version").and_then(Value::as_u64) != Some(1)
        || fields
            .keys()
            .any(|k| !["version", "userAgent", "language", "clientHints"].contains(&k.as_str()))
    {
        return None;
    }
    Some(Evidence {
        user_agent: text("userAgent", HEADER_LIMIT)?,
        language: text("language", 64)?,
        client_hints: match fields.get("clientHints") {
            None | Some(Value::Null) => None,
            Some(hints) => Some(client_hints(hints)?),
        },
    })
}

fn client_hints(value: &Value) -> Option<ClientHints> {
    let fields = value.as_object()?;
    if fields.len() != 3 {
        return None;
    }
    let brands = fields.get("brands")?.as_array().filter(|b| b.len() <= 16)?;
    let platform = fields.get("platform")?.as_str().filter(|p| p.len() <= 64)?;
    Some(ClientHints {
        brands: brands
            .iter()
            .map(|entry| {
                let entry = entry.as_object().filter(|e| e.len() == 2)?;
                let brand = entry.get("brand")?.as_str().filter(|b| b.len() <= 64)?;
                let version = entry.get("version")?.as_str().filter(|v| v.len() <= 32)?;
                Some((brand.to_owned(), version.to_owned()))
            })
            .collect::<Option<_>>()?,
        mobile: fields.get("mobile")?.as_bool()?,
        platform: platform.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const CHROME: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
    const BRANDS: &str = r#""Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140""#;

    fn chrome() -> Value {
        json!({"version":1,"userAgent":CHROME,"language":"en-US","clientHints":{
            "brands":[{"brand":"Chromium","version":"140"},{"brand":"Not=A?Brand","version":"24"},{"brand":"Google Chrome","version":"140"}],
            "mobile":false,"platform":"Windows"}})
    }
    fn chrome_headers() -> Value {
        json!({"userAgent":CHROME,"acceptLanguage":"en-US,en;q=0.9","secChUa":BRANDS,
            "secChUaMobile":"?0","secChUaPlatform":"\"Windows\""})
    }
    fn outcome(
        evidence: Option<Value>,
        headers: Value,
    ) -> (&'static str, Vec<&'static str>, Vec<&'static str>) {
        let result = check(evidence.as_ref(), &headers, None);
        (result.status, result.indicators, result.unavailable_probes)
    }

    #[test]
    fn a_browser_and_its_own_request_agree() {
        assert_eq!(
            outcome(Some(chrome()), chrome_headers()),
            ("not_detected", vec![], vec![])
        );
        let firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0";
        assert_eq!(
            outcome(
                Some(json!({"version":1,"userAgent":firefox,"language":"ja","clientHints":null})),
                json!({"userAgent":firefox,"acceptLanguage":"ja-JP"})
            ),
            ("not_detected", vec![], vec![]),
            "no client hints on either side and a regional Accept-Language agree"
        );
    }

    #[test]
    fn each_contradiction_is_reported_on_its_own() {
        let mut headers = chrome_headers();
        headers["userAgent"] = json!("python-requests/2.32");
        assert_eq!(outcome(Some(chrome()), headers).1, ["user_agent_mismatch"]);
        for (key, value) in [
            (
                "secChUa",
                r#""Chromium";v="139", "Not=A?Brand";v="24", "Google Chrome";v="139""#,
            ),
            ("secChUaMobile", "?1"),
            ("secChUaPlatform", "\"macOS\""),
        ] {
            let mut headers = chrome_headers();
            headers[key] = json!(value);
            assert_eq!(
                outcome(Some(chrome()), headers).1,
                ["client_hints_mismatch"],
                "{key}"
            );
        }
        let mut headers = chrome_headers();
        headers["acceptLanguage"] = json!("de-DE,de;q=0.9");
        assert_eq!(outcome(Some(chrome()), headers).1, ["language_mismatch"]);
    }

    #[test]
    fn missing_or_unreadable_sides_are_unknown_not_false() {
        assert_eq!(
            outcome(Some(chrome()), json!({})),
            ("unknown", vec![], PROBES[..3].to_vec())
        );
        assert_eq!(
            outcome(None, chrome_headers()),
            ("unknown", vec![], PROBES[..3].to_vec()),
            "evidence without the spoofing part"
        );
        for (key, value) in [
            ("secChUa", json!(null)),
            ("secChUa", json!("not a list")),
            ("secChUaMobile", json!("yes")),
            ("secChUaPlatform", json!("Windows")),
        ] {
            let mut headers = chrome_headers();
            headers[key] = value;
            assert_eq!(
                outcome(Some(chrome()), headers),
                ("unknown", vec![], vec!["client_hints_mismatch"]),
                "{key}"
            );
        }
        let mut no_hints = chrome();
        no_hints["clientHints"] = json!(null);
        assert_eq!(
            outcome(Some(no_hints), chrome_headers()).2,
            ["client_hints_mismatch"],
            "headers without claimed hints"
        );
        for language in ["*", "", ";q=1"] {
            let mut headers = chrome_headers();
            headers["acceptLanguage"] = json!(language);
            assert_eq!(
                outcome(Some(chrome()), headers).2,
                ["language_mismatch"],
                "{language:?}"
            );
        }
    }

    #[test]
    fn brand_lists_parse_escapes_and_any_order() {
        let parsed = brand_list(r#""B\"rand";v="1","A;B, C";v="2""#).unwrap();
        assert_eq!(
            parsed,
            BTreeSet::from([
                ("A;B, C".into(), "2".into()),
                ("B\"rand".into(), "1".into())
            ])
        );
        for bad in [
            "",
            r#""A";v="1","#,
            r#""A";x="1""#,
            r#""A";v=1"#,
            r#""A""#,
            r#""A";v="1" "B";v="2""#,
        ] {
            assert_eq!(brand_list(bad), None, "{bad}");
        }
    }

    #[test]
    fn malformed_input_is_rejected_without_a_verdict() {
        for headers in [
            json!(null),
            json!("headers"),
            json!({"cookie":"secret"}),
            json!({"userAgent":1}),
            json!({"userAgent":"x".repeat(HEADER_LIMIT + 1)}),
        ] {
            let result = check(Some(&chrome()), &headers, None);
            assert_eq!(
                (result.status, result.reason),
                ("invalid_input", Some("invalid_headers"))
            );
            assert!(result.indicators.is_empty() && result.unavailable_probes.is_empty());
        }
        let mut too_many = chrome();
        too_many["clientHints"]["brands"] = json!(vec![json!({"brand":"A","version":"1"}); 17]);
        for evidence in [
            json!(null),
            json!({"version":2,"userAgent":CHROME}),
            json!({"version":1,"extra":true}),
            json!({"version":1,"userAgent":""}),
            json!({"version":1,"language":["en"]}),
            json!({"version":1,"clientHints":{"brands":[],"mobile":false}}),
            json!({"version":1,"clientHints":{"brands":[{"brand":"A"}],"mobile":false,"platform":"X"}}),
            too_many,
        ] {
            let result = check(Some(&evidence), &chrome_headers(), None);
            assert_eq!(
                (result.status, result.reason),
                ("invalid_input", Some("invalid_spoofing")),
                "{evidence}"
            );
        }
    }

    #[test]
    fn metrics_count_verdicts_and_each_mismatch() {
        let value = |text: &str, line: &str| -> u64 {
            text.lines()
                .find_map(|l| l.strip_prefix(line))
                .and_then(|v| v.trim().parse().ok())
                .unwrap()
        };
        let before = metrics();
        let mut headers = chrome_headers();
        headers["userAgent"] = json!("curl/8");
        check(Some(&chrome()), &headers, None);
        check(Some(&json!({"version":9})), &headers, None);
        let after = metrics();
        for line in [
            "openfingerprint_spoofing_checks_total{status=\"detected\"}",
            "openfingerprint_spoofing_indicators_total{indicator=\"user_agent_mismatch\"}",
        ] {
            assert!(value(&after, line) > value(&before, line), "{line}");
        }
    }
}
