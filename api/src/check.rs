use std::collections::{BTreeMap, HashSet};

use axum::{
    Json,
    extract::{FromRequest, Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use ring::digest;
use serde::{Deserialize, Serialize};

pub const BODY_LIMIT: usize = 64 * 1024;

pub struct AppState {
    pub domains: crate::domains::DomainStore,
    pub dns: crate::mx::Resolver,
    pub rdap: crate::rdap::Rdap,
    pub countries: crate::country::CountryStore,
    pub network: crate::network::Store,
    pub replay: crate::replay::Replay,
}
impl AppState {
    pub fn from_env() -> Result<Self, &'static str> {
        if std::env::var_os("OPENFINGERPRINT_SITES").is_some() {
            eprintln!(
                "OPENFINGERPRINT_SITES is ignored: the API has no authentication. Restrict who can reach it."
            );
        }
        let redis = crate::cache::client_from_env()?;
        let mut state = Self::configure(
            crate::mx::Resolver::from_env()?,
            crate::rdap::Rdap::from_env(redis.clone())?,
            crate::replay::Replay::from_env(redis)?,
        );
        state.domains = crate::domains::DomainStore::from_env();
        state.countries = crate::country::CountryStore::from_env();
        state.network = crate::network::Store::from_env()?;
        Ok(state)
    }
    fn configure(
        dns: crate::mx::Resolver,
        rdap: crate::rdap::Rdap,
        replay: crate::replay::Replay,
    ) -> Self {
        Self {
            network: crate::network::Store::empty(),
            domains: crate::domains::DomainStore::new(crate::domains::DomainData::unavailable(
                "not_configured",
            )),
            dns,
            rdap,
            replay,
            countries: crate::country::CountryStore::new(None),
        }
    }
    async fn check_domain(&self, value: serde_json::Value) -> crate::domains::DomainCheck {
        let domain = match crate::domains::DomainData::input(value) {
            Ok(domain) => domain,
            Err(invalid) => return *invalid,
        };
        let data = self.domains.current();
        // A public suffix has no mailbox of its own; skipping it keeps it away from DNS.
        let suffix = psl::suffix(domain.as_bytes()).is_some_and(|s| {
            s.as_bytes() == domain.as_bytes() && s.typ() == Some(psl::Type::Icann)
        });
        let mx = async {
            if suffix {
                return (Vec::new(), "not_needed");
            }
            match self.dns.mx(&domain).await {
                crate::mx::Lookup::Hosts(hosts) => (hosts, "resolved"),
                other => (Vec::new(), other.status()),
            }
        };
        let registration = async {
            if data.hosted_tenant(&domain) {
                crate::rdap::Registration::status("not_applicable")
            } else {
                self.rdap.lookup(&domain).await
            }
        };
        let mail_auth = async {
            if suffix {
                (
                    crate::mailauth::Spf::status("not_needed"),
                    crate::mailauth::Dmarc::status("not_needed"),
                )
            } else {
                crate::mailauth::check(&self.dns, &domain).await
            }
        };
        let ((hosts, lookup), registration, (spf, dmarc)) = tokio::join!(
            crate::metrics::timed(crate::metrics::Step::DomainMx, mx),
            crate::metrics::timed(crate::metrics::Step::DomainRegistration, registration),
            crate::metrics::timed(crate::metrics::Step::DomainMailAuth, mail_auth)
        );
        data.check_with(&domain, &hosts, lookup)
            .with_registration(registration)
            .with_mail_auth(spf, dmarc)
    }
    /// The API has no authentication, so a browser must not be able to reach it from a web
    /// page: any request that carries an `Origin` header is refused.
    pub(crate) fn reject_browsers(&self, headers: &HeaderMap) -> Result<(), ApiError> {
        if headers.contains_key(header::ORIGIN) {
            return Err(ApiError::forbidden());
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Signals {
    automation: Option<serde_json::Value>,
    tampering: Option<serde_json::Value>,
    version: u16,
    fingerprint: Option<String>,
    core_fingerprint: Option<String>,
    components: BTreeMap<String, String>,
    hints: BTreeMap<String, String>,
    unavailable: BTreeMap<String, Availability>,
    excluded: Vec<String>,
    duration_ms: f64,
    #[serde(default)]
    storage_id: Option<String>,
    /// Milliseconds since the Unix epoch on the collecting browser's clock.
    #[serde(default)]
    collected_at: Option<f64>,
    #[serde(default)]
    timings: BTreeMap<String, Timing>,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Availability {
    Unsupported,
    Unstable,
    Timeout,
    Error,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Timing {
    duration_ms: f64,
    blocking_ms: f64,
}
#[derive(Serialize)]
struct Profile<'a> {
    components: Vec<(&'a String, &'a String)>,
    hints: Vec<(&'a String, &'a String)>,
}
const GROUPS: [(&str, &[&str]); 4] = [
    ("fonts", &["fontFallbacks", "fontPreferences", "fonts"]),
    (
        "hardware",
        &["architecture", "display", "hardware", "screen"],
    ),
    ("rendering", &["audio", "canvas", "gpu"]),
    (
        "software",
        &["browser", "features", "math", "media", "platform"],
    ),
];

impl Signals {
    fn identity_groups(&self) -> BTreeMap<&'static str, String> {
        GROUPS
            .iter()
            .filter_map(|(group, members)| {
                let entries = members
                    .iter()
                    .map(|m| {
                        let m = *m;
                        let hash = self.components.get(m).or_else(|| self.hints.get(m))?;
                        (!self.excluded.iter().any(|e| e == m)).then_some((m, hash))
                    })
                    .collect::<Option<Vec<_>>>()?;
                let payload = serde_json::to_string(&entries).expect("string entries");
                Some((
                    *group,
                    sha256(&format!(
                        "stealth-group:{group}:{}\0{payload}",
                        self.version
                    )),
                ))
            })
            .collect()
    }

    fn verified(&self) -> Result<Verified, ApiError> {
        if !self.valid() {
            return Err(ApiError::invalid());
        }
        let available = self.fingerprint.is_some();
        Ok(Verified {
            status: if available {
                "ok"
            } else {
                "insufficient_signals"
            },
            schema_version: available.then_some(self.version),
            fingerprint: self.fingerprint.as_deref().map(short_id),
        })
    }

    fn valid(&self) -> bool {
        let hashes = [&self.components, &self.hints];
        if self.version != 1
            || self.storage_id.is_some()
            || self
                .collected_at
                .is_some_and(|at| !(at.is_finite() && (0.0..=1e15).contains(&at)))
            || !ms(self.duration_ms)
            || hashes
                .iter()
                .any(|m| m.len() > 32 || m.iter().any(|(k, v)| !name(k) || !is_hex(v, 64)))
            || self.unavailable.len() > 32
            || self
                .unavailable
                .keys()
                .any(|k| !name(k) || self.components.contains_key(k) || self.hints.contains_key(k))
            || self.components.keys().any(|k| self.hints.contains_key(k))
            || self.timings.len() > 32
            || self
                .timings
                .iter()
                .any(|(k, t)| !name(k) || !ms(t.duration_ms) || !ms(t.blocking_ms))
            || self.excluded.len() > 3
            || self
                .excluded
                .iter()
                .any(|k| !["audio", "canvas", "screen"].contains(&k.as_str()))
            || self.excluded.iter().collect::<HashSet<_>>().len() != self.excluded.len()
        {
            return false;
        }
        let profile = Profile {
            components: self
                .components
                .iter()
                .filter(|(k, _)| !self.excluded.contains(k))
                .collect(),
            hints: self
                .hints
                .iter()
                .filter(|(k, _)| !self.excluded.contains(k))
                .collect(),
        };
        let has_core = !profile.components.is_empty();
        let core = serde_json::to_string(&profile.components).expect("string entries");
        let full = serde_json::to_string(&profile).expect("string entries");
        [
            (self.fingerprint.as_ref(), "stealth-agent", full),
            (self.core_fingerprint.as_ref(), "stealth-core", core),
        ]
        .iter()
        .all(|(value, domain, payload)| {
            value.is_none_or(|v| {
                has_core && *v == sha256(&format!("{domain}:{}\0{payload}", self.version))
            })
        })
    }
}

#[derive(Serialize)]
struct Verified {
    status: &'static str,
    schema_version: Option<u16>,
    fingerprint: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckRequest {
    pub(crate) automation: Option<serde_json::Value>,
    pub(crate) signals: Option<serde_json::Value>,
    pub(crate) domain: Option<serde_json::Value>,
    pub(crate) email: Option<serde_json::Value>,
    pub(crate) ip: Option<serde_json::Value>,
    pub(crate) detail: Option<bool>,
}

#[derive(Serialize)]
struct IpCheck {
    #[serde(flatten)]
    country: crate::country::Check,
    network: serde_json::Value,
}

#[derive(Serialize)]
struct CheckResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    automation: Option<crate::automation::Check>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signals: Option<SignalCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain: Option<crate::domains::DomainCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<crate::email::EmailCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<IpCheck>,
}

#[derive(Serialize)]
pub(crate) struct SignalCheck {
    #[serde(skip_serializing_if = "Option::is_none")]
    automation: Option<crate::automation::Check>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tampering: Option<crate::tampering::Check>,
    #[serde(flatten)]
    profile: Verified,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    evidence: Option<Evidence>,
    /// Whether this exact token was checked before. Absent when Redis could not say.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) replayed: Option<bool>,
    /// Milliseconds between the browser's collection time and now, by the browser's clock.
    /// Negative when that clock is ahead; absent without a collection time.
    #[serde(rename = "tokenAgeMs", skip_serializing_if = "Option::is_none")]
    token_age_ms: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all(serialize = "camelCase"))]
struct Evidence {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    identity_groups: BTreeMap<&'static str, String>,
    included_components: usize,
    included_hints: usize,
    unavailable_probes: usize,
    excluded_probes: usize,
}

/// First 126 bits of the full SHA-256 as 21 base64url characters (NanoID-sized).
fn short_id(hex: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let (mut acc, mut bits, mut out) = (0u32, 0, String::new());
    for pair in hex.as_bytes()[..32].chunks(2) {
        let byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap_or("0"), 16).unwrap_or(0);
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            out.push(ALPHABET[(acc >> bits & 63) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    out.truncate(21);
    out
}

const TOKEN_SEED: u32 = 0x6f66_7031;

/// Reverses the SDK's token obfuscation (see sdk/src/token.ts). This is not
/// encryption: it only hides evidence from casual inspection. Anything that is
/// not a valid token becomes null.
pub(crate) fn open(token: &serde_json::Value) -> serde_json::Value {
    let decode = |text: &str| -> Option<Vec<u8>> {
        let (mut bits, mut acc, mut out) = (0u32, 0u32, Vec::new());
        for c in text.bytes() {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'-' => 62,
                b'_' => 63,
                _ => return None,
            };
            acc = (acc << 6) | u32::from(v);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
                acc &= (1 << bits) - 1;
            }
        }
        Some(out)
    };
    token
        .as_str()
        .and_then(decode)
        .filter(|bytes| bytes.len() > 4)
        .and_then(|bytes| {
            let (nonce, body) = bytes.split_at(4);
            let mut state = u32::from_be_bytes(nonce.try_into().ok()?) ^ TOKEN_SEED;
            let plain: Vec<u8> = body
                .iter()
                .map(|b| {
                    state = state.wrapping_add(0x6d2b_79f5);
                    let mut t = state;
                    t = (t ^ (t >> 15)).wrapping_mul(t | 1);
                    t ^= t.wrapping_add((t ^ (t >> 7)).wrapping_mul(t | 61));
                    b ^ ((t ^ (t >> 14)) & 255) as u8
                })
                .collect();
            serde_json::from_slice(&plain).ok()
        })
        .unwrap_or(serde_json::Value::Null)
}

/// A fact object (`value` plus `status`) reduced to its bare value.
fn bare(fact: &serde_json::Value) -> Option<serde_json::Value> {
    let fact = fact.as_object()?;
    fact.contains_key("status")
        .then(|| fact.get("value").cloned())?
}

/// Default response: one flat object of verdicts. `signals` becomes a bare
/// `fingerprint` (null unless fully verified); every other section contributes
/// only the facts to act on. Unknown facts are omitted, so a missing key means
/// unknown, and rejected inputs are listed under `invalid`.
fn compact(response: &mut serde_json::Value) {
    use serde_json::{Map, Value, json};
    let Some(map) = response.as_object_mut() else {
        return;
    };
    let mut out = Map::new();
    let mut invalid = Vec::new();
    let put = |out: &mut Map<String, Value>, key: &str, fact: &Value| {
        if let Some(fact) = bare(fact)
            .or_else(|| Some(fact.clone()))
            .filter(|f| !f.is_null())
        {
            out.insert(key.into(), fact);
        }
    };
    if let Some(signals) = map.remove("signals") {
        out.insert("fingerprint".into(), signals["fingerprint"].clone());
        for key in ["replayed", "tokenAgeMs"] {
            if let Some(value) = signals.get(key).filter(|v| !v.is_null()) {
                out.insert(key.into(), value.clone());
            }
        }
        if signals["status"] == "invalid_input" {
            invalid.push("signals");
        }
        for key in ["automation", "tampering"] {
            if let Some(check) = signals.get(key) {
                map.entry(key).or_insert_with(|| check.clone());
            }
        }
    }
    for key in ["automation", "tampering"] {
        if let Some(check) = map.remove(key) {
            match check["status"].as_str() {
                Some("detected") => out.insert(key.into(), json!(true)),
                Some("not_detected") => out.insert(key.into(), json!(false)),
                Some("invalid_input") => {
                    invalid.push(key);
                    None
                }
                _ => None,
            };
        }
    }
    let email = map.remove("email");
    if let Some(domain) = map.remove("domain") {
        if domain["status"] == "invalid_input" {
            invalid.push("domain");
        }
        for (name, key) in [
            ("disposable", "disposable"),
            ("free", "publicMailbox"),
            ("spam", "spam"),
            ("relay", "relay"),
            ("cheapTld", "cheapTld"),
        ] {
            put(&mut out, name, &domain[key]);
        }
        match domain["mxLookup"].as_str() {
            Some("resolved") => out.insert("mx".into(), json!(true)),
            Some("no_records" | "no_domain") => out.insert("mx".into(), json!(false)),
            _ => None,
        };
    }
    if email.is_some_and(|e| e["status"] == "invalid_input") {
        invalid.push("email");
    }
    if let Some(ip) = map.remove("ip") {
        if ip["status"] == "invalid_input" {
            invalid.push("ip");
        } else {
            if let Some(code) = ip["countryCode"].as_str() {
                out.insert("country".into(), code.to_ascii_lowercase().into());
            }
            for key in ["vpn", "tor", "datacenter", "proxy"] {
                put(&mut out, key, &ip["network"][key]);
            }
        }
    }
    if !invalid.is_empty() {
        out.insert("invalid".into(), json!(invalid));
    }
    *response = Value::Object(out);
}

pub(crate) fn check_signals(value: serde_json::Value) -> SignalCheck {
    if let Ok(signals) = serde_json::from_value::<Signals>(value)
        && let Ok(profile) = signals.verified()
    {
        let identity_groups = signals.identity_groups();
        return SignalCheck {
            token_age_ms: signals.collected_at.map(age_ms),
            replayed: None,
            automation: signals.automation.map(crate::automation::check),
            tampering: signals.tampering.map(crate::tampering::check),
            profile,
            reason: None,
            evidence: Some(Evidence {
                identity_groups,
                included_components: signals
                    .components
                    .keys()
                    .filter(|k| !signals.excluded.contains(k))
                    .count(),
                included_hints: signals
                    .hints
                    .keys()
                    .filter(|k| !signals.excluded.contains(k))
                    .count(),
                unavailable_probes: signals.unavailable.len(),
                excluded_probes: signals.excluded.len(),
            }),
        };
    }
    SignalCheck {
        automation: None,
        tampering: None,
        profile: Verified {
            status: "invalid_input",
            schema_version: None,
            fingerprint: None,
        },
        reason: Some("invalid_signals"),
        evidence: None,
        replayed: None,
        token_age_ms: None,
    }
}

fn age_ms(collected_at: f64) -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64);
    now - collected_at as i64
}

pub(crate) fn domain(value: &str) -> bool {
    let value = value.strip_suffix('.').unwrap_or(value);
    value.len() <= 253
        && value.is_ascii()
        && value.contains('.')
        && value
            .rsplit('.')
            .next()
            .is_some_and(|label| label.bytes().any(|b| b.is_ascii_alphabetic()))
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[derive(Debug)]
pub struct ApiError(pub(crate) StatusCode, pub(crate) &'static str);
impl ApiError {
    fn forbidden() -> Self {
        Self(StatusCode::FORBIDDEN, "origin_not_allowed")
    }
    pub(crate) fn invalid() -> Self {
        Self(StatusCode::BAD_REQUEST, "invalid_request")
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({"error":self.1}))).into_response()
    }
}

pub async fn check(
    State(state): State<std::sync::Arc<AppState>>,
    request: Request,
) -> Result<Response, ApiError> {
    state.reject_browsers(request.headers())?;
    let Json(input) = Json::<CheckRequest>::from_request(request, &())
        .await
        .map_err(json_error)?;
    Ok(Json(evaluate(&state, input).await?).into_response())
}

pub(crate) async fn evaluate(
    state: &AppState,
    input: CheckRequest,
) -> Result<serde_json::Value, ApiError> {
    let empty = input.automation.is_none()
        && input.signals.is_none()
        && input.domain.is_none()
        && input.email.is_none()
        && input.ip.is_none();
    if empty || (input.domain.is_some() && input.email.is_some()) {
        return Err(ApiError::invalid());
    }
    use crate::metrics::{Step, start, timed};
    let (email, domain) = match input.email.as_ref().map(crate::email::parse) {
        Some(Some((local, domain))) => (
            Some(crate::email::check(&local)),
            Some(serde_json::Value::String(domain)),
        ),
        Some(None) => (Some(crate::email::invalid()), None),
        None => (None, input.domain),
    };
    let domain = match domain {
        Some(value) => Some(timed(Step::Domain, state.check_domain(value)).await),
        None => None,
    };
    let signals = match input.signals {
        Some(token) => {
            let opened = open(&token);
            let mut check = {
                let _timer = start(Step::Signals);
                check_signals(opened.clone())
            };
            if check.profile.status != "invalid_input" {
                let key = crate::replay::key(&opened);
                check.replayed = timed(Step::Replay, state.replay.first_seen(&key))
                    .await
                    .map(|first| !first);
            }
            Some(check)
        }
        None => None,
    };
    let mut response = serde_json::to_value(CheckResponse {
        automation: input.automation.map(|a| {
            let _timer = start(Step::Automation);
            crate::automation::check(a)
        }),
        signals,
        domain,
        email,
        ip: input.ip.map(|ip| IpCheck {
            country: {
                let _timer = start(Step::IpCountry);
                state.countries.check(ip.clone())
            },
            network: {
                let _timer = start(Step::IpNetwork);
                state.network.current().check(ip, "backend_supplied")
            },
        }),
    })
    .map_err(|_| ApiError::invalid())?;
    if input.detail != Some(true) {
        compact(&mut response);
    }
    Ok(response)
}

pub(crate) fn json_error(error: axum::extract::rejection::JsonRejection) -> ApiError {
    if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large")
    } else {
        ApiError::invalid()
    }
}
fn name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.as_bytes()[0].is_ascii_alphabetic()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
}
fn ms(v: f64) -> bool {
    v.is_finite() && (0.0..=60000.0).contains(&v)
}
fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(crate) fn sha256(s: &str) -> String {
    hex(digest::digest(&digest::SHA256, s.as_bytes()).as_ref())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn dns() -> crate::mx::Resolver {
        crate::mx::Resolver::new("127.0.0.1:9", None).unwrap()
    }
    fn rdap() -> crate::rdap::Rdap {
        crate::rdap::Rdap::new(
            br#"{"services":[[["test"],["https://rdap.invalid/"]]]}"#,
            false,
            crate::cache::Cache::new(crate::cache::tests::client_for("127.0.0.1:9")),
        )
        .unwrap()
    }
    fn state_with_redis(addr: &str) -> AppState {
        AppState::configure(
            dns(),
            rdap(),
            crate::replay::Replay::new(crate::cache::tests::client_for(addr), 60),
        )
    }
    pub(crate) fn state() -> AppState {
        state_with_redis("127.0.0.1:9")
    }
    /// The SDK's token obfuscation (sdk/src/token.ts), to build tokens for `evaluate`.
    fn seal(value: &serde_json::Value, nonce: [u8; 4]) -> String {
        let mut state = u32::from_be_bytes(nonce) ^ TOKEN_SEED;
        let mut bytes = nonce.to_vec();
        for b in value.to_string().bytes() {
            state = state.wrapping_add(0x6d2b_79f5);
            let mut t = state;
            t = (t ^ (t >> 15)).wrapping_mul(t | 1);
            t ^= t.wrapping_add((t ^ (t >> 7)).wrapping_mul(t | 61));
            bytes.push(b ^ ((t ^ (t >> 14)) & 255) as u8);
        }
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let (mut acc, mut bits, mut out) = (0u32, 0, String::new());
        for byte in bytes {
            acc = (acc << 8) | u32::from(byte);
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                out.push(ALPHABET[(acc >> bits & 63) as usize] as char);
            }
            acc &= (1 << bits) - 1;
        }
        if bits > 0 {
            out.push(ALPHABET[(acc << (6 - bits) & 63) as usize] as char);
        }
        out
    }
    fn request(token: &str, detail: bool) -> CheckRequest {
        CheckRequest {
            automation: None,
            signals: Some(serde_json::json!(token)),
            domain: None,
            email: None,
            ip: None,
            detail: detail.then_some(true),
        }
    }
    fn now_ms() -> f64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as f64
    }
    fn signals() -> Signals {
        let mut s: Signals = serde_json::from_value(serde_json::json!({"version":1,"fingerprint":null,"coreFingerprint":null,"components":{"fontPreferences":sha256("fixture")},"hints":{},"unavailable":{},"excluded":[],"durationMs":1})).unwrap();
        let entries: Vec<_> = s.components.iter().collect();
        s.core_fingerprint = Some(sha256(&format!(
            "stealth-core:1\0{}",
            serde_json::to_string(&entries).unwrap()
        )));
        s.fingerprint = Some(sha256(&format!(
            "stealth-agent:1\0{}",
            serde_json::json!({"components":entries,"hints":[]})
        )));
        s
    }

    fn payload() -> serde_json::Value {
        let s = signals();
        serde_json::json!({
            "version": s.version, "fingerprint": s.fingerprint,
            "coreFingerprint": s.core_fingerprint, "components": s.components,
            "hints": s.hints, "unavailable": {}, "excluded": s.excluded,
            "durationMs": s.duration_ms
        })
    }

    #[test]
    fn browsers_are_refused_and_any_authorization_header_is_ignored() {
        let state = state();
        let mut headers = HeaderMap::new();
        assert!(state.reject_browsers(&headers).is_ok());
        headers.insert(header::AUTHORIZATION, "Bearer anything".parse().unwrap());
        assert!(state.reject_browsers(&headers).is_ok());
        headers.insert(header::ORIGIN, "https://example.test".parse().unwrap());
        assert_eq!(
            state.reject_browsers(&headers).unwrap_err().0,
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn seals_and_opens_the_same_tokens_as_the_sdk() {
        let value = serde_json::json!({"a":1,"b":"é"});
        assert_eq!(
            seal(&value, [0x38, 0xa4, 0x7f, 0xd8]),
            "OKR_2CEL-DnVEGq_-LZU_x_gYVU"
        );
        assert_eq!(open(&serde_json::json!(seal(&value, [1, 2, 3, 4]))), value);
    }

    #[test]
    fn collection_time_must_be_plausible_and_gives_the_token_age() {
        let mut s = signals();
        for ok in [None, Some(0.0), Some(1.7e12)] {
            s.collected_at = ok;
            assert!(s.valid());
        }
        for bad in [-1.0, f64::NAN, f64::INFINITY, 2e15] {
            s.collected_at = Some(bad);
            assert!(!s.valid());
        }
        let mut input = payload();
        input["collectedAt"] = serde_json::json!(now_ms() - 90_000.0);
        let age = check_signals(input.clone()).token_age_ms.unwrap();
        assert!((90_000..120_000).contains(&age), "{age}");
        input["collectedAt"] = serde_json::json!(now_ms() + 5_000.0);
        let age = check_signals(input).token_age_ms.unwrap();
        assert!(
            (-5_100..0).contains(&age),
            "a clock ahead gives a negative age: {age}"
        );
        assert!(check_signals(payload()).token_age_ms.is_none());
        assert!(check_signals(serde_json::json!({})).token_age_ms.is_none());
    }

    #[tokio::test]
    async fn a_token_checked_twice_is_replayed_even_when_resealed_and_unknown_without_redis() {
        let (addr, store) = crate::cache::tests::fake_redis(None).await;
        let state = state_with_redis(&addr);
        let replayed = |response: serde_json::Value| response["signals"]["replayed"].clone();

        let token = seal(&payload(), [1, 2, 3, 4]);
        let first = evaluate(&state, request(&token, true)).await.unwrap();
        assert_eq!(replayed(first), false);
        let again = evaluate(&state, request(&token, true)).await.unwrap();
        assert_eq!(replayed(again), true);
        let resealed = seal(&payload(), [9, 9, 9, 9]);
        let copy = evaluate(&state, request(&resealed, true)).await.unwrap();
        assert_eq!(
            replayed(copy),
            true,
            "a new random prefix is not new evidence"
        );

        let mut other = payload();
        other["durationMs"] = serde_json::json!(2);
        let fresh = evaluate(&state, request(&seal(&other, [1, 2, 3, 4]), true))
            .await
            .unwrap();
        assert_eq!(replayed(fresh), false);
        assert_eq!(store.lock().unwrap().len(), 2);

        let invalid = evaluate(
            &state,
            request(&seal(&serde_json::json!({"x":1}), [1, 2, 3, 4]), true),
        )
        .await
        .unwrap();
        assert!(invalid["signals"].get("replayed").is_none());
        assert_eq!(
            store.lock().unwrap().len(),
            2,
            "invalid tokens leave no marker"
        );

        let compact = evaluate(&state, request(&token, false)).await.unwrap();
        assert_eq!(compact["replayed"], true);

        let without = evaluate(&self::state(), request(&token, false))
            .await
            .unwrap();
        assert!(without.get("replayed").is_none(), "unknown is not false");
        assert!(without["fingerprint"].is_string());
    }

    #[test]
    fn validates_schema_missingness_and_canonical_identity() {
        assert!(signals().valid());
        let mut s = signals();
        s.version = 2;
        assert!(!s.valid());
        let mut s = signals();
        s.version = 0;
        assert!(!s.valid());
        let mut s = signals();
        s.fingerprint = Some("b".repeat(64));
        assert!(!s.valid());
        let mut s = signals();
        s.components.insert("fontPreferences".into(), "raw".into());
        assert!(!s.valid());
        let mut s = signals();
        s.unavailable
            .insert("fontPreferences".into(), Availability::Error);
        assert!(!s.valid());
        let mut s = signals();
        s.hints = s.components.clone();
        assert!(!s.valid());
        let mut s = signals();
        s.storage_id = Some("unsolicited".into());
        assert!(!s.valid());
        let mut s = signals();
        s.excluded = vec!["canvas".into(), "canvas".into()];
        assert!(!s.valid());
        let mut s = signals();
        s.duration_ms = f64::NAN;
        assert!(!s.valid());
        let mut s = signals();
        s.components.clear();
        assert!(!s.valid());
        s.fingerprint = None;
        s.core_fingerprint = None;
        assert!(s.valid());
    }

    #[test]
    fn identity_groups_need_every_member_and_ignore_other_probes() {
        let mut s = signals();
        assert!(s.identity_groups().is_empty());
        for m in ["audio", "canvas"] {
            s.components.insert(m.into(), sha256(m));
        }
        s.hints.insert("gpu".into(), sha256("gpu"));
        let groups = s.identity_groups();
        assert_eq!(groups.keys().copied().collect::<Vec<_>>(), ["rendering"]);
        let baseline = groups["rendering"].clone();

        s.components
            .insert("fontPreferences".into(), sha256("other"));
        assert_eq!(s.identity_groups()["rendering"], baseline);

        s.hints.insert("gpu".into(), sha256("other gpu"));
        assert_ne!(s.identity_groups()["rendering"], baseline);

        s.excluded = vec!["canvas".into()];
        assert!(s.identity_groups().is_empty());
        s.version = 2;
        s.excluded.clear();
        assert_ne!(s.identity_groups()["rendering"], baseline);
    }

    #[test]
    fn short_id_is_21_url_safe_characters_from_the_hash_prefix() {
        // Reference: Buffer.from(hex, 'hex').subarray(0, 16).toString('base64url').slice(0, 21)
        let id = short_id(&format!("00ff10{}", "ab".repeat(29)));
        assert_eq!(id, "AP8Qq6urq6urq6urq6urq");
    }

    #[test]
    fn opens_sdk_tokens_and_rejects_everything_else() {
        assert_eq!(
            open(&serde_json::json!("OKR_2CEL-DnVEGq_-LZU_x_gYVU")),
            serde_json::json!({"a":1,"b":"é"})
        );
        for bad in [
            serde_json::json!({"a":1}),
            serde_json::json!("not a token!"),
            serde_json::json!("AAAA"),
            serde_json::Value::Null,
        ] {
            assert!(open(&bad).is_null());
        }
    }

    #[test]
    fn compact_responses_are_flat_verdicts() {
        let mut response = serde_json::json!({
            "signals": {"status":"ok","fingerprint":"abc","replayed":true,"tokenAgeMs":1200,"evidence":{},
                "automation":{"status":"detected","ruleVersion":2,"source":"client_reported","indicators":["webdriver"],"unavailableProbes":[]},
                "tampering":{"status":"not_detected","rule_version":1,"source":"client_reported","indicators":[],"unavailable_probes":[]}},
            "email": {"status":"checked","roleAccount":true},
            "domain": {"status":"ok","disposable":{"value":true,"status":"listed","scope":"s","sources":[]},
                "spam":{"value":null,"status":"unknown"},
                "publicMailbox":{"value":false,"status":"not_listed"},
                "cheapTld":{"value":true,"status":"cheap"},
                "mxLookup":"resolved","registration":{"status":"found"}},
            "ip": {"status":"ok","countryCode":"DK","source":{},
                "network":{"status":"ok","source":"x","tor":{"value":false,"status":"ok","source":null},
                    "vpn":{"value":null,"status":"unknown"},"asn":{"value":{"number":1},"status":"ok"}}}
        });
        compact(&mut response);
        assert_eq!(
            response,
            serde_json::json!({
                "fingerprint":"abc","replayed":true,"tokenAgeMs":1200,"automation":true,
                "tampering":false,"disposable":true,"free":false,"cheapTld":true,"mx":true,
                "country":"dk","tor":false
            })
        );
        let mut domain = serde_json::json!({"domain":{"status":"ok","mxLookup":"no_domain"}});
        compact(&mut domain);
        assert_eq!(domain, serde_json::json!({"mx":false}));
        let mut invalid = serde_json::json!({
            "signals":{"status":"invalid_input","fingerprint":null},
            "automation":{"status":"invalid_input"},
            "email":{"status":"invalid_input","reason":"invalid_email"},
            "ip":{"status":"invalid_input","reason":"invalid_ip","network":{}}});
        compact(&mut invalid);
        assert_eq!(
            invalid,
            serde_json::json!({"fingerprint":null,"invalid":["signals","automation","email","ip"]})
        );
    }

    #[test]
    fn signal_results_report_counts_not_confidence_or_core_fallbacks() {
        let result = check_signals(payload());
        assert_eq!(result.profile.status, "ok");
        let evidence = result.evidence.unwrap();
        assert_eq!(evidence.included_components, 1);
        assert_eq!(evidence.included_hints, 0);
        assert_eq!(evidence.excluded_probes, 0);
        assert_eq!(evidence.unavailable_probes, 0);

        let mut input = payload();
        input["components"]["canvas"] = serde_json::json!(sha256("diagnostic"));
        input["excluded"] = serde_json::json!(["canvas"]);
        let result = check_signals(input);
        assert_eq!(result.profile.status, "ok");
        let evidence = result.evidence.unwrap();
        assert_eq!(evidence.included_components, 1);
        assert_eq!(evidence.excluded_probes, 1);

        let mut input = payload();
        input["fingerprint"] = serde_json::Value::Null;
        let result = check_signals(input);
        assert_eq!(result.profile.status, "insufficient_signals");
        assert!(result.profile.fingerprint.is_none());
        assert!(result.profile.schema_version.is_none());
        assert!(result.evidence.is_some());

        for input in [serde_json::json!("not evidence"), serde_json::json!({}), {
            let mut p = payload();
            p["fingerprint"] = serde_json::json!("b".repeat(64));
            p
        }] {
            let result = check_signals(input);
            assert_eq!(result.profile.status, "invalid_input");
            assert_eq!(result.reason, Some("invalid_signals"));
            assert!(result.evidence.is_none());
            assert!(result.profile.fingerprint.is_none());
        }
    }

    #[test]
    fn domain_inputs_are_bounded_ascii_hostnames_not_urls_or_addresses() {
        for valid in [
            "example.com",
            "ExAmPlE.COM.",
            "a-b.example",
            "xn--bcher-kva.example",
        ] {
            assert!(domain(valid));
            let result =
                serde_json::to_value(state().domains.current().check(serde_json::json!(valid)))
                    .unwrap();
            assert_eq!(result["status"], "unknown");
            assert_eq!(result["reason"], "not_configured");
        }
        let maximum = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert!(domain(&maximum));
        assert!(!domain(&(maximum + "e")));
        for invalid in [
            "",
            "localhost",
            "example.com..",
            ".example.com",
            "example..com",
            "-a.example",
            "a-.example",
            "a_b.example",
            "*.example.com",
            "https://example.com",
            "example.com/path",
            "example.com:443",
            "person@example.com",
            " example.com",
            "example.com\n",
            "bücher.example",
            "192.0.2.1",
            "2001:db8::1",
        ] {
            assert!(!domain(invalid));
            let result =
                serde_json::to_value(state().domains.current().check(serde_json::json!(invalid)))
                    .unwrap();
            assert_eq!(result["status"], "invalid_input");
            assert_eq!(result["reason"], "invalid_domain");
        }
        assert!(!domain(&format!("{}.example", "a".repeat(64))));
        let result =
            serde_json::to_value(state().domains.current().check(serde_json::json!([]))).unwrap();
        assert_eq!(result["status"], "invalid_input");
    }

    #[test]
    fn network_inputs_are_ip_literals_and_never_clean_verdicts() {
        for valid in [
            "192.0.2.1",
            "2001:db8::1",
            "::ffff:192.0.2.1",
            "127.0.0.1",
            "::1",
        ] {
            let result = state().countries.check(serde_json::json!(valid));
            assert_eq!(result.status, "unknown");
            assert_eq!(result.reason, Some("not_configured"));
            let result = crate::network::Store::empty()
                .current()
                .check(serde_json::json!(valid), "backend_supplied");
            assert_eq!(result["status"], "unknown");
            assert_eq!(result["reason"], "non_global_ip");
        }
        for invalid in [
            "",
            "example.com",
            "https://192.0.2.1",
            "192.0.2.1:80",
            "192.0.2.0/24",
            "[2001:db8::1]",
            "fe80::1%eth0",
            " 192.0.2.1",
        ] {
            let result = state().countries.check(serde_json::json!(invalid));
            assert_eq!(result.status, "invalid_input");
            assert_eq!(result.reason, Some("invalid_ip"));
        }
        assert_eq!(
            state().countries.check(serde_json::json!(42)).status,
            "invalid_input"
        );
    }
}
