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
    pub identifications: crate::identify::Identifications,
    pub visitors: Option<crate::visitor::Store>,
}
impl AppState {
    pub fn from_env() -> Result<Self, &'static str> {
        let redis = crate::cache::client_from_env()?;
        let mut state = Self::configure(
            crate::mx::Resolver::from_env()?,
            crate::rdap::Rdap::from_env(redis.clone())?,
            crate::replay::Replay::new(redis.clone()),
            crate::identify::Identifications::new(redis),
        );
        state.domains = crate::domains::DomainStore::from_env();
        state.countries = crate::country::CountryStore::from_env();
        state.network = crate::network::Store::from_env()?;
        state.visitors = crate::visitor::Store::from_env()?;
        Ok(state)
    }
    fn configure(
        dns: crate::mx::Resolver,
        rdap: crate::rdap::Rdap,
        replay: crate::replay::Replay,
        identifications: crate::identify::Identifications,
    ) -> Self {
        Self {
            network: crate::network::Store::empty(),
            domains: crate::domains::DomainStore::new(crate::domains::DomainData::unavailable(
                "not_configured",
            )),
            dns,
            rdap,
            replay,
            identifications,
            countries: crate::country::CountryStore::new(None),
            visitors: None,
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
struct Evidence {
    automation: Option<serde_json::Value>,
    tampering: Option<serde_json::Value>,
    #[serde(default)]
    spoofing: Option<serde_json::Value>,
    #[serde(default)]
    behavior: Option<serde_json::Value>,
    version: u16,
    fingerprint: Option<String>,
    core_fingerprint: Option<String>,
    components: BTreeMap<String, String>,
    hints: BTreeMap<String, String>,
    unavailable: BTreeMap<String, Availability>,
    excluded: Vec<String>,
    duration_ms: f64,
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

impl Evidence {
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
        })
    }

    fn valid(&self) -> bool {
        let hashes = [&self.components, &self.hints];
        if self.version != 1
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

pub(crate) fn visitor_profile(value: serde_json::Value) -> Option<crate::visitor::Profile> {
    const COMPONENTS: [&str; 6] = [
        "audio",
        "canvas",
        "fontFallbacks",
        "fontPreferences",
        "fonts",
        "gpu",
    ];
    const HINTS: [&str; 10] = [
        "architecture",
        "browser",
        "display",
        "features",
        "hardware",
        "locale",
        "math",
        "media",
        "platform",
        "screen",
    ];
    let evidence: Evidence = serde_json::from_value(value).ok()?;
    if !evidence.valid() {
        return None;
    }
    let fingerprint = evidence.fingerprint.clone()?;
    let mut excluded = evidence.excluded.clone();
    excluded.sort();
    if !excluded.is_empty() && excluded != ["audio", "canvas", "screen"] {
        return None;
    }
    let complete = |map: &BTreeMap<String, String>, expected: &[&str]| {
        map.keys().all(|key| expected.contains(&key.as_str()))
            && expected
                .iter()
                .all(|key| excluded.iter().any(|e| e == key) || map.contains_key(*key))
    };
    if !complete(&evidence.components, &COMPONENTS) || !complete(&evidence.hints, &HINTS) {
        return None;
    }
    let identity_groups: BTreeMap<String, String> = evidence
        .identity_groups()
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect();
    let locale_signature =
        (excluded.is_empty() && identity_groups.len() == GROUPS.len()).then(|| {
            sha256(&format!(
                "openfingerprint:visitor:locale:1\0{}",
                serde_json::to_string(&identity_groups).expect("group hashes")
            ))
        });
    let included = |map: BTreeMap<String, String>| {
        map.into_iter()
            .filter(|(name, _)| !excluded.contains(name))
            .collect()
    };
    Some(crate::visitor::Profile {
        schema_version: i32::from(evidence.version),
        fingerprint,
        components: included(evidence.components),
        hints: included(evidence.hints),
        identity_groups,
        locale_signature,
        excluded,
    })
}

#[derive(Serialize)]
struct Verified {
    status: &'static str,
    schema_version: Option<u16>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CheckRequest {
    /// From the browser's `POST /v1/identify`.
    pub(crate) identification_id: Option<serde_json::Value>,
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
    identification: Option<IdentificationCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain: Option<crate::domains::DomainCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<crate::email::EmailCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<IpCheck>,
}

#[derive(Serialize)]
#[serde(rename_all(serialize = "camelCase"))]
pub(crate) struct IdentificationCheck {
    #[serde(skip_serializing_if = "Option::is_none")]
    automation: Option<crate::automation::Check>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tampering: Option<crate::tampering::Check>,
    #[serde(skip_serializing_if = "Option::is_none")]
    spoofing: Option<crate::spoofing::Check>,
    #[serde(skip_serializing_if = "Option::is_none")]
    behavior: Option<crate::behavior::Check>,
    #[serde(flatten)]
    profile: Verified,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    evidence: Option<EvidenceCounts>,
    /// Whether this identification was looked up before. Absent when Redis could not say.
    #[serde(skip_serializing_if = "Option::is_none")]
    replayed: Option<bool>,
    /// Milliseconds since the identification was stored, by the API's clock.
    #[serde(skip_serializing_if = "Option::is_none")]
    age_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ja4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_client: Option<crate::tls::Client>,
    #[serde(skip_serializing_if = "Option::is_none")]
    visitor_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reconciliation: Option<crate::visitor::Decision>,
}
impl IdentificationCheck {
    /// Well-formed evidence (with or without a full ID) whose automation, tampering,
    /// spoofing and behavior parts all parsed.
    pub(crate) fn is_valid(&self) -> bool {
        matches!(self.profile.status, "ok" | "insufficient_signals")
            && !self.automation.as_ref().is_some_and(|c| c.rejected())
            && !self.tampering.as_ref().is_some_and(|c| c.rejected())
            && !self.spoofing.as_ref().is_some_and(|c| c.rejected())
            && !self.behavior.as_ref().is_some_and(|c| c.rejected())
    }
    fn failed(status: &'static str, reason: &'static str) -> Self {
        let mut check = check_evidence(serde_json::Value::Null, None, None);
        check.profile.status = status;
        check.reason = Some(reason);
        check
    }
}

#[derive(Serialize)]
#[serde(rename_all(serialize = "camelCase"))]
struct EvidenceCounts {
    included_components: usize,
    included_hints: usize,
    unavailable_probes: usize,
    excluded_probes: usize,
}

/// A fact object (`value` plus `status`) reduced to its bare value.
fn bare(fact: &serde_json::Value) -> Option<serde_json::Value> {
    let fact = fact.as_object()?;
    fact.contains_key("status")
        .then(|| fact.get("value").cloned())?
}

/// Default response: one flat object of verdicts. `identification` becomes a bare
/// visitor ID when resolved; every other section contributes only the facts to act on.
/// Unknown facts are omitted, and rejected inputs are listed under `invalid`.
pub(crate) fn compact(response: &mut serde_json::Value) {
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
    if let Some(identification) = map.remove("identification") {
        for key in ["visitorId", "replayed", "ageMs"] {
            if let Some(value) = identification.get(key).filter(|v| !v.is_null()) {
                out.insert(key.into(), value.clone());
            }
        }
        if identification["status"] == "invalid_input" {
            invalid.push("identificationId");
        }
        for key in ["automation", "tampering", "spoofing"] {
            if let Some(check) = identification.get(key) {
                match check["status"].as_str() {
                    Some("detected") => out.insert(key.into(), json!(true)),
                    Some("not_detected") => out.insert(key.into(), json!(false)),
                    _ => None,
                };
            }
        }
        if identification["behavior"]["status"] == "observed" {
            out.insert(
                "behavior".into(),
                identification["behavior"]["patterns"].clone(),
            );
            put(
                &mut out,
                "suspiciousClickPattern",
                &identification["behavior"]["suspiciousClickPattern"],
            );
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
                match &ip["network"][key]["value"] {
                    Value::Null => {}
                    Value::Bool(listed) => {
                        out.insert(key.into(), json!(listed));
                    }
                    _ => {
                        out.insert(key.into(), json!(true));
                    }
                }
            }
        }
    }
    if !invalid.is_empty() {
        out.insert("invalid".into(), json!(invalid));
    }
    *response = Value::Object(out);
}

/// Verifies the SDK's evidence. `headers` and `tls` are what the identify listener saw of the
/// request that carried it (`tls`: its JA4, `Some(None)` when none could be read).
pub(crate) fn check_evidence(
    value: serde_json::Value,
    headers: Option<&serde_json::Value>,
    tls: Option<Option<&str>>,
) -> IdentificationCheck {
    let mut check = IdentificationCheck {
        automation: None,
        tampering: None,
        spoofing: None,
        behavior: None,
        profile: Verified {
            status: "invalid_input",
            schema_version: None,
        },
        reason: Some("invalid_evidence"),
        evidence: None,
        replayed: None,
        age_ms: None,
        origin: None,
        ja4: None,
        tls_client: None,
        visitor_id: None,
        reconciliation: None,
    };
    if let Ok(evidence) = serde_json::from_value::<Evidence>(value)
        && let Ok(profile) = evidence.verified()
    {
        check.evidence = Some(EvidenceCounts {
            included_components: evidence
                .components
                .keys()
                .filter(|k| !evidence.excluded.contains(k))
                .count(),
            included_hints: evidence
                .hints
                .keys()
                .filter(|k| !evidence.excluded.contains(k))
                .count(),
            unavailable_probes: evidence.unavailable.len(),
            excluded_probes: evidence.excluded.len(),
        });
        check.automation = evidence.automation.map(crate::automation::check);
        check.tampering = evidence.tampering.map(crate::tampering::check);
        check.spoofing =
            headers.map(|h| crate::spoofing::check(evidence.spoofing.as_ref(), h, tls));
        check.behavior = evidence.behavior.map(crate::behavior::check);
        check.profile = profile;
        check.reason = None;
    }
    check
}

fn age_ms(created_at_ms: u64) -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64);
    now - created_at_ms as i64
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
        if self.0.is_server_error() {
            sentry::capture_message(self.1, sentry::Level::Error);
        }
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
    let empty = input.identification_id.is_none()
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
    let identification = async {
        match &input.identification_id {
            Some(id) => Some(check_identification(state, id).await),
            None => None,
        }
    };
    let domain = async {
        match domain {
            Some(value) => Some(timed(Step::Domain, state.check_domain(value)).await),
            None => None,
        }
    };
    let (identification, domain) = tokio::join!(identification, domain);
    let mut response = serde_json::to_value(CheckResponse {
        identification,
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

async fn check_identification(state: &AppState, id: &serde_json::Value) -> IdentificationCheck {
    use crate::metrics::{Step, timed};
    let Some(id) = id.as_str().filter(|id| crate::identify::valid_id(id)) else {
        return IdentificationCheck::failed("invalid_input", "invalid_identification_id");
    };
    let record = match timed(Step::Identification, state.identifications.get(id)).await {
        Ok(Some(record)) => record,
        Ok(None) => return IdentificationCheck::failed("invalid_input", "unknown_identification"),
        Err(()) => {
            return IdentificationCheck::failed("unavailable", "identification_unavailable");
        }
    };
    let mut check = {
        let _timer = crate::metrics::start(Step::Evidence);
        check_evidence(
            record.evidence.clone(),
            Some(&record.headers),
            Some(record.ja4.as_deref()),
        )
    };
    if check.is_valid() {
        check.age_ms = Some(age_ms(record.created_at_ms));
        check.replayed = timed(Step::Replay, state.replay.first_seen(id))
            .await
            .map(|first| !first);
    }
    if let Some(visitors) = &state.visitors {
        let decision = if check.is_valid() {
            visitors.resolve(id, &record).await
        } else {
            crate::visitor::Decision::unknown("invalid_evidence")
        };
        check.visitor_id = decision.visitor_id.clone();
        check.reconciliation = Some(decision);
    }
    check.tls_client = record.ja4.as_deref().and_then(crate::tls::client);
    check.ja4 = record.ja4;
    check.origin = Some(record.origin);
    check
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
    pub(crate) fn state_with_redis(addr: &str) -> AppState {
        AppState::configure(
            dns(),
            rdap(),
            crate::replay::Replay::new(crate::cache::tests::client_for(addr)),
            crate::identify::Identifications::new(crate::cache::tests::client_for(addr)),
        )
    }
    pub(crate) fn state() -> AppState {
        state_with_redis("127.0.0.1:9")
    }
    fn request(identification_id: serde_json::Value, detail: bool) -> CheckRequest {
        CheckRequest {
            identification_id: Some(identification_id),
            domain: None,
            email: None,
            ip: None,
            detail: detail.then_some(true),
        }
    }
    pub(crate) fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }
    fn evidence() -> Evidence {
        let mut s: Evidence = serde_json::from_value(serde_json::json!({"version":1,"fingerprint":null,"coreFingerprint":null,"components":{"fontPreferences":sha256("fixture")},"hints":{},"unavailable":{},"excluded":[],"durationMs":1})).unwrap();
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

    pub(crate) fn payload() -> serde_json::Value {
        let s = evidence();
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

    #[tokio::test]
    async fn identifications_are_evaluated_from_what_the_listener_observed() {
        const CHROME: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36";
        let (addr, _) = crate::cache::tests::fake_redis(None).await;
        let state = state_with_redis(&addr);
        let mut evidence = payload();
        evidence["spoofing"] = serde_json::json!({"version":1,"userAgent":CHROME,"language":"en-US","clientHints":null});
        let record = |ja4: &str| crate::identify::Record {
            evidence: evidence.clone(),
            headers: serde_json::json!({"userAgent":CHROME,"acceptLanguage":"en-US,en;q=0.9"}),
            ja4: Some(ja4.into()),
            origin: "https://app.example.test".into(),
            created_at_ms: now_ms() - 1_500,
            namespace: None,
        };
        let id = "AbCdEfGhIjKlMnOpQrStU_";
        let curl = "t13d4907h2_0d8feac7bc37_7395dae3b2f3";
        state
            .identifications
            .store(id, &record(curl))
            .await
            .unwrap();
        let detail = evaluate(&state, request(id.into(), true)).await.unwrap();
        let found = &detail["identification"];
        assert_eq!(found["status"], "ok");
        assert_eq!(
            (&found["origin"], &found["ja4"], &found["tlsClient"]),
            (
                &serde_json::json!("https://app.example.test"),
                &serde_json::json!(curl),
                &serde_json::json!("curl")
            )
        );
        assert_eq!(
            found["spoofing"]["indicators"],
            serde_json::json!(["tls_mismatch"]),
            "a Chrome evidence sent with curl's handshake, even with Chrome's headers"
        );
        let age = found["ageMs"].as_i64().unwrap();
        assert!(
            (1_500..10_000).contains(&age),
            "age by the server clock: {age}"
        );
        assert_eq!(found["replayed"], false);
        let compact = evaluate(&state, request(id.into(), false)).await.unwrap();
        assert_eq!(
            (&compact["spoofing"], &compact["replayed"]),
            (&serde_json::json!(true), &serde_json::json!(true))
        );

        let other = "ZbCdEfGhIjKlMnOpQrStU_";
        state
            .identifications
            .store(other, &record("t13d1517h2_8daaf6152771_cb7bf5808d99"))
            .await
            .unwrap();
        let chrome = evaluate(&state, request(other.into(), true)).await.unwrap();
        assert_eq!(
            chrome["identification"]["spoofing"]["status"],
            "not_detected"
        );
        assert_eq!(chrome["identification"]["tlsClient"], "chromium");

        for unknown in [
            serde_json::json!("AAAAAAAAAAAAAAAAAAAAAA"),
            serde_json::json!("x"),
            serde_json::json!(7),
        ] {
            assert_eq!(
                evaluate(&state, request(unknown.clone(), false))
                    .await
                    .unwrap(),
                serde_json::json!({"invalid":["identificationId"]}),
                "{unknown}"
            );
        }
        let down = state_with_redis("127.0.0.1:9");
        assert_eq!(
            evaluate(&down, request(id.into(), false)).await.unwrap(),
            serde_json::json!({}),
            "unknown, not invalid, when Redis cannot answer"
        );
        let removed: Result<CheckRequest, _> =
            serde_json::from_value(serde_json::json!({"signals":"token"}));
        assert!(removed.is_err(), "tokens are no longer accepted");
        let empty = CheckRequest {
            identification_id: None,
            ..request(serde_json::Value::Null, false)
        };
        assert!(evaluate(&state, empty).await.is_err());
    }

    #[test]
    fn evidence_with_malformed_parts_is_not_valid() {
        assert!(check_evidence(payload(), None, None).is_valid());
        for (key, value) in [
            ("automation", serde_json::json!({"version": 1})),
            ("tampering", serde_json::json!({"version": 9})),
        ] {
            let mut input = payload();
            input[key] = value;
            assert!(!check_evidence(input, None, None).is_valid(), "{key}");
        }
        let mut input = payload();
        input["spoofing"] = serde_json::json!({"version": 2});
        assert!(!check_evidence(input, Some(&serde_json::json!({})), Some(None)).is_valid());
        for removed in ["token", "storageId", "collectedAt"] {
            let mut input = payload();
            input[removed] = serde_json::json!(null);
            assert!(!check_evidence(input, None, None).is_valid(), "{removed}");
        }
    }

    #[test]
    fn validates_schema_missingness_and_canonical_identity() {
        assert!(evidence().valid());
        let mut s = evidence();
        s.version = 2;
        assert!(!s.valid());
        let mut s = evidence();
        s.version = 0;
        assert!(!s.valid());
        let mut s = evidence();
        s.fingerprint = Some("b".repeat(64));
        assert!(!s.valid());
        let mut s = evidence();
        s.components.insert("fontPreferences".into(), "raw".into());
        assert!(!s.valid());
        let mut s = evidence();
        s.unavailable
            .insert("fontPreferences".into(), Availability::Error);
        assert!(!s.valid());
        let mut s = evidence();
        s.hints = s.components.clone();
        assert!(!s.valid());
        let mut s = evidence();
        s.excluded = vec!["canvas".into(), "canvas".into()];
        assert!(!s.valid());
        let mut s = evidence();
        s.duration_ms = f64::NAN;
        assert!(!s.valid());
        let mut s = evidence();
        s.components.clear();
        assert!(!s.valid());
        s.fingerprint = None;
        s.core_fingerprint = None;
        assert!(s.valid());
    }

    #[test]
    fn identity_groups_need_every_member_and_ignore_other_probes() {
        let mut s = evidence();
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
    fn identification_details_do_not_expose_identity_hashes() {
        for input in [
            payload(),
            {
                let mut input = payload();
                input["fingerprint"] = serde_json::Value::Null;
                input
            },
            serde_json::Value::Null,
        ] {
            let detail = serde_json::to_value(check_evidence(input, None, None)).unwrap();
            assert!(detail.get("fingerprint").is_none());
            assert!(detail.get("coreFingerprint").is_none());
            assert!(detail["evidence"].get("identityGroups").is_none());
        }
    }

    #[test]
    fn compact_responses_are_flat_verdicts() {
        let mut response = serde_json::json!({
            "identification": {"status":"ok","fingerprint":"abc","visitorId":"visitor","replayed":true,"ageMs":1200,"evidence":{},"origin":"https://a.test","ja4":"t13d","tlsClient":"chromium",
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
                    "vpn":{"value":null,"status":"unknown"},
                    "datacenter":{"value":{"scope":"listed_datacenter_range"},"status":"listed"},
                    "proxy":{"value":{"protocols":["http"],"scope":"listed_open_proxy"},"status":"listed"},
                    "asn":{"value":{"number":1},"status":"ok"}}}
        });
        compact(&mut response);
        assert_eq!(
            response,
            serde_json::json!({
                "visitorId":"visitor","replayed":true,"ageMs":1200,"automation":true,
                "tampering":false,"disposable":true,"free":false,"cheapTld":true,"mx":true,
                "country":"dk","tor":false,"datacenter":true,"proxy":true
            })
        );
        for (spoofing, expected) in [
            (
                serde_json::json!({"status":"detected","indicators":["tls_mismatch"]}),
                serde_json::json!({"spoofing":true}),
            ),
            (
                serde_json::json!({"status":"unknown"}),
                serde_json::json!({}),
            ),
        ] {
            let mut response = serde_json::json!({"identification":{"status":"ok","fingerprint":"abc","spoofing":spoofing}});
            compact(&mut response);
            assert_eq!(response, expected);
        }
        let mut domain = serde_json::json!({"domain":{"status":"ok","mxLookup":"no_domain"}});
        compact(&mut domain);
        assert_eq!(domain, serde_json::json!({"mx":false}));
        let mut invalid = serde_json::json!({
            "identification":{"status":"invalid_input","fingerprint":null},
            "email":{"status":"invalid_input","reason":"invalid_email"},
            "ip":{"status":"invalid_input","reason":"invalid_ip","network":{}}});
        compact(&mut invalid);
        assert_eq!(
            invalid,
            serde_json::json!({"invalid":["identificationId","email","ip"]})
        );
    }

    #[test]
    fn compact_click_flag_keeps_false_and_omits_unknown() {
        for value in [
            serde_json::Value::Null,
            serde_json::json!(false),
            serde_json::json!(true),
        ] {
            let mut response = serde_json::json!({"identification": {
                "fingerprint": "abc", "behavior": {
                    "status": "observed", "patterns": [], "suspiciousClickPattern": value
                }
            }});
            compact(&mut response);
            assert_eq!(
                response.get("suspiciousClickPattern"),
                (!value.is_null()).then_some(&value)
            );
        }
    }

    #[test]
    fn evidence_results_report_counts_not_confidence_or_core_fallbacks() {
        let result = check_evidence(payload(), None, None);
        assert_eq!(result.profile.status, "ok");
        let evidence = result.evidence.unwrap();
        assert_eq!(evidence.included_components, 1);
        assert_eq!(evidence.included_hints, 0);
        assert_eq!(evidence.excluded_probes, 0);
        assert_eq!(evidence.unavailable_probes, 0);

        let mut input = payload();
        input["components"]["canvas"] = serde_json::json!(sha256("diagnostic"));
        input["excluded"] = serde_json::json!(["canvas"]);
        let result = check_evidence(input, None, None);
        assert_eq!(result.profile.status, "ok");
        let evidence = result.evidence.unwrap();
        assert_eq!(evidence.included_components, 1);
        assert_eq!(evidence.excluded_probes, 1);

        let mut input = payload();
        input["fingerprint"] = serde_json::Value::Null;
        let result = check_evidence(input, None, None);
        assert_eq!(result.profile.status, "insufficient_signals");
        assert!(result.profile.schema_version.is_none());
        assert!(result.evidence.is_some());

        for input in [serde_json::json!("not evidence"), serde_json::json!({}), {
            let mut p = payload();
            p["fingerprint"] = serde_json::json!("b".repeat(64));
            p
        }] {
            let result = check_evidence(input, None, None);
            assert_eq!(result.profile.status, "invalid_input");
            assert_eq!(result.reason, Some("invalid_evidence"));
            assert!(result.evidence.is_none());
            assert!(result.profile.schema_version.is_none());
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
