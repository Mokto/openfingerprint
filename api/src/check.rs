use std::collections::{BTreeMap, HashSet};

use axum::{
    Json,
    extract::{FromRequest, Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use ring::{digest, hmac};
use serde::{Deserialize, Serialize};

pub const BODY_LIMIT: usize = 64 * 1024;
const AUTH_DOMAIN: &[u8] = b"openfingerprint-server-auth";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SiteConfig {
    id: String,
    secret_key: String,
    #[serde(default)]
    site_key: Option<String>,
    #[serde(default, rename = "origins")]
    _origins: Option<Vec<String>>,
}
pub(crate) struct Site {
    secret: hmac::Tag,
}
pub struct AppState {
    sites: Vec<Site>,
    pub collection: Option<crate::collection::Store>,
    pub domains: crate::domains::DomainStore,
    pub dns: crate::mx::Resolver,
    pub rdap: crate::rdap::Rdap,
    pub countries: crate::country::CountryStore,
    pub network: crate::network::Store,
}
impl AppState {
    pub fn from_env() -> Result<Self, &'static str> {
        let config = std::env::var("OPENFINGERPRINT_SITES")
            .map_err(|_| "OPENFINGERPRINT_SITES is required")?;
        let redis = crate::cache::client_from_env()?;
        let mut state = Self::configure(
            &config,
            crate::mx::Resolver::from_env()?,
            crate::rdap::Rdap::from_env(redis.clone())?,
        )?;
        state.domains = crate::domains::DomainStore::from_env();
        state.countries = crate::country::CountryStore::from_env();
        state.collection = Some(crate::collection::Store::from_env(redis)?);
        state.network = crate::network::Store::from_env()?;
        Ok(state)
    }
    fn configure(
        config: &str,
        dns: crate::mx::Resolver,
        rdap: crate::rdap::Rdap,
    ) -> Result<Self, &'static str> {
        if config.len() > BODY_LIMIT {
            return Err("Invalid OPENFINGERPRINT_SITES");
        }
        let configs: Vec<SiteConfig> =
            serde_json::from_str(config).map_err(|_| "Invalid OPENFINGERPRINT_SITES")?;
        if configs.is_empty() || configs.len() > 16 {
            return Err("Configure 1-16 sites");
        }
        let mut ids = HashSet::new();
        let mut keys = HashSet::new();
        for c in &configs {
            if !name(&c.id)
                || !ids.insert(c.id.clone())
                || !credential(&c.secret_key)
                || !keys.insert(c.secret_key.clone())
                || c.site_key
                    .as_ref()
                    .is_some_and(|public| !credential(public) || !keys.insert(public.clone()))
            {
                return Err("Invalid or duplicate site configuration");
            }
        }
        let sites = configs
            .into_iter()
            .map(|c| Site {
                secret: hmac::sign(
                    &hmac::Key::new(hmac::HMAC_SHA256, c.secret_key.as_bytes()),
                    AUTH_DOMAIN,
                ),
            })
            .collect();
        Ok(Self {
            sites,
            collection: None,
            network: crate::network::Store::empty(),
            domains: crate::domains::DomainStore::new(crate::domains::DomainData::unavailable(
                "not_configured",
            )),
            dns,
            rdap,
            countries: crate::country::CountryStore::new(None),
        })
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
        let ((hosts, lookup), registration, (spf, dmarc)) =
            tokio::join!(mx, registration, mail_auth);
        data.check_with(&domain, &hosts, lookup)
            .with_registration(registration)
            .with_mail_auth(spf, dmarc)
    }
    pub(crate) fn authorize(&self, headers: &HeaderMap) -> Result<&Site, ApiError> {
        let site = self.authenticate(headers)?;
        if headers.contains_key(header::ORIGIN) {
            return Err(ApiError::forbidden());
        }
        Ok(site)
    }
    fn authenticate(&self, headers: &HeaderMap) -> Result<&Site, ApiError> {
        let secret = header_text(headers, header::AUTHORIZATION.as_str())
            .and_then(|s| s.strip_prefix("Bearer "))
            .filter(|s| credential(s))
            .ok_or_else(ApiError::unauthorized)?;
        // HMAC verification keeps credential checks constant-time without a signing key.
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        self.sites
            .iter()
            .find(|s| hmac::verify(&key, AUTH_DOMAIN, s.secret.as_ref()).is_ok())
            .ok_or_else(ApiError::unauthorized)
    }
}

impl Site {
    pub(crate) fn scope(&self) -> String {
        sha256(&hex(self.secret.as_ref()))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Signals {
    automation: Option<serde_json::Value>,
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
            fingerprint: self.fingerprint.clone(),
        })
    }

    fn valid(&self) -> bool {
        let hashes = [&self.components, &self.hints];
        if !(4..=5).contains(&self.version)
            || self.storage_id.is_some()
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
struct CheckRequest {
    automation: Option<serde_json::Value>,
    signals: Option<serde_json::Value>,
    domain: Option<serde_json::Value>,
    ip: Option<serde_json::Value>,
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
    ip: Option<IpCheck>,
}

#[derive(Serialize)]
pub(crate) struct SignalCheck {
    #[serde(skip_serializing_if = "Option::is_none")]
    automation: Option<crate::automation::Check>,
    #[serde(flatten)]
    profile: Verified,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    evidence: Option<Evidence>,
}

#[derive(Serialize)]
struct Evidence {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    identity_groups: BTreeMap<&'static str, String>,
    included_components: usize,
    included_hints: usize,
    unavailable_probes: usize,
    excluded_probes: usize,
}

pub(crate) fn check_signals(value: serde_json::Value) -> SignalCheck {
    if let Ok(signals) = serde_json::from_value::<Signals>(value)
        && let Ok(profile) = signals.verified()
    {
        let identity_groups = signals.identity_groups();
        return SignalCheck {
            automation: signals.automation.map(crate::automation::check),
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
        profile: Verified {
            status: "invalid_input",
            schema_version: None,
            fingerprint: None,
        },
        reason: Some("invalid_signals"),
        evidence: None,
    }
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
    fn unauthorized() -> Self {
        Self(StatusCode::UNAUTHORIZED, "unauthorized")
    }
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

pub async fn verify(
    State(state): State<std::sync::Arc<AppState>>,
    request: Request,
) -> Result<Response, ApiError> {
    state.authorize(request.headers())?;
    let Json(signals) = Json::<Signals>::from_request(request, &())
        .await
        .map_err(json_error)?;
    Ok(Json(signals.verified()?).into_response())
}

pub async fn check(
    State(state): State<std::sync::Arc<AppState>>,
    request: Request,
) -> Result<Response, ApiError> {
    state.authorize(request.headers())?;
    let Json(input) = Json::<CheckRequest>::from_request(request, &())
        .await
        .map_err(json_error)?;
    if input.automation.is_none()
        && input.signals.is_none()
        && input.domain.is_none()
        && input.ip.is_none()
    {
        return Err(ApiError::invalid());
    }
    let domain = match input.domain {
        Some(value) => Some(state.check_domain(value).await),
        None => None,
    };
    Ok(Json(CheckResponse {
        automation: input.automation.map(crate::automation::check),
        signals: input.signals.map(check_signals),
        domain,
        ip: input.ip.map(|ip| IpCheck {
            country: state.countries.check(ip.clone()),
            network: state.network.current().check(ip, "backend_supplied"),
        }),
    })
    .into_response())
}

pub(crate) fn json_error(error: axum::extract::rejection::JsonRejection) -> ApiError {
    if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large")
    } else {
        ApiError::invalid()
    }
}
fn header_text<'a>(headers: &'a HeaderMap, key: &str) -> Option<&'a str> {
    headers.get(key)?.to_str().ok()
}
fn name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.as_bytes()[0].is_ascii_alphabetic()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
}
fn credential(s: &str) -> bool {
    (32..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
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
mod tests {
    use super::*;

    fn config() -> String {
        serde_json::json!([
            {"id":"alpha","secret_key":"s".repeat(32)},
            {"id":"beta","secret_key":"t".repeat(32)}
        ])
        .to_string()
    }
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
    fn state() -> AppState {
        AppState::configure(&config(), dns(), rdap()).unwrap()
    }
    fn signals() -> Signals {
        let mut s: Signals = serde_json::from_value(serde_json::json!({"version":4,"fingerprint":null,"coreFingerprint":null,"components":{"fontPreferences":sha256("fixture")},"hints":{},"unavailable":{},"excluded":[],"durationMs":1})).unwrap();
        let entries: Vec<_> = s.components.iter().collect();
        s.core_fingerprint = Some(sha256(&format!(
            "stealth-core:4\0{}",
            serde_json::to_string(&entries).unwrap()
        )));
        s.fingerprint = Some(sha256(&format!(
            "stealth-agent:4\0{}",
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
    fn minimal_and_legacy_configuration_keep_server_credentials_compatible() {
        let legacy = serde_json::json!([
            {"id":"alpha","secret_key":"s".repeat(32),"site_key":"p".repeat(32),"origins":["https://alpha.test"]}
        ]);
        let legacy = AppState::configure(&legacy.to_string(), dns(), rdap()).unwrap();
        let minimal = state();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", "s".repeat(32)).parse().unwrap(),
        );
        assert!(legacy.authenticate(&headers).is_ok());
        assert!(std::ptr::eq(
            minimal.authenticate(&headers).unwrap(),
            &minimal.sites[0]
        ));
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", "t".repeat(32)).parse().unwrap(),
        );
        assert!(std::ptr::eq(
            minimal.authenticate(&headers).unwrap(),
            &minimal.sites[1]
        ));
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", "p".repeat(32)).parse().unwrap(),
        );
        assert!(legacy.authenticate(&headers).is_err());
        assert!(minimal.authenticate(&headers).is_err());
    }

    #[test]
    fn configuration_fails_closed_without_echoing_credentials() {
        for invalid in [
            "[]".to_owned(),
            "{}".to_owned(),
            "not-json".to_owned(),
            config().replace("beta", "alpha"),
            config().replace(&"t".repeat(32), &"s".repeat(32)),
            config().replace(&"t".repeat(32), "short"),
            serde_json::json!([{"id":"alpha","secret_key":"s".repeat(32),"site_key":"s".repeat(32)}]).to_string(),
            serde_json::json!([{"id":"alpha","secret_key":"s".repeat(32),"extra":true}]).to_string(),
            serde_json::json!([{"id":"bad id","secret_key":"s".repeat(32)}]).to_string(),
            serde_json::json!([{"id":"alpha","secret_key":"s".repeat(32),"site_key":"t".repeat(32)},{"id":"beta","secret_key":"t".repeat(32)}]).to_string(),
            "x".repeat(BODY_LIMIT + 1),
        ] {
            let error = AppState::configure(&invalid, dns(), rdap()).err().expect("reject invalid config");
            assert!(!error.contains(&"s".repeat(32)));
            assert!(!error.contains(&"t".repeat(32)));
        }
        let too_many: Vec<_> = (0..17)
            .map(|i| serde_json::json!({"id":format!("site{i}"),"secret_key":format!("{i:032}")}))
            .collect();
        assert!(
            AppState::configure(&serde_json::to_string(&too_many).unwrap(), dns(), rdap()).is_err()
        );
    }

    #[test]
    fn public_or_malformed_authorization_is_not_a_server_credential() {
        let state = state();
        let mut headers = HeaderMap::new();
        assert!(state.authenticate(&headers).is_err());
        for value in [
            "Basic abc".to_owned(),
            "Bearer short".to_owned(),
            format!("bearer {}", "s".repeat(32)),
            format!("Bearer {} ", "s".repeat(32)),
            format!("Bearer {}", "x".repeat(129)),
        ] {
            headers.insert(header::AUTHORIZATION, value.parse().unwrap());
            assert!(state.authenticate(&headers).is_err());
        }
    }

    #[test]
    fn validates_schema_missingness_and_canonical_identity() {
        assert!(signals().valid());
        let mut s = signals();
        s.version = 2;
        assert!(!s.valid());
        let mut s = signals();
        s.version = 6;
        assert!(!s.valid());
        let mut s = signals();
        s.version = 5;
        assert!(!s.valid(), "schema-4 hashes must not verify as schema 5");
        let entries: Vec<_> = s.components.iter().collect();
        s.core_fingerprint = Some(sha256(&format!(
            "stealth-core:5\0{}",
            serde_json::to_string(&entries).unwrap()
        )));
        s.fingerprint = Some(sha256(&format!(
            "stealth-agent:5\0{}",
            serde_json::json!({"components":entries,"hints":[]})
        )));
        assert!(s.valid());
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

    #[tokio::test]
    async fn verification_returns_only_status_and_hashes() {
        let state = std::sync::Arc::new(state());
        for _ in 0..2 {
            let payload = payload();
            let request = Request::builder()
                .header(header::AUTHORIZATION, format!("Bearer {}", "s".repeat(32)))
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(payload.to_string()))
                .unwrap();
            let response = verify(State(std::sync::Arc::clone(&state)), request)
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body.as_object().unwrap().len(), 3);
            assert_eq!(body["status"], "ok");
            assert!(body.get("components").is_none());
        }
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
        s.version = 5;
        s.excluded.clear();
        assert_ne!(s.identity_groups()["rendering"], baseline);
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
