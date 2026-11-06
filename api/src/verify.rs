use std::{
    collections::{BTreeMap, HashSet},
    sync::Mutex,
    time::{Duration, Instant},
};

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
struct Site {
    secret: hmac::Tag,
    rate: Mutex<Rate>,
}
struct Rate {
    // ponytail: per-process fixed windows; use a shared limiter for a multi-replica quota.
    start: Instant,
    count: u16,
}
impl Rate {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            count: 0,
        }
    }
    fn take(&mut self, now: Instant) -> Result<(), ApiError> {
        if now.duration_since(self.start) >= Duration::from_secs(60) {
            self.start = now;
            self.count = 0;
        }
        if self.count >= 60 {
            return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "rate_limit"));
        }
        self.count += 1;
        Ok(())
    }
}

pub struct AppState {
    sites: Vec<Site>,
}
impl AppState {
    pub fn from_env() -> Result<Self, &'static str> {
        let config = std::env::var("OPENFINGERPRINT_SITES")
            .map_err(|_| "OPENFINGERPRINT_SITES is required")?;
        Self::configure(&config)
    }
    fn configure(config: &str) -> Result<Self, &'static str> {
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
                rate: Mutex::new(Rate::new()),
            })
            .collect();
        Ok(Self { sites })
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Signals {
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
impl Signals {
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

#[derive(Debug)]
pub struct ApiError(StatusCode, &'static str);
impl ApiError {
    fn unauthorized() -> Self {
        Self(StatusCode::UNAUTHORIZED, "unauthorized")
    }
    fn forbidden() -> Self {
        Self(StatusCode::FORBIDDEN, "origin_not_allowed")
    }
    fn unavailable() -> Self {
        Self(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
    }
    fn invalid() -> Self {
        Self(StatusCode::BAD_REQUEST, "invalid_request")
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({"error":self.1}))).into_response()
    }
}

pub async fn verify(
    State(state): State<std::sync::Arc<AppState>>,
    request: Request,
) -> Result<Response, ApiError> {
    let site = state.authenticate(request.headers())?;
    if request.headers().contains_key(header::ORIGIN) {
        return Err(ApiError::forbidden());
    }
    site.rate
        .lock()
        .map_err(|_| ApiError::unavailable())?
        .take(Instant::now())?;
    let Json(signals) = Json::<Signals>::from_request(request, &())
        .await
        .map_err(json_error)?;
    if !signals.valid() {
        return Err(ApiError::invalid());
    }
    let available = signals.fingerprint.is_some();
    Ok(Json(Verified {
        status: if available {
            "ok"
        } else {
            "insufficient_signals"
        },
        schema_version: available.then_some(signals.version),
        fingerprint: signals.fingerprint,
    })
    .into_response())
}

fn json_error(error: axum::extract::rejection::JsonRejection) -> ApiError {
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
fn sha256(s: &str) -> String {
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
    fn state() -> AppState {
        AppState::configure(&config()).unwrap()
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

    #[test]
    fn minimal_and_legacy_configuration_keep_server_credentials_compatible() {
        let legacy = serde_json::json!([
            {"id":"alpha","secret_key":"s".repeat(32),"site_key":"p".repeat(32),"origins":["https://alpha.test"]}
        ]);
        let legacy = AppState::configure(&legacy.to_string()).unwrap();
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
            let error = AppState::configure(&invalid).err().expect("reject invalid config");
            assert!(!error.contains(&"s".repeat(32)));
            assert!(!error.contains(&"t".repeat(32)));
        }
        let too_many: Vec<_> = (0..17)
            .map(|i| serde_json::json!({"id":format!("site{i}"),"secret_key":format!("{i:032}")}))
            .collect();
        assert!(AppState::configure(&serde_json::to_string(&too_many).unwrap()).is_err());
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
    async fn verification_retains_only_per_site_quota_state() {
        let state = std::sync::Arc::new(state());
        for _ in 0..2 {
            let signals = signals();
            let payload = serde_json::json!({
                "version": signals.version, "fingerprint": signals.fingerprint,
                "coreFingerprint": signals.core_fingerprint, "components": signals.components,
                "hints": signals.hints, "unavailable": {}, "excluded": signals.excluded,
                "durationMs": signals.duration_ms
            });
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
        assert_eq!(state.sites[0].rate.lock().unwrap().count, 2);
        assert_eq!(state.sites[1].rate.lock().unwrap().count, 0);
    }

    #[test]
    fn quota_window_uses_monotonic_time() {
        let mut rate = Rate::new();
        let now = rate.start;
        for _ in 0..60 {
            assert!(rate.take(now).is_ok());
        }
        assert!(rate.take(now).is_err());
        assert!(rate.take(now + Duration::from_secs(60)).is_ok());
    }
}
