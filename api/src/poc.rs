use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json,
    extract::{FromRequest, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use hickory_resolver::TokioResolver;
use ring::{
    digest, hmac,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};

use crate::email;

const TOKEN_TTL: Duration = Duration::from_secs(15 * 60);
const LINK_TTL: Duration = Duration::from_secs(30 * 24 * 3600);
const MAX_OBSERVATIONS_PER_SITE: usize = 256;
const MAX_LINKS_PER_SITE: usize = 512;
pub const BODY_LIMIT: usize = 64 * 1024;

#[derive(Clone, Copy)]
struct Time {
    unix: u64,
    tick: Instant,
}
impl Time {
    fn now() -> Result<Self, ApiError> {
        Ok(Self {
            unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| ApiError::unavailable())?
                .as_secs(),
            tick: Instant::now(),
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SiteConfig {
    id: String,
    site_key: String,
    secret_key: String,
    origins: Vec<String>,
}
struct Site {
    id: String,
    site_key: String,
    secret: hmac::Tag,
    origins: Vec<String>,
    collect_rate: Mutex<Rate>,
    check_rate: Mutex<Rate>,
}
struct Rate {
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
    resolver: TokioResolver,
    key: hmac::Key,
    sites: Vec<Site>,
    store: Mutex<Store>,
}

impl AppState {
    pub fn from_env() -> Result<Self, &'static str> {
        let key = std::env::var("OPENFINGERPRINT_SIGNING_KEY").map_err(
            |_| "OPENFINGERPRINT_SIGNING_KEY is required (32 random bytes as lowercase hex)",
        )?;
        let config = std::env::var("OPENFINGERPRINT_SITES")
            .map_err(|_| "OPENFINGERPRINT_SITES is required")?;
        Self::configure(&key, &config)
    }
    fn configure(key: &str, config: &str) -> Result<Self, &'static str> {
        let bytes = unhex(key, 32).ok_or("Invalid OPENFINGERPRINT_SIGNING_KEY")?;
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
                || !credential(&c.site_key)
                || !credential(&c.secret_key)
                || !keys.insert(c.site_key.clone())
                || !keys.insert(c.secret_key.clone())
                || c.origins.is_empty()
                || c.origins.len() > 16
                || c.origins.iter().any(|s| !origin(s))
            {
                return Err("Invalid or duplicate site configuration");
            }
        }
        let key = hmac::Key::new(hmac::HMAC_SHA256, &bytes);
        let sites = configs
            .into_iter()
            .map(|c| Site {
                id: c.id,
                site_key: c.site_key,
                secret: hmac::sign(&key, format!("secret\0{}", c.secret_key).as_bytes()),
                origins: c.origins,
                collect_rate: Mutex::new(Rate::new()),
                check_rate: Mutex::new(Rate::new()),
            })
            .collect();
        Ok(Self {
            resolver: email::resolver(Duration::from_millis(800)),
            key,
            sites,
            store: Mutex::new(Store::default()),
        })
    }
    pub fn cleanup(&self) {
        if let (Ok(now), Ok(mut store)) = (Time::now(), self.store.lock()) {
            store.prune(now);
        }
    }
    fn authenticate(&self, headers: &HeaderMap) -> Result<&Site, ApiError> {
        let secret = header_text(headers, header::AUTHORIZATION.as_str())
            .and_then(|s| s.strip_prefix("Bearer "))
            .filter(|s| credential(s))
            .ok_or_else(ApiError::unauthorized)?;
        let message = format!("secret\0{secret}");
        self.sites
            .iter()
            .find(|s| hmac::verify(&self.key, message.as_bytes(), s.secret.as_ref()).is_ok())
            .ok_or_else(ApiError::unauthorized)
    }
    fn collect_site(&self, headers: &HeaderMap) -> Result<(&Site, HeaderValue), ApiError> {
        let key = header_text(headers, "x-site-key").ok_or_else(ApiError::unauthorized)?;
        let site = self
            .sites
            .iter()
            .find(|s| s.site_key == key)
            .ok_or_else(ApiError::unauthorized)?;
        let origin = header_text(headers, "origin").ok_or_else(ApiError::forbidden)?;
        if !site.origins.iter().any(|s| s == origin) {
            return Err(ApiError::forbidden());
        }
        Ok((site, headers[header::ORIGIN].clone()))
    }
    fn token(&self, site: &Site, id: &str, expires: u64) -> String {
        let payload = format!("visitor:v1\0{}\0{id}\0{expires}", site.id);
        format!(
            "v1.{id}.{expires}.{}",
            hex(hmac::sign(&self.key, payload.as_bytes()).as_ref())
        )
    }
    fn claims<'a>(
        &self,
        site: &Site,
        token: &'a str,
        now: Time,
    ) -> Result<(&'a str, u64), &'static str> {
        if token.len() > 160 {
            return Err("invalid_token");
        }
        let parts: Vec<_> = token.split('.').collect();
        if parts.len() != 4 || parts[0] != "v1" || !is_hex(parts[1], 32) {
            return Err("invalid_token");
        }
        let expires: u64 = parts[2].parse().map_err(|_| "invalid_token")?;
        if expires.to_string() != parts[2] {
            return Err("invalid_token");
        }
        let signature = unhex(parts[3], 32).ok_or("invalid_token")?;
        let payload = format!("visitor:v1\0{}\0{}\0{expires}", site.id, parts[1]);
        hmac::verify(&self.key, payload.as_bytes(), &signature).map_err(|_| "invalid_token")?;
        if expires <= now.unix {
            return Err("expired_token");
        }
        Ok((parts[1], expires))
    }
    fn link(&self, site: &Site, token: Option<&str>, address: Option<&str>, now: Time) -> Linking {
        let Some(address) = address else {
            return Linking::unknown("invalid_email");
        };
        let Some(token) = token else {
            return Linking::unknown("not_collected");
        };
        let (id, expires) = match self.claims(site, token, now) {
            Ok(v) => v,
            Err(reason) => return Linking::unknown(reason),
        };
        let Ok(mut store) = self.store.lock() else {
            return Linking::unknown("linking_unavailable");
        };
        store.prune(now);
        let Some(observation) = store.observations.get(id) else {
            return Linking::unknown("observation_unavailable");
        };
        if observation.site != site.id || observation.expires != expires {
            return Linking::unknown("invalid_token");
        }
        let Some(profile) = observation.signals.fingerprint.clone() else {
            return Linking::unknown("insufficient_signals");
        };
        let email: [u8; 32] = hmac::sign(
            &self.key,
            format!("email\0{}\0{address}", site.id).as_bytes(),
        )
        .as_ref()
        .try_into()
        .expect("SHA256 tag");
        if observation.email.is_some_and(|bound| bound != email) {
            return Linking::unknown("token_already_bound");
        }
        let key = LinkKey {
            site: site.id.clone(),
            schema: observation.signals.version,
            profile,
            email,
        };
        let other_emails = store
            .links
            .keys()
            .filter(|k| {
                k.site == key.site
                    && k.schema == key.schema
                    && k.profile == key.profile
                    && k.email != key.email
            })
            .count();
        if !store.links.contains_key(&key)
            && store.links.keys().filter(|k| k.site == site.id).count() >= MAX_LINKS_PER_SITE
        {
            return Linking::unknown("linking_unavailable");
        }
        store.links.entry(key).or_insert(now.tick + LINK_TTL);
        store
            .observations
            .get_mut(id)
            .expect("locked observation")
            .email = Some(email);
        Linking {
            status: "ok",
            other_emails_seen: Some(other_emails),
            recorded: true,
        }
    }
}

#[derive(Default)]
struct Store {
    // ponytail: bounded single-process RAM and O(n) scans; use indexed Postgres transactions before scaling.
    observations: HashMap<String, Observation>,
    links: HashMap<LinkKey, Instant>,
}
struct Observation {
    site: String,
    signals: Signals,
    expires: u64,
    deadline: Instant,
    email: Option<[u8; 32]>,
}
#[derive(Hash, PartialEq, Eq)]
struct LinkKey {
    site: String,
    schema: u16,
    profile: String,
    email: [u8; 32],
}
impl Store {
    fn prune(&mut self, now: Time) {
        self.observations
            .retain(|_, o| o.expires > now.unix && o.deadline > now.tick);
        self.links.retain(|_, expires| *expires > now.tick);
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
        if self.version != 4
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
            (self.fingerprint.as_ref(), "stealth-agent:4\0", full),
            (self.core_fingerprint.as_ref(), "stealth-core:4\0", core),
        ]
        .iter()
        .all(|(value, domain, payload)| {
            value.is_none_or(|v| has_core && *v == sha256(&format!("{domain}{payload}")))
        })
    }
}

#[derive(Serialize)]
struct Collected {
    visitor_token: String,
    expires_at: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckRequest {
    email: String,
    visitor_token: Option<String>,
}
#[derive(Serialize)]
struct CheckResponse {
    verdict: email::Verdict,
    reasons: Vec<&'static str>,
    email: email::EmailSignals,
    linking: Linking,
}
#[derive(Serialize)]
struct Linking {
    status: &'static str,
    other_emails_seen: Option<usize>,
    recorded: bool,
}
impl Linking {
    fn unknown(status: &'static str) -> Self {
        Self {
            status,
            other_emails_seen: None,
            recorded: false,
        }
    }
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

pub async fn collect(State(state): State<std::sync::Arc<AppState>>, request: Request) -> Response {
    let (site, origin) = match state.collect_site(request.headers()) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    cors(
        collect_inner(&state, site, request)
            .await
            .unwrap_or_else(IntoResponse::into_response),
        origin,
    )
}
async fn collect_inner(
    state: &AppState,
    site: &Site,
    request: Request,
) -> Result<Response, ApiError> {
    site.collect_rate
        .lock()
        .map_err(|_| ApiError::unavailable())?
        .take(Instant::now())?;
    let Json(signals) = Json::<Signals>::from_request(request, &())
        .await
        .map_err(json_error)?;
    if !signals.valid() {
        return Err(ApiError::invalid());
    }
    let now = Time::now()?;
    let mut store = state.store.lock().map_err(|_| ApiError::unavailable())?;
    store.prune(now);
    if store
        .observations
        .values()
        .filter(|o| o.site == site.id)
        .count()
        >= MAX_OBSERVATIONS_PER_SITE
    {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "observation_capacity",
        ));
    }
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| ApiError::unavailable())?;
    let id = hex(&bytes);
    if store.observations.contains_key(&id) {
        return Err(ApiError::unavailable());
    }
    let expires = now
        .unix
        .checked_add(TOKEN_TTL.as_secs())
        .ok_or_else(ApiError::unavailable)?;
    let token = state.token(site, &id, expires);
    store.observations.insert(
        id,
        Observation {
            site: site.id.clone(),
            signals,
            expires,
            deadline: now.tick + TOKEN_TTL,
            email: None,
        },
    );
    Ok(Json(Collected {
        visitor_token: token,
        expires_at: expires,
    })
    .into_response())
}

pub async fn check(
    State(state): State<std::sync::Arc<AppState>>,
    request: Request,
) -> Result<Response, ApiError> {
    let site = state.authenticate(request.headers())?;
    if request.headers().contains_key(header::ORIGIN) {
        return Err(ApiError::forbidden());
    }
    site.check_rate
        .lock()
        .map_err(|_| ApiError::unavailable())?
        .take(Instant::now())?;
    let Json(req) = Json::<CheckRequest>::from_request(request, &())
        .await
        .map_err(json_error)?;
    if req.email.len() > 254
        || req.email.chars().any(char::is_control)
        || req.visitor_token.as_ref().is_some_and(|s| s.len() > 160)
    {
        return Err(ApiError::invalid());
    }
    let e = email::check(&req.email, &state.resolver, Duration::from_millis(800)).await;
    let linking = state.link(
        site,
        req.visitor_token.as_deref(),
        e.signals.normalized.as_deref(),
        Time::now()?,
    );
    Ok(Json(CheckResponse {
        verdict: email::verdict(&e.reasons),
        reasons: e.reasons,
        email: e.signals,
        linking,
    })
    .into_response())
}

pub async fn preflight(
    State(state): State<std::sync::Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let Some(origin) = header_text(&headers, "origin") else {
        return ApiError::forbidden().into_response();
    };
    if !state
        .sites
        .iter()
        .any(|s| s.origins.iter().any(|s| s == origin))
        || header_text(&headers, "access-control-request-method") != Some("POST")
        || header_text(&headers, "access-control-request-headers").is_some_and(|s| {
            s.split(',').any(|h| {
                !["content-type", "x-site-key"].contains(&h.trim().to_ascii_lowercase().as_str())
            })
        })
    {
        return ApiError::forbidden().into_response();
    }
    let mut response = cors(
        StatusCode::NO_CONTENT.into_response(),
        headers[header::ORIGIN].clone(),
    );
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("POST"),
    );
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("content-type, x-site-key"),
    );
    response
}
fn cors(mut response: Response, origin: HeaderValue) -> Response {
    response
        .headers_mut()
        .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    response.headers_mut().insert(
        header::VARY,
        HeaderValue::from_static(
            "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
        ),
    );
    response
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
fn origin(s: &str) -> bool {
    if s.len() > 256 {
        return false;
    }
    let Ok(uri) = s.parse::<Uri>() else {
        return false;
    };
    let Some(authority) = uri.authority() else {
        return false;
    };
    let scheme = uri.scheme_str().unwrap_or("");
    matches!(scheme, "http" | "https")
        && !authority.as_str().contains('@')
        && s == format!("{scheme}://{authority}")
        && (scheme == "https" || ["localhost", "127.0.0.1", "[::1]"].contains(&authority.host()))
}
fn ms(v: f64) -> bool {
    v.is_finite() && (0.0..=60000.0).contains(&v)
}
fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn unhex(s: &str, bytes: usize) -> Option<Vec<u8>> {
    if !is_hex(s, bytes * 2) {
        return None;
    }
    (0..bytes)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
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
            {"id":"alpha","site_key":"p".repeat(32),"secret_key":"s".repeat(32),"origins":["https://alpha.test"]},
            {"id":"beta","site_key":"q".repeat(32),"secret_key":"t".repeat(32),"origins":["https://beta.test"]}
        ]).to_string()
    }
    fn state() -> AppState {
        AppState::configure(&"a".repeat(64), &config()).unwrap()
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
    fn observe(state: &AppState, site: &Site, index: u64, now: Time) -> String {
        let id = format!("{index:032x}");
        let expires = now.unix + TOKEN_TTL.as_secs();
        state.store.lock().unwrap().observations.insert(
            id.clone(),
            Observation {
                site: site.id.clone(),
                signals: signals(),
                expires,
                deadline: now.tick + TOKEN_TTL,
                email: None,
            },
        );
        state.token(site, &id, expires)
    }

    #[test]
    fn config_fails_closed_without_printing_credentials() {
        assert!(AppState::configure("short", &config()).is_err());
        assert!(AppState::configure(&"a".repeat(64), "[]").is_err());
        assert!(
            AppState::configure(
                &"a".repeat(64),
                &config().replace("https://beta.test", "https://beta.test/path")
            )
            .is_err()
        );
        assert!(
            AppState::configure(
                &"a".repeat(64),
                &config().replace(&"t".repeat(32), &"p".repeat(32))
            )
            .is_err()
        );
        for value in [
            "*",
            "null",
            "https://host/path",
            "https://user@host",
            "http://example.test",
            "https://host?query",
            "https://host/",
        ] {
            assert!(!origin(value));
        }
        for value in [
            "https://host",
            "https://host:443",
            "http://localhost:5173",
            "http://127.0.0.1:3000",
            "http://[::1]:3000",
        ] {
            assert!(origin(value));
        }
    }

    #[test]
    fn validates_schema_missingness_and_canonical_identity() {
        assert!(signals().valid());
        let mut s = signals();
        s.version = 2;
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

    #[tokio::test]
    async fn signatures_are_tenant_bound_and_expiring() {
        let state = state();
        let now = Time::now().unwrap();
        let a = &state.sites[0];
        let b = &state.sites[1];
        let token = observe(&state, a, 1, now);
        assert!(state.claims(a, &token, now).is_ok());
        assert!(state.claims(b, &token, now).is_err());
        let mut tampered = token.clone();
        tampered.push('0');
        assert!(state.claims(a, &tampered, now).is_err());
        let expired = Time {
            unix: now.unix + TOKEN_TTL.as_secs(),
            tick: now.tick + TOKEN_TTL,
        };
        assert!(state.claims(a, &token, expired).is_err());
        assert_eq!(
            state
                .link(a, Some(&token), Some("normalized"), expired)
                .status,
            "expired_token"
        );
    }

    #[tokio::test]
    async fn counts_other_emails_atomically_and_never_crosses_tenants() {
        let state = state();
        let now = Time::now().unwrap();
        let a = &state.sites[0];
        let b = &state.sites[1];
        let first = observe(&state, a, 1, now);
        let second = observe(&state, a, 2, now);
        let other = observe(&state, b, 3, now);
        assert_eq!(
            state
                .link(a, Some(&first), Some("first"), now)
                .other_emails_seen,
            Some(0)
        );
        let deadline = *state.store.lock().unwrap().links.values().next().unwrap();
        assert_eq!(
            state
                .link(
                    a,
                    Some(&first),
                    Some("first"),
                    Time {
                        unix: now.unix + 1,
                        tick: now.tick + Duration::from_secs(1)
                    }
                )
                .other_emails_seen,
            Some(0)
        );
        assert!(*state.store.lock().unwrap().links.values().next().unwrap() == deadline);
        assert_eq!(
            state.link(a, Some(&first), Some("second"), now).status,
            "token_already_bound"
        );
        assert_eq!(
            state
                .link(a, Some(&second), Some("second"), now)
                .other_emails_seen,
            Some(1)
        );
        assert_eq!(
            state
                .link(b, Some(&other), Some("third"), now)
                .other_emails_seen,
            Some(0)
        );
        assert_eq!(
            state.link(b, Some(&second), Some("third"), now).status,
            "invalid_token"
        );
    }

    #[tokio::test]
    async fn expires_observations_and_links_even_when_wall_clock_moves_back() {
        let state = state();
        let now = Time::now().unwrap();
        let a = &state.sites[0];
        let token = observe(&state, a, 1, now);
        assert!(state.link(a, Some(&token), Some("first"), now).recorded);
        let later = Time {
            unix: now.unix.saturating_sub(1),
            tick: now.tick + TOKEN_TTL,
        };
        assert_eq!(
            state.link(a, Some(&token), Some("first"), later).status,
            "observation_unavailable"
        );
        assert_eq!(state.store.lock().unwrap().observations.len(), 0);
        let mut store = state.store.lock().unwrap();
        store.prune(Time {
            unix: now.unix,
            tick: now.tick + LINK_TTL,
        });
        assert!(store.links.is_empty());
    }

    #[tokio::test]
    async fn capacity_degradation_is_unknown_not_a_zero_match() {
        let state = state();
        let now = Time::now().unwrap();
        let a = &state.sites[0];
        let token = observe(&state, a, 1, now);
        {
            let mut store = state.store.lock().unwrap();
            for i in 0..MAX_LINKS_PER_SITE {
                store.links.insert(
                    LinkKey {
                        site: a.id.clone(),
                        schema: 4,
                        profile: i.to_string(),
                        email: [0; 32],
                    },
                    now.tick + LINK_TTL,
                );
            }
        }
        let result = state.link(a, Some(&token), Some("first"), now);
        assert!(!result.recorded && result.other_emails_seen.is_none());
        assert_eq!(result.status, "linking_unavailable");
        let b = &state.sites[1];
        let other = observe(&state, b, 2, now);
        assert!(state.link(b, Some(&other), Some("first"), now).recorded);
    }

    #[tokio::test]
    async fn bounds_public_observations_without_evicting_existing_tokens() {
        let state = state();
        let now = Time::now().unwrap();
        let a = &state.sites[0];
        let first = observe(&state, a, 0, now);
        for i in 1..MAX_OBSERVATIONS_PER_SITE {
            observe(&state, a, i as u64, now);
        }
        let request=Request::builder().header(header::CONTENT_TYPE,"application/json").body(axum::body::Body::from(serde_json::json!({"version":4,"components":{},"hints":{},"unavailable":{},"excluded":[],"durationMs":0}).to_string())).unwrap();
        assert!(matches!(
            collect_inner(&state, a, request).await,
            Err(ApiError(StatusCode::TOO_MANY_REQUESTS, _))
        ));
        assert!(state.link(a, Some(&first), Some("first"), now).recorded);
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
