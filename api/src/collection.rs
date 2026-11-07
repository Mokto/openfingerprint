use std::{sync::Arc, time::Duration};

use axum::{
    Json,
    extract::{FromRequest, Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use redis::FromRedisValue;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::check::{ApiError, AppState, check_signals, json_error};

const ISSUE: &str = r#"
local time = redis.call('TIME')
local now = time[1] * 1000 + math.floor(time[2] / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[3]) then return 0 end
if not redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2], 'NX') then return 0 end
redis.call('ZADD', KEYS[2], now + tonumber(ARGV[2]), KEYS[1])
if redis.call('PTTL', KEYS[2]) < tonumber(ARGV[2]) then redis.call('PEXPIRE', KEYS[2], ARGV[2]) end
return 1
"#;
const PUBLISH: &str = r#"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
local time = redis.call('TIME')
local now = time[1] * 1000 + math.floor(time[2] / 1000)
local record = cjson.decode(ARGV[2])
record.created_at_unix_ms = now
record.expires_at_unix_ms = now + tonumber(ARGV[3])
if not redis.call('SET', KEYS[2], cjson.encode(record), 'PX', ARGV[3], 'NX') then return 0 end
redis.call('DEL', KEYS[1])
redis.call('ZREM', KEYS[3], KEYS[1])
redis.call('ZADD', KEYS[3], now + tonumber(ARGV[3]), KEYS[2])
if redis.call('PTTL', KEYS[3]) < tonumber(ARGV[3]) then redis.call('PEXPIRE', KEYS[3], ARGV[3]) end
return 1
"#;
const CONSUME: &str = r#"
local record = redis.call('GET', KEYS[1])
if not record or cjson.decode(record).binding ~= ARGV[1] then return nil end
redis.call('DEL', KEYS[1])
redis.call('ZREM', KEYS[2], KEYS[1])
return record
"#;

pub struct Store {
    client: redis::Client,
    ttl_ms: u64,
    capacity: usize,
}
impl Store {
    pub fn from_env(client: redis::Client) -> Result<Self, &'static str> {
        let number = |name: &str, default: u64, max: u64| match std::env::var(name) {
            Err(std::env::VarError::NotPresent) => Ok(default),
            Ok(value) => value
                .parse::<u64>()
                .ok()
                .filter(|n| (1..=max).contains(n))
                .ok_or("Invalid collection limits"),
            Err(_) => Err("Invalid collection limits"),
        };
        Ok(Self {
            client,
            ttl_ms: number("OPENFINGERPRINT_COLLECTION_TTL_SECONDS", 120, 300)? * 1000,
            capacity: number("OPENFINGERPRINT_COLLECTION_CAPACITY", 1024, 100_000)? as usize,
        })
    }
    async fn run<T: FromRedisValue>(
        &self,
        script: &str,
        keys: &[String],
        args: &[String],
    ) -> Result<T, ApiError> {
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut connection = self.client.get_multiplexed_async_connection().await?;
            let script = redis::Script::new(script);
            let mut command = script.prepare_invoke();
            for key in keys {
                command.key(key);
            }
            for arg in args {
                command.arg(arg);
            }
            command.invoke_async(&mut connection).await
        })
        .await
        .map_err(|_| unavailable())?
        .map_err(|_: redis::RedisError| unavailable())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ChallengeRecord {
    scope: String,
    binding: String,
    origin: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeInput {
    binding: String,
    origin: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Context {
    user_agent: Option<String>,
    platform: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CollectionInput {
    challenge: String,
    signals: Value,
    context: Context,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumeInput {
    event_id: String,
    binding: String,
}

fn unavailable() -> ApiError {
    ApiError(StatusCode::SERVICE_UNAVAILABLE, "collection_unavailable")
}
fn missing() -> ApiError {
    ApiError(StatusCode::CONFLICT, "expired_used_or_mismatched")
}
fn token(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn random_token() -> Result<String, ApiError> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| unavailable())?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn origin(value: &str) -> bool {
    if value.len() > 512 {
        return false;
    }
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    url.origin().ascii_serialization() == value
        && url.username().is_empty()
        && url.password().is_none()
        && (url.scheme() == "https"
            || (url.scheme() == "http"
                && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))))
}
fn challenge_key(id: &str) -> String {
    format!("openfingerprint:v1:challenge:{id}")
}
fn event_key(scope: &str, id: &str) -> String {
    format!("openfingerprint:v1:{scope}:event:{id}")
}
fn index_key(scope: &str) -> String {
    format!("openfingerprint:v1:{scope}:pending")
}
fn text<'a>(headers: &'a HeaderMap, name: &str, limit: usize) -> Option<&'a str> {
    headers
        .get(name)?
        .to_str()
        .ok()
        .filter(|value| !value.is_empty() && value.len() <= limit)
}
fn headless(value: &str) -> bool {
    value.match_indices("HeadlessChrome/").any(|(i, _)| {
        i == 0
            || (!value.as_bytes()[i - 1].is_ascii_alphanumeric() && value.as_bytes()[i - 1] != b'_')
    })
}

fn consistency(context: &Context, signals: &Value, headers: &HeaderMap) -> Value {
    let ua = text(headers, "user-agent", 512);
    let reported = context.user_agent.as_deref();
    let claimed_headless = signals["automation"]["headlessUserAgent"].as_bool();
    let platform = match context.platform.as_deref() {
        Some("Win32" | "Win64") => Some("\"Windows\""),
        Some("MacIntel" | "MacPPC") => Some("\"macOS\""),
        _ => None,
    };
    let mut indicators = Vec::new();
    let mut unavailable = Vec::new();
    for (name, matches) in [
        ("user_agent_mismatch", reported.zip(ua).map(|(a, b)| a == b)),
        (
            "headless_evidence_mismatch",
            reported
                .zip(claimed_headless)
                .map(|(a, b)| headless(a) == b),
        ),
        (
            "platform_mismatch",
            platform
                .zip(text(headers, "sec-ch-ua-platform", 64))
                .map(|(a, b)| a == b),
        ),
    ] {
        match matches {
            Some(false) => indicators.push(name),
            None => unavailable.push(name),
            Some(true) => {}
        }
    }
    json!({
        "rule_version": 1,
        "status": if !indicators.is_empty() { "detected" } else if !unavailable.is_empty() { "unknown" } else { "not_detected" },
        "indicators": indicators,
        "unavailable_checks": unavailable
    })
}

pub async fn challenge(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Response, ApiError> {
    let site = state.authorize(request.headers())?;
    let store = state.collection.as_ref().ok_or_else(unavailable)?;
    let Json(input) = Json::<ChallengeInput>::from_request(request, &())
        .await
        .map_err(json_error)?;
    if !token(&input.binding) || !origin(&input.origin) {
        return Err(ApiError::invalid());
    }
    let id = random_token()?;
    let record = ChallengeRecord {
        scope: site.scope(),
        binding: input.binding,
        origin: input.origin,
    };
    let issued: i32 = store
        .run(
            ISSUE,
            &[challenge_key(&id), index_key(&record.scope)],
            &[
                serde_json::to_string(&record).map_err(|_| unavailable())?,
                store.ttl_ms.to_string(),
                store.capacity.to_string(),
            ],
        )
        .await?;
    if issued != 1 {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "collection_capacity",
        ));
    }
    Ok(Json(json!({"challenge": id, "expires_in_ms": store.ttl_ms})).into_response())
}

pub async fn collect(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Response, ApiError> {
    let store = state.collection.as_ref().ok_or_else(unavailable)?;
    if request.headers().contains_key(header::AUTHORIZATION)
        || request.headers().contains_key(header::COOKIE)
    {
        return Err(ApiError(StatusCode::FORBIDDEN, "credentials_not_allowed"));
    }
    let peer = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .copied();
    let headers = request.headers().clone();
    let request_origin = text(&headers, "origin", 512)
        .filter(|value| origin(value))
        .ok_or(ApiError(StatusCode::FORBIDDEN, "origin_not_allowed"))?;
    let Json(mut input) = Json::<CollectionInput>::from_request(request, &())
        .await
        .map_err(json_error)?;
    if !token(&input.challenge)
        || input
            .context
            .user_agent
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > 512)
        || input
            .context
            .platform
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > 128)
    {
        return Err(ApiError::invalid());
    }
    let initial =
        serde_json::to_value(check_signals(input.signals.clone())).map_err(|_| unavailable())?;
    if initial["status"] == "invalid_input"
        || initial["automation"].is_null()
        || initial["automation"]["status"] == "invalid_input"
    {
        return Err(ApiError::invalid());
    }
    let key = challenge_key(&input.challenge);
    let record: Option<String> = store
        .run(
            "return redis.call('GET', KEYS[1])",
            std::slice::from_ref(&key),
            &[],
        )
        .await?;
    let record = record.ok_or_else(missing)?;
    let challenge: ChallengeRecord = serde_json::from_str(&record).map_err(|_| unavailable())?;
    if challenge.origin != request_origin {
        return Err(ApiError(StatusCode::FORBIDDEN, "origin_not_allowed"));
    }
    let network = state.network.request_check(&headers, peer);
    let consistency = consistency(&input.context, &input.signals, &headers);
    let observed_headless = text(&headers, "user-agent", 512).map(headless);
    if observed_headless == Some(true) {
        input.signals["automation"]["headlessUserAgent"] = json!(true);
    }
    let id = random_token()?;
    // Redis cjson re-encodes empty arrays as objects; keep evaluated JSON opaque.
    let event = json!({
        "binding": challenge.binding,
        "event_json": serde_json::to_string(&json!({
            "event_id": id,
            "signals": check_signals(input.signals),
            "consistency": consistency,
            "ip": network,
            "request": { "origin": request_origin, "headless_user_agent": observed_headless }
        })).map_err(|_| unavailable())?
    });
    let published: i32 = store
        .run(
            PUBLISH,
            &[
                key,
                event_key(&challenge.scope, &id),
                index_key(&challenge.scope),
            ],
            &[
                record,
                serde_json::to_string(&event).map_err(|_| unavailable())?,
                store.ttl_ms.to_string(),
            ],
        )
        .await?;
    if published != 1 {
        return Err(missing());
    }
    Ok(Json(json!({"event_id": id})).into_response())
}

pub async fn consume(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Response, ApiError> {
    let site = state.authorize(request.headers())?;
    let store = state.collection.as_ref().ok_or_else(unavailable)?;
    let Json(input) = Json::<ConsumeInput>::from_request(request, &())
        .await
        .map_err(json_error)?;
    if !token(&input.event_id) || !token(&input.binding) {
        return Err(ApiError::invalid());
    }
    let record: Option<String> = store
        .run(
            CONSUME,
            &[
                event_key(&site.scope(), &input.event_id),
                index_key(&site.scope()),
            ],
            &[input.binding],
        )
        .await?;
    let record: Value =
        serde_json::from_str(&record.ok_or_else(missing)?).map_err(|_| unavailable())?;
    let mut event: Value =
        serde_json::from_str(record["event_json"].as_str().ok_or_else(unavailable)?)
            .map_err(|_| unavailable())?;
    crate::network::expire_event(&mut event["ip"]);
    event["created_at_unix_ms"] = record["created_at_unix_ms"].clone();
    event["expires_at_unix_ms"] = record["expires_at_unix_ms"].clone();
    Ok(Json(event).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redis_tls_has_a_crypto_provider() {
        let _ = rustls::ClientConfig::builder();
    }

    #[test]
    fn accepts_only_exact_secure_origins_and_loopback_development() {
        for value in [
            "https://example.test",
            "https://example.test:8443",
            "http://localhost:3000",
            "http://127.0.0.1:8000",
            "http://[::1]:8000",
        ] {
            assert!(origin(value), "{value}");
        }
        for value in [
            "null",
            "http://example.test",
            "https://example.test/",
            "https://example.test/path",
            "https://example.test?x",
            "https://user@example.test",
            "https://EXAMPLE.test",
            "https://example.test:443",
            "file://local",
            "https://example.test#hash",
        ] {
            assert!(!origin(value), "{value}");
        }
        assert!(token(&random_token().unwrap()));
        assert!(!token(&"A".repeat(64)));
    }

    #[test]
    fn compares_observations_without_promoting_missing_evidence() {
        let context = Context {
            user_agent: Some("Chrome/156".into()),
            platform: Some("Win32".into()),
        };
        let signals = json!({"automation": {"headlessUserAgent": false}});
        let mut headers = HeaderMap::new();
        assert_eq!(
            consistency(&context, &signals, &headers)["status"],
            "unknown"
        );
        headers.insert("user-agent", "Chrome/156".parse().unwrap());
        headers.insert("sec-ch-ua-platform", "\"Windows\"".parse().unwrap());
        assert_eq!(
            consistency(&context, &signals, &headers)["status"],
            "not_detected"
        );
        headers.insert("user-agent", "HeadlessChrome/156".parse().unwrap());
        assert_eq!(
            consistency(&context, &signals, &headers)["indicators"],
            json!(["user_agent_mismatch"])
        );
        let context = Context {
            user_agent: Some("HeadlessChrome/156".into()),
            platform: None,
        };
        assert_eq!(
            consistency(&context, &signals, &headers)["indicators"],
            json!(["headless_evidence_mismatch"])
        );
        assert!(headless("Mozilla/5.0 HeadlessChrome/156"));
        assert!(!headless("NotHeadlessChrome/156"));
    }
}
