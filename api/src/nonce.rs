//! Single-use nonces for the caller's backend: it mints one per page, the SDK seals it into the
//! token, and `/v1/check` reports whether it was issued here, is unexpired and was not used
//! before. One hashed key per nonce, expiring with it; nothing else is stored. Optional: tokens
//! without a nonce are checked as before.

use std::{
    fmt::Write as _,
    ops::RangeInclusive,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{Json, extract::State};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::{cache::Link, check::ApiError};

const TIMEOUT: Duration = Duration::from_millis(250);
pub const DEFAULT_TTL_SECONDS: u64 = 1800;
pub const TTL_SECONDS: RangeInclusive<u64> = 60..=86_400;
const RESULTS: [&str; 7] = [
    "issued",
    "valid",
    "reused",
    "expired",
    "not_issued",
    "missing",
    "error",
];
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Valid,
    Reused,
    Expired,
    NotIssued,
    /// The token has none although `OPENFINGERPRINT_REQUIRE_NONCE` is set.
    Missing,
    /// Redis could not say; never reported as valid or invalid.
    Unavailable,
}

#[derive(Debug, Serialize)]
pub struct Check {
    pub status: Status,
}

pub struct Nonces {
    link: Link,
    counts: [AtomicU64; RESULTS.len()],
}

fn key(nonce: &str) -> String {
    format!("openfingerprint:nonce:v1:{}", crate::check::sha256(nonce))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// 8 bytes of expiry (Unix seconds, big-endian) and 16 random bytes, as 32 base64url characters.
fn encode(bytes: &[u8; 24]) -> String {
    bytes
        .chunks(3)
        .flat_map(|c| {
            let n = u32::from(c[0]) << 16 | u32::from(c[1]) << 8 | u32::from(c[2]);
            [18, 12, 6, 0].map(|shift| ALPHABET[(n >> shift & 63) as usize] as char)
        })
        .collect()
}

/// The expiry a nonce claims, or `None` when it is not one of ours in shape.
fn expiry(nonce: &str) -> Option<u64> {
    if nonce.len() != 32 {
        return None;
    }
    let mut bytes = Vec::with_capacity(24);
    for chunk in nonce.as_bytes().chunks(4) {
        let n = chunk.iter().try_fold(0u32, |n, c| {
            Some(n << 6 | ALPHABET.iter().position(|a| a == c)? as u32)
        })?;
        bytes.extend_from_slice(&n.to_be_bytes()[1..]);
    }
    Some(u64::from_be_bytes(bytes[..8].try_into().ok()?))
}

impl Nonces {
    pub fn new(client: redis::Client) -> Self {
        Self {
            link: Link::new(client),
            counts: Default::default(),
        }
    }

    fn count(&self, result: &str) {
        if let Some(i) = RESULTS.iter().position(|r| *r == result) {
            self.counts[i].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A new nonce and its expiry in Unix seconds, or `None` when Redis cannot store it.
    pub async fn issue(&self, ttl_seconds: u64) -> Option<(String, u64)> {
        let expires_at = now() + ttl_seconds;
        let mut bytes = [0u8; 24];
        bytes[..8].copy_from_slice(&expires_at.to_be_bytes());
        SystemRandom::new().fill(&mut bytes[8..]).ok()?;
        let nonce = encode(&bytes);
        let mut command = redis::cmd("SET");
        command
            .arg(key(&nonce))
            .arg("issued")
            .arg("NX")
            .arg("EX")
            .arg(ttl_seconds);
        let command = &command;
        let reply: Result<Option<String>, ()> = self
            .link
            .run(TIMEOUT, |mut connection| async move {
                command.query_async(&mut connection).await
            })
            .await;
        if matches!(reply, Ok(Some(_))) {
            self.count("issued");
            Some((nonce, expires_at))
        } else {
            self.count("error");
            None
        }
    }

    /// Marks `nonce` used and says what it was before. Needs Redis 7 or later (`SET XX GET`).
    pub async fn consume(&self, nonce: &str) -> Status {
        let status = match expiry(nonce) {
            None => Status::NotIssued,
            Some(expires_at) if expires_at <= now() => Status::Expired,
            Some(_) => {
                let mut command = redis::cmd("SET");
                command
                    .arg(key(nonce))
                    .arg("used")
                    .arg("XX")
                    .arg("KEEPTTL")
                    .arg("GET");
                let command = &command;
                let reply: Result<Option<String>, ()> = self
                    .link
                    .run(TIMEOUT, |mut connection| async move {
                        command.query_async(&mut connection).await
                    })
                    .await;
                match reply {
                    Ok(Some(previous)) if previous == "issued" => Status::Valid,
                    Ok(Some(_)) => Status::Reused,
                    Ok(None) => Status::NotIssued,
                    Err(()) => Status::Unavailable,
                }
            }
        };
        self.count(match status {
            Status::Valid => "valid",
            Status::Reused => "reused",
            Status::Expired => "expired",
            Status::NotIssued => "not_issued",
            Status::Missing => "missing",
            Status::Unavailable => "error",
        });
        status
    }

    /// The outcome for a token without a nonce when one is required.
    pub fn missing(&self) -> Status {
        self.count("missing");
        Status::Missing
    }

    pub fn metrics(&self) -> String {
        let mut out = String::from(
            "# HELP openfingerprint_nonces_total Nonces issued, and nonces found in checked tokens by outcome.\n# TYPE openfingerprint_nonces_total counter\n",
        );
        for (result, count) in RESULTS.iter().zip(&self.counts) {
            let _ = writeln!(
                out,
                "openfingerprint_nonces_total{{result=\"{result}\"}} {}",
                count.load(Ordering::Relaxed)
            );
        }
        out
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreateRequest {
    pub(crate) ttl_seconds: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Created {
    pub(crate) nonce: String,
    pub(crate) expires_at: u64,
}

pub(crate) async fn create(
    state: &crate::check::AppState,
    request: CreateRequest,
) -> Result<Created, ApiError> {
    let ttl = request.ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);
    if !TTL_SECONDS.contains(&ttl) {
        return Err(ApiError::invalid());
    }
    let (nonce, expires_at) = state.nonces.issue(ttl).await.ok_or(ApiError(
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "nonce_unavailable",
    ))?;
    Ok(Created { nonce, expires_at })
}

pub async fn handler(
    State(state): State<std::sync::Arc<crate::check::AppState>>,
    request: axum::extract::Request,
) -> Result<Json<Created>, ApiError> {
    use axum::extract::FromRequest;
    state.reject_browsers(request.headers())?;
    let Json(input) = Json::<CreateRequest>::from_request(request, &())
        .await
        .map_err(crate::check::json_error)?;
    Ok(Json(create(&state, input).await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce_expiring(at: u64) -> String {
        let mut bytes = [7u8; 24];
        bytes[..8].copy_from_slice(&at.to_be_bytes());
        encode(&bytes)
    }

    #[test]
    fn nonces_carry_their_expiry_and_reject_other_shapes() {
        let nonce = nonce_expiring(1_900_000_000);
        assert_eq!(nonce.len(), 32);
        assert!(nonce.bytes().all(|b| ALPHABET.contains(&b)));
        assert_eq!(expiry(&nonce), Some(1_900_000_000));
        for bad in [
            "",
            "short",
            &"A".repeat(31),
            &"A".repeat(33),
            &"!".repeat(32),
        ] {
            assert_eq!(expiry(bad), None, "{bad}");
        }
    }

    #[tokio::test]
    async fn a_nonce_is_valid_once_then_reused() {
        let (addr, store) = crate::cache::tests::fake_redis(None).await;
        let nonces = Nonces::new(crate::cache::tests::client_for(&addr));
        let (nonce, expires_at) = nonces.issue(600).await.unwrap();
        assert!((now() + 599..=now() + 600).contains(&expires_at));
        assert_eq!(expiry(&nonce), Some(expires_at));
        let stored = store.lock().unwrap().get(&key(&nonce)).cloned();
        assert_eq!(
            stored,
            Some(("issued".into(), "600".into())),
            "hashed key, its own TTL"
        );
        assert_eq!(nonces.consume(&nonce).await, Status::Valid);
        assert_eq!(nonces.consume(&nonce).await, Status::Reused);
        assert_eq!(
            nonces.consume(&nonces.issue(600).await.unwrap().0).await,
            Status::Valid
        );
        assert_eq!(
            nonces.consume(&nonce_expiring(now() + 600)).await,
            Status::NotIssued,
            "well-formed but never issued"
        );
        assert_eq!(
            nonces.consume(&nonce_expiring(now() - 1)).await,
            Status::Expired
        );
        assert_eq!(nonces.consume("not a nonce").await, Status::NotIssued);
        let metrics = nonces.metrics();
        for line in [
            "result=\"issued\"} 2",
            "result=\"valid\"} 2",
            "result=\"reused\"} 1",
            "result=\"expired\"} 1",
            "result=\"not_issued\"} 2",
        ] {
            assert!(metrics.contains(line), "{line}\n{metrics}");
        }
    }

    #[tokio::test]
    async fn without_redis_nothing_is_issued_and_checks_are_unknown() {
        let nonces = Nonces::new(crate::cache::tests::client_for("127.0.0.1:9"));
        assert_eq!(nonces.issue(600).await, None);
        assert_eq!(
            nonces.consume(&nonce_expiring(now() + 600)).await,
            Status::Unavailable
        );
        assert_eq!(
            nonces.consume(&nonce_expiring(now() - 1)).await,
            Status::Expired,
            "expiry needs no Redis"
        );
    }
}
