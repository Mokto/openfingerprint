//! Replay markers: has this exact SDK token been checked before? One hashed key per token with
//! a TTL; no fingerprint, account or address is stored with it. Best effort: it catches a
//! captured token submitted again, not an attacker who builds a fresh one.

use std::{
    fmt::Write as _,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use crate::cache::Link;

const TIMEOUT: Duration = Duration::from_millis(250);
const RESULTS: [&str; 3] = ["new", "replayed", "error"];
const DEFAULT_WINDOW_SECONDS: u64 = 3600;

pub struct Replay {
    link: Link,
    window_seconds: u64,
    counts: [AtomicU64; 3],
}

/// The marker key of a decoded token. Hashing the content, not the sealed string, means
/// re-sealing the same evidence under a new random prefix does not make it look new.
pub fn key(content: &serde_json::Value) -> String {
    format!(
        "openfingerprint:replay:v1:{}",
        crate::check::sha256(&content.to_string())
    )
}

impl Replay {
    pub fn new(client: redis::Client, window_seconds: u64) -> Self {
        Self {
            link: Link::new(client),
            window_seconds,
            counts: Default::default(),
        }
    }

    pub fn from_env(client: redis::Client) -> Result<Self, &'static str> {
        let seconds = match std::env::var("OPENFINGERPRINT_REPLAY_WINDOW_SECONDS") {
            Err(_) => DEFAULT_WINDOW_SECONDS,
            Ok(s) => s
                .parse()
                .ok()
                .filter(|s| (1..=604_800).contains(s))
                .ok_or("OPENFINGERPRINT_REPLAY_WINDOW_SECONDS must be 1-604800")?,
        };
        Ok(Self::new(client, seconds))
    }

    /// `Some(true)` the first time `key` is seen within the window, `Some(false)` after that,
    /// `None` when Redis cannot say. Unknown is never reported as new or replayed.
    pub async fn first_seen(&self, key: &str) -> Option<bool> {
        let mut command = redis::cmd("SET");
        command
            .arg(key)
            .arg(1)
            .arg("NX")
            .arg("EX")
            .arg(self.window_seconds);
        let command = &command;
        let reply: Result<Option<String>, ()> = self
            .link
            .run(TIMEOUT, |mut connection| async move {
                command.query_async(&mut connection).await
            })
            .await;
        let (index, first) = match reply {
            Ok(Some(_)) => (0, Some(true)),
            Ok(None) => (1, Some(false)),
            Err(()) => (2, None),
        };
        self.counts[index].fetch_add(1, Ordering::Relaxed);
        first
    }

    pub fn metrics(&self) -> String {
        let mut out = String::from(
            "# HELP openfingerprint_replay_checks_total Token replay checks by outcome: first sighting, seen before, or Redis unavailable.\n# TYPE openfingerprint_replay_checks_total counter\n",
        );
        for (result, count) in RESULTS.iter().zip(&self.counts) {
            let _ = writeln!(
                out,
                "openfingerprint_replay_checks_total{{result=\"{result}\"}} {}",
                count.load(Ordering::Relaxed)
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::tests::{client_for, fake_redis};

    #[test]
    fn the_key_depends_on_content_only() {
        let a = serde_json::json!({"b": 1, "a": [1, 2]});
        let reordered: serde_json::Value = serde_json::from_str(r#"{"a":[1,2],"b":1}"#).unwrap();
        assert_eq!(key(&a), key(&reordered));
        assert_ne!(key(&a), key(&serde_json::json!({"b": 2, "a": [1, 2]})));
        let prefix = "openfingerprint:replay:v1:";
        assert!(key(&a).starts_with(prefix) && key(&a).len() == prefix.len() + 64);
    }

    #[tokio::test]
    async fn marks_each_key_once_per_window_and_reports_unknown_when_redis_fails() {
        let (addr, store) = fake_redis(None).await;
        let replay = Replay::new(client_for(&addr), 90);
        assert_eq!(replay.first_seen("k").await, Some(true));
        assert_eq!(replay.first_seen("k").await, Some(false));
        assert_eq!(replay.first_seen("other").await, Some(true));
        assert_eq!(store.lock().unwrap()["k"].1, "90", "always with a TTL");

        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let down = Replay::new(client_for(&closed.local_addr().unwrap().to_string()), 90);
        drop(closed);
        assert_eq!(down.first_seen("k").await, None);

        let metrics = replay.metrics();
        assert!(
            metrics.contains("result=\"new\"} 2") && metrics.contains("result=\"replayed\"} 1")
        );
        assert!(down.metrics().contains("result=\"error\"} 1"));
    }
}
