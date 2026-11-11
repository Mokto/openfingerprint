//! Replay markers: has this identification been looked up before? One hashed key per
//! identification, expiring with it; nothing else is stored.

use std::{
    fmt::Write as _,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use crate::cache::Link;

const TIMEOUT: Duration = Duration::from_millis(250);
const RESULTS: [&str; 3] = ["new", "replayed", "error"];

pub struct Replay {
    link: Link,
    counts: [AtomicU64; 3],
}

fn key(identification_id: &str) -> String {
    format!(
        "openfingerprint:replay:v2:{}",
        crate::check::sha256(identification_id)
    )
}

impl Replay {
    pub fn new(client: redis::Client) -> Self {
        Self {
            link: Link::new(client),
            counts: Default::default(),
        }
    }

    /// `Some(true)` the first time an identification is looked up, `Some(false)` after that,
    /// `None` when Redis cannot say. Unknown is never reported as new or replayed.
    pub async fn first_seen(&self, identification_id: &str) -> Option<bool> {
        let mut command = redis::cmd("SET");
        command
            .arg(key(identification_id))
            .arg(1)
            .arg("NX")
            .arg("EX")
            .arg(crate::identify::TTL_SECONDS);
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
            "# HELP openfingerprint_replay_checks_total Identification lookups by outcome: first, looked up before, or Redis unavailable.\n# TYPE openfingerprint_replay_checks_total counter\n",
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

    #[tokio::test]
    async fn marks_each_identification_once_and_reports_unknown_when_redis_fails() {
        let (addr, store) = fake_redis(None).await;
        let replay = Replay::new(client_for(&addr));
        assert_eq!(replay.first_seen("k").await, Some(true));
        assert_eq!(replay.first_seen("k").await, Some(false));
        assert_eq!(replay.first_seen("other").await, Some(true));
        let (stored, ttl) = store.lock().unwrap()[&key("k")].clone();
        assert_eq!(
            (stored.as_str(), ttl.as_str()),
            ("1", "3600"),
            "hashed, with the identification's TTL"
        );

        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let down = Replay::new(client_for(&closed.local_addr().unwrap().to_string()));
        drop(closed);
        assert_eq!(down.first_seen("k").await, None);

        let metrics = replay.metrics();
        assert!(
            metrics.contains("result=\"new\"} 2") && metrics.contains("result=\"replayed\"} 1")
        );
        assert!(down.metrics().contains("result=\"error\"} 1"));
    }
}
