use std::{
    fmt::Write as _,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use redis::aio::MultiplexedConnection;
use tokio::{sync::Mutex, time::Instant};

const TIMEOUT: Duration = Duration::from_millis(250);
const RESULTS: [&str; 3] = ["hit", "miss", "error"];
// Well under the 330 s idle timeout of the bundled HAProxy, so a reused connection is never
// one that a proxy or NAT already dropped.
// Background writes in flight; beyond this, a write is dropped (and counted as an error) rather
// than queueing behind a slow Redis.
const MAX_PENDING_WRITES: usize = 64;
const IDLE: Duration = Duration::from_secs(60);

/// The Redis shared by the RDAP cache and the token replay markers. Required: the API does not start
/// without it, but each feature handles an unreachable Redis on its own.
pub fn client_from_env() -> Result<redis::Client, &'static str> {
    let url = std::env::var("OPENFINGERPRINT_REDIS_URL").map_err(|_| {
        "OPENFINGERPRINT_REDIS_URL is required: the Redis for the RDAP cache and token replay markers"
    })?;
    client(&url, std::env::var("OPENFINGERPRINT_REDIS_PASSWORD").ok())
}

fn client(url: &str, password: Option<String>) -> Result<redis::Client, &'static str> {
    const INVALID: &str = "Invalid OPENFINGERPRINT_REDIS_URL";
    let client = redis::Client::open(url).map_err(|_| INVALID)?;
    let info = client.get_connection_info();
    if !matches!(
        info.addr(),
        redis::ConnectionAddr::Tcp(..)
            | redis::ConnectionAddr::TcpTls {
                insecure: false,
                ..
            }
    ) {
        return Err(INVALID);
    }
    match password.filter(|p| !p.is_empty()) {
        None => Ok(client),
        Some(password) => {
            let settings = info.redis_settings().clone().set_password(password);
            redis::Client::open(info.clone().set_redis_settings(settings)).map_err(|_| INVALID)
        }
    }
}

struct Slot {
    id: u64,
    connection: MultiplexedConnection,
    used: Instant,
}

/// One lazily opened Redis connection shared by every request of a consumer, so a command
/// costs a round trip instead of a TCP (and TLS) handshake plus one. The connection is
/// multiplexed: concurrent commands do not queue behind each other. It is replaced after any
/// error or timeout, and when idle longer than `IDLE`; commands are never retried.
pub struct Link {
    client: redis::Client,
    slot: Mutex<Option<Slot>>,
    next: AtomicU64,
    idle: Duration,
}

impl Link {
    pub fn new(client: redis::Client) -> Self {
        Self::with_idle(client, IDLE)
    }

    fn with_idle(client: redis::Client, idle: Duration) -> Self {
        Self {
            client,
            slot: Mutex::new(None),
            next: AtomicU64::new(1),
            idle,
        }
    }

    async fn connection(&self) -> redis::RedisResult<(u64, MultiplexedConnection)> {
        let mut slot = self.slot.lock().await;
        if let Some(slot) = slot.as_mut()
            && slot.used.elapsed() < self.idle
        {
            slot.used = Instant::now();
            return Ok((slot.id, slot.connection.clone()));
        }
        let connection = self.client.get_multiplexed_async_connection().await?;
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        *slot = Some(Slot {
            id,
            connection: connection.clone(),
            used: Instant::now(),
        });
        Ok((id, connection))
    }

    /// Runs `operation` on the shared connection, connecting first if needed, within `limit`.
    /// Failure of any kind discards the connection so the next call starts a fresh one.
    pub async fn run<T, Fut>(
        &self,
        limit: Duration,
        operation: impl FnOnce(MultiplexedConnection) -> Fut,
    ) -> Result<T, ()>
    where
        Fut: Future<Output = redis::RedisResult<T>>,
    {
        let used = AtomicU64::new(0);
        let result = tokio::time::timeout(limit, async {
            let (id, connection) = self.connection().await?;
            used.store(id, Ordering::Relaxed);
            operation(connection).await
        })
        .await;
        if let Ok(Ok(value)) = result {
            return Ok(value);
        }
        // Only the connection that failed: another call may already have replaced it.
        let id = used.load(Ordering::Relaxed);
        let mut slot = self.slot.lock().await;
        if slot.as_ref().is_some_and(|slot| slot.id == id) {
            *slot = None;
        }
        Err(())
    }
}

/// RDAP answer cache: every failure is a miss, never a failed check.
#[derive(Clone)]
pub struct Cache {
    link: Arc<Link>,
    counts: Arc<[AtomicU64; 3]>,
    pending: Arc<AtomicUsize>,
}

impl Cache {
    pub fn new(client: redis::Client) -> Self {
        Self {
            link: Arc::new(Link::new(client)),
            counts: Default::default(),
            pending: Default::default(),
        }
    }

    /// Writes without making the caller wait: a cache write is a best-effort optimisation for
    /// later lookups, so the request that computed the answer returns without it.
    pub fn set_later(&self, key: String, value: String, ttl_seconds: u64) {
        if self.pending.fetch_add(1, Ordering::Relaxed) >= MAX_PENDING_WRITES {
            self.pending.fetch_sub(1, Ordering::Relaxed);
            self.counts[2].fetch_add(1, Ordering::Relaxed);
            return;
        }
        let cache = self.clone();
        tokio::spawn(async move {
            cache.set(&key, &value, ttl_seconds).await;
            cache.pending.fetch_sub(1, Ordering::Relaxed);
        });
    }

    #[cfg(test)]
    pub async fn flush(&self) {
        while self.pending.load(Ordering::Relaxed) > 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    pub async fn get(&self, key: &str) -> Option<String> {
        let reply: Result<Option<String>, ()> = crate::metrics::timed(
            crate::metrics::Step::RedisGet,
            self.run(redis::cmd("GET").arg(key)),
        )
        .await;
        let i = match &reply {
            Ok(Some(_)) => 0,
            Ok(None) => 1,
            Err(()) => 2,
        };
        self.counts[i].fetch_add(1, Ordering::Relaxed);
        reply.ok().flatten()
    }

    pub async fn set(&self, key: &str, value: &str, ttl_seconds: u64) {
        let reply: Result<(), ()> = crate::metrics::timed(
            crate::metrics::Step::RedisSet,
            self.run(
                redis::cmd("SET")
                    .arg(key)
                    .arg(value)
                    .arg("EX")
                    .arg(ttl_seconds),
            ),
        )
        .await;
        if reply.is_err() {
            self.counts[2].fetch_add(1, Ordering::Relaxed);
        }
    }

    async fn run<T: redis::FromRedisValue>(&self, command: &redis::Cmd) -> Result<T, ()> {
        self.link
            .run(TIMEOUT, |mut connection| async move {
                command.query_async(&mut connection).await
            })
            .await
    }

    pub fn metrics(&self) -> String {
        let mut out = String::from(
            "# HELP openfingerprint_rdap_cache_total RDAP cache reads by outcome, and failed writes as errors.\n# TYPE openfingerprint_rdap_cache_total counter\n",
        );
        for (result, count) in RESULTS.iter().zip(self.counts.iter()) {
            let _ = writeln!(
                out,
                "openfingerprint_rdap_cache_total{{result=\"{result}\"}} {}",
                count.load(Ordering::Relaxed)
            );
        }
        out
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    pub fn client_for(addr: &str) -> redis::Client {
        client(&format!("redis://{addr}/"), None).unwrap()
    }

    /// An in-memory RESP server for GET, SET … EX, SET … NX EX and AUTH; other commands get an error reply.
    pub async fn fake_redis(
        password: Option<&'static str>,
    ) -> (String, Arc<Mutex<HashMap<String, (String, String)>>>) {
        let server = counted_redis(password).await;
        (server.addr, server.store)
    }

    pub struct FakeRedis {
        pub addr: String,
        pub store: Arc<Mutex<HashMap<String, (String, String)>>>,
        pub accepted: Arc<AtomicU64>,
        connections: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
    }
    impl FakeRedis {
        pub fn drop_connections(&self) {
            for connection in self.connections.lock().unwrap().drain(..) {
                connection.abort();
            }
        }
    }

    pub async fn counted_redis(password: Option<&'static str>) -> FakeRedis {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let store: Arc<Mutex<HashMap<String, (String, String)>>> = Default::default();
        let shared = store.clone();
        let accepted = Arc::new(AtomicU64::new(0));
        let connections: Arc<Mutex<Vec<tokio::task::AbortHandle>>> = Default::default();
        let (counter, handles) = (accepted.clone(), connections.clone());
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                counter.fetch_add(1, Ordering::Relaxed);
                let store = shared.clone();
                let task = tokio::spawn(async move {
                    let mut stream = BufReader::new(stream);
                    let mut authed = password.is_none();
                    loop {
                        let mut header = String::new();
                        if stream.read_line(&mut header).await.unwrap_or(0) == 0 {
                            return;
                        }
                        let n: usize = header.trim()[1..].parse().unwrap();
                        let mut args = Vec::new();
                        for _ in 0..n {
                            let mut len = String::new();
                            stream.read_line(&mut len).await.unwrap();
                            let mut arg = vec![0; len.trim()[1..].parse::<usize>().unwrap() + 2];
                            stream.read_exact(&mut arg).await.unwrap();
                            args.push(String::from_utf8_lossy(&arg[..arg.len() - 2]).into_owned());
                        }
                        let reply = match args[0].to_ascii_uppercase().as_str() {
                            "AUTH" if Some(args.last().unwrap().as_str()) == password => {
                                authed = true;
                                "+OK\r\n".to_owned()
                            }
                            _ if !authed => "-NOAUTH Authentication required.\r\n".to_owned(),
                            "GET" => match store.lock().unwrap().get(&args[1]) {
                                Some((v, _)) => format!("${}\r\n{v}\r\n", v.len()),
                                None => "$-1\r\n".to_owned(),
                            },
                            "SET" if args.len() == 6 && args[3] == "NX" && args[4] == "EX" => {
                                let mut store = store.lock().unwrap();
                                if store.contains_key(&args[1]) {
                                    "$-1\r\n".to_owned()
                                } else {
                                    store.insert(
                                        args[1].clone(),
                                        (args[2].clone(), args[5].clone()),
                                    );
                                    "+OK\r\n".to_owned()
                                }
                            }
                            "SET"
                                if args.len() == 6
                                    && args[3] == "XX"
                                    && args[4] == "KEEPTTL"
                                    && args[5] == "GET" =>
                            {
                                let mut store = store.lock().unwrap();
                                match store.get_mut(&args[1]) {
                                    Some((value, _)) => {
                                        let previous = std::mem::replace(value, args[2].clone());
                                        format!("${}\r\n{previous}\r\n", previous.len())
                                    }
                                    None => "$-1\r\n".to_owned(),
                                }
                            }
                            "SET" if args.len() == 5 && args[3] == "EX" => {
                                store
                                    .lock()
                                    .unwrap()
                                    .insert(args[1].clone(), (args[2].clone(), args[4].clone()));
                                "+OK\r\n".to_owned()
                            }
                            _ => "-ERR unsupported\r\n".to_owned(),
                        };
                        stream.get_mut().write_all(reply.as_bytes()).await.unwrap();
                    }
                });
                handles.lock().unwrap().push(task.abort_handle());
            }
        });
        FakeRedis {
            addr,
            store,
            accepted,
            connections,
        }
    }

    #[test]
    fn accepts_only_tcp_and_verified_tls_urls_and_applies_a_separate_password() {
        for ok in [
            "redis://redis:6379/",
            "rediss://user:pw@redis.example:6380/0",
            "redis://10.0.0.1/",
        ] {
            assert!(client(ok, None).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "redis",
            "redis:6379",
            "rediss://redis:6379/#insecure",
            "redis+unix:///tmp/r.sock",
            "http://redis:6379",
        ] {
            assert!(client(bad, None).is_err(), "{bad}");
        }
        let with_password = client("redis://redis:6379/", Some("s3cr/t@:".into())).unwrap();
        assert_eq!(
            with_password
                .get_connection_info()
                .redis_settings()
                .password(),
            Some("s3cr/t@:")
        );
        let unchanged = client("redis://:inline@redis:6379/", Some(String::new())).unwrap();
        assert_eq!(
            unchanged.get_connection_info().redis_settings().password(),
            Some("inline")
        );
    }

    #[tokio::test]
    async fn reads_and_writes_with_expiry_and_treats_failures_as_misses() {
        let (addr, store) = fake_redis(Some("secret")).await;
        let cache = Cache::new(client(&format!("redis://{addr}/"), Some("secret".into())).unwrap());
        assert_eq!(cache.get("k").await, None);
        cache.set("k", "found:808372800", 86400).await;
        assert_eq!(cache.get("k").await.as_deref(), Some("found:808372800"));
        assert_eq!(store.lock().unwrap()["k"].1, "86400");

        let unauthenticated = Cache::new(client_for(&addr));
        assert_eq!(unauthenticated.get("k").await, None);
        unauthenticated.set("other", "x", 1).await;
        assert!(!store.lock().unwrap().contains_key("other"));

        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let down = Cache::new(client_for(&closed.local_addr().unwrap().to_string()));
        drop(closed);
        assert_eq!(down.get("k").await, None);

        let metrics = cache.metrics();
        assert!(metrics.contains("result=\"hit\"} 1") && metrics.contains("result=\"miss\"} 1"));
        assert!(metrics.contains("result=\"error\"} 0"));
        assert!(unauthenticated.metrics().contains("result=\"error\"} 2"));
        assert!(down.metrics().contains("result=\"error\"} 1"));
    }

    #[tokio::test]
    async fn one_connection_serves_every_command_until_it_fails_or_idles() {
        let server = counted_redis(None).await;
        let cache = Cache::new(client_for(&server.addr));
        let accepted = || server.accepted.load(Ordering::Relaxed);
        cache.set("k", "v", 60).await;
        let (a, b, c, d) = tokio::join!(
            cache.get("k"),
            cache.get("k"),
            cache.get("k"),
            cache.get("k")
        );
        assert!([a, b, c, d].iter().all(|v| v.as_deref() == Some("v")));
        assert_eq!(accepted(), 1, "commands share one connection");

        server.drop_connections();
        assert_eq!(cache.get("k").await, None, "a dead connection fails once");
        assert_eq!(cache.get("k").await.as_deref(), Some("v"));
        assert_eq!(accepted(), 2, "and the next command reconnects");

        let idle = Link::with_idle(client_for(&server.addr), Duration::from_millis(50));
        async fn get(link: &Link) -> Result<Option<String>, ()> {
            let mut command = redis::cmd("GET");
            command.arg("k");
            let command = &command;
            link.run(TIMEOUT, |mut connection| async move {
                command.query_async(&mut connection).await
            })
            .await
        }
        assert_eq!(get(&idle).await.unwrap().as_deref(), Some("v"));
        assert_eq!(get(&idle).await.unwrap().as_deref(), Some("v"));
        assert_eq!(accepted(), 3, "fresh connections are reused");
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(get(&idle).await.unwrap().as_deref(), Some("v"));
        assert_eq!(accepted(), 4, "an idle connection is replaced before use");
    }

    #[tokio::test]
    async fn background_writes_do_not_block_the_caller_and_are_bounded() {
        let (addr, store) = fake_redis(None).await;
        let cache = Cache::new(client_for(&addr));
        cache.set_later("k".into(), "v".into(), 60);
        cache.flush().await;
        assert_eq!(store.lock().unwrap()["k"], ("v".into(), "60".into()));

        // A Redis that accepts connections but never answers.
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stuck = Cache::new(client_for(&silent.local_addr().unwrap().to_string()));
        let started = Instant::now();
        for i in 0..MAX_PENDING_WRITES + 10 {
            stuck.set_later(format!("k{i}"), "v".into(), 60);
        }
        assert!(
            started.elapsed() < TIMEOUT / 2,
            "callers never wait for Redis"
        );
        assert!(
            stuck.metrics().contains("result=\"error\"} 10"),
            "writes beyond the bound are dropped"
        );
        stuck.flush().await;
        assert!(
            stuck
                .metrics()
                .contains(&format!("result=\"error\"}} {}", MAX_PENDING_WRITES + 10))
        );
    }
}
