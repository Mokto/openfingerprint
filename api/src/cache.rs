use std::{
    fmt::Write as _,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

const TIMEOUT: Duration = Duration::from_millis(250);
const RESULTS: [&str; 3] = ["hit", "miss", "error"];

/// The Redis shared by collection state and the RDAP cache. Required: the API does not start
/// without it, but each feature handles an unreachable Redis on its own.
pub fn client_from_env() -> Result<redis::Client, &'static str> {
    let url = std::env::var("OPENFINGERPRINT_REDIS_URL").map_err(|_| {
        "OPENFINGERPRINT_REDIS_URL is required: the Redis for collection state and the RDAP cache"
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

// ponytail: a new connection per command, like the collection store. Switch both to a shared
// ConnectionManager if Redis round trips show up in latency.
/// RDAP answer cache: every failure is a miss, never a failed check.
pub struct Cache {
    client: redis::Client,
    counts: [AtomicU64; 3],
}

impl Cache {
    pub fn new(client: redis::Client) -> Self {
        Self {
            client,
            counts: Default::default(),
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
        tokio::time::timeout(TIMEOUT, async {
            let mut connection = self.client.get_multiplexed_async_connection().await?;
            command.query_async(&mut connection).await
        })
        .await
        .map_err(drop)?
        .map_err(|_: redis::RedisError| ())
    }

    pub fn metrics(&self) -> String {
        let mut out = String::from(
            "# HELP openfingerprint_rdap_cache_total RDAP cache reads by outcome, and failed writes as errors.\n# TYPE openfingerprint_rdap_cache_total counter\n",
        );
        for (result, count) in RESULTS.iter().zip(&self.counts) {
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

    /// An in-memory RESP server for GET, SET … EX and AUTH; other commands get an error reply.
    pub async fn fake_redis(
        password: Option<&'static str>,
    ) -> (String, Arc<Mutex<HashMap<String, (String, String)>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let store: Arc<Mutex<HashMap<String, (String, String)>>> = Default::default();
        let shared = store.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let store = shared.clone();
                tokio::spawn(async move {
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
            }
        });
        (addr, store)
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
}
