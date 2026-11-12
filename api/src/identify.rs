//! The public listener: the SDK posts its evidence to `POST /v1/identify` over TLS. The API
//! reads the request headers and the TLS ClientHello (JA4) itself, stores them with the
//! evidence under a random identification ID, and the internal `/v1/check` evaluates the
//! identification by that ID.

use std::{
    collections::HashMap,
    fmt::Write as _,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
    serve::IncomingStream,
};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use crate::check::AppState;

const REDIS_TIMEOUT: Duration = Duration::from_millis(250);
pub const TTL_SECONDS: u64 = 3600;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HANDSHAKES: usize = 1024;
const MAX_RECORD: usize = 5 + 16384 + 2048;
const CERT_RELOAD: Duration = Duration::from_secs(300);
const DEFAULT_PER_MINUTE: u32 = 60;

const RESULTS: [&str; 5] = [
    "stored",
    "origin_refused",
    "rate_limited",
    "invalid",
    "error",
];
const LOOKUPS: [&str; 3] = ["found", "unknown", "error"];
const CLIENTS: [&str; 9] = [
    "chromium", "firefox", "apple", "curl", "python", "go", "node", "unknown", "none",
];
static RESULT_COUNTS: [AtomicU64; RESULTS.len()] = [const { AtomicU64::new(0) }; RESULTS.len()];
static LOOKUP_COUNTS: [AtomicU64; LOOKUPS.len()] = [const { AtomicU64::new(0) }; LOOKUPS.len()];
static CLIENT_COUNTS: [AtomicU64; CLIENTS.len()] = [const { AtomicU64::new(0) }; CLIENTS.len()];
static CERTIFICATES: AtomicU64 = AtomicU64::new(0);
static CERT_RELOAD_FAILURES: AtomicU64 = AtomicU64::new(0);

fn count(table: &[AtomicU64], names: &[&str], name: &str) {
    if let Some(i) = names.iter().position(|n| *n == name) {
        table[i].fetch_add(1, Ordering::Relaxed);
    }
}

pub fn metrics() -> String {
    let mut out = String::new();
    let mut family = |name: &str, help: &str, label: &str, names: &[&str], table: &[AtomicU64]| {
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} counter");
        for (value, n) in names.iter().zip(table) {
            let _ = writeln!(
                out,
                "{name}{{{label}=\"{value}\"}} {}",
                n.load(Ordering::Relaxed)
            );
        }
    };
    family(
        "openfingerprint_identifications_total",
        "Browser posts to /v1/identify, by outcome.",
        "result",
        &RESULTS,
        &RESULT_COUNTS,
    );
    family(
        "openfingerprint_identification_lookups_total",
        "Identifications looked up by /v1/check, by outcome.",
        "result",
        &LOOKUPS,
        &LOOKUP_COUNTS,
    );
    family(
        "openfingerprint_identification_tls_clients_total",
        "Stored identifications by the TLS stack their ClientHello matched.",
        "client",
        &CLIENTS,
        &CLIENT_COUNTS,
    );
    let _ = write!(
        out,
        "# HELP openfingerprint_identify_certificates Certificates loaded for the identify listener.\n# TYPE openfingerprint_identify_certificates gauge\nopenfingerprint_identify_certificates {}\n# HELP openfingerprint_identify_certificate_reload_failures_total Certificate directory reloads that failed; the previous certificates stay in use.\n# TYPE openfingerprint_identify_certificate_reload_failures_total counter\nopenfingerprint_identify_certificate_reload_failures_total {}\n",
        CERTIFICATES.load(Ordering::Relaxed),
        CERT_RELOAD_FAILURES.load(Ordering::Relaxed),
    );
    out
}

/// The browser's evidence and what the API saw of its request.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub evidence: serde_json::Value,
    pub headers: serde_json::Value,
    pub ja4: Option<String>,
    pub origin: String,
    pub created_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

pub struct Identifications {
    link: crate::cache::Link,
}

pub fn key(id: &str) -> String {
    format!(
        "openfingerprint:identification:v1:{}",
        crate::check::sha256(id)
    )
}

pub fn valid_id(id: &str) -> bool {
    id.len() == 22
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

pub(crate) fn new_id() -> Option<String> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut bytes = [0u8; 16];
    SystemRandom::new().fill(&mut bytes).ok()?;
    let n = u128::from_be_bytes(bytes);
    Some(
        (0..22)
            .map(|i| {
                let sextet = if i < 21 { n >> (122 - 6 * i) } else { n << 4 };
                ALPHABET[(sextet & 63) as usize] as char
            })
            .collect(),
    )
}

impl Identifications {
    pub fn new(client: redis::Client) -> Self {
        Self {
            link: crate::cache::Link::new(client),
        }
    }

    pub(crate) async fn store(&self, id: &str, record: &Record) -> Result<(), ()> {
        let value = serde_json::to_string(record).map_err(|_| ())?;
        let mut command = redis::cmd("SET");
        command
            .arg(key(id))
            .arg(value)
            .arg("NX")
            .arg("EX")
            .arg(TTL_SECONDS);
        let command = &command;
        let stored: Option<String> = self
            .link
            .run(REDIS_TIMEOUT, |mut c| async move {
                command.query_async(&mut c).await
            })
            .await?;
        stored.map(|_| ()).ok_or(())
    }

    /// `Ok(None)` when no such identification exists or it expired.
    pub async fn get(&self, id: &str) -> Result<Option<Record>, ()> {
        let key = key(id);
        let key = &key;
        let found: Result<Option<String>, ()> = self
            .link
            .run(REDIS_TIMEOUT, |mut c| async move {
                redis::cmd("GET").arg(key).query_async(&mut c).await
            })
            .await;
        let result = match found {
            Ok(Some(value)) => serde_json::from_str(&value).map(Some).map_err(|_| ()),
            Ok(None) => Ok(None),
            Err(()) => Err(()),
        };
        count(
            &LOOKUP_COUNTS,
            &LOOKUPS,
            match &result {
                Ok(Some(_)) => "found",
                Ok(None) => "unknown",
                Err(()) => "error",
            },
        );
        result
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Origins {
    Any,
    List(Vec<String>),
}
impl Origins {
    fn parse(value: &str) -> Option<Self> {
        if value.trim() == "*" {
            return Some(Self::Any);
        }
        let list: Vec<String> = value
            .split(',')
            .map(|o| o.trim().trim_end_matches('/').to_ascii_lowercase())
            .filter(|o| !o.is_empty())
            .collect();
        let valid = |o: &String| {
            url::Url::parse(o).is_ok_and(|u| {
                matches!(u.scheme(), "https" | "http")
                    && u.host_str().is_some()
                    && u.path() == "/"
                    && u.query().is_none()
                    && u.origin().ascii_serialization() == *o
            })
        };
        (!list.is_empty() && list.iter().all(valid)).then_some(Self::List(list))
    }
    fn allows(&self, origin: &str) -> bool {
        match self {
            Self::Any => true,
            Self::List(list) => list.iter().any(|o| o.eq_ignore_ascii_case(origin)),
        }
    }
}

pub struct Config {
    addr: String,
    certs: PathBuf,
    origins: Origins,
    proxy_protocol: bool,
    per_minute: u32,
}

pub fn config_from_env() -> Result<Config, &'static str> {
    let addr = std::env::var("OPENFINGERPRINT_IDENTIFY_ADDR")
        .map_err(|_| "OPENFINGERPRINT_IDENTIFY_ADDR is required, for example 0.0.0.0:8443")?;
    let certs = std::env::var("OPENFINGERPRINT_IDENTIFY_CERTS").map_err(
        |_| "OPENFINGERPRINT_IDENTIFY_CERTS is required: a directory with tls.crt and tls.key",
    )?;
    let origins = std::env::var("OPENFINGERPRINT_IDENTIFY_ORIGINS")
        .ok()
        .and_then(|o| Origins::parse(&o))
        .ok_or("OPENFINGERPRINT_IDENTIFY_ORIGINS must be * or a comma-separated list of origins such as https://app.example.com")?;
    let proxy_protocol = match std::env::var("OPENFINGERPRINT_IDENTIFY_PROXY_PROTOCOL").as_deref() {
        Err(_) | Ok("false") => false,
        Ok("true") => true,
        Ok(_) => return Err("OPENFINGERPRINT_IDENTIFY_PROXY_PROTOCOL must be true or false"),
    };
    let per_minute = match std::env::var("OPENFINGERPRINT_IDENTIFY_LIMIT_PER_MINUTE") {
        Err(_) => DEFAULT_PER_MINUTE,
        Ok(n) => n
            .parse()
            .ok()
            .filter(|n| (1..=1_000_000).contains(n))
            .ok_or("OPENFINGERPRINT_IDENTIFY_LIMIT_PER_MINUTE must be 1-1000000")?,
    };
    Ok(Config {
        addr,
        certs: certs.into(),
        origins,
        proxy_protocol,
        per_minute,
    })
}

#[derive(Default)]
struct Loaded {
    by_name: HashMap<String, Arc<CertifiedKey>>,
    default: Option<Arc<CertifiedKey>>,
}

/// Certificates from a directory: `tls.crt` and `tls.key` at its root serve any name, and
/// each subdirectory named after a hostname serves that name (the layout of mounted
/// Kubernetes TLS Secrets).
#[derive(Debug)]
struct Certificates {
    dir: PathBuf,
    loaded: RwLock<Arc<Loaded>>,
}
impl std::fmt::Debug for Loaded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Loaded")
            .field("names", &self.by_name.keys())
            .finish()
    }
}

fn certified_key(dir: &Path) -> Result<Option<Arc<CertifiedKey>>, ()> {
    let (crt, key) = (dir.join("tls.crt"), dir.join("tls.key"));
    if !crt.exists() && !key.exists() {
        return Ok(None);
    }
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(&std::fs::read(crt).map_err(|_| ())?)
            .collect::<Result<_, _>>()
            .map_err(|_| ())?;
    let key =
        PrivateKeyDer::from_pem_slice(&std::fs::read(key).map_err(|_| ())?).map_err(|_| ())?;
    if chain.is_empty() {
        return Err(());
    }
    let signer = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|_| ())?;
    let certified = CertifiedKey::new(chain, signer);
    if let Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::KeyMismatch)) =
        certified.keys_match()
    {
        return Err(());
    }
    Ok(Some(Arc::new(certified)))
}

fn load(dir: &Path) -> Result<Loaded, ()> {
    let mut loaded = Loaded {
        default: certified_key(dir)?,
        ..Loaded::default()
    };
    for entry in std::fs::read_dir(dir).map_err(|_| ())? {
        let entry = entry.map_err(|_| ())?;
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        // Kubernetes mounts Secrets through `..data` symlinks; only hostnames are certificates.
        if name.starts_with('.') || !entry.path().is_dir() || !crate::check::domain(&name) {
            continue;
        }
        if let Some(key) = certified_key(&entry.path())? {
            loaded.by_name.insert(name, key);
        }
    }
    if loaded.default.is_none() && loaded.by_name.len() == 1 {
        loaded.default = loaded.by_name.values().next().cloned();
    }
    if loaded.default.is_none() && loaded.by_name.is_empty() {
        return Err(());
    }
    CERTIFICATES.store(
        (loaded.by_name.len() + usize::from(loaded.default.is_some())) as u64,
        Ordering::Relaxed,
    );
    Ok(loaded)
}

impl Certificates {
    fn reload(&self) {
        match load(&self.dir) {
            Ok(loaded) => *self.loaded.write().unwrap() = Arc::new(loaded),
            Err(()) => {
                CERT_RELOAD_FAILURES.fetch_add(1, Ordering::Relaxed);
                sentry::capture_message(
                    "Identify certificate reload failed; keeping the previous certificates",
                    sentry::Level::Warning,
                );
            }
        }
    }
}
impl ResolvesServerCert for Certificates {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let loaded = self.loaded.read().unwrap().clone();
        hello
            .server_name()
            .and_then(|name| loaded.by_name.get(&name.to_ascii_lowercase()))
            .or(loaded.default.as_ref())
            .cloned()
    }
}

/// A stream that first replays bytes already read from it.
pub struct Rewind<S> {
    prefix: Vec<u8>,
    position: usize,
    inner: S,
}
impl<S: AsyncRead + Unpin> AsyncRead for Rewind<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.position < self.prefix.len() {
            let n = buf.remaining().min(self.prefix.len() - self.position);
            let start = self.position;
            buf.put_slice(&self.prefix[start..start + n]);
            self.position += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Rewind<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A PROXY protocol v1 or v2 header at the start of `buf`: the client address and the header
/// length, `Ok(None)` when more bytes are needed, `Err` when it is not one.
fn proxy_header(buf: &[u8]) -> Result<Option<(Option<IpAddr>, usize)>, ()> {
    const V2: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
    if buf.starts_with(V2) {
        if buf.len() < 16 {
            return Ok(None);
        }
        let length = 16 + usize::from(u16::from_be_bytes([buf[14], buf[15]]));
        if buf.len() < length {
            return Ok(None);
        }
        if buf[12] >> 4 != 2 {
            return Err(());
        }
        let address = &buf[16..length];
        let ip = match (buf[12] & 0x0f, buf[13] >> 4) {
            (0, _) => None,
            (1, 1) if address.len() >= 12 => Some(IpAddr::from(
                <[u8; 4]>::try_from(&address[..4]).map_err(|_| ())?,
            )),
            (1, 2) if address.len() >= 36 => Some(IpAddr::from(
                <[u8; 16]>::try_from(&address[..16]).map_err(|_| ())?,
            )),
            (1, _) => None,
            _ => return Err(()),
        };
        return Ok(Some((ip, length)));
    }
    if V2.starts_with(buf) || b"PROXY ".starts_with(buf) {
        return Ok(None);
    }
    if !buf.starts_with(b"PROXY ") {
        return Err(());
    }
    let Some(end) = buf.windows(2).take(107).position(|w| w == b"\r\n") else {
        return if buf.len() >= 107 { Err(()) } else { Ok(None) };
    };
    let line = std::str::from_utf8(&buf[..end]).map_err(|_| ())?;
    let mut parts = line.split(' ');
    let ip = match (parts.nth(1), parts.next()) {
        (Some("UNKNOWN"), _) => None,
        (Some("TCP4" | "TCP6"), Some(source)) => Some(source.parse().map_err(|_| ())?),
        _ => return Err(()),
    };
    Ok(Some((ip, end + 2)))
}

#[derive(Clone, Debug)]
pub struct Peer {
    ip: IpAddr,
    ja4: Option<String>,
}
impl axum::extract::connect_info::Connected<IncomingStream<'_, Incoming>> for Peer {
    fn connect_info(stream: IncomingStream<'_, Incoming>) -> Self {
        stream.remote_addr().clone()
    }
}

type Tls = tokio_rustls::server::TlsStream<Rewind<tokio::net::TcpStream>>;

/// Hands finished TLS handshakes to the HTTP server; handshakes run in their own tasks so a
/// slow client cannot hold up the others.
pub struct Incoming {
    receiver: tokio::sync::mpsc::Receiver<(Tls, Peer)>,
    local: SocketAddr,
}
impl axum::serve::Listener for Incoming {
    type Io = Tls;
    type Addr = Peer;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.receiver.recv().await {
            Some(connection) => connection,
            None => std::future::pending().await,
        }
    }
    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(Peer {
            ip: self.local.ip(),
            ja4: None,
        })
    }
}

async fn fill(buf: &mut Vec<u8>, tcp: &mut tokio::net::TcpStream) -> Option<()> {
    let mut chunk = [0u8; 4096];
    let n = tcp.read(&mut chunk).await.ok()?;
    (n > 0).then(|| buf.extend_from_slice(&chunk[..n]))
}

async fn handshake(
    mut tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    proxy_protocol: bool,
    acceptor: tokio_rustls::TlsAcceptor,
) -> Option<(Tls, Peer)> {
    let mut buf = Vec::with_capacity(2048);
    let mut ip = peer.ip();
    let mut start = 0;
    if proxy_protocol {
        loop {
            match proxy_header(&buf) {
                Ok(Some((source, length))) => {
                    ip = source.unwrap_or(ip);
                    start = length;
                    break;
                }
                Ok(None) => fill(&mut buf, &mut tcp).await?,
                Err(()) => return None,
            }
        }
    }
    while buf.len() < start + 5 {
        fill(&mut buf, &mut tcp).await?;
    }
    let record = 5 + usize::from(u16::from_be_bytes([buf[start + 3], buf[start + 4]]));
    if buf[start] != 0x16 || record > MAX_RECORD {
        return None;
    }
    while buf.len() < start + record {
        fill(&mut buf, &mut tcp).await?;
    }
    let ja4 = crate::tls::ja4(&buf[start..start + record]);
    let stream = Rewind {
        prefix: buf.split_off(start),
        position: 0,
        inner: tcp,
    };
    let tls = acceptor.accept(stream).await.ok()?;
    Some((
        tls,
        Peer {
            ip: match ip {
                IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
                v4 => v4,
            },
            ja4,
        },
    ))
}

/// Identifications per client network per minute, per process.
// ponytail: an in-memory fixed window per replica, so the real limit is this times the
// replica count; move it to Redis if one replica set ever needs an exact shared limit.
struct Limiter {
    per_minute: u32,
    windows: Mutex<HashMap<[u8; 8], (u64, u32)>>,
}
impl Limiter {
    fn new(per_minute: u32) -> Self {
        Self {
            per_minute,
            windows: Mutex::default(),
        }
    }
    fn allow(&self, ip: IpAddr) -> bool {
        let network = match ip {
            IpAddr::V4(v4) => {
                let mut k = [0u8; 8];
                k[..4].copy_from_slice(&v4.octets());
                k[4] = 4;
                k
            }
            IpAddr::V6(v6) => v6.octets()[..8].try_into().unwrap_or_default(),
        };
        let minute = now_ms() / 60_000;
        let mut windows = self.windows.lock().unwrap();
        if windows.len() > 100_000 {
            windows.retain(|_, (m, _)| *m == minute);
        }
        let window = windows.entry(network).or_insert((minute, 0));
        if window.0 != minute {
            *window = (minute, 0);
        }
        window.1 += 1;
        window.1 <= self.per_minute
    }
}

struct Identify {
    state: Arc<AppState>,
    origins: Origins,
    limiter: Limiter,
}

fn cors(origin: &str, mut response: Response) -> Response {
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(origin) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
    }
    headers.insert(header::VARY, HeaderValue::from_static("Origin"));
    response
}

fn refuse(status: StatusCode, error: &'static str, result: &str) -> Response {
    count(&RESULT_COUNTS, &RESULTS, result);
    (status, Json(serde_json::json!({ "error": error }))).into_response()
}

fn observed_headers(headers: &HeaderMap) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    for (name, key) in [
        (header::USER_AGENT.as_str(), "userAgent"),
        (header::ACCEPT_LANGUAGE.as_str(), "acceptLanguage"),
        ("sec-ch-ua", "secChUa"),
        ("sec-ch-ua-mobile", "secChUaMobile"),
        ("sec-ch-ua-platform", "secChUaPlatform"),
    ] {
        if let Some(value) = headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .filter(|v| v.len() <= 1024)
        {
            out.insert(key.into(), value.into());
        }
    }
    serde_json::Value::Object(out)
}

fn allowed_origin<'a>(identify: &Identify, headers: &'a HeaderMap) -> Option<&'a str> {
    headers
        .get(header::ORIGIN)
        .and_then(|o| o.to_str().ok())
        .filter(|o| identify.origins.allows(o))
}

async fn create(
    State(identify): State<Arc<Identify>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(origin) = allowed_origin(&identify, &headers) else {
        return refuse(
            StatusCode::FORBIDDEN,
            "origin_not_allowed",
            "origin_refused",
        );
    };
    if !identify.limiter.allow(peer.ip) {
        return cors(
            origin,
            refuse(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "rate_limited",
            ),
        );
    }
    let evidence: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let observed = observed_headers(&headers);
    if !crate::check::check_evidence(evidence.clone(), Some(&observed), Some(peer.ja4.as_deref()))
        .is_valid()
    {
        return cors(
            origin,
            refuse(StatusCode::BAD_REQUEST, "invalid_evidence", "invalid"),
        );
    }
    let record = Record {
        evidence,
        headers: observed,
        ja4: peer.ja4.clone(),
        origin: origin.to_ascii_lowercase(),
        created_at_ms: now_ms(),
        namespace: identify
            .state
            .visitors
            .as_ref()
            .map(|store| store.namespace().to_owned()),
    };
    let Some(id) = new_id() else {
        return cors(
            origin,
            refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "identify_unavailable",
                "error",
            ),
        );
    };
    if identify
        .state
        .identifications
        .store(&id, &record)
        .await
        .is_err()
    {
        return cors(
            origin,
            refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "identify_unavailable",
                "error",
            ),
        );
    }
    count(&RESULT_COUNTS, &RESULTS, "stored");
    let client = match peer.ja4.as_deref() {
        None => "none",
        Some(ja4) => match crate::tls::client(ja4) {
            Some(client) => CLIENTS
                .iter()
                .find(|c| serde_json::to_value(client).is_ok_and(|v| v == **c))
                .copied()
                .unwrap_or("unknown"),
            None => "unknown",
        },
    };
    count(&CLIENT_COUNTS, &CLIENTS, client);
    cors(
        origin,
        Json(serde_json::json!({ "identificationId": id })).into_response(),
    )
}

async fn preflight(State(identify): State<Arc<Identify>>, headers: HeaderMap) -> Response {
    let Some(origin) = allowed_origin(&identify, &headers) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let mut response = StatusCode::NO_CONTENT.into_response();
    let out = response.headers_mut();
    out.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("POST"),
    );
    out.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("content-type"),
    );
    out.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("600"),
    );
    cors(origin, response)
}

fn router(identify: Arc<Identify>) -> Router {
    Router::new()
        .route("/v1/identify", post(create).options(preflight))
        .layer(DefaultBodyLimit::max(crate::check::BODY_LIMIT))
        .with_state(identify)
}

/// Loads the certificates and binds the listener, so configuration errors stop startup;
/// the returned future serves identification until the process ends.
pub async fn bind(
    config: Config,
    state: Arc<AppState>,
    layers: impl FnOnce(Router) -> Router,
) -> Result<impl Future<Output = std::io::Result<()>>, Box<dyn std::error::Error>> {
    let certificates = Arc::new(Certificates {
        loaded: RwLock::new(Arc::new(load(&config.certs).map_err(
            |()| "No usable tls.crt and tls.key in OPENFINGERPRINT_IDENTIFY_CERTS",
        )?)),
        dir: config.certs,
    });
    {
        let certificates = certificates.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(CERT_RELOAD);
            tick.tick().await;
            loop {
                tick.tick().await;
                let certificates = certificates.clone();
                let _ = tokio::task::spawn_blocking(move || certificates.reload()).await;
            }
        });
    }
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_cert_resolver(certificates);
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = tokio::net::TcpListener::bind(&config.addr).await?;
    let local = listener.local_addr()?;
    println!("identify on {local}");
    let (sender, receiver) = tokio::sync::mpsc::channel(256);
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_HANDSHAKES));
    let proxy_protocol = config.proxy_protocol;
    tokio::spawn(async move {
        loop {
            let Ok((tcp, peer)) = listener.accept().await else {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            };
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                continue;
            };
            let (sender, acceptor) = (sender.clone(), acceptor.clone());
            tokio::spawn(async move {
                let _permit = permit;
                if let Ok(Some(connection)) = tokio::time::timeout(
                    HANDSHAKE_TIMEOUT,
                    handshake(tcp, peer, proxy_protocol, acceptor),
                )
                .await
                {
                    let _ = sender.send(connection).await;
                }
            });
        }
    });
    let identify = Arc::new(Identify {
        state,
        origins: config.origins,
        limiter: Limiter::new(config.per_minute),
    });
    Ok(axum::serve(
        Incoming { receiver, local },
        layers(router(identify)).into_make_service_with_connect_info::<Peer>(),
    )
    .into_future())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_are_exact_and_validated() {
        let list = Origins::parse("https://app.example.com, http://localhost:5173/").unwrap();
        assert!(list.allows("https://app.example.com"));
        assert!(list.allows("http://localhost:5173"));
        assert!(!list.allows("https://evil.example.com"));
        assert!(!list.allows("https://app.example.com.evil.test"));
        assert_eq!(Origins::parse(" * "), Some(Origins::Any));
        for bad in [
            "",
            "app.example.com",
            "https://a.test/path",
            "ftp://a.test",
            "https://a.test?x",
        ] {
            assert_eq!(Origins::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn proxy_headers_give_the_client_address() {
        let v1 = b"PROXY TCP4 203.0.113.7 10.0.0.1 51234 443\r\n\x16\x03";
        assert_eq!(
            proxy_header(v1),
            Ok(Some((Some("203.0.113.7".parse().unwrap()), v1.len() - 2)))
        );
        assert_eq!(proxy_header(b"PROXY TCP4 203.0"), Ok(None));
        assert_eq!(proxy_header(b"PRO"), Ok(None));
        assert_eq!(proxy_header(b"PROXY UNKNOWN\r\n"), Ok(Some((None, 15))));
        let mut v2 = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
        v2.extend([
            0x21, 0x11, 0, 12, 198, 51, 100, 9, 10, 0, 0, 1, 0xc8, 0x10, 1, 187,
        ]);
        assert_eq!(
            proxy_header(&v2),
            Ok(Some((Some("198.51.100.9".parse().unwrap()), 28)))
        );
        assert_eq!(proxy_header(&v2[..20]), Ok(None));
        for bad in [&b"\x16\x03\x01\x02\x00"[..], b"GET / HTTP/1.1\r\n\r\n"] {
            assert_eq!(proxy_header(bad), Err(()));
        }
    }

    #[test]
    fn identification_ids_are_random_and_well_formed() {
        let (a, b) = (new_id().unwrap(), new_id().unwrap());
        assert!(valid_id(&a) && valid_id(&b) && a != b, "{a} {b}");
        assert!(!valid_id("short") && !valid_id(&"!".repeat(22)));
    }

    #[test]
    fn the_limit_applies_per_network() {
        let limiter = Limiter::new(DEFAULT_PER_MINUTE);
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert!((0..DEFAULT_PER_MINUTE).all(|_| limiter.allow(ip)));
        assert!(!limiter.allow(ip));
        assert!(limiter.allow("203.0.113.8".parse().unwrap()));
        let v6 = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!((0..DEFAULT_PER_MINUTE).all(|_| limiter.allow(v6("2001:db8::1"))));
        assert!(!limiter.allow(v6("2001:db8::ffff")), "the same /64");
    }
}
