use std::{
    collections::{BTreeSet, HashMap},
    io::Read,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{extract::ConnectInfo, http::HeaderMap};
use ipnetwork::IpNetwork as IpNet;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const MANIFEST_LIMIT: u64 = 16 * 1024 * 1024;
const ASN_LIMIT: u64 = 64 * 1024 * 1024;
const DAY: u64 = 86400;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    id: String,
    license: String,
    license_url: String,
    attribution: String,
    #[serde(default, skip_serializing)]
    license_text: String,
    url: String,
    revision: String,
    updated_at_unix: u64,
    fetched_at_unix: u64,
    expires_at_unix: u64,
}
impl Metadata {
    fn valid(&self, id: &str, license: &str, lifetime: u64) -> bool {
        self.id == id
            && self.license == license
            && self.url.len() <= 512
            && self.url.starts_with("https://")
            && self.license_url.starts_with("https://")
            && self.license_url.len() <= 256
            && !self.attribution.is_empty()
            && self.attribution.len() <= 256
            && !self.attribution.chars().any(char::is_control)
            && self.license_text.len() <= 32768
            && matches!(self.revision.len(), 40 | 64)
            && self.revision.bytes().all(|b| b.is_ascii_hexdigit())
            && self.updated_at_unix > 0
            && self.fetched_at_unix >= self.updated_at_unix
            && self.expires_at_unix > self.updated_at_unix
            && self.expires_at_unix <= self.updated_at_unix.saturating_add(lifetime)
    }
    fn status(&self, now: u64) -> &'static str {
        if self.updated_at_unix > now || self.fetched_at_unix > now {
            "clock_skew"
        } else if now >= self.expires_at_unix {
            "stale_data"
        } else {
            "fresh"
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source<T> {
    metadata: Metadata,
    entries: T,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum TorEntry {
    Observed(TorObservation),
    Legacy(IpAddr),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TorObservation {
    ip: IpAddr,
    observed_at_unix: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostingRange {
    network: IpNet,
    provider: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u8,
    tor: Option<Source<Vec<TorEntry>>>,
    hosting: Option<Source<Vec<HostingRange>>>,
    asn: Option<Metadata>,
}

pub struct Data {
    metadata: [Option<Metadata>; 3],
    tor: HashMap<IpAddr, Option<u64>>,
    hosting: HashMap<IpNet, BTreeSet<String>>,
    asn: Option<maxminddb::Reader<Vec<u8>>>,
    reason: &'static str,
}
impl Data {
    fn unavailable(reason: &'static str) -> Self {
        Self {
            metadata: [None, None, None],
            tor: HashMap::new(),
            hosting: HashMap::new(),
            asn: None,
            reason,
        }
    }
    fn load(path: &Path, bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() as u64 > MANIFEST_LIMIT {
            return Err(());
        }
        let snapshot: Snapshot = serde_json::from_slice(bytes).map_err(|_| ())?;
        if snapshot.version != 1
            || (snapshot.tor.is_none() && snapshot.hosting.is_none() && snapshot.asn.is_none())
        {
            return Err(());
        }
        let mut data = Self::unavailable("not_configured");
        if let Some(source) = snapshot.tor {
            if !source.metadata.valid("tor_exit", "CC0-1.0", 3 * 3600)
                || source.entries.is_empty()
                || source.entries.len() > 100000
            {
                return Err(());
            }
            for entry in source.entries {
                let (ip, observed) = match entry {
                    TorEntry::Observed(entry) => {
                        if entry.observed_at_unix == 0
                            || entry.observed_at_unix > source.metadata.fetched_at_unix
                            || entry.observed_at_unix.saturating_add(DAY)
                                <= source.metadata.fetched_at_unix
                        {
                            return Err(());
                        }
                        (entry.ip, Some(entry.observed_at_unix))
                    }
                    TorEntry::Legacy(ip) => (ip, None),
                };
                data.tor
                    .entry(ip.to_canonical())
                    .and_modify(|previous| *previous = (*previous).max(observed))
                    .or_insert(observed);
            }
            data.metadata[0] = Some(source.metadata);
        }
        if let Some(source) = snapshot.hosting {
            if !source.metadata.valid("cloud_ranges", "MIT", 7 * DAY)
                || source.metadata.license_text.is_empty()
                || source.entries.is_empty()
                || source.entries.len() > 200000
            {
                return Err(());
            }
            for entry in source.entries {
                if entry.network.ip() != entry.network.network()
                    || entry.network.prefix() == 0
                    || entry.provider.is_empty()
                    || entry.provider.len() > 64
                    || !entry
                        .provider
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b" _-".contains(&b))
                {
                    return Err(());
                }
                data.hosting
                    .entry(entry.network)
                    .or_default()
                    .insert(entry.provider);
            }
            data.metadata[1] = Some(source.metadata);
        }
        if let Some(mut metadata) = snapshot.asn {
            if !metadata.valid("dbip_asn", "CC-BY-4.0", 45 * DAY) || metadata.revision.len() != 64 {
                return Err(());
            }
            let file = path
                .parent()
                .ok_or(())?
                .join(format!("asn-{}.mmdb", metadata.revision));
            let bytes = read(&file, ASN_LIMIT).ok_or(())?;
            if sha256(&bytes) != metadata.revision {
                return Err(());
            }
            let reader = maxminddb::Reader::from_source(bytes).map_err(|_| ())?;
            reader.verify().map_err(|_| ())?;
            if !matches!(
                reader.metadata().database_type.as_str(),
                "DBIP-ASN-Lite" | "DBIP-ASN-Lite (compat=GeoLite2-ASN)"
            ) || reader.metadata().ip_version != 6
                || reader.metadata().build_epoch == 0
                || reader.metadata().build_epoch > metadata.fetched_at_unix
            {
                return Err(());
            }
            let mut records = 0;
            for record in reader.networks(Default::default()).map_err(|_| ())? {
                let asn = record
                    .map_err(|_| ())?
                    .decode::<Asn>()
                    .map_err(|_| ())?
                    .ok_or(())?;
                records += 1;
                if records > 2_000_000
                    || asn.autonomous_system_organization.len() > 512
                    || asn
                        .autonomous_system_organization
                        .chars()
                        .any(char::is_control)
                {
                    return Err(());
                }
            }
            if records == 0 {
                return Err(());
            }
            metadata.updated_at_unix = metadata.updated_at_unix.min(reader.metadata().build_epoch);
            metadata.expires_at_unix = metadata
                .expires_at_unix
                .min(metadata.updated_at_unix.saturating_add(45 * DAY));
            data.metadata[2] = Some(metadata);
            data.asn = Some(reader);
        }
        Ok(data)
    }
    pub fn check(&self, value: Value, source: &'static str) -> Value {
        match value.as_str().and_then(|s| s.parse::<IpAddr>().ok()) {
            Some(ip) => self.check_at(ip.to_canonical(), source, now()),
            None => json!({"status":"invalid_input", "reason":"invalid_ip", "source":source}),
        }
    }
    fn fact(&self, index: usize, value: Value, now: u64, missing: &'static str) -> Value {
        let (value, status) = match &self.metadata[index] {
            Some(meta) if meta.status(now) == "fresh" => {
                let status = if value.is_null() { missing } else { "matched" };
                (value, status)
            }
            Some(meta) => (Value::Null, meta.status(now)),
            None => (Value::Null, self.reason),
        };
        json!({"value": value, "status": status, "source": self.metadata[index]})
    }
    fn check_at(&self, ip: IpAddr, source: &'static str, now: u64) -> Value {
        if !public(ip) {
            return json!({"status":"unknown", "reason":"non_global_ip", "source":source});
        }
        let mut tor = self.fact(
            0,
            if self.tor.contains_key(&ip) {
                json!(true)
            } else {
                Value::Null
            },
            now,
            "not_listed",
        );
        if let (Some(Some(observed)), Some(meta)) = (self.tor.get(&ip), &self.metadata[0]) {
            tor["expires_at_unix"] = json!(meta.expires_at_unix.min(observed.saturating_add(DAY)));
        }
        let mut providers = BTreeSet::new();
        for prefix in 1..=if ip.is_ipv4() { 32 } else { 128 } {
            let network = IpNet::new(ip, prefix).unwrap().network();
            if let Some(names) = self.hosting.get(&IpNet::new(network, prefix).unwrap()) {
                providers.extend(names.iter());
            }
        }
        let hosting = self.fact(
            1,
            if providers.is_empty() {
                Value::Null
            } else {
                json!({"providers":providers, "scope":"published_cloud_range"})
            },
            now,
            "not_listed",
        );
        let decoded = self
            .asn
            .as_ref()
            .map(|reader| reader.lookup(ip).and_then(|result| result.decode::<Asn>()));
        let missing = if decoded.as_ref().is_some_and(|r| r.is_err()) {
            "lookup_failed"
        } else {
            "not_in_database"
        };
        let asn = decoded.and_then(Result::ok).flatten().filter(|a| {
            a.autonomous_system_number > 0
                && !a.autonomous_system_organization.is_empty()
                && a.autonomous_system_organization.len() <= 512
                && !a
                    .autonomous_system_organization
                    .chars()
                    .any(char::is_control)
        });
        let asn = self.fact(2, asn.map_or(Value::Null, |a| json!({"number":a.autonomous_system_number,"organization":a.autonomous_system_organization})), now, missing);
        let mut check = json!({"source":source,"tor":tor,"hosting":hosting,"asn":asn,
            "vpn":{"value":null,"status":"not_configured"},"proxy":{"value":null,"status":"not_configured"}});
        expire_at(&mut check, now);
        check
    }
}
#[derive(Deserialize)]
struct Asn {
    autonomous_system_number: u32,
    autonomous_system_organization: String,
}

pub struct Store {
    path: Option<PathBuf>,
    data: RwLock<Arc<Data>>,
    seen: Mutex<Option<String>>,
    failures: AtomicU64,
    proxies: Vec<IpNet>,
}
impl Store {
    pub fn empty() -> Self {
        Self {
            path: None,
            data: RwLock::new(Arc::new(Data::unavailable("not_configured"))),
            seen: Mutex::new(None),
            failures: AtomicU64::new(0),
            proxies: Vec::new(),
        }
    }
    pub fn from_env() -> Result<Self, &'static str> {
        let mut store = Self::empty();
        if let Ok(value) = std::env::var("OPENFINGERPRINT_TRUSTED_PROXIES") {
            if value.len() > 8192 {
                return Err("Invalid OPENFINGERPRINT_TRUSTED_PROXIES");
            }
            store.proxies = serde_json::from_str::<Vec<IpNet>>(&value)
                .map_err(|_| "Invalid OPENFINGERPRINT_TRUSTED_PROXIES")?;
            if store.proxies.len() > 128
                || store
                    .proxies
                    .iter()
                    .any(|p| p.prefix() == 0 || p.ip() != p.network())
            {
                return Err("Invalid OPENFINGERPRINT_TRUSTED_PROXIES");
            }
        }
        if let Ok(path) = std::env::var("OPENFINGERPRINT_NETWORK_DATA") {
            store.path = Some(PathBuf::from(path));
            store.reload();
        }
        Ok(store)
    }
    pub fn reloads(&self) -> bool {
        self.path.is_some()
    }
    pub fn current(&self) -> Arc<Data> {
        self.data.read().unwrap().clone()
    }
    pub fn reload(&self) {
        let Some(path) = &self.path else { return };
        let bytes = read(path, MANIFEST_LIMIT);
        let digest = bytes.as_deref().map(sha256);
        let mut seen = self.seen.lock().unwrap();
        if digest.is_some() && *seen == digest {
            return;
        }
        match bytes
            .as_deref()
            .ok_or(())
            .and_then(|bytes| Data::load(path, bytes))
        {
            Ok(data) => {
                *self.data.write().unwrap() = Arc::new(data);
                seen.clone_from(&digest);
            }
            Err(()) => {
                self.failures.fetch_add(1, Ordering::Relaxed);
                let mut data = self.data.write().unwrap();
                if data.metadata.iter().all(Option::is_none) {
                    *data = Arc::new(Data::unavailable("invalid_data"));
                }
            }
        }
    }
    pub fn client_address(
        &self,
        headers: &HeaderMap,
        peer: Option<ConnectInfo<SocketAddr>>,
    ) -> Option<IpAddr> {
        self.client_ip(headers, peer.map(|p| p.0.ip()))
            .ok()
            .map(|(ip, _)| ip)
            .filter(|ip| public(*ip))
    }
    pub fn request_check(
        &self,
        headers: &HeaderMap,
        peer: Option<ConnectInfo<SocketAddr>>,
    ) -> Value {
        match self.client_ip(headers, peer.map(|p| p.0.ip())) {
            Ok((ip, source)) => self.current().check_at(ip, source, now()),
            Err(reason) => json!({"status":"unknown", "reason":reason, "source":"request"}),
        }
    }
    fn client_ip(
        &self,
        headers: &HeaderMap,
        peer: Option<IpAddr>,
    ) -> Result<(IpAddr, &'static str), &'static str> {
        let peer = peer.ok_or("peer_unavailable")?.to_canonical();
        let trusted = |ip: IpAddr| self.proxies.iter().any(|p| p.contains(ip));
        if !trusted(peer) {
            return Ok((peer, "peer"));
        }
        let values = headers.get_all("x-forwarded-for");
        if values.iter().count() != 1 {
            return Err("forwarded_ip_unavailable");
        }
        let value = values
            .iter()
            .next()
            .and_then(|h| h.to_str().ok())
            .ok_or("invalid_forwarded_ip")?;
        let mut client = peer;
        for (i, hop) in value.rsplit(',').enumerate() {
            if !trusted(client) {
                break;
            }
            if i >= 16 || hop.trim().len() > 64 {
                return Err("invalid_forwarded_ip");
            }
            client = hop
                .trim()
                .parse::<IpAddr>()
                .map_err(|_| "invalid_forwarded_ip")?
                .to_canonical();
        }
        if trusted(client) {
            return Err("forwarded_ip_unavailable");
        }
        Ok((client, "trusted_proxy"))
    }
    pub fn metrics(&self) -> String {
        let data = self.current();
        let mut out = format!(
            "# TYPE openfingerprint_network_data_reload_failures_total counter\nopenfingerprint_network_data_reload_failures_total {}\n",
            self.failures.load(Ordering::Relaxed)
        );
        out += "# TYPE openfingerprint_network_data_source_expiry_timestamp_seconds gauge\n# TYPE openfingerprint_network_data_source_fresh gauge\n";
        for (i, id) in ["tor_exit", "cloud_ranges", "dbip_asn"].iter().enumerate() {
            let meta = data.metadata[i].as_ref();
            out += &format!(
                "openfingerprint_network_data_source_expiry_timestamp_seconds{{source=\"{id}\"}} {}\nopenfingerprint_network_data_source_fresh{{source=\"{id}\"}} {}\n",
                meta.map_or(0, |m| m.expires_at_unix),
                u8::from(meta.is_some_and(|m| m.status(now()) == "fresh"))
            );
        }
        out
    }
}

pub fn validate(path: &Path) -> Result<(), &'static str> {
    let bytes = read(path, MANIFEST_LIMIT).ok_or("Invalid network snapshot")?;
    Data::load(path, &bytes)
        .map(|_| ())
        .map_err(|_| "Invalid network snapshot")
}
pub fn expire_event(check: &mut Value) {
    expire_at(check, now());
}
fn expire_at(check: &mut Value, now: u64) {
    if check.get("tor").is_none() {
        return;
    }
    for name in ["tor", "hosting", "asn"] {
        if let Ok(meta) = serde_json::from_value::<Metadata>(check[name]["source"].clone()) {
            let status = meta.status(now);
            if status != "fresh" {
                check[name]["value"] = Value::Null;
                check[name]["status"] = json!(status);
            }
        }
    }
    if check["tor"]["value"] == true {
        let status = match check["tor"]["expires_at_unix"].as_u64() {
            Some(expiry) if now >= expiry => "stale_data",
            Some(_) => "matched",
            None => "observation_time_unavailable",
        };
        if status != "matched" {
            check["tor"]["value"] = Value::Null;
            check["tor"]["status"] = json!(status);
        }
    }
    check["status"] = json!(if ["tor", "hosting", "asn"]
        .iter()
        .any(|name| !check[name]["value"].is_null())
    {
        "ok"
    } else {
        "unknown"
    });
}
// ponytail: conservative special-use exclusions; use IANA's live registries if exact global exceptions become necessary.
fn public(ip: IpAddr) -> bool {
    let ranges: &[&str] = match ip {
        IpAddr::V4(_) => &[
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.168.0.0/16",
            "192.88.99.0/24",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/4",
            "240.0.0.0/4",
        ],
        IpAddr::V6(_) => {
            if !"2000::/3".parse::<IpNet>().unwrap().contains(ip) {
                return false;
            }
            &["2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"]
        }
    };
    !ranges
        .iter()
        .any(|r| r.parse::<IpNet>().unwrap().contains(ip))
}
fn read(path: &Path, limit: u64) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= limit).then_some(bytes)
}
fn sha256(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot() -> Value {
        let meta = |id, license, expiry| json!({"id":id,"license":license,"license_url":"https://example.test/license","license_text":"test license","attribution":"fixture","url":"https://example.test/source","revision":"a".repeat(64),"updated_at_unix":1000,"fetched_at_unix":1000,"expires_at_unix":expiry});
        json!({"version":1,
            "tor":{"metadata":meta("tor_exit","CC0-1.0",2000),"entries":[{"ip":"8.8.8.8","observed_at_unix":1000},{"ip":"2606:4700:4700::1111","observed_at_unix":1000}]},
            "hosting":{"metadata":meta("cloud_ranges","MIT",3000),"entries":[{"network":"8.8.8.0/24","provider":"Example Cloud"},{"network":"2606:4700::/32","provider":"IPv6 Cloud"}]}
        })
    }
    fn fixture() -> Data {
        Data::load(
            Path::new("/tmp/network.json"),
            &serde_json::to_vec(&snapshot()).unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn fresh_evidence_and_missingness_are_independent() {
        let d = fixture();
        let c = |ip: &str, time| d.check_at(ip.parse().unwrap(), "backend_supplied", time);
        assert_eq!(c("8.8.8.8", 1500)["tor"]["value"], true);
        assert_eq!(
            c("8.8.8.8", 1500)["hosting"]["value"]["providers"],
            json!(["Example Cloud"])
        );
        assert_eq!(c("8.8.8.9", 1500)["tor"]["status"], "not_listed");
        assert!(c("9.9.9.9", 1500)["hosting"]["value"].is_null());
        assert_eq!(c("8.8.8.8", 2000)["tor"]["status"], "stale_data");
        assert!(!c("8.8.8.8", 2000)["hosting"]["value"].is_null());
        assert_eq!(c("8.8.8.8", 999)["tor"]["status"], "clock_skew");
        assert_eq!(c("2606:4700:4700::1111", 1500)["tor"]["value"], true);
        assert_eq!(
            c("2606:4700:4700::1111", 1500)["hosting"]["value"]["providers"],
            json!(["IPv6 Cloud"])
        );
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "192.0.2.1",
            "224.0.0.1",
            "192.88.99.1",
            "::1",
            "fc00::1",
            "2001:db8::1",
            "3fff::1",
        ] {
            assert_eq!(c(ip, 1500)["reason"], "non_global_ip", "{ip}");
        }
    }
    #[test]
    fn tor_observations_expire_individually_and_keep_the_latest_canonical_address() {
        let mut input = snapshot();
        for name in ["tor", "hosting"] {
            input[name]["metadata"]["updated_at_unix"] = json!(DAY);
            input[name]["metadata"]["fetched_at_unix"] = json!(DAY + 1);
            input[name]["metadata"]["expires_at_unix"] = json!(DAY + 3600);
        }
        input["tor"]["entries"] = json!([
            {"ip":"8.8.8.8","observed_at_unix":2},
            {"ip":"::ffff:8.8.8.8","observed_at_unix":3},
            {"ip":"2606:4700:4700::1111","observed_at_unix":DAY}
        ]);
        let path = Path::new("/tmp/network.json");
        let data = Data::load(path, &serde_json::to_vec(&input).unwrap()).unwrap();
        let ip = "8.8.8.8".parse().unwrap();
        let mut event = data.check_at(ip, "trusted_proxy", DAY + 2);
        assert_eq!(event["tor"]["value"], true);
        assert_eq!(event["tor"]["expires_at_unix"], DAY + 3);
        expire_at(&mut event, DAY + 3);
        let current = data.check_at(ip, "backend_supplied", DAY + 3);
        for result in [&event, &current] {
            assert!(result["tor"]["value"].is_null());
            assert_eq!(result["tor"]["status"], "stale_data");
            assert!(!result["hosting"]["value"].is_null());
            assert_eq!(result["status"], "ok");
        }
        assert_eq!(
            data.check_at("2606:4700:4700::1111".parse().unwrap(), "peer", DAY + 3)["tor"]["value"],
            true
        );
        for invalid in [0, 1, DAY + 2] {
            input["tor"]["entries"][0]["observed_at_unix"] = json!(invalid);
            assert!(Data::load(path, &serde_json::to_vec(&input).unwrap()).is_err());
        }
    }
    #[test]
    fn timestamp_free_tor_snapshots_and_events_stay_unknown() {
        let mut input = snapshot();
        input["tor"]["entries"] = json!(["8.8.8.8"]);
        let data = Data::load(
            Path::new("/tmp/network.json"),
            &serde_json::to_vec(&input).unwrap(),
        )
        .unwrap();
        let legacy = data.check_at("8.8.8.8".parse().unwrap(), "peer", 1500);
        assert!(legacy["tor"]["value"].is_null());
        assert_eq!(legacy["tor"]["status"], "observation_time_unavailable");
        assert!(!legacy["hosting"]["value"].is_null());
        let mut event = fixture().check_at("8.8.8.8".parse().unwrap(), "trusted_proxy", 1500);
        event["tor"]
            .as_object_mut()
            .unwrap()
            .remove("expires_at_unix");
        expire_at(&mut event, 1501);
        assert_eq!(event["tor"], legacy["tor"]);
        assert!(!event["hosting"]["value"].is_null());
    }
    #[test]
    fn stored_events_lose_expired_matches_before_consumption() {
        let mut event = fixture().check_at("8.8.8.8".parse().unwrap(), "trusted_proxy", 1500);
        expire_at(&mut event, 2500);
        assert!(event["tor"]["value"].is_null());
        assert_eq!(event["tor"]["status"], "stale_data");
        assert_eq!(event["status"], "ok");
        expire_at(&mut event, 3500);
        assert_eq!(event["status"], "unknown");
    }
    #[test]
    fn invalid_replacements_keep_the_last_good_snapshot_without_extending_expiry() {
        let path = std::env::temp_dir().join(format!(
            "openfingerprint-network-{}-{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut store = Store::empty();
        store.path = Some(path.clone());
        std::fs::write(&path, serde_json::to_vec(&snapshot()).unwrap()).unwrap();
        store.reload();
        let previous = store.current();
        std::fs::write(&path, b"invalid").unwrap();
        store.reload();
        assert!(Arc::ptr_eq(&previous, &store.current()));
        assert_eq!(store.failures.load(Ordering::Relaxed), 1);
        store.reload();
        assert_eq!(store.failures.load(Ordering::Relaxed), 2);
        let mut invalid = snapshot();
        invalid["hosting"]["entries"][0]["network"] = json!("8.8.8.1/24");
        assert!(Data::load(&path, &serde_json::to_vec(&invalid).unwrap()).is_err());
        invalid = snapshot();
        invalid["tor"]["metadata"]["expires_at_unix"] = json!(999999);
        assert!(Data::load(&path, &serde_json::to_vec(&invalid).unwrap()).is_err());
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn only_trusted_peers_can_forward_and_untrusted_prefixes_are_ignored() {
        let mut store = Store::empty();
        store.proxies = vec!["10.0.0.0/8".parse().unwrap()];
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "1.1.1.1, 8.8.8.8, 10.0.0.2".parse().unwrap(),
        );
        let resolve =
            |s: &Store, h: &HeaderMap, ip: &str| s.client_ip(h, Some(ip.parse().unwrap()));
        assert_eq!(
            resolve(&store, &headers, "10.0.0.1").unwrap(),
            ("8.8.8.8".parse().unwrap(), "trusted_proxy")
        );
        assert_eq!(
            resolve(&store, &headers, "9.9.9.9").unwrap(),
            ("9.9.9.9".parse().unwrap(), "peer")
        );
        assert_eq!(
            resolve(&store, &headers, "::ffff:10.0.0.1").unwrap().0,
            "8.8.8.8".parse::<IpAddr>().unwrap()
        );
        headers.insert("x-forwarded-for", "unknown, 8.8.8.8".parse().unwrap());
        assert_eq!(
            resolve(&store, &headers, "10.0.0.1").unwrap().0,
            "8.8.8.8".parse::<IpAddr>().unwrap()
        );
        headers.insert("x-forwarded-for", "8.8.8.8:80".parse().unwrap());
        assert!(resolve(&store, &headers, "10.0.0.1").is_err());
        headers.remove("x-forwarded-for");
        assert!(resolve(&store, &headers, "10.0.0.1").is_err());
        assert!(store.client_ip(&headers, None).is_err());
    }
}
