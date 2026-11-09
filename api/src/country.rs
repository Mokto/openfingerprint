use std::{
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use maxminddb::Reader;
use serde::Serialize;

const MAX_BYTES: u64 = 32 * 1024 * 1024;
const MAX_AGE: u64 = 62 * 86400;

#[derive(Serialize)]
pub struct Check {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<Source>,
}

#[derive(Serialize)]
struct Source {
    id: &'static str,
    license: &'static str,
    url: &'static str,
    attribution: &'static str,
    updated_at_unix: u64,
    expires_at_unix: u64,
    sha256: String,
}

struct Data {
    reader: Reader<Vec<u8>>,
    sha256: String,
}

pub struct CountryStore {
    path: Option<PathBuf>,
    current: RwLock<Option<Arc<Data>>>,
    seen: Mutex<Option<Vec<u8>>>,
    failures: AtomicU64,
}

impl CountryStore {
    pub fn new(path: Option<PathBuf>) -> Self {
        let store = Self {
            path,
            current: RwLock::new(None),
            seen: Mutex::new(None),
            failures: AtomicU64::new(0),
        };
        store.reload();
        store
    }

    pub fn from_env() -> Self {
        Self::new(std::env::var_os("OPENFINGERPRINT_COUNTRY_DATA").map(PathBuf::from))
    }

    pub fn reloads(&self) -> bool {
        self.path.is_some()
    }

    pub fn reload(&self) {
        let Some(path) = &self.path else { return };
        let bytes = read(path);
        let digest = bytes.as_ref().map(|b| {
            ring::digest::digest(&ring::digest::SHA256, b)
                .as_ref()
                .to_vec()
        });
        {
            let mut seen = self.seen.lock().unwrap();
            if *seen == digest {
                return;
            }
            *seen = digest.clone();
        }
        let data = bytes.and_then(parse);
        if let Some(reader) = data {
            let mut current = self.current.write().unwrap();
            if current
                .as_ref()
                .is_none_or(|d| reader.metadata().build_epoch >= d.reader.metadata().build_epoch)
            {
                *current = Some(Arc::new(Data {
                    reader,
                    sha256: digest.unwrap().iter().map(|b| format!("{b:02x}")).collect(),
                }));
                return;
            }
        }
        self.failures.fetch_add(1, Ordering::Relaxed);
        sentry::capture_message("country snapshot reload failed", sentry::Level::Error);
    }

    pub fn check(&self, value: serde_json::Value) -> Check {
        let unknown = |status, reason, source| Check {
            status,
            reason: Some(reason),
            country_code: None,
            source,
        };
        let Some(ip) = value.as_str().and_then(|s| s.parse::<IpAddr>().ok()) else {
            return unknown("invalid_input", "invalid_ip", None);
        };
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            _ => ip,
        };
        let Some(data) = self.current.read().unwrap().clone() else {
            return unknown(
                "unknown",
                if self.path.is_some() {
                    "unavailable"
                } else {
                    "not_configured"
                },
                None,
            );
        };
        let built = data.reader.metadata().build_epoch;
        let source = Some(Source {
            id: "dbip_country_lite",
            license: "CC-BY-4.0",
            url: "https://db-ip.com/db/download/ip-to-country-lite",
            attribution: "IP Geolocation by DB-IP (https://db-ip.com/)",
            updated_at_unix: built,
            expires_at_unix: built.saturating_add(MAX_AGE),
            sha256: data.sha256.clone(),
        });
        if !public(ip) {
            return unknown("unknown", "non_public_ip", source);
        }
        if built > now().saturating_add(300) || now() >= built.saturating_add(MAX_AGE) {
            return unknown("unknown", "stale_data", source);
        }
        match data
            .reader
            .lookup(ip)
            .and_then(|r| r.decode_path::<String>(&maxminddb::path!["country", "iso_code"]))
        {
            Ok(Some(code)) if country_code(&code) => Check {
                status: "ok",
                reason: None,
                country_code: Some(code),
                source,
            },
            Ok(_) => unknown("unknown", "not_found", source),
            Err(_) => unknown("unknown", "invalid_data", source),
        }
    }

    pub fn metrics(&self) -> String {
        let current = self.current.read().unwrap();
        let built = current
            .as_ref()
            .map_or(0, |d| d.reader.metadata().build_epoch);
        let expiry = if built == 0 {
            0
        } else {
            built.saturating_add(MAX_AGE)
        };
        format!(
            "# HELP openfingerprint_country_data_loaded Whether a country database is loaded.\n# TYPE openfingerprint_country_data_loaded gauge\nopenfingerprint_country_data_loaded {}\n# HELP openfingerprint_country_data_expiry_timestamp_seconds Country database expiry.\n# TYPE openfingerprint_country_data_expiry_timestamp_seconds gauge\nopenfingerprint_country_data_expiry_timestamp_seconds {}\n# HELP openfingerprint_country_data_reload_failures_total Rejected changed country databases.\n# TYPE openfingerprint_country_data_reload_failures_total counter\nopenfingerprint_country_data_reload_failures_total {}\n",
            u8::from(current.is_some()),
            expiry,
            self.failures.load(Ordering::Relaxed)
        )
    }
}

fn read(path: &Path) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= MAX_BYTES).then_some(bytes)
}

fn parse(bytes: Vec<u8>) -> Option<Reader<Vec<u8>>> {
    let reader = Reader::from_source(bytes).ok()?;
    let metadata = reader.metadata();
    if metadata.database_type != "DBIP-Country-Lite"
        || metadata.ip_version != 6
        || metadata.build_epoch == 0
        || metadata.build_epoch > now().saturating_add(300)
    {
        return None;
    }
    reader.verify().ok()?;
    Some(reader)
}

pub fn validate(candidate: &Path, previous: Option<&Path>) -> Result<(), &'static str> {
    let reader = read(candidate)
        .and_then(parse)
        .ok_or("Invalid country database")?;
    let built = reader.metadata().build_epoch;
    if now() >= built.saturating_add(MAX_AGE) {
        return Err("Expired country database");
    }
    if let Some(previous) = previous.and_then(read).and_then(parse)
        && built < previous.metadata().build_epoch
    {
        return Err("Country database rollback rejected");
    }
    Ok(())
}

fn country_code(code: &str) -> bool {
    "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS XK YE YT ZA ZM ZW".split_ascii_whitespace().any(|c| c == code)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ponytail: only ordinary public IPv4 and 2000::/3; special-purpose exceptions stay
// unknown. Add explicit ranges when those networks need geolocation support.
fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let n = u32::from(ip);
            ![
                (0x00000000, 8),
                (0x0a000000, 8),
                (0x64400000, 10),
                (0x7f000000, 8),
                (0xa9fe0000, 16),
                (0xac100000, 12),
                (0xc0000000, 24),
                (0xc0000200, 24),
                (0xc0586300, 24),
                (0xc0a80000, 16),
                (0xc6120000, 15),
                (0xc6336400, 24),
                (0xcb007100, 24),
                (0xe0000000, 3),
            ]
            .iter()
            .any(|&(base, prefix)| n >> (32 - prefix) == base >> (32 - prefix))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            s[0] & 0xe000 == 0x2000
                && !(s[0] == 0x2001 && (s[1] < 0x200 || s[1] == 0xdb8))
                && s[0] != 0x2002
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn special_use_addresses_are_never_geolocated() {
        for ip in [
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.0.0.9",
            "192.0.2.1",
            "192.168.0.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "2001:20::1",
            "2002::1",
            "3fff::1",
        ] {
            assert!(!public(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.0",
            "172.32.0.1",
            "2001:4860::8888",
            "2606:4700::1111",
        ] {
            assert!(public(ip.parse().unwrap()), "{ip}");
        }
    }
}
