use std::{collections::BTreeMap, io::BufReader, time::Duration};

use deadpool_postgres::{Manager, Pool};
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use tokio_postgres::{Config, Transaction, config::SslMode};
use tokio_postgres_rustls::MakeRustlsConnect;

const TIMEOUT: Duration = Duration::from_secs(2);
const MIGRATION_LOCK: i64 = 0x4f46505649534954;
const MIGRATIONS: [&str; 2] = [
    include_str!("../migrations/001_visitors.sql"),
    include_str!("../migrations/002_locale_rule.sql"),
];
const LOCALE_RULE: &str = "locale-v1";
const CANDIDATE_LIMIT: usize = 8;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Profile {
    pub schema_version: i32,
    pub fingerprint: String,
    pub components: BTreeMap<String, String>,
    pub hints: BTreeMap<String, String>,
    pub excluded: Vec<String>,
    pub identity_groups: BTreeMap<String, String>,
    pub locale_signature: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Decision {
    pub status: String,
    pub rule_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visitor_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

impl Decision {
    pub fn unknown(status: &str) -> Self {
        Self {
            status: status.into(),
            rule_version: MIGRATIONS.len() as u32,
            visitor_id: None,
            method: None,
        }
    }
}

pub struct Store {
    pool: Pool,
    namespace: String,
    default_scope: Option<String>,
    require_scope: bool,
}

impl Store {
    pub fn from_env() -> Result<Option<Self>, &'static str> {
        let default_scope = match std::env::var("OPENFINGERPRINT_VISITOR_SCOPE") {
            Ok(scope) => Some(scope),
            Err(std::env::VarError::NotPresent) => None,
            Err(_) => return Err("Invalid OPENFINGERPRINT_VISITOR_SCOPE"),
        };
        let require_scope = match std::env::var("OPENFINGERPRINT_VISITOR_REQUIRE_SCOPE").as_deref()
        {
            Ok("true") => true,
            Ok("false") | Err(std::env::VarError::NotPresent) => false,
            _ => return Err("Invalid OPENFINGERPRINT_VISITOR_REQUIRE_SCOPE"),
        };
        let url = match std::env::var("OPENFINGERPRINT_POSTGRES_URL") {
            Ok(url) => url,
            Err(std::env::VarError::NotPresent) if default_scope.is_some() || require_scope => {
                return Err("Visitor scopes require OPENFINGERPRINT_POSTGRES_URL");
            }
            Err(std::env::VarError::NotPresent) => return Ok(None),
            Err(_) => return Err("Invalid OPENFINGERPRINT_POSTGRES_URL"),
        };
        let namespace = std::env::var("OPENFINGERPRINT_VISITOR_NAMESPACE")
            .map_err(|_| "OPENFINGERPRINT_VISITOR_NAMESPACE is required with PostgreSQL")?;
        let mut config: Config = url
            .parse()
            .map_err(|_| "Invalid OPENFINGERPRINT_POSTGRES_URL")?;
        if let Ok(password) = std::env::var("OPENFINGERPRINT_POSTGRES_PASSWORD") {
            config.password(password);
        }
        if config.get_ssl_mode() == SslMode::Prefer {
            config.ssl_mode(SslMode::Require);
        }
        let mut roots = rustls::RootCertStore::empty();
        for certificate in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(certificate);
        }
        if let Ok(path) = std::env::var("OPENFINGERPRINT_POSTGRES_CA") {
            let pem = std::fs::File::open(path).map_err(|_| "Cannot read PostgreSQL CA")?;
            use rustls::pki_types::pem::PemObject;
            let certificates: Vec<_> = CertificateDer::pem_reader_iter(BufReader::new(pem))
                .collect::<Result<_, _>>()
                .map_err(|_| "Invalid PostgreSQL CA")?;
            if certificates.is_empty() {
                return Err("Empty PostgreSQL CA");
            }
            for certificate in certificates {
                roots
                    .add(certificate)
                    .map_err(|_| "Invalid PostgreSQL CA")?;
            }
        }
        Self::new(config, namespace, roots, default_scope, require_scope).map(Some)
    }

    pub(crate) fn new(
        config: Config,
        namespace: String,
        roots: rustls::RootCertStore,
        default_scope: Option<String>,
        require_scope: bool,
    ) -> Result<Self, &'static str> {
        if default_scope
            .as_deref()
            .is_some_and(|scope| !valid_scope(scope))
            || (require_scope && default_scope.is_some())
        {
            return Err("Invalid visitor scope configuration");
        }
        if namespace.is_empty()
            || namespace.len() > 64
            || !namespace
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("Invalid OPENFINGERPRINT_VISITOR_NAMESPACE");
        }
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let pool = Pool::builder(Manager::new(config, MakeRustlsConnect::new(tls)))
            .max_size(8)
            .build()
            .map_err(|_| "Invalid PostgreSQL pool")?;
        Ok(Self {
            pool,
            namespace,
            default_scope,
            require_scope,
        })
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub async fn migrate(&self) -> Result<(), &'static str> {
        self.migrate_to(MIGRATIONS.len()).await
    }

    async fn migrate_to(&self, target: usize) -> Result<(), &'static str> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| "PostgreSQL unavailable")?;
        for version in 1..=target {
            let transaction = client.transaction().await.map_err(|_| "Migration failed")?;
            transaction
                .execute("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK])
                .await
                .map_err(|_| "Migration lock unavailable")?;
            transaction.batch_execute("SET LOCAL synchronous_commit = on; CREATE TABLE IF NOT EXISTS of_migrations (version integer PRIMARY KEY, checksum text NOT NULL)")
                .await.map_err(|_| "Migration history unavailable")?;
            let history = transaction
                .query(
                    "SELECT version, checksum FROM of_migrations ORDER BY version",
                    &[],
                )
                .await
                .map_err(|_| "Migration history unavailable")?;
            for (index, row) in history.iter().enumerate() {
                let applied: i32 = row.get(0);
                let checksum: String = row.get(1);
                if applied != index as i32 + 1
                    || index >= MIGRATIONS.len()
                    || checksum != crate::check::sha256(MIGRATIONS[index])
                {
                    return Err("Unsupported or modified visitor migration history");
                }
            }
            if history.len() < version {
                let sql = MIGRATIONS[version - 1];
                transaction
                    .batch_execute(sql)
                    .await
                    .map_err(|_| "Visitor migration failed")?;
                transaction
                    .execute(
                        "INSERT INTO of_migrations (version, checksum) VALUES ($1, $2)",
                        &[&(version as i32), &crate::check::sha256(sql)],
                    )
                    .await
                    .map_err(|_| "Migration history write failed")?;
            }
            transaction
                .commit()
                .await
                .map_err(|_| "Migration commit unavailable")?;
        }
        Ok(())
    }

    pub(crate) fn valid_scope(&self, scope: Option<&str>) -> bool {
        scope.is_none_or(valid_scope) && (!self.require_scope || scope.is_some())
    }

    pub async fn resolve(
        &self,
        scope: Option<&str>,
        id: &str,
        record: &crate::identify::Record,
    ) -> Decision {
        if !self.valid_scope(scope) {
            return Decision::unknown("invalid_scope");
        }
        let namespace = scope.or(self.default_scope.as_deref()).map_or_else(
            || self.namespace.clone(),
            |scope| {
                format!(
                    "{}:scope:v1:{}",
                    self.namespace,
                    crate::check::sha256(scope)
                )
            },
        );
        if record.namespace.as_deref() != Some(self.namespace()) {
            return Decision::unknown("namespace_mismatch");
        }
        let Some(site) = canonical_site(&record.origin) else {
            return Decision::unknown("invalid_site");
        };
        let expires = record
            .created_at_ms
            .checked_add(crate::identify::TTL_SECONDS * 1000);
        let Some(expires) = expires.and_then(|value| i64::try_from(value).ok()) else {
            return Decision::unknown("invalid_observation_time");
        };
        let profile = crate::check::visitor_profile(record.evidence.clone());
        match tokio::time::timeout(
            TIMEOUT,
            self.resolve_inner(&namespace, id, &site, expires, profile.as_ref()),
        )
        .await
        {
            Ok(Ok(decision)) => decision,
            _ => Decision::unknown("unavailable"),
        }
    }

    async fn resolve_inner(
        &self,
        namespace: &str,
        id: &str,
        site: &str,
        expires: i64,
        profile: Option<&Profile>,
    ) -> Result<Decision, ()> {
        let mut client = self.pool.get().await.map_err(|_| ())?;
        let transaction = client.transaction().await.map_err(|_| ())?;
        transaction.batch_execute("SET LOCAL statement_timeout = '1500ms'; SET LOCAL lock_timeout = '1000ms'; SET LOCAL synchronous_commit = on")
            .await.map_err(|_| ())?;
        transaction
            .execute(
                "SELECT pg_advisory_xact_lock_shared($1)",
                &[&MIGRATION_LOCK],
            )
            .await
            .map_err(|_| ())?;
        let id_hash = crate::check::sha256(id);
        let mut locks = vec![lock_key(namespace, site, "identification", &id_hash)];
        if let Some(profile) = profile {
            locks.push(lock_key(namespace, site, "exact", &profile.fingerprint));
            if let Some(signature) = &profile.locale_signature {
                locks.push(lock_key(namespace, site, LOCALE_RULE, signature));
            }
        }
        locks.sort_unstable();
        locks.dedup();
        for key in locks {
            transaction
                .execute("SELECT pg_advisory_xact_lock($1)", &[&key])
                .await
                .map_err(|_| ())?;
        }
        let alive: bool = transaction
            .query_one(
                "SELECT to_timestamp($1::double precision / 1000) > clock_timestamp()",
                &[&(expires as f64)],
            )
            .await
            .map_err(|_| ())?
            .get(0);
        if !alive {
            return Ok(Decision::unknown("expired_identification"));
        }
        if let Some(row) = transaction.query_opt("SELECT decision FROM of_resolutions WHERE namespace=$1 AND site=$2 AND identification_hash=$3 AND expires_at > clock_timestamp()",
            &[&namespace, &site, &id_hash]).await.map_err(|_| ())? {
            return serde_json::from_value(row.get(0)).map_err(|_| ());
        }
        let version: i32 = transaction
            .query_one("SELECT COALESCE(MAX(version), 0) FROM of_migrations", &[])
            .await
            .map_err(|_| ())?
            .get(0);
        if version < 1 || version as usize > MIGRATIONS.len() {
            return Err(());
        }
        let mut decision = Decision::unknown("insufficient_evidence");
        decision.rule_version = version as u32;
        if let Some(profile) = profile {
            decision = Self::match_profile(&transaction, namespace, site, profile, version).await?;
        }
        let value = serde_json::to_value(&decision).map_err(|_| ())?;
        transaction.execute("INSERT INTO of_resolutions (namespace, site, identification_hash, decision, expires_at) VALUES ($1, $2, $3, $4, LEAST(to_timestamp($5::double precision / 1000), now() + interval '1 hour'))",
            &[&namespace, &site, &id_hash, &value, &(expires as f64)]).await.map_err(|_| ())?;
        transaction.commit().await.map_err(|_| ())?;
        Ok(decision)
    }

    async fn match_profile(
        transaction: &Transaction<'_>,
        namespace: &str,
        site: &str,
        profile: &Profile,
        version: i32,
    ) -> Result<Decision, ()> {
        let mut visitor = None;
        let mut method = "exact";
        if let Some(row) = transaction.query_opt("SELECT visitor_id FROM of_fingerprints WHERE namespace=$1 AND site=$2 AND schema_version=$3 AND fingerprint=$4",
            &[&namespace, &site, &profile.schema_version, &profile.fingerprint]).await.map_err(|_| ())? {
            visitor = Some(row.get::<_, String>(0));
        } else if version >= 2 && let Some(signature) = &profile.locale_signature {
            let candidates = transaction.query("SELECT visitor_id FROM of_rule_indexes WHERE namespace=$1 AND site=$2 AND rule=$3 AND signature=$4 ORDER BY visitor_id LIMIT $5",
                &[&namespace, &site, &LOCALE_RULE, signature, &((CANDIDATE_LIMIT + 1) as i64)]).await.map_err(|_| ())?;
            if candidates.len() > 1 {
                let mut decision = Decision::unknown("ambiguous");
                decision.rule_version = version as u32;
                return Ok(decision);
            }
            if let Some(candidate) = candidates.first() {
                let candidate_id: String = candidate.get(0);
                let row = transaction.query_one("SELECT profile FROM of_visitors WHERE namespace=$1 AND site=$2 AND visitor_id=$3",
                    &[&namespace, &site, &candidate_id]).await.map_err(|_| ())?;
                let reference: Profile = serde_json::from_value(row.get(0)).map_err(|_| ())?;
                if reference.schema_version != profile.schema_version
                    || reference.excluded != profile.excluded
                    || reference.components != profile.components
                    || reference.identity_groups != profile.identity_groups
                    || reference.hints.iter().filter(|(key, _)| *key != "locale")
                        .ne(profile.hints.iter().filter(|(key, _)| *key != "locale"))
                {
                    return Err(());
                }
                visitor = Some(candidate_id);
                method = LOCALE_RULE;
            }
        }
        let visitor = match visitor {
            Some(visitor) => visitor,
            None => {
                method = "new";
                let visitor = crate::identify::new_id().ok_or(())?;
                let value = serde_json::to_value(profile).map_err(|_| ())?;
                transaction.execute("INSERT INTO of_visitors (namespace, site, visitor_id, profile) VALUES ($1, $2, $3, $4)",
                    &[&namespace, &site, &visitor, &value]).await.map_err(|_| ())?;
                if version >= 2
                    && let Some(signature) = &profile.locale_signature
                {
                    transaction.execute("INSERT INTO of_rule_indexes (namespace, site, rule, signature, visitor_id) VALUES ($1, $2, $3, $4, $5)",
                        &[&namespace, &site, &LOCALE_RULE, signature, &visitor]).await.map_err(|_| ())?;
                }
                visitor
            }
        };
        transaction.execute("INSERT INTO of_fingerprints (namespace, site, schema_version, fingerprint, visitor_id) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
            &[&namespace, &site, &profile.schema_version, &profile.fingerprint, &visitor]).await.map_err(|_| ())?;
        Ok(Decision {
            status: "resolved".into(),
            rule_version: version as u32,
            visitor_id: Some(visitor),
            method: Some(method.into()),
        })
    }

    pub async fn prune(&self) -> Result<u64, ()> {
        tokio::time::timeout(TIMEOUT, async {
            let client = self.pool.get().await.map_err(|_| ())?;
            client.execute("DELETE FROM of_resolutions WHERE (namespace, site, identification_hash) IN (SELECT namespace, site, identification_hash FROM of_resolutions WHERE expires_at <= now() ORDER BY expires_at LIMIT 1000)", &[])
                .await.map_err(|_| ())
        }).await.map_err(|_| ())?
    }
}

pub(crate) fn valid_scope(scope: &str) -> bool {
    !scope.is_empty()
        && scope.len() <= 128
        && scope
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn lock_key(namespace: &str, site: &str, kind: &str, value: &str) -> i64 {
    let key = crate::check::sha256(&serde_json::json!([namespace, site, kind, value]).to_string());
    u64::from_str_radix(&key[..16], 16).expect("SHA-256 hex") as i64
}

fn canonical_site(origin: &str) -> Option<String> {
    if origin.len() > 512 {
        return None;
    }
    let url = url::Url::parse(origin).ok()?;
    (matches!(url.scheme(), "https" | "http")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none())
    .then(|| url.origin().ascii_serialization())
}

#[cfg(test)]
pub(crate) mod tests;
