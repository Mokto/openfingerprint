use super::*;
use serde_json::{Value, json};

static DATABASE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub(crate) struct Database {
    _guard: tokio::sync::MutexGuard<'static, ()>,
    pub config: Config,
    client: tokio_postgres::Client,
    schema: String,
}

impl Database {
    pub(crate) async fn new() -> Self {
        let guard = DATABASE_LOCK.lock().await;
        let url = std::env::var("OPENFINGERPRINT_TEST_POSTGRES_URL")
            .expect("Set OPENFINGERPRINT_TEST_POSTGRES_URL to a disposable PostgreSQL database");
        let mut config: Config = url.parse().unwrap();
        assert_eq!(
            config.get_ssl_mode(),
            SslMode::Disable,
            "Local tests require explicit sslmode=disable"
        );
        let (client, connection) = config.connect(tokio_postgres::NoTls).await.unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let schema = format!(
            "test_{}",
            crate::check::sha256(&crate::identify::new_id().unwrap())
        );
        client
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        config.options(format!("-c search_path={schema}"));
        Self {
            _guard: guard,
            config,
            client,
            schema,
        }
    }

    pub(crate) fn store(&self, namespace: &str) -> Store {
        Store::new(
            self.config.clone(),
            namespace.into(),
            rustls::RootCertStore::empty(),
        )
        .unwrap()
    }

    pub(crate) async fn cleanup(self) {
        self.client
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

pub(crate) fn record() -> crate::identify::Record {
    let mut evidence = json!({"version":1,"fingerprint":null,"coreFingerprint":null,
        "components":{},"hints":{},"unavailable":{},"excluded":[],"durationMs":1});
    for name in [
        "audio",
        "canvas",
        "fontFallbacks",
        "fontPreferences",
        "fonts",
        "gpu",
    ] {
        evidence["components"][name] = crate::check::sha256(name).into();
    }
    for name in [
        "architecture",
        "browser",
        "display",
        "features",
        "hardware",
        "locale",
        "math",
        "media",
        "platform",
        "screen",
    ] {
        evidence["hints"][name] = crate::check::sha256(name).into();
    }
    rehash(&mut evidence);
    crate::identify::Record {
        evidence,
        headers: json!({}),
        ja4: None,
        origin: "https://app.example.test".into(),
        namespace: Some("study".into()),
        created_at_ms: crate::check::tests::now_ms(),
    }
}

fn rehash(evidence: &mut Value) {
    let included = |map: &Value| {
        map.as_object()
            .unwrap()
            .iter()
            .filter(|(name, _)| {
                !evidence["excluded"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|e| e == name.as_str())
            })
            .map(|(name, value)| (name.clone(), value.as_str().unwrap().to_owned()))
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .collect::<Vec<_>>()
    };
    let components = included(&evidence["components"]);
    let hints = included(&evidence["hints"]);
    evidence["coreFingerprint"] = crate::check::sha256(&format!(
        "stealth-core:1\0{}",
        serde_json::to_string(&components).unwrap()
    ))
    .into();
    evidence["fingerprint"] = crate::check::sha256(&format!(
        "stealth-agent:1\0{}",
        json!({"components":components,"hints":hints})
    ))
    .into();
}

fn change(record: &mut crate::identify::Record, section: &str, name: &str, value: &str) {
    record.evidence[section][name] = crate::check::sha256(value).into();
    rehash(&mut record.evidence);
}

#[test]
fn completeness_and_exclusions_are_not_group_count_heuristics() {
    let baseline = record();
    let profile = crate::check::visitor_profile(baseline.evidence.clone()).unwrap();
    assert_eq!(profile.identity_groups.len(), 4);
    assert!(profile.locale_signature.is_some());
    for (section, name) in [("components", "canvas"), ("hints", "locale")] {
        let mut missing = record();
        missing.evidence[section]
            .as_object_mut()
            .unwrap()
            .remove(name);
        missing.evidence["unavailable"][name] = "error".into();
        rehash(&mut missing.evidence);
        assert!(crate::check::visitor_profile(missing.evidence).is_none());
    }
    let mut wrong_place = record();
    wrong_place.evidence["hints"]["gpu"] = wrong_place.evidence["components"]["gpu"].take();
    wrong_place.evidence["components"]
        .as_object_mut()
        .unwrap()
        .remove("gpu");
    rehash(&mut wrong_place.evidence);
    assert!(crate::check::visitor_profile(wrong_place.evidence).is_none());
    let mut safari = record();
    safari.evidence["excluded"] = json!(["screen", "canvas", "audio"]);
    for (section, name) in [
        ("components", "audio"),
        ("components", "canvas"),
        ("hints", "screen"),
    ] {
        safari.evidence[section]
            .as_object_mut()
            .unwrap()
            .remove(name);
        safari.evidence["unavailable"][name] = "unsupported".into();
    }
    rehash(&mut safari.evidence);
    let profile = crate::check::visitor_profile(safari.evidence).unwrap();
    assert!(profile.locale_signature.is_none());
    assert_eq!(profile.identity_groups.len(), 2);
    let mut invalid = record();
    invalid.evidence["fingerprint"] = "a".repeat(64).into();
    assert!(crate::check::visitor_profile(invalid.evidence).is_none());
    let mut absent = record();
    absent.evidence["fingerprint"] = Value::Null;
    assert!(crate::check::visitor_profile(absent.evidence).is_none());
    assert_eq!(
        canonical_site("HTTPS://APP.EXAMPLE.TEST:443/"),
        Some("https://app.example.test".into())
    );
    for origin in [
        "null",
        "https://user@app.test",
        "https://app.test/path",
        "https://app.test/?x=1",
    ] {
        assert!(canonical_site(origin).is_none());
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn exact_locale_partial_groups_isolation_and_persistent_aliases() {
    let db = Database::new().await;
    let store = db.store("study");
    store.migrate().await.unwrap();
    let mut observation = record();
    let first = store.resolve("first", &observation).await;
    assert_eq!(first.status, "resolved");
    assert_eq!(first.method.as_deref(), Some("new"));
    assert_eq!(store.resolve("first", &observation).await, first);
    assert_eq!(
        store.resolve("repeat", &observation).await.visitor_id,
        first.visitor_id
    );
    change(&mut observation, "hints", "locale", "travelling");
    let locale = store.resolve("locale", &observation).await;
    assert_eq!(locale.visitor_id, first.visitor_id);
    assert_eq!(locale.method.as_deref(), Some(LOCALE_RULE));
    let restarted = db.store("study");
    assert_eq!(
        restarted
            .resolve("locale-exact", &observation)
            .await
            .method
            .as_deref(),
        Some("exact")
    );
    assert_eq!(
        restarted.resolve("old-profile", &record()).await.visitor_id,
        first.visitor_id
    );

    for (section, name) in [
        ("hints", "browser"),
        ("hints", "hardware"),
        ("components", "canvas"),
    ] {
        let mut other = record();
        change(&mut other, section, name, "different browser evidence");
        let separate = store.resolve(name, &other).await;
        assert_eq!(separate.method.as_deref(), Some("new"));
        assert_ne!(separate.visitor_id, first.visitor_id);
    }
    let mut other_site = record();
    other_site.origin = "https://other.example.test".into();
    assert_ne!(
        store.resolve("other-site", &other_site).await.visitor_id,
        first.visitor_id
    );
    let other_namespace = db.store("other");
    assert_eq!(
        other_namespace.resolve("same-id", &record()).await.status,
        "namespace_mismatch"
    );
    let mut other_record = record();
    other_record.namespace = Some("other".into());
    assert_ne!(
        other_namespace
            .resolve("first", &other_record)
            .await
            .visitor_id,
        first.visitor_id
    );
    let mut legacy = record();
    legacy.namespace = None;
    assert_eq!(
        store.resolve("legacy", &legacy).await.status,
        "namespace_mismatch"
    );

    let client = store.pool.get().await.unwrap();
    client
        .execute(
            "UPDATE of_visitors SET created_at = now() - interval '3 years'",
            &[],
        )
        .await
        .unwrap();
    client
        .execute(
            "UPDATE of_resolutions SET expires_at = now() - interval '1 second'",
            &[],
        )
        .await
        .unwrap();
    drop(client);
    store.prune().await.unwrap();
    assert_eq!(
        store.resolve("years-later", &record()).await.visitor_id,
        first.visitor_id
    );
    let mut expired = record();
    expired.created_at_ms -= (crate::identify::TTL_SECONDS + 1) * 1000;
    let expired = store.resolve("expired", &expired).await;
    assert_eq!(expired.status, "expired_identification");
    assert!(expired.visitor_id.is_none());
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn migrations_preserve_ids_frozen_decisions_and_ambiguous_roots() {
    let db = Database::new().await;
    let store = db.store("study");
    store.migrate_to(1).await.unwrap();
    let baseline = record();
    let first = store.resolve("before-migration", &baseline).await;
    let mut second = record();
    change(
        &mut second,
        "hints",
        "locale",
        "second independently enrolled browser",
    );
    let separate = store.resolve("separate", &second).await;
    assert_ne!(first.visitor_id, separate.visitor_id);
    store.migrate().await.unwrap();
    store.migrate().await.unwrap();
    assert_eq!(store.resolve("before-migration", &baseline).await, first);
    assert_eq!(
        store.resolve("after-exact", &baseline).await.visitor_id,
        first.visitor_id
    );
    assert_eq!(
        store.resolve("second-exact", &second).await.visitor_id,
        separate.visitor_id
    );
    let mut third = record();
    change(&mut third, "hints", "locale", "unseen locale");
    let ambiguous = store.resolve("ambiguous", &third).await;
    assert_eq!(ambiguous.status, "ambiguous");
    assert!(ambiguous.visitor_id.is_none());
    let client = store.pool.get().await.unwrap();
    client
        .execute(
            "DELETE FROM of_visitors WHERE visitor_id=$1",
            &[&separate.visitor_id],
        )
        .await
        .unwrap();
    assert_eq!(store.resolve("ambiguous", &third).await, ambiguous);
    assert_eq!(
        store.resolve("new-identification", &third).await.visitor_id,
        first.visitor_id
    );
    client
        .execute(
            "UPDATE of_migrations SET checksum='changed' WHERE version=1",
            &[],
        )
        .await
        .unwrap();
    assert!(store.migrate().await.is_err());
    client
        .execute("INSERT INTO of_migrations VALUES (3, 'future')", &[])
        .await
        .unwrap();
    assert_eq!(store.resolve("before-migration", &baseline).await, first);
    assert_eq!(
        store.resolve("unsupported", &baseline).await.status,
        "unavailable"
    );
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn saturated_rule_indexes_abstain_and_inconsistent_references_are_unavailable() {
    let db = Database::new().await;
    let store = db.store("study");
    store.migrate_to(1).await.unwrap();
    for index in 0..10 {
        let mut observation = record();
        change(
            &mut observation,
            "hints",
            "locale",
            &format!("enrolled-{index}"),
        );
        assert_eq!(
            store
                .resolve(&format!("enrolled-{index}"), &observation)
                .await
                .status,
            "resolved"
        );
    }
    store.migrate().await.unwrap();
    assert_eq!(
        store.resolve("overflow", &record()).await.status,
        "ambiguous"
    );
    let client = store.pool.get().await.unwrap();
    client.batch_execute("DELETE FROM of_visitors WHERE visitor_id NOT IN (SELECT visitor_id FROM of_visitors ORDER BY visitor_id LIMIT 1); UPDATE of_visitors SET profile=jsonb_set(profile, '{hints,browser}', to_jsonb(repeat('a', 64)))").await.unwrap();
    let unavailable = store.resolve("corrupt-reference", &record()).await;
    assert_eq!(unavailable.status, "unavailable");
    assert!(unavailable.visitor_id.is_none());
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn concurrent_replicas_and_lost_response_retries_converge() {
    let db = Database::new().await;
    db.store("study").migrate().await.unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..32 {
        let replica = db.store("study");
        tasks.spawn(async move {
            let mut observation = record();
            change(
                &mut observation,
                "hints",
                "locale",
                &format!("locale-{index}"),
            );
            let id = format!("observation-{index}");
            let decision = replica.resolve(&id, &observation).await;
            (id, observation, decision)
        });
    }
    let mut decisions = Vec::new();
    while let Some(task) = tasks.join_next().await {
        decisions.push(task.unwrap());
    }
    let store = db.store("study");
    let mut identities = std::collections::HashSet::new();
    for (id, observation, decision) in decisions {
        let retried = store.resolve(&id, &observation).await;
        assert_eq!(retried.status, "resolved");
        if decision.status == "unavailable" {
            assert_eq!(decision, Decision::unknown("unavailable"));
        } else {
            assert_eq!(decision.status, "resolved");
            assert_eq!(retried, decision);
        }
        identities.insert(retried.visitor_id.unwrap());
    }
    assert_eq!(identities.len(), 1);
    let baseline = record();
    let lost_reply = store.resolve("lost-reply", &baseline).await;
    assert_eq!(lost_reply.status, "resolved");
    drop(store);
    let replica = db.store("study");
    assert_eq!(replica.resolve("lost-reply", &baseline).await, lost_reply);
    let client = replica.pool.get().await.unwrap();
    let count: i64 = client
        .query_one("SELECT count(*) FROM of_visitors", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn missing_evidence_database_failure_timeout_and_rollback_stay_unknown() {
    let db = Database::new().await;
    let store = db.store("study");
    store.migrate().await.unwrap();
    let mut missing = record();
    missing.evidence = crate::check::tests::payload();
    let insufficient = store.resolve("insufficient", &missing).await;
    assert_eq!(insufficient.status, "insufficient_evidence");
    missing.evidence = record().evidence;
    assert_eq!(store.resolve("insufficient", &missing).await, insufficient);

    let mut blocked_client = store.pool.get().await.unwrap();
    let blocker = blocked_client.transaction().await.unwrap();
    blocker
        .execute("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK])
        .await
        .unwrap();
    let timeout = store.resolve("timeout", &record()).await;
    assert_eq!(timeout.status, "unavailable");
    assert!(timeout.visitor_id.is_none());
    blocker.rollback().await.unwrap();
    let recovered = store.resolve("timeout", &record()).await;
    assert_eq!(recovered.status, "resolved");
    assert_eq!(store.resolve("timeout", &record()).await, recovered);

    let client = store.pool.get().await.unwrap();
    client.batch_execute("CREATE FUNCTION reject_resolution() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test failure'; END $$; CREATE TRIGGER reject_resolution BEFORE INSERT ON of_resolutions FOR EACH ROW EXECUTE FUNCTION reject_resolution()").await.unwrap();
    let mut rolled_back = record();
    change(
        &mut rolled_back,
        "hints",
        "hardware",
        "transaction rollback",
    );
    assert_eq!(
        store.resolve("rollback", &rolled_back).await.status,
        "unavailable"
    );
    let count: i64 = client
        .query_one("SELECT count(*) FROM of_visitors", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        count, 1,
        "a failure after visitor/alias inserts must roll everything back"
    );
    client
        .batch_execute(
            "DROP TRIGGER reject_resolution ON of_resolutions; DROP FUNCTION reject_resolution()",
        )
        .await
        .unwrap();
    assert_eq!(
        store.resolve("rollback", &rolled_back).await.status,
        "resolved"
    );
    drop(client);

    let dead: Config = "host=127.0.0.1 port=1 user=unavailable dbname=unused sslmode=disable"
        .parse()
        .unwrap();
    let down = Store::new(dead, "study".into(), rustls::RootCertStore::empty()).unwrap();
    assert_eq!(down.resolve("down", &record()).await.status, "unavailable");
    let (redis, contents) = crate::cache::tests::fake_redis(None).await;
    let mut state = crate::check::tests::state_with_redis(&redis);
    state.visitors = Some(db.store("study"));
    let id = crate::identify::new_id().unwrap();
    state.identifications.store(&id, &record()).await.unwrap();
    let input = || crate::check::CheckRequest {
        identification_id: Some(id.clone().into()),
        domain: None,
        email: None,
        ip: None,
        detail: Some(true),
    };
    let known = Box::pin(crate::check::evaluate(&state, input()))
        .await
        .unwrap();
    assert!(known["identification"]["visitorId"].is_string());
    assert!(known["identification"].get("fingerprint").is_none());
    assert!(
        known["identification"]["evidence"]
            .get("identityGroups")
            .is_none()
    );
    let mut compact = known.clone();
    crate::check::compact(&mut compact);
    assert_eq!(compact["visitorId"], known["identification"]["visitorId"]);
    assert!(compact.get("fingerprint").is_none());
    contents.lock().unwrap().clear();
    let expired = Box::pin(crate::check::evaluate(&state, input()))
        .await
        .unwrap();
    assert!(expired["identification"]["visitorId"].is_null());
    assert_eq!(
        expired["identification"]["reason"],
        "unknown_identification"
    );
    let mut down_state = crate::check::tests::state_with_redis("127.0.0.1:1");
    down_state.visitors = Some(db.store("study"));
    let unavailable = Box::pin(crate::check::evaluate(&down_state, input()))
        .await
        .unwrap();
    assert_eq!(unavailable["identification"]["status"], "unavailable");
    assert!(unavailable["identification"]["visitorId"].is_null());
    for mut response in [expired, unavailable] {
        crate::check::compact(&mut response);
        assert!(response.get("visitorId").is_none());
        assert!(response.get("fingerprint").is_none());
    }
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; synthetic labels are not real-device validation"]
async fn independently_labelled_synthetic_cases_expose_splits_and_indistinguishability() {
    let db = Database::new().await;
    let store = db.store("study");
    store.migrate().await.unwrap();
    let mut locale = record();
    change(&mut locale, "hints", "locale", "travel");
    let mut update = record();
    change(&mut update, "hints", "browser", "browser update");
    let mut different = record();
    change(&mut different, "components", "gpu", "different GPU");
    let cases = [
        ("browser-a", record()),
        ("browser-a", locale),
        ("browser-a", update),
        ("browser-b", different),
        ("browser-c", record()),
    ];
    let mut resolved = Vec::new();
    for (index, (label, observation)) in cases.iter().enumerate() {
        let decision = store.resolve(&format!("case-{index}"), observation).await;
        resolved.push((*label, decision.visitor_id.unwrap()));
    }
    let mut false_merges = 0;
    let mut false_splits = 0;
    for (index, (label, visitor)) in resolved.iter().enumerate() {
        for (other_label, other_visitor) in &resolved[..index] {
            false_merges += usize::from(label != other_label && visitor == other_visitor);
            false_splits += usize::from(label == other_label && visitor != other_visitor);
        }
    }
    assert_eq!((false_merges, false_splits), (2, 2));
    println!(
        "Synthetic observation-pair comparisons only: false merges={false_merges}, false splits={false_splits}; real-device cases=0"
    );
    db.cleanup().await;
}
