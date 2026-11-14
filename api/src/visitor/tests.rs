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
            None,
            false,
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
async fn scope_configuration_is_validated_without_a_database() {
    let make = |default_scope, require_scope| {
        Store::new(
            Config::new(),
            "study".into(),
            rustls::RootCertStore::empty(),
            default_scope,
            require_scope,
        )
    };
    for scope in [
        "",
        "account/customer",
        "customer space",
        "é",
        &"a".repeat(129),
    ] {
        assert!(!valid_scope(scope));
        assert!(make(Some(scope.into()), false).is_err());
    }
    for scope in ["account-1", "account_2", &"a".repeat(128)] {
        assert!(valid_scope(scope));
    }
    assert!(make(Some("account-1".into()), true).is_err());
    let required = make(None, true).unwrap();
    assert!(!required.valid_scope(None));
    assert!(required.valid_scope(Some("account-1")));
    assert_eq!(
        required.resolve(None, "id", &record()).await.status,
        "invalid_scope"
    );
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn customer_scopes_isolate_exact_aliases_candidates_and_frozen_decisions() {
    let db = Database::new().await;
    let store = db.store("study");
    store.migrate().await.unwrap();
    let observation = record();
    let legacy = store
        .resolve(None, "shared-identification", &observation)
        .await;
    let a = store
        .resolve(Some("customer-a"), "shared-identification", &observation)
        .await;
    let b = store
        .resolve(Some("customer-b"), "shared-identification", &observation)
        .await;
    assert_eq!(a.status, "resolved");
    assert_eq!(b.status, "resolved");
    assert_ne!(a.visitor_id, b.visitor_id);
    assert_ne!(a.visitor_id, legacy.visitor_id);
    assert_ne!(b.visitor_id, legacy.visitor_id);
    assert_eq!(
        store
            .resolve(None, "shared-identification", &observation)
            .await,
        legacy
    );
    for (scope, expected) in [("customer-a", &a), ("customer-b", &b)] {
        assert_eq!(
            store
                .resolve(Some(scope), "shared-identification", &observation)
                .await,
            *expected
        );
        let repeat = store.resolve(Some(scope), "repeat", &observation).await;
        assert_eq!(repeat.visitor_id, expected.visitor_id);
        assert_eq!(repeat.method.as_deref(), Some("exact"));
    }
    let mut locale = record();
    change(&mut locale, "hints", "locale", "travel");
    let isolated = store.resolve(Some("customer-c"), "locale", &locale).await;
    assert_eq!(isolated.method.as_deref(), Some("new"));
    assert_ne!(isolated.visitor_id, a.visitor_id);
    assert_ne!(isolated.visitor_id, b.visitor_id);
    for (scope, expected) in [("customer-a", &a), ("customer-b", &b)] {
        let matched = store.resolve(Some(scope), "locale", &locale).await;
        assert_eq!(matched.method.as_deref(), Some("locale-v1"));
        assert_eq!(matched.visitor_id, expected.visitor_id);
        let alias = store.resolve(Some(scope), "locale-alias", &locale).await;
        assert_eq!(alias.method.as_deref(), Some("exact"));
        assert_eq!(alias.visitor_id, expected.visitor_id);
    }
    let mut restarted = db.store("study");
    restarted.default_scope = Some("customer-a".into());
    assert_eq!(
        restarted
            .resolve(None, "shared-identification", &observation)
            .await,
        a
    );
    let other_site = {
        let mut observation = record();
        observation.origin = "https://other.example.test".into();
        observation
    };
    assert_ne!(
        store
            .resolve(Some("customer-a"), "other-site", &other_site)
            .await
            .visitor_id,
        a.visitor_id
    );
    let client = store.pool.get().await.unwrap();
    let partitions: i64 = client
        .query_one("SELECT count(DISTINCT namespace) FROM of_visitors", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(partitions, 4);
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn exact_locale_partial_groups_isolation_and_persistent_aliases() {
    let db = Database::new().await;
    let store = db.store("study");
    store.migrate().await.unwrap();
    let mut observation = record();
    let first = store.resolve(None, "first", &observation).await;
    assert_eq!(first.status, "resolved");
    assert_eq!(first.method.as_deref(), Some("new"));
    assert_eq!(store.resolve(None, "first", &observation).await, first);
    assert_eq!(
        store.resolve(None, "repeat", &observation).await.visitor_id,
        first.visitor_id
    );
    change(&mut observation, "hints", "locale", "travelling");
    let locale = store.resolve(None, "locale", &observation).await;
    assert_eq!(locale.visitor_id, first.visitor_id);
    assert_eq!(locale.method.as_deref(), Some(LOCALE_RULE));
    let restarted = db.store("study");
    assert_eq!(
        restarted
            .resolve(None, "locale-exact", &observation)
            .await
            .method
            .as_deref(),
        Some("exact")
    );
    assert_eq!(
        restarted
            .resolve(None, "old-profile", &record())
            .await
            .visitor_id,
        first.visitor_id
    );

    for (section, name) in [
        ("hints", "browser"),
        ("hints", "hardware"),
        ("components", "canvas"),
    ] {
        let mut other = record();
        change(&mut other, section, name, "different browser evidence");
        let separate = store.resolve(None, name, &other).await;
        assert_eq!(separate.method.as_deref(), Some("new"));
        assert_ne!(separate.visitor_id, first.visitor_id);
    }
    let mut other_site = record();
    other_site.origin = "https://other.example.test".into();
    assert_ne!(
        store
            .resolve(None, "other-site", &other_site)
            .await
            .visitor_id,
        first.visitor_id
    );
    let other_namespace = db.store("other");
    assert_eq!(
        other_namespace
            .resolve(None, "same-id", &record())
            .await
            .status,
        "namespace_mismatch"
    );
    let mut other_record = record();
    other_record.namespace = Some("other".into());
    assert_ne!(
        other_namespace
            .resolve(None, "first", &other_record)
            .await
            .visitor_id,
        first.visitor_id
    );
    let mut legacy = record();
    legacy.namespace = None;
    assert_eq!(
        store.resolve(None, "legacy", &legacy).await.status,
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
        store
            .resolve(None, "years-later", &record())
            .await
            .visitor_id,
        first.visitor_id
    );
    let mut expired = record();
    expired.created_at_ms -= (crate::identify::TTL_SECONDS + 1) * 1000;
    let expired = store.resolve(None, "expired", &expired).await;
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
    let first = store.resolve(None, "before-migration", &baseline).await;
    let mut second = record();
    change(
        &mut second,
        "hints",
        "locale",
        "second independently enrolled browser",
    );
    let separate = store.resolve(None, "separate", &second).await;
    assert_ne!(first.visitor_id, separate.visitor_id);
    store.migrate().await.unwrap();
    store.migrate().await.unwrap();
    assert_eq!(
        store.resolve(None, "before-migration", &baseline).await,
        first
    );
    assert_eq!(
        store
            .resolve(None, "after-exact", &baseline)
            .await
            .visitor_id,
        first.visitor_id
    );
    assert_eq!(
        store
            .resolve(None, "second-exact", &second)
            .await
            .visitor_id,
        separate.visitor_id
    );
    let mut third = record();
    change(&mut third, "hints", "locale", "unseen locale");
    let ambiguous = store.resolve(None, "ambiguous", &third).await;
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
    assert_eq!(store.resolve(None, "ambiguous", &third).await, ambiguous);
    assert_eq!(
        store
            .resolve(None, "new-identification", &third)
            .await
            .visitor_id,
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
    assert_eq!(
        store.resolve(None, "before-migration", &baseline).await,
        first
    );
    assert_eq!(
        store.resolve(None, "unsupported", &baseline).await.status,
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
                .resolve(None, &format!("enrolled-{index}"), &observation)
                .await
                .status,
            "resolved"
        );
    }
    store.migrate().await.unwrap();
    assert_eq!(
        store.resolve(None, "overflow", &record()).await.status,
        "ambiguous"
    );
    let client = store.pool.get().await.unwrap();
    client.batch_execute("DELETE FROM of_visitors WHERE visitor_id NOT IN (SELECT visitor_id FROM of_visitors ORDER BY visitor_id LIMIT 1); UPDATE of_visitors SET profile=jsonb_set(profile, '{hints,browser}', to_jsonb(repeat('a', 64)))").await.unwrap();
    let unavailable = store.resolve(None, "corrupt-reference", &record()).await;
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
            let decision = replica.resolve(None, &id, &observation).await;
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
        let retried = store.resolve(None, &id, &observation).await;
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
    let lost_reply = store.resolve(None, "lost-reply", &baseline).await;
    assert_eq!(lost_reply.status, "resolved");
    drop(store);
    let replica = db.store("study");
    assert_eq!(
        replica.resolve(None, "lost-reply", &baseline).await,
        lost_reply
    );
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
    let insufficient = store.resolve(None, "insufficient", &missing).await;
    assert_eq!(insufficient.status, "insufficient_evidence");
    missing.evidence = record().evidence;
    assert_eq!(
        store.resolve(None, "insufficient", &missing).await,
        insufficient
    );

    let mut blocked_client = store.pool.get().await.unwrap();
    let blocker = blocked_client.transaction().await.unwrap();
    blocker
        .execute("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK])
        .await
        .unwrap();
    let timeout = store.resolve(None, "timeout", &record()).await;
    assert_eq!(timeout.status, "unavailable");
    assert!(timeout.visitor_id.is_none());
    blocker.rollback().await.unwrap();
    let recovered = store.resolve(None, "timeout", &record()).await;
    assert_eq!(recovered.status, "resolved");
    assert_eq!(store.resolve(None, "timeout", &record()).await, recovered);

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
        store.resolve(None, "rollback", &rolled_back).await.status,
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
        store.resolve(None, "rollback", &rolled_back).await.status,
        "resolved"
    );
    drop(client);

    let dead: Config = "host=127.0.0.1 port=1 user=unavailable dbname=unused sslmode=disable"
        .parse()
        .unwrap();
    let down = Store::new(
        dead,
        "study".into(),
        rustls::RootCertStore::empty(),
        None,
        false,
    )
    .unwrap();
    assert_eq!(
        down.resolve(None, "down", &record()).await.status,
        "unavailable"
    );
    let (redis, contents) = crate::cache::tests::fake_redis(None).await;
    let mut state = crate::check::tests::state_with_redis(&redis);
    state.visitors = Some(db.store("study"));
    let id = crate::identify::new_id().unwrap();
    state.identifications.store(&id, &record()).await.unwrap();
    let input = || crate::check::CheckRequest {
        visitor_scope: None,
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
        let decision = store
            .resolve(None, &format!("case-{index}"), observation)
            .await;
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

async fn call_delete(
    state: &std::sync::Arc<crate::check::AppState>,
    origin: bool,
    body: Value,
) -> (axum::http::StatusCode, Value) {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .header("content-type", "application/json");
    if origin {
        request = request.header("origin", "https://evil.example");
    }
    let request = request
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = match delete(axum::extract::State(state.clone()), request).await {
        Ok(response) => response,
        Err(error) => axum::response::IntoResponse::into_response(error),
    };
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn deletion_endpoint_validates_before_touching_the_store() {
    let id = crate::identify::new_id().unwrap();
    let mut state = crate::check::tests::state();
    let state_without_store = std::sync::Arc::new(crate::check::tests::state());
    assert_eq!(
        call_delete(&state_without_store, false, json!({"visitorId": id})).await,
        (
            axum::http::StatusCode::NOT_FOUND,
            json!({"error": "not_configured"})
        )
    );
    state.visitors = Some(
        Store::new(
            Config::new(),
            "study".into(),
            rustls::RootCertStore::empty(),
            None,
            true,
        )
        .unwrap(),
    );
    let state = std::sync::Arc::new(state);
    assert_eq!(
        call_delete(&state, true, json!({"visitorId": id, "visitorScope": "a"}))
            .await
            .1,
        json!({"error": "origin_not_allowed"})
    );
    for body in [
        json!({"visitorId": id}),
        json!({"visitorId": id, "visitorScope": "not valid"}),
        json!({"visitorId": "short", "visitorScope": "a"}),
        json!({"visitorId": id, "visitorScope": "a", "extra": 1}),
        json!({"visitorScope": "a"}),
    ] {
        assert_eq!(
            call_delete(&state, false, body).await,
            (
                axum::http::StatusCode::BAD_REQUEST,
                json!({"error": "invalid_request"})
            )
        );
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn deleting_a_visitor_removes_it_from_its_customer_scope_only() {
    let db = Database::new().await;
    let store = db.store("study");
    store.migrate().await.unwrap();
    let observation = record();
    let mut locale = record();
    change(&mut locale, "hints", "locale", "travel");
    let a = store
        .resolve(Some("customer-a"), "a-first", &observation)
        .await
        .visitor_id
        .unwrap();
    let alias = store.resolve(Some("customer-a"), "a-locale", &locale).await;
    assert_eq!(alias.visitor_id.as_deref(), Some(a.as_str()));
    let b = store
        .resolve(Some("customer-b"), "b-first", &observation)
        .await
        .visitor_id
        .unwrap();
    let legacy = store
        .resolve(None, "legacy-first", &observation)
        .await
        .visitor_id
        .unwrap();
    let rows = |table: &'static str, id: &str| {
        let id = id.to_owned();
        let pool = store.pool.clone();
        async move {
            pool.get()
                .await
                .unwrap()
                .query_one(
                    &format!("SELECT count(*) FROM {table} WHERE visitor_id = $1"),
                    &[&id],
                )
                .await
                .unwrap()
                .get::<_, i64>(0)
        }
    };
    assert_eq!(rows("of_fingerprints", &a).await, 2);
    assert_eq!(rows("of_rule_indexes", &a).await, 1);
    let frozen = |id: String| {
        let pool = store.pool.clone();
        async move {
            pool.get()
                .await
                .unwrap()
                .query_one(
                    "SELECT count(*) FROM of_resolutions WHERE decision->>'visitorId' = $1",
                    &[&id],
                )
                .await
                .unwrap()
                .get::<_, i64>(0)
        }
    };
    assert_eq!(frozen(a.clone()).await, 2);

    for (scope, id) in [
        (Some("customer-b"), a.as_str()),
        (Some("customer-a"), b.as_str()),
        (None, a.as_str()),
        (Some("customer-c"), a.as_str()),
    ] {
        assert_eq!(store.delete_visitor(scope, id).await, Ok(false));
    }
    for id in [&a, &b, &legacy] {
        assert_eq!(rows("of_visitors", id).await, 1);
    }

    assert_eq!(store.delete_visitor(Some("customer-a"), &a).await, Ok(true));
    assert_eq!(
        store.delete_visitor(Some("customer-a"), &a).await,
        Ok(false)
    );
    for table in ["of_visitors", "of_fingerprints", "of_rule_indexes"] {
        assert_eq!(rows(table, &a).await, 0, "{table}");
    }
    assert_eq!(frozen(a.clone()).await, 0);
    for (scope, id) in [(Some("customer-b"), &b), (None, &legacy)] {
        assert_eq!(rows("of_visitors", id).await, 1);
        assert_eq!(
            store
                .resolve(scope, "unchanged", &observation)
                .await
                .visitor_id,
            Some(id.clone())
        );
    }
    assert_eq!(
        store
            .resolve(Some("customer-b"), "b-first", &observation)
            .await
            .visitor_id,
        Some(b)
    );

    let again = store
        .resolve(Some("customer-a"), "a-first", &observation)
        .await;
    assert_eq!(again.method.as_deref(), Some("new"));
    assert_ne!(again.visitor_id.as_deref(), Some(a.as_str()));
    db.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires disposable PostgreSQL"]
async fn deletion_racing_a_resolve_never_leaves_a_decision_for_the_deleted_visitor() {
    let db = Database::new().await;
    let store = std::sync::Arc::new(db.store("study"));
    store.migrate().await.unwrap();
    let observation = std::sync::Arc::new(record());
    for round in 0..200 {
        let scope = format!("customer-{round}");
        let visitor = store
            .resolve(Some(&scope), "first", &observation)
            .await
            .visitor_id
            .unwrap();
        let resolve = tokio::spawn({
            let (store, scope, observation) = (store.clone(), scope.clone(), observation.clone());
            async move { store.resolve(Some(&scope), "second", &observation).await }
        });
        let delete = tokio::spawn({
            let (store, scope, visitor) = (store.clone(), scope.clone(), visitor.clone());
            async move { store.delete_visitor(Some(&scope), &visitor).await }
        });
        resolve.await.unwrap();
        assert_eq!(delete.await.unwrap(), Ok(true));
        let orphans: i64 = store
            .pool
            .get()
            .await
            .unwrap()
            .query_one(
                "SELECT count(*) FROM of_resolutions WHERE decision->>'visitorId' = $1",
                &[&visitor],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(orphans, 0, "round {round}");
    }
    db.cleanup().await;
}
