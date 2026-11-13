//! `OpenFingerprint.Check` over Connect, gRPC and gRPC-Web, see
//! proto/openfingerprint.proto. Mounted next to the JSON routes.
use std::sync::Arc;

use axum::{Router, http::StatusCode};
use connectrpc::{
    ConnectError, ConnectRpcService, Interceptor, Limits, Next, NextStream, PayloadStream,
    RequestContext, Response, ServiceRequest, ServiceResult,
    interceptor::{StreamRequest, StreamResponse, UnaryRequest, UnaryResponse},
};
use serde_json::Value;

use crate::check::{ApiError, AppState, BODY_LIMIT, CheckRequest as Input, compact};

pub mod proto {
    connectrpc::include_generated!();
}
use proto::openfingerprint::v1::{CheckRequest, CheckResponse, OpenFingerprint};

const PATHS: [&str; 3] = [
    "/openfingerprint.v1.OpenFingerprint/Check",
    "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
];

pub fn is_rpc(path: &str) -> bool {
    PATHS.contains(&path)
}

impl From<ApiError> for ConnectError {
    fn from(ApiError(status, reason): ApiError) -> Self {
        match status {
            StatusCode::FORBIDDEN => Self::permission_denied(reason),
            StatusCode::BAD_REQUEST => Self::invalid_argument(reason),
            StatusCode::PAYLOAD_TOO_LARGE => Self::resource_exhausted(reason),
            _ => Self::internal(reason),
        }
    }
}

struct Check(Arc<AppState>);

#[allow(refining_impl_trait)]
impl OpenFingerprint for Check {
    async fn check(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, CheckRequest>,
    ) -> ServiceResult<CheckResponse> {
        let text = |s: Option<&str>| s.map(|s| Value::String(s.to_owned()));
        let input = Input {
            identification_id: text(request.identification_id),
            domain: text(request.domain),
            email: text(request.email),
            ip: text(request.ip),
            detail: request.detail,
        };
        Response::ok(respond(&self.0, input).await?)
    }
}

async fn respond(state: &AppState, input: Input) -> Result<CheckResponse, ConnectError> {
    let detail = input.detail == Some(true);
    let mut verdicts = crate::check::evaluate(state, input).await?;
    if detail {
        let identification = verdicts.get("identification").cloned();
        compact(&mut verdicts);
        if let Some(identification) = identification {
            verdicts["identification"] = identification;
        }
    }
    serde_json::from_value(verdicts).map_err(|_| ConnectError::internal("encode"))
}

/// Applies the `/v1/check` browser rule to every RPC, reflection included.
struct RejectBrowsers(Arc<AppState>);

#[connectrpc::async_trait]
impl Interceptor for RejectBrowsers {
    async fn intercept_unary(
        &self,
        req: UnaryRequest,
        next: Next<'_>,
    ) -> Result<UnaryResponse, ConnectError> {
        self.0.reject_browsers(req.ctx.headers())?;
        next.run(req).await
    }

    async fn intercept_streaming(
        &self,
        req: StreamRequest,
        inbound: PayloadStream,
        next: NextStream<'_>,
    ) -> Result<StreamResponse, ConnectError> {
        self.0.reject_browsers(req.ctx.headers())?;
        next.run(req, inbound).await
    }
}

pub fn routes<S: Clone + Send + Sync + 'static>(state: Arc<AppState>) -> Router<S> {
    let router = connectrpc_reflection::install(
        connectrpc::Router::new().add_service(Arc::new(Check(state.clone()))),
        connectrpc_reflection::Reflector::from_descriptor_set_bytes(include_bytes!(
            "../proto/openfingerprint.fds.bin"
        ))
        .expect("embedded descriptor set"),
    );
    let service = ConnectRpcService::new(router)
        .with_limits(
            Limits::default()
                .with_max_request_body_size(BODY_LIMIT)
                .with_max_message_size(BODY_LIMIT),
        )
        .with_interceptor(RejectBrowsers(state));
    PATHS.into_iter().fold(Router::new(), |r, path| {
        r.route_service(path, service.clone())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_compact_key_has_a_field_in_the_response_message() {
        let response: CheckResponse = serde_json::from_value(serde_json::json!({
            "visitorId":"visitor","automation":true,"tampering":false,"spoofing":true,"disposable":true,
            "free":false,"spam":true,"relay":false,"cheapTld":true,"replayed":true,"ageMs":1500,"mx":true,"country":"dk","vpn":true,
            "tor":false,"datacenter":true,"proxy":false,"suspiciousClickPattern":false,"invalid":["ip"]
        }))
        .unwrap();
        assert_eq!(response.visitor_id.as_deref(), Some("visitor"));
        assert_eq!(response.country.as_deref(), Some("dk"));
        assert_eq!(
            [
                response.automation,
                response.tampering,
                response.spoofing,
                response.disposable,
                response.free,
                response.spam,
                response.relay,
                response.cheap_tld,
                response.replayed,
                response.mx,
                response.vpn,
                response.tor,
                response.datacenter,
                response.proxy
            ],
            [
                Some(true),
                Some(false),
                Some(true),
                Some(true),
                Some(false),
                Some(true),
                Some(false),
                Some(true),
                Some(true),
                Some(true),
                Some(true),
                Some(false),
                Some(true),
                Some(false)
            ]
        );
        assert_eq!(response.suspicious_click_pattern, Some(false));
        assert_eq!(response.age_ms, Some(1500));
        assert_eq!(response.invalid, ["ip"]);
        assert_eq!(
            serde_json::from_value::<CheckResponse>(serde_json::json!({})).unwrap(),
            CheckResponse::default()
        );
    }

    #[test]
    fn listed_network_facts_encode_as_booleans() {
        let fact = |value| serde_json::json!({"value":value,"status":"listed"});
        let mut response = serde_json::json!({"ip":{"status":"ok","countryCode":"DK","network":{
            "status":"ok",
            "tor":fact(serde_json::json!(true)),
            "vpn":fact(serde_json::json!({"scope":"listed_vpn_range"})),
            "datacenter":fact(serde_json::json!({"scope":"listed_datacenter_range"})),
            "proxy":fact(serde_json::json!({"protocols":["http"],"scope":"listed_open_proxy"}))}}});
        compact(&mut response);
        let message: CheckResponse = serde_json::from_value(response).unwrap();
        assert_eq!(
            [message.tor, message.vpn, message.datacenter, message.proxy],
            [Some(true); 4]
        );
        assert_eq!(message.country.as_deref(), Some("dk"));
    }

    const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36";
    const CHROME_JA4: &str = "t13d1517h2_8daaf6152771_cb7bf5808d99";
    const CURL_JA4: &str = "t13d4907h2_0d8feac7bc37_7395dae3b2f3";
    const UNLISTED_JA4: &str = "t13d1517h2_000000000000_000000000000";

    fn input(id: Option<Value>, detail: Option<bool>) -> Input {
        Input {
            identification_id: id,
            domain: None,
            email: None,
            ip: None,
            detail,
        }
    }

    fn record(ja4: Option<&str>) -> crate::identify::Record {
        let mut evidence = crate::check::tests::payload();
        evidence["automation"] = serde_json::json!({"version":7,"webdriver":true});
        evidence["tampering"] = serde_json::json!({"version":1,"canvasReadbackAltered":true,"audioRenderAltered":false});
        evidence["spoofing"] = serde_json::json!({"version":1,"userAgent":CHROME_UA,"language":"en-US","clientHints":null});
        evidence["behavior"] = serde_json::json!({"version":1,"watchedMs":900,"pointerMoves":1,"mouseClicks":1,
            "clicksWithoutMovement":1,"centeredClicks":0,"keys":0,"instantKeys":0,"insertedTexts":0,
            "touches":0,"wheels":0,"untrustedEvents":0});
        crate::identify::Record {
            evidence,
            headers: serde_json::json!({"userAgent":CHROME_UA,"acceptLanguage":"en-US,en;q=0.9"}),
            ja4: ja4.map(str::to_owned),
            origin: "https://app.example.test".into(),
            created_at_ms: crate::check::tests::now_ms() - 1_500,
            namespace: None,
        }
    }

    fn comparable(value: &Value) -> Value {
        match value {
            Value::Object(map) => Value::Object(
                map.iter()
                    .filter(|(k, v)| {
                        *k != "ageMs" && !v.is_null() && v.as_array().is_none_or(|a| !a.is_empty())
                    })
                    .map(|(k, v)| {
                        let key = match k.as_str() {
                            "schema_version" => "schemaVersion",
                            "rule_version" => "ruleVersion",
                            "unavailable_probes" => "unavailableProbes",
                            _ => k,
                        };
                        (key.to_owned(), comparable(v))
                    })
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    async fn parity(state: &AppState, id: &str) -> CheckResponse {
        let rest = crate::check::evaluate(state, input(Some(id.into()), Some(true)))
            .await
            .unwrap()["identification"]
            .clone();
        let rpc = respond(state, input(Some(id.into()), Some(true)))
            .await
            .unwrap();
        let mut json = serde_json::to_value(&rpc).unwrap()["identification"].clone();
        json["replayed"] = rest["replayed"].clone();
        assert_eq!(comparable(&json), comparable(&rest));
        rpc
    }

    #[tokio::test]
    async fn detail_matches_rest_for_known_tls_clients() {
        let (addr, _) = crate::cache::tests::fake_redis(None).await;
        let state = crate::check::tests::state_with_redis(&addr);
        for (ja4, client) in [(CHROME_JA4, "chromium"), (CURL_JA4, "curl")] {
            let id = format!("{client:0<22}");
            state
                .identifications
                .store(&id, &record(Some(ja4)))
                .await
                .unwrap();
            let rpc = Box::pin(parity(&state, &id)).await;
            let detail = rpc.identification.as_option().unwrap();
            assert_eq!(detail.status.as_deref(), Some("ok"));
            assert_eq!(detail.tls_client.as_deref(), Some(client));
            assert_eq!(detail.ja4.as_deref(), Some(ja4));
            assert_eq!(detail.origin.as_deref(), Some("https://app.example.test"));
            assert_eq!(detail.schema_version, Some(1));
            assert!(
                serde_json::to_value(&rpc)
                    .unwrap()
                    .get("fingerprint")
                    .is_none()
            );
            assert!((1_500..10_000).contains(&detail.age_ms.unwrap()));
            let automation = detail.automation.as_option().unwrap();
            assert_eq!(automation.status.as_deref(), Some("detected"));
            assert_eq!(automation.indicators, ["webdriver"]);
            assert_eq!(automation.rule_version, Some(7));
            assert_eq!(automation.unavailable_probes.len(), 19);
            let tampering = detail.tampering.as_option().unwrap();
            assert_eq!(tampering.indicators, ["canvas_readback_altered"]);
            assert_eq!(tampering.rule_version, Some(1));
            let spoofing = detail.spoofing.as_option().unwrap();
            assert_eq!(
                spoofing.status.as_deref(),
                Some(if client == "curl" {
                    "detected"
                } else {
                    "not_detected"
                })
            );
            assert_eq!(
                detail.behavior.as_option().unwrap().patterns,
                ["clicks_without_movement"]
            );
            let counts = detail.evidence.as_option().unwrap();
            assert_eq!(
                (
                    counts.included_components,
                    counts.included_hints,
                    counts.unavailable_probes,
                    counts.excluded_probes
                ),
                (Some(1), Some(0), Some(0), Some(0))
            );
            assert_eq!((rpc.replayed, detail.replayed), (Some(true), Some(true)));
        }
    }

    #[tokio::test]
    async fn click_flag_keeps_true_false_and_unknown_in_both_shapes() {
        let (addr, _) = crate::cache::tests::fake_redis(None).await;
        let state = crate::check::tests::state_with_redis(&addr);
        for (i, (version, clicks, low, centered, expected)) in [
            (2, 3, 3, 3, Some(true)),
            (2, 3, 2, 3, Some(false)),
            (2, 3, 3, 2, Some(false)),
            (2, 2, 2, 2, None),
            (2, 0, 0, 0, None),
            (1, 3, 3, 3, None),
        ]
        .into_iter()
        .enumerate()
        {
            let id = format!("ClickIdentification{i:03}");
            let mut record = record(Some(CHROME_JA4));
            for (key, value) in [
                ("version", version),
                ("mouseClicks", clicks),
                ("clicksWithoutMovement", low),
                ("centeredClicks", centered),
            ] {
                record.evidence["behavior"][key] = serde_json::json!(value);
            }
            state.identifications.store(&id, &record).await.unwrap();
            let rpc = Box::pin(parity(&state, &id)).await;
            assert_eq!(rpc.suspicious_click_pattern, expected);
            let behavior = rpc
                .identification
                .as_option()
                .unwrap()
                .behavior
                .as_option()
                .unwrap();
            assert_eq!(behavior.suspicious_click_pattern, expected);
            assert_eq!(behavior.rule_version, Some(2));
            let compact = Box::pin(respond(&state, input(Some(id.into()), None)))
                .await
                .unwrap();
            assert_eq!(compact.suspicious_click_pattern, expected);
        }
    }

    #[tokio::test]
    async fn default_and_false_keep_the_compact_fields() {
        let (addr, _) = crate::cache::tests::fake_redis(None).await;
        let state = crate::check::tests::state_with_redis(&addr);
        for (n, detail) in [None, Some(false), Some(true)].into_iter().enumerate() {
            let id = format!("CompactIdentification{n}");
            state
                .identifications
                .store(&id, &record(Some(CHROME_JA4)))
                .await
                .unwrap();
            let mut rpc = Box::pin(respond(&state, input(Some(id.clone().into()), detail)))
                .await
                .unwrap();
            assert_eq!(rpc.identification.is_set(), detail == Some(true));
            assert_eq!(rpc.replayed, Some(false));
            let mut rest = Box::pin(crate::check::evaluate(&state, input(Some(id.into()), None)))
                .await
                .unwrap();
            rest["replayed"] = serde_json::json!(false);
            rest.as_object_mut().unwrap().remove("ageMs");
            rpc.age_ms = None;
            rpc.identification = Default::default();
            assert_eq!(rpc, serde_json::from_value(rest).unwrap());
        }
    }

    #[tokio::test]
    async fn unknown_evidence_and_tls_stay_unknown() {
        let (addr, _) = crate::cache::tests::fake_redis(None).await;
        let state = crate::check::tests::state_with_redis(&addr);
        for (n, ja4) in [Some(UNLISTED_JA4), None].into_iter().enumerate() {
            let id = format!("UnknownIdentification{n}");
            let mut record = record(ja4);
            record.evidence["fingerprint"] = Value::Null;
            record.evidence["coreFingerprint"] = Value::Null;
            for probe in ["audio", "canvas", "gpu"] {
                record.evidence["components"][probe] = Value::String(crate::check::sha256(probe));
            }
            record.evidence["automation"] = serde_json::json!({"version":7});
            record.evidence["tampering"] = Value::Null;
            record.evidence["behavior"] = Value::Null;
            state.identifications.store(&id, &record).await.unwrap();
            let rpc = Box::pin(parity(&state, &id)).await;
            let detail = rpc.identification.as_option().unwrap();
            assert_eq!(detail.status.as_deref(), Some("insufficient_signals"));
            assert_eq!(detail.ja4.as_deref(), ja4);
            assert_eq!(
                (detail.tls_client.as_deref(), detail.schema_version),
                (None, None)
            );
            assert!(detail.tampering.is_unset() && detail.behavior.is_unset());
            let automation = detail.automation.as_option().unwrap();
            assert_eq!(automation.status.as_deref(), Some("unknown"));
            assert!(automation.indicators.is_empty());
            assert_eq!(automation.unavailable_probes.len(), 20);
            let spoofing = detail.spoofing.as_option().unwrap();
            assert_eq!(spoofing.status.as_deref(), Some("unknown"));
            assert_eq!(spoofing.unavailable_probes, ["tls_mismatch"]);
            assert_eq!(
                (rpc.visitor_id, rpc.automation, rpc.tampering, rpc.spoofing),
                (None, None, None, None)
            );
        }
    }

    #[tokio::test]
    async fn missing_invalid_expired_and_unavailable_identifications() {
        let (addr, store) = crate::cache::tests::fake_redis(None).await;
        let state = crate::check::tests::state_with_redis(&addr);
        let expired = "ExpiredIdentification1";
        state
            .identifications
            .store(expired, &record(Some(CHROME_JA4)))
            .await
            .unwrap();
        // The fake Redis does not expire keys; a deletion models its TTL elapsing.
        store.lock().unwrap().clear();
        for (id, reason) in [
            ("x", "invalid_identification_id"),
            ("AAAAAAAAAAAAAAAAAAAAAA", "unknown_identification"),
            (expired, "unknown_identification"),
        ] {
            let rpc = Box::pin(parity(&state, id)).await;
            let detail = rpc.identification.as_option().unwrap();
            assert_eq!(
                (detail.status.as_deref(), detail.reason.as_deref()),
                (Some("invalid_input"), Some(reason))
            );
            assert!(
                detail.evidence.is_unset() && detail.origin.is_none() && detail.replayed.is_none()
            );
            assert_eq!(
                (rpc.visitor_id, rpc.invalid),
                (None, vec!["identificationId".to_owned()])
            );
        }
        let down = crate::check::tests::state_with_redis("127.0.0.1:9");
        let rpc = Box::pin(parity(&down, expired)).await;
        let detail = rpc.identification.as_option().unwrap();
        assert_eq!(
            (detail.status.as_deref(), detail.reason.as_deref()),
            (Some("unavailable"), Some("identification_unavailable"))
        );
        assert!(rpc.invalid.is_empty());
        let ip_only = Input {
            ip: Some("192.0.2.1".into()),
            ..input(None, Some(true))
        };
        assert!(
            Box::pin(respond(&state, ip_only))
                .await
                .unwrap()
                .identification
                .is_unset()
        );
        assert!(
            Box::pin(respond(&state, input(None, Some(true))))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL"]
    async fn visitor_reconciliation_matches_rest_and_protobuf_presence() {
        let db = crate::visitor::tests::Database::new().await;
        let store = db.store("study");
        store.migrate().await.unwrap();
        let (addr, _) = crate::cache::tests::fake_redis(None).await;
        let mut state = crate::check::tests::state_with_redis(&addr);
        state.visitors = Some(store);
        let id = crate::identify::new_id().unwrap();
        let record = crate::visitor::tests::record();
        state.identifications.store(&id, &record).await.unwrap();
        let rpc = Box::pin(parity(&state, &id)).await;
        let visitor = rpc.visitor_id.clone().unwrap();
        let json = serde_json::to_value(&rpc).unwrap();
        assert!(json["identification"].get("fingerprint").is_none());
        assert!(
            json["identification"]["evidence"]
                .get("identityGroups")
                .is_none()
        );
        let detail = rpc.identification.as_option().unwrap();
        assert_eq!(detail.visitor_id.as_ref(), Some(&visitor));
        assert_eq!(
            detail.reconciliation.as_option().unwrap().status.as_deref(),
            Some("resolved")
        );
        use buffa::Message;
        assert_eq!(
            CheckResponse::decode_from_slice(&rpc.encode_to_vec()).unwrap(),
            rpc
        );
        let mut missing = crate::visitor::tests::record();
        missing.evidence = crate::check::tests::payload();
        let missing_id = crate::identify::new_id().unwrap();
        state
            .identifications
            .store(&missing_id, &missing)
            .await
            .unwrap();
        let rpc = Box::pin(parity(&state, &missing_id)).await;
        let detail = rpc.identification.as_option().unwrap();
        assert!(rpc.visitor_id.is_none() && detail.visitor_id.is_none());
        assert_eq!(
            detail.reconciliation.as_option().unwrap().status.as_deref(),
            Some("insufficient_evidence")
        );
        db.cleanup().await;
    }

    #[test]
    fn api_errors_map_to_connect_codes() {
        use connectrpc::ErrorCode::*;
        for (status, code) in [
            (StatusCode::FORBIDDEN, PermissionDenied),
            (StatusCode::BAD_REQUEST, InvalidArgument),
            (StatusCode::PAYLOAD_TOO_LARGE, ResourceExhausted),
            (StatusCode::BAD_GATEWAY, Internal),
        ] {
            assert_eq!(ConnectError::from(ApiError(status, "x")).code, code);
        }
    }
}
