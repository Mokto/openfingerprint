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

use crate::check::{ApiError, AppState, BODY_LIMIT, CheckRequest as Input};

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
            detail: None,
        };
        let verdicts = crate::check::evaluate(&self.0, input).await?;
        Response::ok(
            serde_json::from_value(verdicts).map_err(|_| ConnectError::internal("encode"))?,
        )
    }
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
            "fingerprint":"abc","automation":true,"tampering":false,"spoofing":true,"disposable":true,
            "free":false,"spam":true,"relay":false,"cheapTld":true,"replayed":true,"ageMs":1500,"mx":true,"country":"dk","vpn":true,
            "tor":false,"datacenter":true,"proxy":false,"invalid":["ip"]
        }))
        .unwrap();
        assert_eq!(response.fingerprint.as_deref(), Some("abc"));
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
        crate::check::compact(&mut response);
        let message: CheckResponse = serde_json::from_value(response).unwrap();
        assert_eq!(
            [message.tor, message.vpn, message.datacenter, message.proxy],
            [Some(true); 4]
        );
        assert_eq!(message.country.as_deref(), Some("dk"));
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
