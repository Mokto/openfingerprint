//! gRPC front for `/v1/check`, see proto/openfingerprint.proto. Hand-written
//! instead of generated so the build needs no protoc.
use std::{future::Future, pin::Pin, sync::Arc};

use axum::{
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::Value;
use tonic::{
    Code, Status,
    codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder},
    server::UnaryService,
};

use crate::check::{ApiError, AppState, BODY_LIMIT, CheckRequest};

pub const PATH: &str = "/openfingerprint.v1.OpenFingerprint/Check";

#[derive(Clone, PartialEq, prost::Message)]
pub struct Query {
    #[prost(string, optional, tag = "1")]
    signals: Option<String>,
    #[prost(string, optional, tag = "2")]
    domain: Option<String>,
    #[prost(string, optional, tag = "3")]
    email: Option<String>,
    #[prost(string, optional, tag = "4")]
    ip: Option<String>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Verdicts {
    #[prost(string, optional, tag = "1")]
    fingerprint: Option<String>,
    #[prost(bool, optional, tag = "2")]
    automation: Option<bool>,
    #[prost(bool, optional, tag = "3")]
    tampering: Option<bool>,
    #[prost(bool, optional, tag = "4")]
    disposable: Option<bool>,
    #[prost(bool, optional, tag = "5")]
    free: Option<bool>,
    #[prost(bool, optional, tag = "6")]
    spam: Option<bool>,
    #[prost(bool, optional, tag = "7")]
    relay: Option<bool>,
    #[prost(bool, optional, tag = "8")]
    mx: Option<bool>,
    #[prost(string, optional, tag = "9")]
    country: Option<String>,
    #[prost(bool, optional, tag = "10")]
    vpn: Option<bool>,
    #[prost(bool, optional, tag = "11")]
    tor: Option<bool>,
    #[prost(bool, optional, tag = "12")]
    datacenter: Option<bool>,
    #[prost(bool, optional, tag = "13")]
    proxy: Option<bool>,
    #[prost(string, repeated, tag = "14")]
    invalid: Vec<String>,
}

impl From<&Value> for Verdicts {
    fn from(v: &Value) -> Self {
        let text = |k: &str| v[k].as_str().map(str::to_owned);
        let flag = |k: &str| v[k].as_bool();
        Self {
            fingerprint: text("fingerprint"),
            automation: flag("automation"),
            tampering: flag("tampering"),
            disposable: flag("disposable"),
            free: flag("free"),
            spam: flag("spam"),
            relay: flag("relay"),
            mx: flag("mx"),
            country: text("country"),
            vpn: flag("vpn"),
            tor: flag("tor"),
            datacenter: flag("datacenter"),
            proxy: flag("proxy"),
            invalid: v["invalid"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|s| s.as_str().map(str::to_owned))
                .collect(),
        }
    }
}

struct Check(Arc<AppState>);

impl UnaryService<Query> for Check {
    type Response = Verdicts;
    type Future = Pin<Box<dyn Future<Output = Result<tonic::Response<Verdicts>, Status>> + Send>>;
    fn call(&mut self, request: tonic::Request<Query>) -> Self::Future {
        let state = self.0.clone();
        Box::pin(async move {
            let (metadata, _, query) = request.into_parts();
            state.authorize(&metadata.into_headers())?;
            let text = |s: Option<String>| s.map(Value::String);
            let input = CheckRequest {
                automation: None,
                signals: text(query.signals),
                domain: text(query.domain),
                email: text(query.email),
                ip: text(query.ip),
                detail: None,
            };
            let verdicts = crate::check::evaluate(&state, input).await?;
            Ok(tonic::Response::new(Verdicts::from(&verdicts)))
        })
    }
}

impl From<ApiError> for Status {
    fn from(ApiError(status, reason): ApiError) -> Self {
        let code = match status {
            StatusCode::UNAUTHORIZED => Code::Unauthenticated,
            StatusCode::FORBIDDEN => Code::PermissionDenied,
            StatusCode::BAD_REQUEST => Code::InvalidArgument,
            StatusCode::PAYLOAD_TOO_LARGE => Code::ResourceExhausted,
            _ => Code::Internal,
        };
        Status::new(code, reason)
    }
}

/// The protobuf codec from tonic-prost, which ships without license files and
/// so cannot pass the image build's license collection.
#[derive(Default)]
struct Proto;

impl Codec for Proto {
    type Encode = Verdicts;
    type Decode = Query;
    type Encoder = Self;
    type Decoder = Self;
    fn encoder(&mut self) -> Self {
        Self
    }
    fn decoder(&mut self) -> Self {
        Self
    }
}

impl Encoder for Proto {
    type Item = Verdicts;
    type Error = Status;
    fn encode(&mut self, item: Verdicts, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
        prost::Message::encode(&item, dst).map_err(|e| Status::internal(e.to_string()))
    }
}

impl Decoder for Proto {
    type Item = Query;
    type Error = Status;
    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Query>, Status> {
        prost::Message::decode(src)
            .map(Some)
            .map_err(|e| Status::invalid_argument(e.to_string()))
    }
}

pub async fn check(State(state): State<Arc<AppState>>, request: Request) -> Response {
    tonic::server::Grpc::new(Proto)
        .max_decoding_message_size(BODY_LIMIT)
        .unary(Check(state), request)
        .await
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use prost::Message;

    async fn call(query: &Query, key: Option<&str>) -> (u16, Option<Verdicts>, String) {
        let mut body = vec![0, 0, 0, 0, 0];
        query.encode(&mut body).unwrap();
        let len = (body.len() - 5) as u32;
        body[1..5].copy_from_slice(&len.to_be_bytes());
        let mut request = Request::post(PATH).header("content-type", "application/grpc");
        if let Some(key) = key {
            request = request.header("authorization", format!("Bearer {key}"));
        }
        let response = check(
            State(Arc::new(crate::check::tests::state())),
            request.body(Body::from(body)).unwrap(),
        )
        .await;
        let mut headers = response.headers().clone();
        let collected = response.into_body().collect().await.unwrap();
        if let Some(trailers) = collected.trailers() {
            headers.extend(trailers.clone());
        }
        let bytes = collected.to_bytes();
        let verdicts = (bytes.len() > 5).then(|| Verdicts::decode(&bytes[5..]).unwrap());
        let status = headers["grpc-status"].to_str().unwrap().parse().unwrap();
        let message = headers
            .get("grpc-message")
            .map_or("", |m| m.to_str().unwrap());
        (status, verdicts, message.to_owned())
    }

    fn query(domain: &str) -> Query {
        Query {
            domain: Some(domain.into()),
            ..Query::default()
        }
    }

    #[tokio::test]
    async fn answers_with_typed_verdicts_and_maps_errors_to_grpc_codes() {
        let key = "s".repeat(32);
        assert_eq!(call(&query("example.test"), Some(&key)).await.0, 0);

        let bad = Query {
            ip: Some("nope".into()),
            signals: Some("not a token".into()),
            ..Query::default()
        };
        let (_, verdicts, _) = call(&bad, Some(&key)).await;
        let verdicts = verdicts.unwrap();
        assert_eq!(verdicts.invalid, ["signals", "ip"]);
        assert_eq!((verdicts.fingerprint, verdicts.country), (None, None));

        let (status, _, message) = call(&Query::default(), Some(&key)).await;
        assert_eq!((status, message.as_str()), (3, "invalid_request"));
        let both = Query {
            email: Some("a@example.test".into()),
            ..query("example.test")
        };
        assert_eq!(call(&both, Some(&key)).await.0, 3);
        assert_eq!(call(&query("example.test"), None).await.0, 16);
        assert_eq!(
            call(&query("example.test"), Some(&"x".repeat(32))).await.0,
            16
        );
    }

    #[test]
    fn verdicts_come_from_the_compact_response() {
        let verdicts = Verdicts::from(&serde_json::json!({
            "fingerprint":"abc","automation":true,"tampering":false,"mx":true,
            "country":"dk","tor":false,"invalid":["ip"]
        }));
        assert_eq!(
            verdicts,
            Verdicts {
                fingerprint: Some("abc".into()),
                automation: Some(true),
                tampering: Some(false),
                mx: Some(true),
                country: Some("dk".into()),
                tor: Some(false),
                invalid: vec!["ip".into()],
                ..Verdicts::default()
            }
        );
    }
}
