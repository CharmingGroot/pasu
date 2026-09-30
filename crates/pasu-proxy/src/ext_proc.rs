//! Envoy's External Processing protocol, answered by the same [`Judge`].
//!
//! Envoy (and Envoy Gateway, agentgateway, GKE service extensions — anything
//! that speaks `envoy.service.ext_proc.v3`) forwards the traffic; pasu decides.
//! One gRPC stream is one HTTP request, and each phase maps onto a question the
//! reverse proxy already asks:
//!
//! | phase | pasu |
//! |---|---|
//! | request headers | route the endpoint; refuse an unknown one; ask the upstream for `identity` encoding |
//! | request body | screen the prompt — refuse, or replace it and fix `content-length` |
//! | response headers | note status, type, encoding |
//! | response body | parse the completion and judge its tool calls |
//!
//! Every refusal is an `ImmediateResponse`, sent before the client has seen any
//! of the response. That needs whole bodies: a completion whose body arrives in
//! pieces (`STREAMED`, or a body mode nobody set) cannot be judged, so it is
//! refused with a 500 that names the setting, rather than let through.

use std::pin::Pin;
use std::sync::Arc;

use axum::body::Bytes;
use envoy_types::pb::envoy::config::core::v3::{HeaderMap, HeaderValue, HeaderValueOption};
use envoy_types::pb::envoy::extensions::filters::http::ext_proc::v3::{
    processing_mode::{BodySendMode, HeaderSendMode},
    ProcessingMode,
};
use envoy_types::pb::envoy::r#type::v3::HttpStatus;
use envoy_types::pb::envoy::service::ext_proc::v3::{
    body_mutation::Mutation, external_processor_server::ExternalProcessor,
    processing_request::Request as Phase, processing_response::Response as Reply, BodyMutation,
    BodyResponse, CommonResponse, HeaderMutation, HeadersResponse, HttpBody, HttpHeaders,
    ImmediateResponse, ProcessingRequest, ProcessingResponse, ProtocolConfiguration,
    TrailersResponse,
};
use pasu_core::{Approver, RuleEngine};
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt};

pub use envoy_types::pb::envoy::service::ext_proc::v3::external_processor_server::ExternalProcessorServer;

use crate::judge::{Judge, ResponseView, Screened};
use crate::parse::Route;

const STATUS_FORBIDDEN: i32 = 403;
const STATUS_TOO_LARGE: i32 = 413;
const STATUS_MISCONFIGURED: i32 = 500;

const NOT_BUFFERED: &str = "pasu: this completion's body did not arrive whole, so it could not \
                            be judged. Set the ext_proc processing_mode body modes to BUFFERED";

/// The gRPC service. Hand it to [`ExternalProcessorServer::new`].
pub struct ExtProc<E: RuleEngine, A: Approver> {
    judge: Arc<Judge<E, A>>,
}

impl<E: RuleEngine, A: Approver> ExtProc<E, A> {
    /// A service answering with `judge`.
    pub fn new(judge: Arc<Judge<E, A>>) -> Self {
        Self { judge }
    }
}

type ReplyStream = Pin<Box<dyn Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

#[tonic::async_trait]
impl<E, A> ExternalProcessor for ExtProc<E, A>
where
    E: RuleEngine + Send + Sync + 'static,
    A: Approver + Send + Sync + 'static,
{
    type ProcessStream = ReplyStream;

    async fn process(
        &self,
        request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
    ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
        let mut inbound = request.into_inner();
        let judge = Arc::clone(&self.judge);
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            let mut session = Session::default();
            while let Some(Ok(message)) = inbound.next().await {
                let step = session.handle(&judge, message).await;
                let last = step.is_final();
                if tx.send(Ok(step.into_response())).await.is_err() || last {
                    break;
                }
            }
        });
        Ok(tonic::Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

/// What one HTTP request has shown so far.
#[derive(Default)]
pub struct Session {
    /// The body modes Envoy is configured with, when it says (first message).
    protocol: Option<ProtocolConfiguration>,
    route: Option<Route>,
    status: u16,
    content_type: Option<String>,
    identity_encoded: bool,
}

/// The answer to one phase.
pub enum Step {
    /// Carry on (possibly with mutations).
    Continue(ProcessingResponse),
    /// Stop this request with a local reply. The stream ends here.
    Refuse(ProcessingResponse),
}

impl Step {
    fn is_final(&self) -> bool {
        matches!(self, Step::Refuse(_))
    }

    /// The protobuf to send back.
    pub fn into_response(self) -> ProcessingResponse {
        match self {
            Step::Continue(r) | Step::Refuse(r) => r,
        }
    }

    /// The local reply's status, if this step refuses.
    pub fn refused_with(&self) -> Option<i32> {
        match self {
            Step::Refuse(r) => match &r.response {
                Some(Reply::ImmediateResponse(i)) => i.status.as_ref().map(|s| s.code),
                _ => None,
            },
            Step::Continue(_) => None,
        }
    }
}

impl Session {
    /// Answer one phase of the request.
    pub async fn handle<E: RuleEngine, A: Approver>(
        &mut self,
        judge: &Judge<E, A>,
        message: ProcessingRequest,
    ) -> Step {
        if message.protocol_config.is_some() {
            self.protocol = message.protocol_config;
        }
        match message.request {
            Some(Phase::RequestHeaders(h)) => self.request_headers(judge, &h),
            Some(Phase::RequestBody(b)) => self.request_body(judge, b),
            Some(Phase::ResponseHeaders(h)) => self.response_headers(&h),
            Some(Phase::ResponseBody(b)) => self.response_body(judge, &b).await,
            Some(Phase::RequestTrailers(_)) => {
                Step::Continue(reply(Reply::RequestTrailers(TrailersResponse::default())))
            }
            Some(Phase::ResponseTrailers(_)) => {
                Step::Continue(reply(Reply::ResponseTrailers(TrailersResponse::default())))
            }
            None => refuse(STATUS_MISCONFIGURED, "pasu: an empty ext_proc message"),
        }
    }

    fn request_headers<E: RuleEngine, A: Approver>(
        &mut self,
        judge: &Judge<E, A>,
        h: &HttpHeaders,
    ) -> Step {
        let method = header(h, ":method").unwrap_or_default();
        let path = header(h, ":path").unwrap_or_default();
        let path = path.split('?').next().unwrap_or_default();
        let route = judge.route(&method, path);
        self.route = Some(route);
        match route {
            Route::Unknown => refuse(
                STATUS_FORBIDDEN,
                &Judge::<E, A>::unknown_endpoint(&method, path),
            ),
            Route::Passthrough => {
                Step::Continue(reply(Reply::RequestHeaders(HeadersResponse::default())))
            }
            Route::Completion | Route::RequestOnly => {
                if let Some(problem) = self.misconfigured(route, !judge.inspectors.is_empty()) {
                    return refuse(STATUS_MISCONFIGURED, problem);
                }
                let mut r = reply(Reply::RequestHeaders(HeadersResponse {
                    response: Some(CommonResponse {
                        // A compressed body is bytes the parser cannot read.
                        header_mutation: Some(set_header("accept-encoding", "identity")),
                        ..CommonResponse::default()
                    }),
                }));
                // Honoured only with `allow_mode_override`; harmless without.
                r.mode_override = Some(ProcessingMode {
                    request_header_mode: HeaderSendMode::Send as i32,
                    response_header_mode: HeaderSendMode::Send as i32,
                    request_body_mode: BodySendMode::Buffered as i32,
                    response_body_mode: if route == Route::Completion {
                        BodySendMode::Buffered as i32
                    } else {
                        BodySendMode::None as i32
                    },
                    ..ProcessingMode::default()
                });
                Step::Continue(r)
            }
        }
    }

    /// A filter configured so that a body pasu must judge would never reach it.
    /// Without this, `response_body_mode: NONE` would let every tool call
    /// through unseen — the server cannot judge what it is never sent.
    fn misconfigured(&self, route: Route, inspecting: bool) -> Option<&'static str> {
        let p = self.protocol?;
        let buffered = BodySendMode::Buffered as i32;
        if route == Route::Completion && p.response_body_mode != buffered {
            return Some(
                "pasu: ext_proc response_body_mode must be BUFFERED, or tool calls in \
                 completions would never be judged",
            );
        }
        if inspecting && p.request_body_mode != buffered {
            return Some(
                "pasu: ext_proc request_body_mode must be BUFFERED while an inspector is on, \
                 or prompts would never be screened",
            );
        }
        None
    }

    fn request_body<E: RuleEngine, A: Approver>(
        &mut self,
        judge: &Judge<E, A>,
        b: HttpBody,
    ) -> Step {
        let Some(route) = self.route else {
            return refuse(
                STATUS_MISCONFIGURED,
                "pasu: a body arrived before its headers; set request_header_mode to SEND",
            );
        };
        if route == Route::Passthrough {
            return Step::Continue(reply(Reply::RequestBody(BodyResponse::default())));
        }
        if !b.end_of_stream {
            return refuse(STATUS_MISCONFIGURED, NOT_BUFFERED);
        }
        if b.body.len() > judge.options.max_request_bytes {
            return refuse(STATUS_TOO_LARGE, "pasu: the request body exceeds the limit");
        }
        let original = Bytes::from(b.body);
        match judge.screen_request(original.clone()) {
            Screened::Refuse(reason) => refuse(STATUS_FORBIDDEN, &reason),
            Screened::Send(body) if body == original => {
                Step::Continue(reply(Reply::RequestBody(BodyResponse::default())))
            }
            Screened::Send(body) => {
                // Envoy checks a buffered body against the content-length it
                // already has; a rewrite must carry the new one.
                let length = body.len().to_string();
                Step::Continue(reply(Reply::RequestBody(BodyResponse {
                    response: Some(CommonResponse {
                        header_mutation: Some(set_header("content-length", &length)),
                        body_mutation: Some(BodyMutation {
                            mutation: Some(Mutation::Body(body.to_vec())),
                        }),
                        ..CommonResponse::default()
                    }),
                })))
            }
        }
    }

    fn response_headers(&mut self, h: &HttpHeaders) -> Step {
        self.status = header(h, ":status")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        self.content_type = header(h, "content-type");
        self.identity_encoded =
            header(h, "content-encoding").is_none_or(|e| e.trim().eq_ignore_ascii_case("identity"));
        Step::Continue(reply(Reply::ResponseHeaders(HeadersResponse::default())))
    }

    async fn response_body<E: RuleEngine, A: Approver>(
        &mut self,
        judge: &Judge<E, A>,
        b: &HttpBody,
    ) -> Step {
        let Some(route) = self.route else {
            return refuse(
                STATUS_MISCONFIGURED,
                "pasu: a response arrived for a request whose headers were never sent",
            );
        };
        let judged = route == Route::Completion && (200..300).contains(&self.status);
        if judged && !b.end_of_stream {
            return refuse(STATUS_MISCONFIGURED, NOT_BUFFERED);
        }
        if b.body.len() > judge.options.max_response_bytes {
            return refuse(STATUS_FORBIDDEN, "pasu: the response exceeds the limit");
        }
        let view = ResponseView {
            status: self.status,
            content_type: self.content_type.as_deref(),
            identity_encoded: self.identity_encoded,
            body: &b.body,
        };
        match judge.judge_response(route, view).await {
            Ok(()) => Step::Continue(reply(Reply::ResponseBody(BodyResponse::default()))),
            Err(reason) => refuse(STATUS_FORBIDDEN, &reason),
        }
    }
}

/// A header's value. Envoy sends `raw_value` (bytes); older builds `value`.
fn header(h: &HttpHeaders, name: &str) -> Option<String> {
    let map: &HeaderMap = h.headers.as_ref()?;
    let v: &HeaderValue = map
        .headers
        .iter()
        .find(|v| v.key.eq_ignore_ascii_case(name))?;
    if !v.raw_value.is_empty() {
        return String::from_utf8(v.raw_value.clone()).ok();
    }
    Some(v.value.clone())
}

fn set_header(key: &str, value: &str) -> HeaderMutation {
    HeaderMutation {
        set_headers: vec![HeaderValueOption {
            header: Some(HeaderValue {
                key: key.to_string(),
                raw_value: value.as_bytes().to_vec(),
                ..HeaderValue::default()
            }),
            ..HeaderValueOption::default()
        }],
        remove_headers: Vec::new(),
    }
}

fn reply(r: Reply) -> ProcessingResponse {
    ProcessingResponse {
        response: Some(r),
        ..ProcessingResponse::default()
    }
}

/// A local reply shaped like the reverse proxy's refusal, so a client sees the
/// same error whichever front-end stopped it.
fn refuse(status: i32, message: &str) -> Step {
    let body = serde_json::json!({
        "error": { "message": message, "type": "pasu_policy_block" }
    });
    Step::Refuse(reply(Reply::ImmediateResponse(ImmediateResponse {
        status: Some(HttpStatus { code: status }),
        headers: Some(set_header("content-type", "application/json")),
        body: body.to_string().into_bytes(),
        details: "pasu_policy_block".into(),
        ..ImmediateResponse::default()
    })))
}
