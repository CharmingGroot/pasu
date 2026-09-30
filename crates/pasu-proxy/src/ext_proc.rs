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
//! pasu must see the whole body before any of it reaches the other side, so
//! a body it judges is held until its last byte, whichever body mode Envoy uses:
//!
//! | body mode | while the body arrives | once it is whole |
//! |---|---|---|
//! | `BUFFERED` | (one message) | pass it, rewrite it, or refuse |
//! | `STREAMED` | answer each piece by clearing it, so Envoy forwards nothing | replace the last piece with the whole body, or refuse |
//! | `FULL_DUPLEX_STREAMED` | answer nothing | send the whole body back, or refuse |
//!
//! A refusal is an `ImmediateResponse`. Before the client has seen the
//! response that is a clean local reply; under `STREAMED` the response headers
//! have already gone downstream by the time the body is judged, so a refused
//! completion ends as a reset stream — without any of its bytes. Under
//! `FULL_DUPLEX_STREAMED` pasu also withholds the response headers' answer, so
//! the refusal is again a clean local reply. A body that could only be judged
//! in part (`NONE`, `BUFFERED_PARTIAL`, or a mode nobody reported yet pieces
//! arrived) is refused with a 500 that names the setting, rather than let
//! through.

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
    StreamedBodyResponse, TrailersResponse,
};
use pasu_core::{Approver, RuleEngine};
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt};

pub use envoy_types::pb::envoy::service::ext_proc::v3::external_processor_server::ExternalProcessorServer;

use crate::judge::{Judge, ResponseView, Screened};
use crate::parse::Route;

const STATUS_FORBIDDEN: i32 = 403;
const STATUS_TOO_LARGE: i32 = 413;
const STATUS_MISCONFIGURED: i32 = 500;

/// Envoy's recommended ceiling for one full-duplex body response.
const STREAMED_REPLY_BYTES: usize = 64 * 1024;

const NOT_BUFFERED: &str = "pasu: this completion's body did not arrive whole, so it could not \
                            be judged. Set the ext_proc processing_mode body modes to BUFFERED, \
                            STREAMED or FULL_DUPLEX_STREAMED";
const ENDS_IN_TRAILERS: &str = "pasu: a streamed body ended in trailers before it was judged, so \
                                it was not forwarded";
const REQUEST_TOO_LARGE: &str = "pasu: the request body exceeds the limit";
const RESPONSE_TOO_LARGE: &str = "pasu: the response exceeds the limit";

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
                for response in step.into_responses() {
                    if tx.send(Ok(response)).await.is_err() {
                        return;
                    }
                }
                if last {
                    break;
                }
            }
        });
        Ok(tonic::Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

/// Which way a body travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Request,
    Response,
}

/// How Envoy delivers one direction's body, as far as holding it goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delivery {
    /// In one message: `BUFFERED`, or a mode Envoy did not report. A piece is
    /// refused, because nothing says how to hold one back.
    Whole,
    /// `STREAMED`: every piece is answered, so a held piece is answered by
    /// clearing it.
    Streamed,
    /// `FULL_DUPLEX_STREAMED`: pieces are answered freely, so a held piece is
    /// answered by nothing until the body is whole.
    FullDuplex,
}

impl Delivery {
    fn of(mode: i32) -> Self {
        match BodySendMode::try_from(mode) {
            Ok(BodySendMode::Streamed) => Self::Streamed,
            Ok(BodySendMode::FullDuplexStreamed) => Self::FullDuplex,
            _ => Self::Whole,
        }
    }
}

/// Whether `mode` shows the server every byte of a body before it goes on.
fn shows_whole_body(mode: i32) -> bool {
    matches!(
        BodySendMode::try_from(mode),
        Ok(BodySendMode::Buffered | BodySendMode::Streamed | BodySendMode::FullDuplexStreamed)
    )
}

/// The pieces of a judged body that have arrived and been kept back.
#[derive(Default)]
struct Held {
    bytes: Vec<u8>,
    pieces: usize,
}

/// What collecting one piece of a judged body came to.
enum Gathered {
    /// Answer with this and wait for more (or stop).
    Answer(Box<Step>),
    /// The body is whole. `split` if earlier pieces were held back.
    Whole { body: Vec<u8>, split: bool },
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
    request_held: Held,
    response_held: Held,
    /// Full duplex: the answer to the response headers, withheld until the
    /// body is judged so that a refusal can still be a clean local reply.
    response_headers_answer: Option<ProcessingResponse>,
}

/// The answer to one phase.
pub enum Step {
    /// Carry on (possibly with mutations).
    Continue(ProcessingResponse),
    /// Carry on with several answers, in order: a withheld headers answer and
    /// a whole body sent back in pieces (full duplex).
    Release(Vec<ProcessingResponse>),
    /// Answer nothing yet: pasu is holding this piece until the body is whole.
    Hold,
    /// Stop this request with a local reply. The stream ends here.
    Refuse(ProcessingResponse),
}

impl Step {
    fn is_final(&self) -> bool {
        matches!(self, Step::Refuse(_))
    }

    /// The protobufs to send back, in order. Empty while holding.
    pub fn into_responses(self) -> Vec<ProcessingResponse> {
        match self {
            Step::Continue(r) | Step::Refuse(r) => vec![r],
            Step::Release(rs) => rs,
            Step::Hold => Vec::new(),
        }
    }

    /// The local reply's status, if this step refuses.
    pub fn refused_with(&self) -> Option<i32> {
        match self {
            Step::Refuse(r) => match &r.response {
                Some(Reply::ImmediateResponse(i)) => i.status.as_ref().map(|s| s.code),
                _ => None,
            },
            _ => None,
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
            Some(Phase::ResponseBody(b)) => self.response_body(judge, b).await,
            Some(Phase::RequestTrailers(_)) => self.trailers(Direction::Request),
            Some(Phase::ResponseTrailers(_)) => self.trailers(Direction::Response),
            None => refuse(STATUS_MISCONFIGURED, "pasu: an empty ext_proc message"),
        }
    }

    fn delivery(&self, direction: Direction) -> Delivery {
        let Some(p) = self.protocol else {
            return Delivery::Whole;
        };
        Delivery::of(match direction {
            Direction::Request => p.request_body_mode,
            Direction::Response => p.response_body_mode,
        })
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
                // Not sent over a streamed mode: pasu holds those itself, and
                // would otherwise answer pieces for a mode Envoy stopped using.
                if self.delivery(Direction::Request) == Delivery::Whole
                    && self.delivery(Direction::Response) == Delivery::Whole
                {
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
                }
                Step::Continue(r)
            }
        }
    }

    /// A filter configured so that a body pasu must judge would never reach it
    /// whole. Without this, `response_body_mode: NONE` would let every tool
    /// call through unseen — the server cannot judge what it is never sent —
    /// and `BUFFERED_PARTIAL` would show it only the first part.
    fn misconfigured(&self, route: Route, inspecting: bool) -> Option<&'static str> {
        let p = self.protocol?;
        if route == Route::Completion && !shows_whole_body(p.response_body_mode) {
            return Some(
                "pasu: ext_proc response_body_mode must be BUFFERED, STREAMED or \
                 FULL_DUPLEX_STREAMED, or tool calls in completions would never be judged",
            );
        }
        if inspecting && !shows_whole_body(p.request_body_mode) {
            return Some(
                "pasu: ext_proc request_body_mode must be BUFFERED, STREAMED or \
                 FULL_DUPLEX_STREAMED while an inspector is on, or prompts would never be \
                 screened",
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
        let delivery = self.delivery(Direction::Request);
        // A prompt nothing reads is not held. BUFFERED keeps its checks (no
        // pieces, the size cap) either way, as it always has.
        let held = delivery == Delivery::Whole || !judge.inspectors.is_empty();
        if route == Route::Passthrough || !held {
            return forward(Direction::Request, delivery, b);
        }
        let (body, split) = match gather(
            &mut self.request_held,
            Direction::Request,
            delivery,
            b,
            judge.options.max_request_bytes,
            || refuse(STATUS_TOO_LARGE, REQUEST_TOO_LARGE),
        ) {
            Gathered::Answer(step) => return *step,
            Gathered::Whole { body, split } => (body, split),
        };
        let original = Bytes::from(body);
        match judge.screen_request(original.clone()) {
            Screened::Refuse(reason) => refuse(STATUS_FORBIDDEN, &reason),
            Screened::Send(body) => release(Direction::Request, delivery, &original, &body, split),
        }
    }

    fn response_headers(&mut self, h: &HttpHeaders) -> Step {
        self.status = header(h, ":status")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        self.content_type = header(h, "content-type");
        self.identity_encoded =
            header(h, "content-encoding").is_none_or(|e| e.trim().eq_ignore_ascii_case("identity"));
        let answer = reply(Reply::ResponseHeaders(HeadersResponse::default()));
        if self.response_judged()
            && !h.end_of_stream
            && self.delivery(Direction::Response) == Delivery::FullDuplex
        {
            self.response_headers_answer = Some(answer);
            return Step::Hold;
        }
        Step::Continue(answer)
    }

    fn response_judged(&self) -> bool {
        self.route == Some(Route::Completion) && (200..300).contains(&self.status)
    }

    async fn response_body<E: RuleEngine, A: Approver>(
        &mut self,
        judge: &Judge<E, A>,
        b: HttpBody,
    ) -> Step {
        let Some(route) = self.route else {
            return refuse(
                STATUS_MISCONFIGURED,
                "pasu: a response arrived for a request whose headers were never sent",
            );
        };
        let delivery = self.delivery(Direction::Response);
        if !self.response_judged() {
            if b.body.len() > judge.options.max_response_bytes {
                return refuse(STATUS_FORBIDDEN, RESPONSE_TOO_LARGE);
            }
            return forward(Direction::Response, delivery, b);
        }
        let (body, split) = match gather(
            &mut self.response_held,
            Direction::Response,
            delivery,
            b,
            judge.options.max_response_bytes,
            || refuse(STATUS_FORBIDDEN, RESPONSE_TOO_LARGE),
        ) {
            Gathered::Answer(step) => return *step,
            Gathered::Whole { body, split } => (body, split),
        };
        let view = ResponseView {
            status: self.status,
            content_type: self.content_type.as_deref(),
            identity_encoded: self.identity_encoded,
            body: &body,
        };
        if let Err(reason) = judge.judge_response(route, view).await {
            return refuse(STATUS_FORBIDDEN, &reason);
        }
        let released = release(Direction::Response, delivery, &body, &body, split);
        match self.response_headers_answer.take() {
            None => released,
            Some(headers) => {
                let mut all = vec![headers];
                all.extend(released.into_responses());
                Step::Release(all)
            }
        }
    }

    /// Trailers end a body. One still held was never judged, and a streamed
    /// mode has no way left to send it on — so it is refused, not dropped
    /// silently or passed.
    fn trailers(&mut self, direction: Direction) -> Step {
        let holding = match direction {
            Direction::Request => self.request_held.pieces > 0,
            Direction::Response => {
                self.response_held.pieces > 0 || self.response_headers_answer.is_some()
            }
        };
        if holding {
            return refuse(STATUS_MISCONFIGURED, ENDS_IN_TRAILERS);
        }
        let answer = TrailersResponse::default();
        Step::Continue(reply(match direction {
            Direction::Request => Reply::RequestTrailers(answer),
            Direction::Response => Reply::ResponseTrailers(answer),
        }))
    }
}

/// Keep one piece of a judged body, or hand back the whole of it.
fn gather(
    held: &mut Held,
    direction: Direction,
    delivery: Delivery,
    b: HttpBody,
    limit: usize,
    too_large: impl FnOnce() -> Step,
) -> Gathered {
    if delivery == Delivery::Whole && !b.end_of_stream {
        return Gathered::Answer(Box::new(refuse(STATUS_MISCONFIGURED, NOT_BUFFERED)));
    }
    if held.bytes.len().saturating_add(b.body.len()) > limit {
        return Gathered::Answer(Box::new(too_large()));
    }
    if !b.end_of_stream {
        held.bytes.extend_from_slice(&b.body);
        held.pieces += 1;
        return Gathered::Answer(Box::new(match delivery {
            Delivery::Streamed => {
                Step::Continue(body_answer(direction, Some(Mutation::ClearBody(true))))
            }
            Delivery::FullDuplex | Delivery::Whole => Step::Hold,
        }));
    }
    let split = held.pieces > 0;
    let mut body = std::mem::take(&mut held.bytes);
    body.extend_from_slice(&b.body);
    Gathered::Whole { body, split }
}

/// Send a body pasu does not judge on, unchanged.
fn forward(direction: Direction, delivery: Delivery, b: HttpBody) -> Step {
    let mutation = match delivery {
        // Full duplex forwards only what the server sends back.
        Delivery::FullDuplex => Some(Mutation::StreamedResponse(StreamedBodyResponse {
            body: b.body,
            end_of_stream: b.end_of_stream,
            ..StreamedBodyResponse::default()
        })),
        Delivery::Whole | Delivery::Streamed => None,
    };
    Step::Continue(body_answer(direction, mutation))
}

/// Send on a judged body, now whole: `original` as it arrived, `body` as it
/// is to leave.
fn release(
    direction: Direction,
    delivery: Delivery,
    original: &[u8],
    body: &[u8],
    split: bool,
) -> Step {
    match delivery {
        Delivery::Whole if body == original => Step::Continue(body_answer(direction, None)),
        Delivery::Whole => {
            // Envoy checks a buffered body against the content-length it
            // already has; a rewrite must carry the new one.
            let mut r = body_answer(direction, Some(Mutation::Body(body.to_vec())));
            if let Some(common) = body_common(&mut r) {
                common.header_mutation =
                    Some(set_header("content-length", &body.len().to_string()));
            }
            Step::Continue(r)
        }
        // One piece, unchanged: nothing was held back, nothing to put back.
        Delivery::Streamed if !split && body == original => {
            Step::Continue(body_answer(direction, None))
        }
        // The earlier pieces were cleared; the last one carries them all.
        Delivery::Streamed => {
            Step::Continue(body_answer(direction, Some(Mutation::Body(body.to_vec()))))
        }
        Delivery::FullDuplex => Step::Release(streamed_out(direction, body)),
    }
}

/// A whole body as full-duplex answers, the last one ending the stream.
fn streamed_out(direction: Direction, body: &[u8]) -> Vec<ProcessingResponse> {
    let mut pieces: Vec<&[u8]> = body.chunks(STREAMED_REPLY_BYTES).collect();
    if pieces.is_empty() {
        pieces.push(&[]);
    }
    let last = pieces.len() - 1;
    pieces
        .into_iter()
        .enumerate()
        .map(|(i, piece)| {
            body_answer(
                direction,
                Some(Mutation::StreamedResponse(StreamedBodyResponse {
                    body: piece.to_vec(),
                    end_of_stream: i == last,
                    ..StreamedBodyResponse::default()
                })),
            )
        })
        .collect()
}

fn body_answer(direction: Direction, mutation: Option<Mutation>) -> ProcessingResponse {
    let answer = BodyResponse {
        response: mutation.map(|m| CommonResponse {
            body_mutation: Some(BodyMutation { mutation: Some(m) }),
            ..CommonResponse::default()
        }),
    };
    reply(match direction {
        Direction::Request => Reply::RequestBody(answer),
        Direction::Response => Reply::ResponseBody(answer),
    })
}

fn body_common(r: &mut ProcessingResponse) -> Option<&mut CommonResponse> {
    match &mut r.response {
        Some(Reply::RequestBody(b) | Reply::ResponseBody(b)) => b.response.as_mut(),
        _ => None,
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
