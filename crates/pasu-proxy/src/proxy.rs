//! LLM-API reverse proxy. The agent points its `base_url` at pasu-proxy; pasu
//! forwards each request to the real provider, inspects the response's tool
//! calls, and blocks (fail-closed) any the policy denies before the agent sees
//! them.
//!
//! Only endpoints the wire format names are forwarded. A completion's response
//! must parse as the format's response or it is refused, and the upstream is
//! asked for an uncompressed body so that it can be read at all.

use std::sync::Arc;

use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::any,
    Json, Router,
};
use pasu_core::{Approver, Guard, Inspector, RuleEngine, Verdict};

use crate::inspect::inspect;
use crate::parse::{Route, WireFormat};
use crate::prompt::{prompt_text, rewrite_prompt};
use crate::stream::is_event_stream;
use pasu_core::redact::{redact, Action, Policy as RedactionPolicy};

/// Shared proxy state: the guard (policy + HITL + audit), an HTTP client, the
/// upstream provider base URL, and which wire format to parse.
pub struct ProxyState<E: RuleEngine, A: Approver> {
    /// Judges each parsed tool call.
    pub guard: Guard<E, A>,
    /// Client used to forward to the upstream provider.
    pub client: reqwest::Client,
    /// Upstream base URL, e.g. `https://api.openai.com`.
    pub upstream_base: String,
    /// Wire format to parse responses as.
    /// The wire format to parse. A trait object, not the enum: the proxy runs a
    /// format rather than knowing which ones exist, so an in-house shape needs
    /// no change here.
    pub provider: Arc<dyn WireFormat>,
    /// What reads the prompt before it leaves, if anything.
    ///
    /// Empty is the default and means the request path is forwarded untouched —
    /// the behaviour before this existed. A deployment with no exposure to what
    /// an inspector matches should not have an agent stopped mid-task by a
    /// false positive it never asked for.
    ///
    /// A `Vec` rather than one inspector because the question a deployment has
    /// is rarely single: Korean PII *and* cloud credentials *and* an in-house
    /// pattern. Each is a [`pasu_core::Inspector`] and none of them needs this
    /// file to change.
    pub inspectors: Vec<Arc<dyn Inspector>>,
    /// Which findings refuse the request and which are replaced in it.
    ///
    /// Blocking everything is the default and is what the proxy did before
    /// redaction existed.
    pub redaction: RedactionPolicy,
    /// Size limits and operator-named exceptions.
    pub options: ProxyOptions,
}

/// Default request cap. Large enough for vision payloads and long contexts,
/// which routinely exceed axum's 2 MiB default.
pub const DEFAULT_MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;
/// Default response cap. A long streamed completion is mostly SSE framing.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// Knobs with a safe default each.
#[derive(Debug, Clone)]
pub struct ProxyOptions {
    /// A request body larger than this is refused (413).
    pub max_request_bytes: usize,
    /// A response body larger than this is refused rather than buffered. The
    /// read timeout is an idle one, so without this a stream that never stops
    /// sending would be buffered without end.
    pub max_response_bytes: usize,
    /// Paths (no query) forwarded without any inspection, whatever the format
    /// says about them. For endpoints the operator has decided about.
    pub passthrough_paths: Vec<String>,
}

impl Default for ProxyOptions {
    fn default() -> Self {
        Self {
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            passthrough_paths: Vec::new(),
        }
    }
}

/// Build the reverse-proxy router. Every path is forwarded to `upstream_base`.
pub fn router<E, A>(state: Arc<ProxyState<E, A>>) -> Router
where
    E: RuleEngine + Send + Sync + 'static,
    A: Approver + Send + Sync + 'static,
{
    let limit = state.options.max_request_bytes;
    Router::new()
        .route("/", any(forward::<E, A>))
        .route("/*rest", any(forward::<E, A>))
        .layer(DefaultBodyLimit::max(limit))
        .with_state(state)
}

async fn forward<E, A>(
    State(state): State<Arc<ProxyState<E, A>>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    E: RuleEngine + Send + Sync + 'static,
    A: Approver + Send + Sync + 'static,
{
    let path = uri.path_and_query().map_or("/", |p| p.as_str());
    let url = format!("{}{path}", state.upstream_base.trim_end_matches('/'));
    let route = route_for(&state, &method, uri.path());

    if route == Route::Unknown {
        return blocked(&format!(
            "pasu-proxy: {} {} is not an endpoint this proxy guards, so it was not sent \
             (--passthrough-path forwards a path uninspected)",
            method,
            uri.path()
        ));
    }

    // Before the request leaves. Past this point the payload is TLS and the
    // kernel layer can only decide by address, so this is the last place the
    // content is readable at all.
    let body = if route == Route::Passthrough {
        body
    } else {
        match screen_request(&state, body) {
            Screened::Send(body) => body,
            Screened::Refuse(reason) => return blocked(&reason),
        }
    };

    let limit = state.options.max_response_bytes;
    let upstream = match forward_upstream(&state.client, &method, &url, &headers, body, limit).await
    {
        Ok(u) => u,
        // Cannot reach upstream: fail-closed for a security proxy.
        Err(UpstreamError::Transport) => return blocked("pasu-proxy: upstream request failed"),
        Err(UpstreamError::TooLarge) => {
            return blocked(&format!(
                "pasu-proxy: the response exceeded {limit} bytes and was not delivered"
            ))
        }
    };

    if route != Route::Completion || !upstream.status.is_success() {
        // A provider error cannot carry a tool call, and turning a 429 into a
        // 403 would break every client's retry.
        return passthrough(upstream);
    }

    if !upstream.is_identity_encoded() {
        return blocked(
            "pasu-proxy: the provider compressed its response, so it could not be read",
        );
    }

    // The full body is buffered either way, so streaming (SSE) responses are
    // reassembled and guarded just like non-streaming ones.
    let calls = if is_event_stream(upstream.content_type()) {
        state.provider.tool_calls_streaming(&upstream.body)
    } else {
        state.provider.tool_calls(&upstream.body)
    };
    let Some(calls) = calls else {
        return blocked(&format!(
            "pasu-proxy: the response is not a {} response it can read, so its tool calls \
             could not be checked",
            state.provider.name()
        ));
    };
    if !calls.is_empty() {
        let result = inspect(&state.guard, &calls).await;
        if let Verdict::Deny(reason) = &result.overall {
            let denied: Vec<&str> = result.denied_calls().collect();
            return blocked(&format!(
                "pasu-proxy blocked tool call(s) {denied:?}: {reason}"
            ));
        }
    }

    passthrough(upstream)
}

fn route_for<E: RuleEngine, A: Approver>(
    state: &ProxyState<E, A>,
    method: &Method,
    path: &str,
) -> Route {
    if state.options.passthrough_paths.iter().any(|p| p == path) {
        return Route::Passthrough;
    }
    state.provider.route(method.as_str(), path)
}

/// Why this request must not leave, if it must not.
///
/// Fail-closed on a hit, matching what the proxy already does when upstream is
/// unreachable — and on a body that does not parse, since an inspector that
/// cannot see the prompt has not checked it. Endpoints that carry no prompt are
/// routed around this entirely.
/// What screening decided: send this body, or refuse with this reason.
enum Screened {
    Send(Bytes),
    Refuse(String),
}

/// Inspect the prompt, and either refuse, rewrite it, or leave it alone.
///
/// A blocking finding wins over a redactable one in the same request. Sending a
/// body with one rule removed while another rule said "stop" would be answering
/// the wrong question.
fn screen_request<E, A>(state: &ProxyState<E, A>, body: Bytes) -> Screened
where
    E: RuleEngine,
    A: Approver,
{
    if state.inspectors.is_empty() || body.is_empty() {
        return Screened::Send(body);
    }
    let Some(texts) = prompt_text(&body, state.provider.as_ref()) else {
        // An inspector was asked for, and this body cannot be shown to it.
        return Screened::Refuse(format!(
            "pasu-proxy blocked this request: it is not a {} request it can read, so its \
             prompt could not be inspected",
            state.provider.name()
        ));
    };

    let mut findings = Vec::new();
    for text in &texts {
        for inspector in &state.inspectors {
            findings.extend(inspector.inspect(text));
        }
    }
    if findings.is_empty() {
        return Screened::Send(body);
    }

    if let Some(finding) = findings
        .iter()
        .find(|f| state.redaction.action_for(&f.rule) == Action::Block)
    {
        // The inspector and rule ids, never the value. `Finding` carries no
        // value for exactly this reason: a block that quotes what it caught is
        // the leak it was meant to stop.
        return Screened::Refuse(format!(
            "pasu-proxy blocked this request: its prompt matched {}/{} and was not sent",
            finding.inspector, finding.rule
        ));
    }

    let mut replaced: Vec<String> = Vec::new();
    let rewritten = rewrite_prompt(&body, state.provider.as_ref(), &mut |text| {
        let out = redact(text, &findings, &state.redaction)?;
        replaced.extend(out.rules);
        Some(out.text)
    });

    match rewritten {
        Some(new_body) if !replaced.is_empty() => {
            replaced.sort();
            replaced.dedup();
            // An altered prompt that says nothing is a debugging trap: the model
            // answers about text the operator never wrote. Counts and rule ids
            // only — saying which values were removed would undo the removal.
            eprintln!(
                "pasu-proxy: redacted {} span(s) from this request ({})",
                replaced.len(),
                replaced.join(", ")
            );
            Screened::Send(Bytes::from(new_body))
        }
        // Findings existed but none could be replaced — an off-boundary span, or
        // a shape that would not rebuild. Fail closed rather than forward a body
        // that still carries what was found.
        _ => Screened::Refuse(
            "pasu-proxy blocked this request: its prompt matched a rule that could not be \
             redacted safely, so it was not sent"
                .into(),
        ),
    }
}

struct Upstream {
    status: StatusCode,
    headers: reqwest::header::HeaderMap,
    body: Bytes,
}

impl Upstream {
    fn content_type(&self) -> Option<&str> {
        self.headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
    }

    fn is_identity_encoded(&self) -> bool {
        self.headers
            .get_all(reqwest::header::CONTENT_ENCODING)
            .iter()
            .all(|v| {
                v.to_str()
                    .is_ok_and(|e| e.trim().eq_ignore_ascii_case("identity"))
            })
    }
}

enum UpstreamError {
    Transport,
    TooLarge,
}

/// Headers that describe one connection, not the message (RFC 9110 §7.6.1).
/// Forwarding them lets a client steer the proxy's own upstream connection.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Headers the proxy sets itself on the way out.
const SET_BY_PROXY: &[&str] = &["host", "content-length", "accept-encoding"];

fn is_forwardable(name: &str, connection_listed: &[String]) -> bool {
    !HOP_BY_HOP.contains(&name)
        && !SET_BY_PROXY.contains(&name)
        && !connection_listed.iter().any(|c| c == name)
}

/// Header names a `Connection` header lists, which are hop-by-hop too.
fn connection_listed(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

async fn forward_upstream(
    client: &reqwest::Client,
    method: &Method,
    url: &str,
    headers: &HeaderMap,
    body: Bytes,
    max_response_bytes: usize,
) -> Result<Upstream, UpstreamError> {
    let method =
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::POST);
    let listed = connection_listed(headers);
    let mut req = client.request(method, url).body(body);
    for (name, value) in headers {
        if is_forwardable(name.as_str(), &listed) {
            req = req.header(name.as_str(), value.as_bytes());
        }
    }
    // A compressed body is bytes the parser cannot read. Ask for the plain one.
    req = req.header(reqwest::header::ACCEPT_ENCODING, "identity");

    let mut resp = req.send().await.map_err(|_| UpstreamError::Transport)?;
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    if resp
        .content_length()
        .is_some_and(|n| n > max_response_bytes as u64)
    {
        return Err(UpstreamError::TooLarge);
    }
    let headers = std::mem::take(resp.headers_mut());
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|_| UpstreamError::Transport)? {
        if body.len() + chunk.len() > max_response_bytes {
            return Err(UpstreamError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Upstream {
        status,
        headers,
        body: Bytes::from(body),
    })
}

/// Response headers the proxy does not relay: hop-by-hop ones, and the framing
/// headers axum recomputes for the body it sends.
const NOT_RELAYED: &[&str] = &["content-length"];

fn passthrough(upstream: Upstream) -> Response {
    let mut builder = Response::builder().status(upstream.status);
    for (name, value) in &upstream.headers {
        let name = name.as_str();
        if HOP_BY_HOP.contains(&name) || NOT_RELAYED.contains(&name) {
            continue;
        }
        let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) else {
            continue;
        };
        builder = builder.header(name, value);
    }
    builder
        .body(Body::from(upstream.body))
        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
}

fn blocked(message: &str) -> Response {
    let body = serde_json::json!({
        "error": { "message": message, "type": "pasu_policy_block" }
    });
    (StatusCode::FORBIDDEN, Json(body)).into_response()
}
