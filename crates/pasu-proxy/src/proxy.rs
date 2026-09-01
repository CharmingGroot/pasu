//! LLM-API reverse proxy. The agent points its `base_url` at pasu-proxy; pasu
//! forwards each request to the real provider, inspects the response's tool
//! calls, and blocks (fail-closed) any the policy denies before the agent sees
//! them. Requests are forwarded transparently; only responses are inspected.

use std::sync::Arc;

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{header, HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::any,
    Json, Router,
};
use pasu_core::{Approver, Guard, Inspector, RuleEngine, Verdict};

use crate::inspect::inspect;
use crate::parse::WireFormat;
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
}

/// Build the reverse-proxy router. Every path is forwarded to `upstream_base`.
pub fn router<E, A>(state: Arc<ProxyState<E, A>>) -> Router
where
    E: RuleEngine + Send + Sync + 'static,
    A: Approver + Send + Sync + 'static,
{
    Router::new()
        .route("/", any(forward::<E, A>))
        .route("/*rest", any(forward::<E, A>))
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

    // Before the request leaves. Past this point the payload is TLS and the
    // kernel layer can only decide by address, so this is the last place the
    // content is readable at all.
    let body = match screen_request(&state, body) {
        Screened::Send(body) => body,
        Screened::Refuse(reason) => return blocked(&reason),
    };

    let upstream = match forward_upstream(&state.client, &method, &url, &headers, body).await {
        Ok(u) => u,
        // Cannot reach upstream: fail-closed for a security proxy.
        Err(_) => return blocked("pasu-proxy: upstream request failed"),
    };

    // Inspect only bodies that parse as a tool-call-bearing response. The full
    // body is buffered either way, so streaming (SSE) responses are reassembled
    // and guarded just like non-streaming ones.
    let calls = if is_event_stream(upstream.content_type.as_deref()) {
        state.provider.tool_calls_streaming(&upstream.body)
    } else {
        state.provider.tool_calls(&upstream.body)
    };
    if let Some(calls) = calls {
        if !calls.is_empty() {
            let result = inspect(&state.guard, &calls).await;
            if let Verdict::Deny(reason) = &result.overall {
                let denied: Vec<&str> = result.denied_calls().collect();
                return blocked(&format!(
                    "pasu-proxy blocked tool call(s) {denied:?}: {reason}"
                ));
            }
        }
    }

    passthrough(upstream)
}

/// Why this request must not leave, if it must not.
///
/// Fail-closed on a hit, matching what the proxy already does when upstream is
/// unreachable. A body that does not parse as a known request shape is passed
/// through: refusing every unrecognised body would break every endpoint that is
/// not a completion, and the kernel layer is what covers the paths this cannot
/// read.
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
    if state.inspectors.is_empty() {
        return Screened::Send(body);
    }
    let Some(texts) = prompt_text(&body, state.provider.as_ref()) else {
        // Not a shape this can read. The kernel layer is what covers those.
        return Screened::Send(body);
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
    content_type: Option<String>,
    body: Bytes,
}

async fn forward_upstream(
    client: &reqwest::Client,
    method: &Method,
    url: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<Upstream, reqwest::Error> {
    let method =
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::POST);
    let mut req = client.request(method, url).body(body.to_vec());
    for (name, value) in headers {
        // reqwest sets host/content-length itself for the new request.
        if name == header::HOST || name == header::CONTENT_LENGTH {
            continue;
        }
        req = req.header(name.as_str(), value.as_bytes());
    }
    let resp = req.send().await?;
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = resp.bytes().await?;
    Ok(Upstream {
        status,
        content_type,
        body,
    })
}

fn passthrough(upstream: Upstream) -> Response {
    let mut builder = Response::builder().status(upstream.status);
    if let Some(ct) = upstream.content_type {
        builder = builder.header(header::CONTENT_TYPE, ct);
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
