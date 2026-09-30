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
use pasu_core::{Approver, RuleEngine};

use crate::judge::{Judge, ResponseView, Screened};
use crate::parse::Route;

pub use crate::judge::{ProxyOptions, DEFAULT_MAX_REQUEST_BYTES, DEFAULT_MAX_RESPONSE_BYTES};

/// Reverse-proxy state: the decisions, plus where and how to forward.
pub struct ProxyState<E: RuleEngine, A: Approver> {
    /// Every decision the proxy makes.
    pub judge: Judge<E, A>,
    /// Client used to forward to the upstream provider.
    pub client: reqwest::Client,
    /// Upstream base URL, e.g. `https://api.openai.com`.
    pub upstream_base: String,
}

/// Build the reverse-proxy router. Every path is forwarded to `upstream_base`.
pub fn router<E, A>(state: Arc<ProxyState<E, A>>) -> Router
where
    E: RuleEngine + Send + Sync + 'static,
    A: Approver + Send + Sync + 'static,
{
    let limit = state.judge.options.max_request_bytes;
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
    let judge = &state.judge;
    let path = uri.path_and_query().map_or("/", |p| p.as_str());
    let url = format!("{}{path}", state.upstream_base.trim_end_matches('/'));
    let route = judge.route(method.as_str(), uri.path());

    if route == Route::Unknown {
        return blocked(&Judge::<E, A>::unknown_endpoint(
            method.as_str(),
            uri.path(),
        ));
    }

    // Before the request leaves. Past this point the payload is TLS and the
    // kernel layer can only decide by address, so this is the last place the
    // content is readable at all.
    let body = if route == Route::Passthrough {
        body
    } else {
        match judge.screen_request(body) {
            Screened::Send(body) => body,
            Screened::Refuse(reason) => return blocked(&reason),
        }
    };

    let limit = judge.options.max_response_bytes;
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

    let view = ResponseView {
        status: upstream.status.as_u16(),
        content_type: upstream.content_type(),
        identity_encoded: upstream.is_identity_encoded(),
        body: &upstream.body,
    };
    if let Err(reason) = judge.judge_response(route, view).await {
        return blocked(&reason);
    }
    passthrough(upstream)
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
