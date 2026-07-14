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
use pasu_core::{Approver, Guard, RuleEngine, Verdict};

use crate::inspect::inspect;
use crate::parse::{extract, Provider};

/// Shared proxy state: the guard (policy + HITL + audit), an HTTP client, the
/// upstream provider base URL, and which wire format to parse.
pub struct ProxyState<E: RuleEngine, A: Approver> {
    pub guard: Guard<E, A>,
    pub client: reqwest::Client,
    pub upstream_base: String,
    pub provider: Provider,
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

    let upstream = match forward_upstream(&state.client, &method, &url, &headers, body).await {
        Ok(u) => u,
        // Cannot reach upstream: fail-closed for a security proxy.
        Err(_) => return blocked("pasu-proxy: upstream request failed"),
    };

    // Inspect only bodies that parse as a tool-call-bearing response.
    if let Some(calls) = extract(&upstream.body, state.provider) {
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
