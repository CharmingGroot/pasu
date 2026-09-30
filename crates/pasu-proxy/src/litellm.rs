//! LiteLLM's Generic Guardrail API, answered by the same [`Judge`].
//!
//! LiteLLM has already parsed the provider's shape by the time it calls a
//! guardrail — every format arrives as OpenAI-style `tool_calls` — so this
//! front-end does no wire parsing. It maps the two phases LiteLLM calls onto
//! the two questions the proxy asks:
//!
//! * `input_type: "request"` — the prompt `texts`, screened by the inspectors.
//!   A redaction is answered with the rewritten texts, in order, which LiteLLM
//!   writes back into the messages. `tool_calls` on a request are the
//!   conversation's history — calls that already ran — and are not judged.
//! * `input_type: "response"` — the `tool_calls` the model proposed, judged by
//!   the guard.
//!
//! Anything this cannot read is an HTTP error, never `NONE`: LiteLLM treats a
//! non-2xx answer as a failure and, in its default `fail_closed` mode, refuses
//! the call.
//!
//! LiteLLM streams chunks to the client while this endpoint is consulted, so a
//! streamed tool call can reach the agent before a block lands. The companion
//! class in `integrations/litellm/` buffers streams and asks here before any
//! chunk is sent.

use std::sync::Arc;

use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use pasu_core::{Approver, RuleEngine};
use serde_json::{json, Value};

use crate::judge::{Judge, TextScreen};
use crate::parse::ToolCall;

/// Where LiteLLM posts; it appends this to the configured `api_base`.
pub const LITELLM_GUARDRAIL_PATH: &str = "/beta/litellm_basic_guardrail_api";

const API_KEY_HEADER: &str = "x-api-key";

/// State for the guardrail endpoint.
pub struct GuardrailState<E: RuleEngine, A: Approver> {
    /// Every decision.
    pub judge: Judge<E, A>,
    /// When set, every call must carry it as `x-api-key` — LiteLLM's `api_key`.
    pub api_key: Option<String>,
}

/// The guardrail endpoint, plus `GET /healthz`.
pub fn guardrail_router<E, A>(state: Arc<GuardrailState<E, A>>) -> Router
where
    E: RuleEngine + Send + Sync + 'static,
    A: Approver + Send + Sync + 'static,
{
    let limit = state.judge.options.max_request_bytes;
    Router::new()
        .route(LITELLM_GUARDRAIL_PATH, post(apply::<E, A>))
        .route("/healthz", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(limit))
        .with_state(state)
}

async fn apply<E, A>(
    State(state): State<Arc<GuardrailState<E, A>>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response
where
    E: RuleEngine + Send + Sync + 'static,
    A: Approver + Send + Sync + 'static,
{
    if !authorized(state.api_key.as_deref(), &headers) {
        return error(StatusCode::UNAUTHORIZED, "missing or wrong x-api-key");
    }
    let Ok(call) = serde_json::from_slice::<Value>(&body) else {
        return error(StatusCode::BAD_REQUEST, "body is not JSON");
    };
    match call.get("input_type").and_then(Value::as_str) {
        Some("request") => request(&state.judge, &call),
        Some("response") => response(&state.judge, &call).await,
        _ => error(
            StatusCode::BAD_REQUEST,
            "input_type must be \"request\" or \"response\"",
        ),
    }
}

fn request<E: RuleEngine, A: Approver>(judge: &Judge<E, A>, call: &Value) -> Response {
    let Some(texts) = strings(call.get("texts")) else {
        return error(StatusCode::BAD_REQUEST, "texts must be a list of strings");
    };
    match judge.screen_texts(&texts) {
        TextScreen::Clean => Json(json!({"action": "NONE"})).into_response(),
        TextScreen::Refuse(reason) => blocked(&reason),
        TextScreen::Rewritten(texts) => {
            Json(json!({"action": "GUARDRAIL_INTERVENED", "texts": texts})).into_response()
        }
    }
}

async fn response<E: RuleEngine, A: Approver>(judge: &Judge<E, A>, call: &Value) -> Response {
    let Some(calls) = tool_calls(call.get("tool_calls")) else {
        // A proposed call that cannot be read cannot be judged.
        return blocked("pasu: a tool call in this response could not be read, so it was blocked");
    };
    match judge.judge_tool_calls(&calls).await {
        Ok(()) => Json(json!({"action": "NONE"})).into_response(),
        Err(reason) => blocked(&reason),
    }
}

/// `None`, absent and `[]` are no texts; anything else must be all strings.
fn strings(v: Option<&Value>) -> Option<Vec<String>> {
    match v {
        None | Some(Value::Null) => Some(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|i| i.as_str().map(str::to_string))
            .collect(),
        Some(_) => None,
    }
}

/// OpenAI-style calls: `{function: {name, arguments}}`, as a message tool call
/// or a stream chunk. Arguments are a JSON string, or occasionally an object.
fn tool_calls(v: Option<&Value>) -> Option<Vec<ToolCall>> {
    let items = match v {
        None | Some(Value::Null) => return Some(Vec::new()),
        Some(v) => v.as_array()?,
    };
    items
        .iter()
        .map(|item| {
            let function = item.get("function")?;
            let name = function.get("name")?.as_str()?;
            match function.get("arguments") {
                None | Some(Value::Null) => Some(ToolCall::from_raw_arguments(name, "")),
                Some(Value::String(raw)) => Some(ToolCall::from_raw_arguments(name, raw)),
                Some(obj @ Value::Object(_)) => Some(ToolCall {
                    name: name.to_string(),
                    arguments: obj.to_string(),
                }),
                Some(_) => None,
            }
        })
        .collect()
}

fn authorized(expected: Option<&str>, headers: &HeaderMap) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    let given = headers
        .get(API_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    given.len() == expected.len()
        && given
            .bytes()
            .zip(expected.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

fn blocked(reason: &str) -> Response {
    Json(json!({"action": "BLOCKED", "blocked_reason": reason})).into_response()
}

fn error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"error": format!("pasu: {message}")}))).into_response()
}
