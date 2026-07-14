//! pasu-proxy — an LLM-API reverse proxy that guards tool calls.
//!
//! The agent points its `base_url` at pasu-proxy; pasu forwards each request to
//! the real provider, then parses the **response** for the tool calls the model
//! proposed and evaluates them through the pasu-core [`Guard`]. A denied tool
//! call is blocked (fail-closed) before the agent ever sees it.
//!
//! Framework/SDK-agnostic by construction: the tool-call decision rides in the
//! provider response body (function calling), so parsing ~3 provider formats
//! covers every SDK — no per-SDK hook. Intent only; a tool's actual egress is
//! enforced by the kernel layer (`pasu-egress`).
//!
//! Scope today: OpenAI (+ compatible), non-streaming. Streaming (SSE) responses
//! pass through unguarded (follow-up: SSE reassembly). Anthropic / Gemini extend
//! [`parse::Provider`].
//!
//! [`Guard`]: pasu_core::Guard

pub mod inspect;
pub mod parse;
pub mod proxy;

pub use inspect::{inspect, Inspection};
pub use parse::{extract, Provider, ToolCall};
pub use proxy::{router, ProxyState};
