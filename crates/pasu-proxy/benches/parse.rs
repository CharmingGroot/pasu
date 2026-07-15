//! Micro-benchmarks for the proxy hot path — the CPU the guard adds to every
//! LLM response: extracting tool calls from the body (per provider, streaming
//! and not). Policy evaluation on top of this is benched in pasu-rules.
//! Run: `cargo bench -p pasu-proxy`.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pasu_proxy::stream::extract_stream;
use pasu_proxy::{extract, Provider};

// Realistic non-streaming bodies: one tool call plus the usual envelope noise.
const OPENAI_BODY: &[u8] = br#"{
  "id": "chatcmpl-9x0", "object": "chat.completion", "created": 1720000000,
  "model": "gpt-4o", "usage": {"prompt_tokens": 812, "completion_tokens": 41, "total_tokens": 853},
  "choices": [ { "index": 0, "finish_reason": "tool_calls",
    "message": { "role": "assistant", "content": null, "tool_calls": [
      { "id": "call_1", "type": "function",
        "function": { "name": "web_search", "arguments": "{\"query\":\"rust ebpf cgroup egress\",\"top_k\":5}" } }
    ] } } ]
}"#;

const ANTHROPIC_BODY: &[u8] = br#"{
  "id": "msg_01", "type": "message", "role": "assistant", "model": "claude-sonnet-4-5",
  "usage": {"input_tokens": 812, "output_tokens": 41},
  "stop_reason": "tool_use",
  "content": [
    { "type": "text", "text": "I'll search for that." },
    { "type": "tool_use", "id": "tu_1", "name": "web_search",
      "input": { "query": "rust ebpf cgroup egress", "top_k": 5 } }
  ]
}"#;

const GEMINI_BODY: &[u8] = br#"{
  "candidates": [ { "finishReason": "STOP", "content": { "role": "model", "parts": [
    { "functionCall": { "name": "web_search",
      "args": { "query": "rust ebpf cgroup egress", "top_k": 5 } } }
  ] } } ],
  "usageMetadata": { "promptTokenCount": 812, "candidatesTokenCount": 41 }
}"#;

// A ~40-chunk OpenAI SSE stream: a short text preamble, then one tool call with
// its arguments split across chunks — the shape a real streamed call has.
fn openai_sse_body() -> Vec<u8> {
    let mut s = String::new();
    for i in 0..20 {
        s.push_str(&format!(
            "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"token{i} \"}}}}]}}\n\n"
        ));
    }
    s.push_str(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",\"function\":{\"name\":\"web_search\",\"arguments\":\"\"}}]}}]}\n\n",
    );
    let pieces = [
        r#"{\"query\":\"rust"#,
        r#" ebpf"#,
        r#" cgroup"#,
        r#" egress\""#,
        r#",\"top_k\":5}"#,
    ];
    for piece in pieces {
        s.push_str(&format!(
            "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"tool_calls\":[{{\"index\":0,\"function\":{{\"arguments\":\"{piece}\"}}}}]}}}}]}}\n\n"
        ));
    }
    s.push_str("data: [DONE]\n\n");
    s.into_bytes()
}

fn bench_extract(c: &mut Criterion) {
    c.bench_function("extract/openai", |b| {
        b.iter(|| extract(black_box(OPENAI_BODY), Provider::OpenAi))
    });
    c.bench_function("extract/anthropic", |b| {
        b.iter(|| extract(black_box(ANTHROPIC_BODY), Provider::Anthropic))
    });
    c.bench_function("extract/gemini", |b| {
        b.iter(|| extract(black_box(GEMINI_BODY), Provider::Gemini))
    });

    let sse = openai_sse_body();
    c.bench_function("extract_stream/openai_sse_40_chunks", |b| {
        b.iter(|| extract_stream(black_box(&sse), Provider::OpenAi))
    });
}

criterion_group!(benches, bench_extract);
criterion_main!(benches);
