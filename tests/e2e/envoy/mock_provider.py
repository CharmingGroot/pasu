#!/usr/bin/env python3
"""A stand-in OpenAI provider for the Envoy ext_proc E2E (stdlib only).

Every request that reaches it is appended to a JSONL record *before* the reply
is sent, so the harness can assert that a refused request never arrived rather
than assume it. What the model "answers" is chosen by a marker in the prompt:

    TOOL_SHELL   -> the reply is a `shell` tool call
    anything else -> a plain text reply

`"stream": true` in the request selects the SSE form of the same reply, sent
chunked the way a real provider streams it.

    mock_provider.py <bind-host> <port> <record.jsonl>
"""

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MARKER_SHELL = "TOOL_SHELL"
MODEL = "mock-gpt"
REPLY_TEXT = "hello from the mock provider"

_record_lock = threading.Lock()


EVENT_GAP_SECONDS = 0.05


def prompt_text(body):
    """The concatenated message contents of a chat request, or ''."""
    try:
        request = json.loads(body)
    except ValueError:
        return ""
    if not isinstance(request, dict):
        return ""
    parts = []
    for message in request.get("messages") or []:
        content = message.get("content") if isinstance(message, dict) else None
        if isinstance(content, str):
            parts.append(content)
    return "\n".join(parts)


def wants_stream(body):
    try:
        return bool(json.loads(body).get("stream"))
    except (ValueError, AttributeError):
        return False


def completion(tool_call):
    message = {"role": "assistant", "content": None if tool_call else REPLY_TEXT}
    if tool_call:
        message["tool_calls"] = [
            {
                "id": "call_1",
                "type": "function",
                "function": {"name": "shell", "arguments": '{"cmd":"rm -rf /"}'},
            }
        ]
    return {
        "id": "chatcmpl-mock",
        "object": "chat.completion",
        "created": 0,
        "model": MODEL,
        "choices": [
            {
                "index": 0,
                "message": message,
                "finish_reason": "tool_calls" if tool_call else "stop",
            }
        ],
    }


def chunk(delta, finish=None):
    return {
        "id": "chatcmpl-mock",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": MODEL,
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
    }


def stream_events(tool_call):
    """SSE events, one per chunk, ending with [DONE]."""
    if tool_call:
        deltas = [
            chunk({"role": "assistant", "content": None}),
            chunk(
                {
                    "tool_calls": [
                        {
                            "index": 0,
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "shell", "arguments": ""},
                        }
                    ]
                }
            ),
            chunk({"tool_calls": [{"index": 0, "function": {"arguments": '{"cmd":'}}]}),
            chunk({"tool_calls": [{"index": 0, "function": {"arguments": '"rm -rf /"}'}}]}),
            chunk({}, "tool_calls"),
        ]
    else:
        words = REPLY_TEXT.split(" ")
        deltas = [chunk({"role": "assistant", "content": ""})]
        deltas += [chunk({"content": w if i == 0 else " " + w}) for i, w in enumerate(words)]
        deltas.append(chunk({}, "stop"))
    events = ["data: " + json.dumps(d, separators=(",", ":")) + "\n\n" for d in deltas]
    events.append("data: [DONE]\n\n")
    return [e.encode() for e in events]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    record_path = ""

    def log_message(self, fmt, *args):
        sys.stderr.write("mock: " + (fmt % args) + "\n")

    def read_body(self):
        """The request body. A body cut off mid-way (the data plane reset the
        request) is recorded as far as it arrived — "never reached the
        provider" must count bytes that did, not only requests that finished —
        and then the handler stops."""
        body = b""
        try:
            if "chunked" in (self.headers.get("transfer-encoding") or "").lower():
                while True:
                    size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                    if size == 0:
                        self.rfile.readline()
                        return body
                    piece = self.rfile.read(size)
                    body += piece
                    if len(piece) < size:
                        raise ConnectionError("chunk cut short")
                    self.rfile.readline()
            length = int(self.headers.get("content-length") or 0)
            body = self.rfile.read(length) if length else b""
            if len(body) < length:
                raise ConnectionError("body cut short")
            return body
        except (ConnectionError, OSError, ValueError):
            self.record(body, b"", truncated=True)
            raise

    def record(self, body, sent, truncated=False):
        entry = {
            "method": self.command,
            "path": self.path,
            "accept_encoding": self.headers.get("accept-encoding"),
            "content_length": self.headers.get("content-length"),
            "transfer_encoding": self.headers.get("transfer-encoding"),
            "body_bytes": len(body),
            "body": body.decode("utf-8", "replace"),
            "prompt": prompt_text(body),
            "sent": sent.decode("utf-8", "replace"),
            "truncated": truncated,
        }
        with _record_lock, open(self.record_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            f.flush()

    def send_json(self, status, obj, body):
        payload = json.dumps(obj).encode()
        self.record(body, payload)
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_stream(self, events, body):
        self.record(body, b"".join(events))
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.send_header("transfer-encoding", "chunked")
        self.end_headers()
        for event in events:
            self.wfile.write(b"%x\r\n%s\r\n" % (len(event), event))
            self.wfile.flush()
            # A pause between events, as a model generating tokens has, so the
            # data plane sees the stream in pieces. Without it Envoy coalesces
            # a small stream into one piece and piece-by-piece holding is never
            # exercised.
            time.sleep(EVENT_GAP_SECONDS)
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def do_GET(self):
        body = self.read_body()
        if self.path.split("?")[0] == "/v1/models":
            models = {"object": "list", "data": [{"id": MODEL, "object": "model"}]}
            return self.send_json(200, models, body)
        return self.send_json(404, {"error": {"message": "not found"}}, body)

    def do_POST(self):
        body = self.read_body()
        path = self.path.split("?")[0]
        if path == "/v1/chat/completions":
            tool_call = MARKER_SHELL in prompt_text(body)
            if wants_stream(body):
                return self.send_stream(stream_events(tool_call), body)
            return self.send_json(200, completion(tool_call), body)
        if path == "/v1/embeddings":
            embedding = {"object": "list", "data": [{"embedding": [0.0], "index": 0}]}
            return self.send_json(200, embedding, body)
        return self.send_json(404, {"error": {"message": "not found"}}, body)


def main():
    if len(sys.argv) != 4:
        sys.exit("usage: mock_provider.py <bind-host> <port> <record.jsonl>")
    host, port, record = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    Handler.record_path = record
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    sys.stderr.write("mock provider on %s:%d\n" % (host, port))
    server.serve_forever()


if __name__ == "__main__":
    main()
