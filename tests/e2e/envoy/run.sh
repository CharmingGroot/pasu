#!/usr/bin/env bash
# Envoy ext_proc E2E: a real Envoy in front of a mock OpenAI provider, with
# pasu-proxy (--frontend ext-proc) deciding, judged against the PRODUCTION
# ruleset (deploy/rules.yaml, default deny).
#
#   tests/e2e/envoy/run.sh <pasu-proxy binary> <envoy image>
#
# Builds nothing and pulls nothing: both inputs must already exist. Every case
# prints PASS or FAIL; the script exits non-zero if any case fails or the setup
# cannot come up. Needs bash, curl, python3 and docker.
#
# Environment (all optional):
#   PASU_E2E_ENVOY_PORT   Envoy listener            (default 10000)
#   PASU_E2E_ADMIN_PORT   Envoy admin               (default 9901)
#   PASU_E2E_PASU_PORT    pasu ext_proc gRPC        (default 8791)
#   PASU_E2E_MOCK_PORT    mock provider             (default 18901)
#   PASU_E2E_NETWORK      host | bridge | auto      (default auto: host on Linux,
#                         bridge + host.docker.internal elsewhere)
#   PASU_E2E_BIND         address pasu and the mock bind (default 127.0.0.1;
#                         0.0.0.0 for bridge on Linux, where the container
#                         reaches the host through the bridge, not loopback)
#   PASU_E2E_KEEP=1       keep the work directory (logs, rendered configs)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
# Not configurable on purpose: the E2E validates what ships (CLAUDE.md §3).
POLICY="$ROOT/deploy/rules.yaml"

PASU_BIN="${1:-}"
ENVOY_IMAGE="${2:-}"
if [[ -z "$PASU_BIN" || -z "$ENVOY_IMAGE" ]]; then
  echo "usage: $0 <pasu-proxy binary> <envoy image>" >&2
  exit 2
fi
if [[ ! -x "$PASU_BIN" ]]; then
  echo "error: $PASU_BIN is not an executable" >&2
  exit 2
fi
PASU_BIN="$(cd "$(dirname "$PASU_BIN")" && pwd)/$(basename "$PASU_BIN")"
if ! docker image inspect "$ENVOY_IMAGE" >/dev/null 2>&1; then
  echo "error: image $ENVOY_IMAGE is not present (the harness does not pull)" >&2
  exit 2
fi

ENVOY_PORT="${PASU_E2E_ENVOY_PORT:-10000}"
ADMIN_PORT="${PASU_E2E_ADMIN_PORT:-9901}"
PASU_PORT="${PASU_E2E_PASU_PORT:-8791}"
MOCK_PORT="${PASU_E2E_MOCK_PORT:-18901}"
NETWORK="${PASU_E2E_NETWORK:-auto}"
if [[ "$NETWORK" == auto ]]; then
  [[ "$(uname -s)" == Linux ]] && NETWORK=host || NETWORK=bridge
fi

case "$NETWORK" in
  host)
    UPSTREAM_HOST=127.0.0.1
    ENVOY_ADDR=127.0.0.1
    DEFAULT_BIND=127.0.0.1
    DOCKER_NET=(--network host)
    ;;
  bridge)
    UPSTREAM_HOST=host.docker.internal
    ENVOY_ADDR=0.0.0.0
    DOCKER_NET=(-p "127.0.0.1:$ENVOY_PORT:$ENVOY_PORT" -p "127.0.0.1:$ADMIN_PORT:$ADMIN_PORT")
    if [[ "$(uname -s)" == Linux ]]; then
      DOCKER_NET+=(--add-host host.docker.internal:host-gateway)
      DEFAULT_BIND=0.0.0.0
    else
      DEFAULT_BIND=127.0.0.1 # Docker Desktop delivers host.docker.internal to loopback
    fi
    ;;
  *)
    echo "error: PASU_E2E_NETWORK must be host, bridge or auto (got $NETWORK)" >&2
    exit 2
    ;;
esac
BIND="${PASU_E2E_BIND:-$DEFAULT_BIND}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/pasu-envoy-e2e.XXXXXX")"
RECORD="$WORK/provider-requests.jsonl"
: >"$RECORD"
CONTAINER="pasu-envoy-ci-$$"
MOCK_PID=""
PASU_PID=""
PHASE=""

log() { printf '%s\n' "$*"; }

cleanup() {
  local status=$?
  set +e
  [[ -n "$PASU_PID" ]] && kill "$PASU_PID" 2>/dev/null && wait "$PASU_PID" 2>/dev/null
  [[ -n "$MOCK_PID" ]] && kill "$MOCK_PID" 2>/dev/null && wait "$MOCK_PID" 2>/dev/null
  docker rm -f "$CONTAINER" >/dev/null 2>&1
  if [[ "${PASU_E2E_KEEP:-}" == 1 ]]; then
    log "work directory kept: $WORK"
  else
    rm -rf "$WORK"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

# wait_for <seconds> <description> <command...>
wait_for() {
  local deadline=$((SECONDS + $1)) what=$2
  shift 2
  until "$@"; do
    if ((SECONDS >= deadline)); then
      log "SETUP FAILED: timed out waiting for $what"
      return 1
    fi
    sleep 0.2
  done
}

alive() { kill -0 "$1" 2>/dev/null; }

dump_logs() {
  local f
  if envoy_running; then docker logs "$CONTAINER" >"$WORK/envoy-$PHASE.log" 2>&1 || true; fi
  for f in "$WORK"/pasu-*.log "$WORK"/envoy-*.log "$WORK/mock.log"; do
    [[ -f "$f" ]] || continue
    log "---- $(basename "$f") (last 30 lines) ----"
    tail -n 30 "$f"
  done
}

setup_failed() {
  dump_logs
  exit 2
}

start_mock() {
  python3 "$HERE/mock_provider.py" "$BIND" "$MOCK_PORT" "$RECORD" >"$WORK/mock.log" 2>&1 &
  MOCK_PID=$!
  mock_up_or_dead() { port_open "$MOCK_PORT" || ! alive "$MOCK_PID"; }
  wait_for 15 "mock provider on :$MOCK_PORT" mock_up_or_dead || setup_failed
  alive "$MOCK_PID" || { log "SETUP FAILED: mock provider exited"; setup_failed; }
}

start_pasu() {
  if port_open "$PASU_PORT"; then
    log "SETUP FAILED: something already listens on :$PASU_PORT"
    setup_failed
  fi
  "$PASU_BIN" --frontend ext-proc --listen "$BIND:$PASU_PORT" --policy "$POLICY" "$@" \
    >"$WORK/pasu-$PHASE.log" 2>&1 &
  PASU_PID=$!
  pasu_up_or_dead() { port_open "$PASU_PORT" || ! alive "$PASU_PID"; }
  wait_for 15 "pasu gRPC on :$PASU_PORT" pasu_up_or_dead || setup_failed
  alive "$PASU_PID" || { log "SETUP FAILED: pasu-proxy exited"; setup_failed; }
}

stop_pasu() {
  [[ -z "$PASU_PID" ]] && return 0
  kill "$PASU_PID" 2>/dev/null || true
  wait "$PASU_PID" 2>/dev/null || true
  PASU_PID=""
  pasu_down() { ! port_open "$PASU_PORT"; }
  wait_for 15 "pasu to release :$PASU_PORT" pasu_down || setup_failed
}

envoy_ready() {
  [[ "$(curl -s --max-time 2 "http://127.0.0.1:$ADMIN_PORT/ready" 2>/dev/null)" == LIVE* ]] &&
    curl -s --max-time 2 "http://127.0.0.1:$ADMIN_PORT/listeners" 2>/dev/null |
    grep -q ":$ENVOY_PORT"
}

envoy_running() {
  [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" == true ]]
}

# start_envoy <BUFFERED|NONE>
start_envoy() {
  local cfg="$WORK/envoy-$1.yaml" admin_addr=127.0.0.1
  [[ "$NETWORK" == bridge ]] && admin_addr=0.0.0.0
  sed -e "s/@RESPONSE_BODY_MODE@/$1/" \
    -e "s/@ADMIN_ADDR@/$admin_addr/" -e "s/@ADMIN_PORT@/$ADMIN_PORT/" \
    -e "s/@LISTEN_ADDR@/$ENVOY_ADDR/" -e "s/@LISTEN_PORT@/$ENVOY_PORT/" \
    -e "s/@UPSTREAM_HOST@/$UPSTREAM_HOST/g" \
    -e "s/@PASU_PORT@/$PASU_PORT/" -e "s/@MOCK_PORT@/$MOCK_PORT/" \
    "$HERE/envoy.yaml.tmpl" >"$cfg"
  chmod 644 "$cfg"
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker run -d --name "$CONTAINER" "${DOCKER_NET[@]}" \
    -v "$cfg:/etc/envoy/envoy.yaml:ro" \
    "$ENVOY_IMAGE" -c /etc/envoy/envoy.yaml >/dev/null || setup_failed
  ready_or_dead() { envoy_ready || ! envoy_running; }
  wait_for 60 "Envoy admin LIVE with listener :$ENVOY_PORT" ready_or_dead || setup_failed
  envoy_running || { log "SETUP FAILED: Envoy exited"; setup_failed; }
}

stop_envoy() {
  docker logs "$CONTAINER" >"$WORK/envoy-$PHASE.log" 2>&1 || true
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}

# ---- cases ------------------------------------------------------------------

PASSED=0
FAILED=0
SUMMARY=()
CASE=""
CASE_OK=1

begin() {
  CASE=$1
  CASE_OK=1
  : >"$RECORD"
}

check() { # check <description> <command...>
  local what=$1
  shift
  if ! "$@"; then
    CASE_OK=0
    log "      expected: $what"
  fi
}

end() {
  if ((CASE_OK)); then
    PASSED=$((PASSED + 1))
    SUMMARY+=("PASS  $CASE")
    log "PASS  $CASE"
  else
    FAILED=$((FAILED + 1))
    SUMMARY+=("FAIL  $CASE")
    log "FAIL  $CASE  (status $(cat "$WORK/$CASE.status"), body: $(head -c 300 "$WORK/$CASE.body"))"
  fi
}

# send <METHOD> <PATH> [JSON body] [extra curl args...] -> $WORK/$CASE.{status,body}
send() {
  local method=$1 path=$2 body=${3:-}
  shift $(($# < 3 ? $# : 3))
  local args=(-sS --max-time 30 -X "$method" -o "$WORK/$CASE.body" -w '%{http_code}')
  [[ -n "$body" ]] && args+=(-H 'content-type: application/json' --data-binary "$body")
  curl "${args[@]}" "$@" "http://127.0.0.1:$ENVOY_PORT$path" >"$WORK/$CASE.status" 2>"$WORK/$CASE.curl" ||
    true
  [[ -s "$WORK/$CASE.status" ]] || echo 000 >"$WORK/$CASE.status"
  touch "$WORK/$CASE.body"
}

chat() { # chat <prompt> [stream true|false]
  python3 -c 'import json,sys; print(json.dumps({"model":"mock-gpt","stream":sys.argv[2]=="true","messages":[{"role":"user","content":sys.argv[1]}]}, ensure_ascii=False))' \
    "$1" "${2:-false}"
}

status_is() { [[ "$(cat "$WORK/$CASE.status")" == "$1" ]]; }
reached_times() { [[ "$(wc -l <"$RECORD" | tr -d ' ')" == "$1" ]]; }

# py_check <python expression over b (client body bytes) and r (records)>
py_check() {
  python3 - "$WORK/$CASE.body" "$RECORD" "$1" <<'EOF'
import json, sys
b = open(sys.argv[1], "rb").read()
r = [json.loads(l) for l in open(sys.argv[2], encoding="utf-8") if l.strip()]
def pasu_block():
    try:
        return json.loads(b)["error"]["type"] == "pasu_policy_block"
    except (ValueError, KeyError, TypeError):
        return False
sys.exit(0 if eval(sys.argv[3]) else 1)
EOF
}

is_pasu_block() { py_check 'pasu_block()'; }

# ---- phase 1: supported setup (BUFFERED), no inspectors ---------------------

run_buffered_plain() {
  PHASE=buffered
  log "== phase: Envoy BUFFERED, pasu (no inspector) =="
  start_pasu
  start_envoy BUFFERED

  begin models-passthrough
  send GET /v1/models
  check "200" status_is 200
  check "provider reached once" reached_times 1
  check "the provider's model list" py_check 'b"mock-gpt" in b'
  end

  begin text-completion
  send POST /v1/chat/completions "$(chat 'say hello')"
  check "200" status_is 200
  check "provider reached once" reached_times 1
  check "the text reply, unchanged" py_check 'b == r[-1]["sent"].encode()'
  end

  begin text-completion-streamed
  send POST /v1/chat/completions "$(chat 'say hello' true)"
  check "200" status_is 200
  check "provider reached once" reached_times 1
  check "every SSE data line intact (byte-equal to what the provider sent)" \
    py_check 'b == r[-1]["sent"].encode() and b.count(b"data: ") >= 3 and b.endswith(b"data: [DONE]\n\n")'
  end

  begin accept-encoding-identity
  send POST /v1/chat/completions "$(chat 'say hello')" -H 'accept-encoding: gzip'
  check "200" status_is 200
  check "provider saw accept-encoding: identity, not the client's gzip" \
    py_check 'len(r) == 1 and r[0]["accept_encoding"] == "identity"'
  end

  begin shell-tool-call
  send POST /v1/chat/completions "$(chat 'TOOL_SHELL please')"
  check "403" status_is 403
  check "pasu_policy_block JSON" is_pasu_block
  check "the model did answer with the tool call (refused on the response)" reached_times 1
  check "no tool call in what the client got" py_check 'b"call_1" not in b and b"rm -rf" not in b'
  end

  begin shell-tool-call-streamed
  send POST /v1/chat/completions "$(chat 'TOOL_SHELL please' true)"
  check "403" status_is 403
  check "pasu_policy_block JSON" is_pasu_block
  check "the model did stream the tool call" reached_times 1
  check "no SSE chunk delivered" py_check 'b"data:" not in b and b"call_1" not in b'
  end

  begin unknown-endpoint-embeddings
  send POST /v1/embeddings '{"model":"mock-embed","input":"hello"}'
  check "403" status_is 403
  check "pasu_policy_block JSON" is_pasu_block
  check "never reached the provider" reached_times 0
  end

  stop_envoy
  stop_pasu
}

# ---- phase 2: Korean PII refused --------------------------------------------

RRN='900101-1234567'

run_pii_block() {
  PHASE=pii-block
  log "== phase: Envoy BUFFERED, pasu --block-pii-kr =="
  start_pasu --block-pii-kr
  start_envoy BUFFERED

  begin pii-clean-prompt-passes
  send POST /v1/chat/completions "$(chat 'my order number is 12345')"
  check "200" status_is 200
  check "provider reached once" reached_times 1
  end

  begin pii-rrn-refused
  send POST /v1/chat/completions "$(chat "주민번호는 $RRN 입니다")"
  check "403" status_is 403
  check "pasu_policy_block JSON" is_pasu_block
  check "never reached the provider" reached_times 0
  check "the refusal does not quote the value" py_check "b'$RRN' not in b"
  end

  stop_envoy
  stop_pasu
}

# ---- phase 3: Korean PII redacted -------------------------------------------

run_pii_redact() {
  PHASE=pii-redact
  log "== phase: Envoy BUFFERED, pasu --block-pii-kr --redact =="
  start_pasu --block-pii-kr --redact
  start_envoy BUFFERED

  begin pii-rrn-redacted
  send POST /v1/chat/completions "$(chat "주민번호는 $RRN 입니다")"
  check "200 (Envoy accepted the rewritten body)" status_is 200
  check "provider reached once" reached_times 1
  check "provider got [REDACTED:ko-rrn] and not the number" \
    py_check "'[REDACTED:ko-rrn]' in r[0]['prompt'] and '$RRN' not in r[0]['body']"
  check "content-length matches the rewritten body" \
    py_check 'r[0]["content_length"] is not None and int(r[0]["content_length"]) == r[0]["body_bytes"]'
  end

  stop_envoy
  stop_pasu
}

# ---- phase 4: misconfigured Envoy (response_body_mode: NONE) ----------------

run_misconfigured() {
  PHASE=none
  log "== phase: Envoy response_body_mode NONE, pasu (no inspector) =="
  start_pasu
  start_envoy NONE

  begin none-passthrough-still-works
  send GET /v1/models
  check "200 (nothing to judge on a passthrough)" status_is 200
  check "provider reached once" reached_times 1
  end

  begin none-shell-refused
  send POST /v1/chat/completions "$(chat 'TOOL_SHELL please')"
  check "500 (pasu refuses a completion it would never be shown)" status_is 500
  check "pasu_policy_block JSON naming the setting" \
    py_check 'pasu_block() and b"response_body_mode" in b'
  check "never reached the provider" reached_times 0
  end

  stop_envoy
  stop_pasu
}

# ---- phase 5: pasu not running ----------------------------------------------

run_pasu_down() {
  PHASE=pasu-down
  log "== phase: Envoy BUFFERED, pasu NOT running =="
  start_envoy BUFFERED

  begin pasu-down-fails-closed
  check "nothing listening on the pasu port" eval '! port_open "$PASU_PORT"'
  send POST /v1/chat/completions "$(chat 'say hello')"
  check "500 (failure_mode_allow: false)" status_is 500
  check "never reached the provider" reached_times 0
  end

  stop_envoy
}

log "pasu-proxy: $PASU_BIN"
log "envoy:      $ENVOY_IMAGE"
log "policy:     $POLICY"
log "network:    $NETWORK (envoy :$ENVOY_PORT admin :$ADMIN_PORT, pasu $BIND:$PASU_PORT, mock $BIND:$MOCK_PORT)"

start_mock
run_buffered_plain
run_pii_block
run_pii_redact
run_misconfigured
run_pasu_down

log ""
log "== summary: $PASSED passed, $FAILED failed =="
for line in "${SUMMARY[@]}"; do log "  $line"; done
if ((FAILED > 0)); then
  dump_logs
  exit 1
fi
