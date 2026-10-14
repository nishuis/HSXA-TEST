#!/usr/bin/env bash
# End-to-end acceptance for the banner fingerprinting system (plan.md §6.2).
#
# It builds both binaries, starts a server, then checks, in order:
#   1 field level match against testdata/acceptance/expected.json
#   2 missing values are empty strings, never null
#   3 port is an integer and confidence a two decimal float
#   4 results are 1:1 with the input and in input order
#   5 the CLI and the documented curl command both work end to end
#   6 malformed, empty and binary banners degrade with HTTP 200
#   7 zero outbound: the engine, rules and API layers contain no dialing code
#   8 throughput: 100k records within the budget
#
# Environment knobs:
#   BFP_ACCEPTANCE_PORT       port for the temporary server (default 18099)
#   BFP_PERF_RECORDS          records for the throughput check (default 100000)
#   BFP_PERF_BUDGET_SECONDS   budget for that check (default 10)
#   BFP_SKIP_PERF=1           skip the throughput check
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${BFP_ACCEPTANCE_PORT:-18099}"
BASE="http://127.0.0.1:${PORT}"
BIN_DIR="$ROOT/bin"
WORK="$(mktemp -d)"
SERVER_PID=""
CHECKS=0
FAILED=0

INPUT="testdata/acceptance/input.json"
EXPECTED="testdata/acceptance/expected.json"
ORDER="testdata/acceptance/order.json"
ORDER_EXPECTED="testdata/acceptance/order_expected.json"
ROBUSTNESS="testdata/acceptance/robustness.json"

cleanup() {
	if [ -n "$SERVER_PID" ]; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT

step() { printf '\n=== %s\n' "$*"; }
pass() { CHECKS=$((CHECKS + 1)); printf '  PASS  %s\n' "$*"; }
fail() { CHECKS=$((CHECKS + 1)); FAILED=$((FAILED + 1)); printf '  FAIL  %s\n' "$*"; }

bt() { go run ./scripts/bfptool "$@"; }

# --------------------------------------------------------------------------
step "build"
if go build -o "$BIN_DIR/bfp-server" ./cmd/bfp-server && go build -o "$BIN_DIR/bfp-cli" ./cmd/bfp-cli; then
	pass "bfp-server and bfp-cli built into bin/"
else
	fail "build failed"
	exit 1
fi

# --------------------------------------------------------------------------
step "start server on ${BASE} with BFP_RULES_DIR=rules"
BFP_LISTEN_ADDR="127.0.0.1:${PORT}" BFP_LOG_LEVEL=error BFP_RULES_DIR=rules \
	"$BIN_DIR/bfp-server" >"$WORK/server.log" 2>&1 &
SERVER_PID=$!

ready=0
for _ in $(seq 1 50); do
	if curl -fsS "${BASE}/healthz" >/dev/null 2>&1; then
		ready=1
		break
	fi
	sleep 0.2
done
if [ "$ready" = 1 ]; then
	pass "server answered /healthz"
else
	fail "server did not become healthy; log:"
	cat "$WORK/server.log" >&2
	exit 1
fi

meta="$(curl -fsS "${BASE}/api/v1/meta")"
if printf '%s' "$meta" | grep -q '"protocols"'; then
	pass "GET /api/v1/meta: $(printf '%s' "$meta" | head -c 200)"
else
	fail "GET /api/v1/meta returned $meta"
fi

# --------------------------------------------------------------------------
step "1. field level match (protocol / product / version / os_hint)"
curl -fsS -X POST "${BASE}/api/v1/identify?output=array" -d @"$INPUT" -o "$WORK/curl_array.json" \
	|| fail "identify request failed"
if bt compare --epsilon 0.05 "$EXPECTED" "$WORK/curl_array.json"; then
	pass "curl output matches testdata/acceptance/expected.json"
else
	fail "curl output differs from the expectation"
fi

# --------------------------------------------------------------------------
step "2. missing values are empty strings, not null"
if grep -q 'null' "$WORK/curl_array.json"; then
	fail "response contains null: $(head -c 200 "$WORK/curl_array.json")"
else
	pass "no null in the response body"
fi

# --------------------------------------------------------------------------
step "3. types: port integer, confidence two decimal float"
if bt shape --count 7 "$WORK/curl_array.json"; then
	pass "serialisation contract holds"
else
	fail "serialisation contract violated"
fi

# --------------------------------------------------------------------------
step "4. results are 1:1 with the input and in input order"
curl -fsS -X POST "${BASE}/api/v1/identify?output=array" -d @"$ORDER" -o "$WORK/order.json" \
	|| fail "order request failed"
if bt compare --epsilon 0.05 "$ORDER_EXPECTED" "$WORK/order.json"; then
	pass "shuffled input keeps its order"
else
	fail "results are not in input order"
fi

# --------------------------------------------------------------------------
step "5. CLI end to end (bfp-cli identify/ping, the README commands)"
if "$BIN_DIR/bfp-cli" identify --server "$BASE" --input "$INPUT" --quiet >"$WORK/cli_array.json"; then
	if bt compare --epsilon 0.05 "$EXPECTED" "$WORK/cli_array.json"; then
		pass "bfp-cli identify --out-format array matches the expectation"
	else
		fail "bfp-cli output differs from the expectation"
	fi
else
	fail "bfp-cli identify exited non-zero"
fi

if "$BIN_DIR/bfp-cli" ping --server "$BASE" >/dev/null; then
	pass "bfp-cli ping"
else
	fail "bfp-cli ping failed"
fi

if "$BIN_DIR/bfp-cli" identify --server "$BASE" --input "$INPUT" --out-format jsonl --quiet >"$WORK/cli.jsonl" \
	&& [ "$(wc -l <"$WORK/cli.jsonl" | tr -d ' ')" = "7" ]; then
	pass "--out-format jsonl emits one result per record"
else
	fail "--out-format jsonl"
fi

if "$BIN_DIR/bfp-cli" identify --server "$BASE" --input "$INPUT" --out-format csv --quiet >"$WORK/cli.csv" \
	&& head -1 "$WORK/cli.csv" | grep -q '^ip,port,protocol,product,version,os_hint,confidence$'; then
	pass "--out-format csv emits the documented header"
else
	fail "--out-format csv"
fi

# the documented curl one-liner must work against data/sample.json
if cmp -s data/sample.json "$INPUT"; then
	pass "data/sample.json is identical to the acceptance input"
else
	fail "data/sample.json drifted from testdata/acceptance/input.json"
fi
if curl -fsS -X POST "${BASE}/api/v1/identify?output=array" -d @data/sample.json -o "$WORK/sample.json" \
	&& bt shape --count 7 "$WORK/sample.json" >/dev/null; then
	pass "curl -d @data/sample.json returns a valid 7 record array"
else
	fail "curl -d @data/sample.json"
fi

# exit codes of plan.md §3.2
"$BIN_DIR/bfp-cli" identify --server "$BASE" --input "$INPUT" --in-format nonsense >/dev/null 2>&1
[ $? -eq 2 ] && pass "usage error exits 2" || fail "usage error should exit 2"
"$BIN_DIR/bfp-cli" ping --server "http://127.0.0.1:1" --timeout 1s --retry 0 >/dev/null 2>&1
[ $? -eq 3 ] && pass "unreachable server exits 3" || fail "unreachable server should exit 3"

# --------------------------------------------------------------------------
step "6. robustness: malformed, empty and binary banners stay HTTP 200"
status="$(curl -sS -o "$WORK/robust.json" -w '%{http_code}' -X POST "${BASE}/api/v1/identify?output=array" -d @"$ROBUSTNESS")"
if [ "$status" = "200" ]; then
	pass "HTTP 200 for malformed payloads"
else
	fail "malformed payloads returned HTTP $status"
fi
if bt shape --count 6 "$WORK/robust.json" >/dev/null; then
	pass "degraded results keep the contract (6 results, no null)"
else
	fail "degraded results broke the contract"
fi
if grep -q '"protocol":"unknown"' "$WORK/robust.json" && grep -q '"protocol":"SSH"' "$WORK/robust.json"; then
	pass "the batch mixes degraded and identified records"
else
	fail "expected both unknown and SSH results in the robustness batch"
fi

# --------------------------------------------------------------------------
step "7. zero outbound: no dialing code in the engine, rules, API"
dial_hits="$(grep -rnE 'net\.Dial|net\.Lookup|http\.Get\(|http\.Post\(|http\.DefaultClient' \
	internal/engine internal/rules internal/api internal/model 2>/dev/null || true)"
if [ -z "$dial_hits" ]; then
	pass "no dialing primitives in engine/rules/api/model"
else
	fail "dialing code found: $dial_hits"
fi
if grep -rn 'net/http' internal/engine >/dev/null 2>&1; then
	fail "the engine package imports net/http"
else
	pass "the engine package does not import net/http"
fi

# --------------------------------------------------------------------------
step "8. throughput"
if [ "${BFP_SKIP_PERF:-0}" = "1" ]; then
	printf '  SKIP  throughput check disabled by BFP_SKIP_PERF\n'
else
	records="${BFP_PERF_RECORDS:-100000}"
	budget="${BFP_PERF_BUDGET_SECONDS:-10}"
	bt gen --records "$records" --out "$WORK/big.json" >/dev/null 2>&1 || fail "sample generation failed"
	bytes=$(wc -c <"$WORK/big.json" | tr -d ' ')
	elapsed="$(curl -sS -o "$WORK/big_out.json" -w '%{time_total}' -X POST "${BASE}/api/v1/identify?output=array" -d @"$WORK/big.json")"
	count="$(grep -o '"ip"' "$WORK/big_out.json" | wc -l | tr -d ' ')"
	printf '  info  %s records, %s bytes, %ss round trip, %s results\n' "$records" "$bytes" "$elapsed" "$count"
	if [ "$count" = "$records" ]; then
		pass "all ${records} records returned"
	else
		fail "expected $records results, got $count"
	fi
	if awk -v e="$elapsed" -v b="$budget" 'BEGIN { exit !(e <= b) }'; then
		pass "round trip ${elapsed}s is within the ${budget}s budget"
	else
		fail "round trip ${elapsed}s exceeds the ${budget}s budget"
	fi
fi

# --------------------------------------------------------------------------
step "summary"
printf 'checks: %d, failures: %d\n' "$CHECKS" "$FAILED"
if [ "$FAILED" -gt 0 ]; then
	printf 'acceptance FAILED\n' >&2
	exit 1
fi
printf 'acceptance PASSED\n'
exit 0
