#!/usr/bin/env bash
# Smoke test: starts the server, exercises the full lifecycle, and verifies.
set -euo pipefail

KASE="cargo run --quiet --"
PORT=13847
export KASE_URL="http://127.0.0.1:${PORT}"

cleanup() {
    if [[ -n "${SERVER_PID:-}" ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "=== Building ==="
cargo build --quiet

echo "=== Starting server on port ${PORT} ==="
$KASE serve --port "$PORT" &
SERVER_PID=$!
sleep 1

# Verify server is up
curl -sf "$KASE_URL/api/v1/health" > /dev/null
echo "Server healthy"

echo ""
echo "=== Ingesting sample scan ==="
$KASE ingest examples/scan-result.json

echo ""
echo "=== Listing cases ==="
$KASE list

echo ""
echo "=== Listing cases (JSON mode) ==="
CASE_ID=$($KASE list --json | jq -r '.[0].id')
echo "First case ID: $CASE_ID"

echo ""
echo "=== Show case ==="
$KASE show "$CASE_ID"

echo ""
echo "=== Assign case ==="
$KASE assign "$CASE_ID" --to bryan

echo ""
echo "=== Add note ==="
$KASE note "$CASE_ID" "Terraform PR opened for versioning fix"

echo ""
echo "=== Update status ==="
$KASE status "$CASE_ID" in-progress

echo ""
echo "=== Metrics ==="
$KASE metrics

echo ""
echo "=== Metrics (JSON) ==="
$KASE metrics --json | jq '{open: .total_open, in_progress: .total_in_progress, closed: .total_closed}'

echo ""
echo "=== Resolve case ==="
$KASE close "$CASE_ID" --resolution remediated --evidence "PR #42"

echo ""
echo "=== Final metrics ==="
$KASE metrics

echo ""
echo "=== All smoke tests passed ==="
