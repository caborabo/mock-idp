#!/usr/bin/env bash
# Starts a fresh in-memory mock-idp and runs the real-library interop suites
# against it. Usage: interop/run.sh [node|go]   (MOCKIDP_URL=... to target a running one)
set -euo pipefail
cd "$(dirname "$0")/.."
PORT="${PORT:-7171}"
if [ -z "${MOCKIDP_URL:-}" ]; then
  # No target given: start a fresh in-memory mock-idp. Set MOCKIDP_URL to test
  # a running one instead, e.g. the Docker container.
  BIN="$(mktemp -d)/mock-idp"
  go build -o "$BIN" .
  "$BIN" -addr ":$PORT" -data "" >/tmp/mock-idp-interop.log 2>&1 &
  PID=$!
  trap 'kill $PID 2>/dev/null' EXIT
  export MOCKIDP_URL="http://localhost:$PORT"
fi
for _ in $(seq 50); do curl -sf "$MOCKIDP_URL/api/info" >/dev/null && break; sleep 0.2; done

status=0
if [ "${1:-all}" != go ]; then
  (cd interop/node && npm ci --silent --no-audit --no-fund 2>/dev/null && node --test --test-reporter=spec) || status=1
fi
if [ "${1:-all}" != node ]; then
  (cd interop/go && go test -count=1 -v ./...) || status=1
fi
exit $status
