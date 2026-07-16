#!/usr/bin/env bash
# Smoke tests hit after deploy — Module 12.
set -euo pipefail
BASE="${1:-http://localhost}"

fail=0
check() {
  local name="$1" url="$2" expect="${3:-200}"
  code=$(curl -s -o /dev/null -w '%{http_code}' "$url")
  if [ "$code" = "$expect" ]; then
    echo "  ok  $name ($code)"
  else
    echo "  FAIL $name expected=$expect got=$code" >&2
    fail=1
  fi
}

check liveness    "$BASE/api/v1/platform/live"      200
check readiness   "$BASE/api/v1/platform/ready"     200
check version     "$BASE/version"                   200
check openapi     "$BASE/openapi.json"              200
check root_health "$BASE/healthz"                   200

exit "$fail"
