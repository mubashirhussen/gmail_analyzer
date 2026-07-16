#!/usr/bin/env bash
# Wait for a host:port to accept connections before continuing.
set -e
host="$1"; port="$2"; shift 2 || true
timeout=${TIMEOUT:-30}
for i in $(seq 1 "$timeout"); do
  if (echo > "/dev/tcp/$host/$port") 2>/dev/null; then
    echo "$host:$port is up"; exec "$@"
  fi
  sleep 1
done
echo "timeout waiting for $host:$port" >&2
exit 1
