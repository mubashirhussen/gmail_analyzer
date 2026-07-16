#!/usr/bin/env bash
# Deploy helper — Module 12.
# Pulls the requested image tag, restarts services with zero-downtime intent,
# and verifies /healthz. Prints a rollback command on failure.

set -euo pipefail

TAG="${1:?image tag required}"
COMPOSE="deploy/docker-compose.prod.yml"
PREV_TAG_FILE="/opt/guardianmail/.last_tag"

cd /opt/guardianmail
PREVIOUS="$(cat "$PREV_TAG_FILE" 2>/dev/null || echo "")"

export IMAGE_TAG="$TAG"
echo "[deploy] pulling $TAG"
docker compose -f "$COMPOSE" pull

echo "[deploy] rolling api"
docker compose -f "$COMPOSE" up -d --no-deps --remove-orphans api worker beat

for i in {1..30}; do
  if curl -fsS http://localhost/healthz >/dev/null; then
    echo "[deploy] healthy"
    echo "$TAG" > "$PREV_TAG_FILE"
    exit 0
  fi
  sleep 5
done

echo "[deploy] health check failed" >&2
if [ -n "$PREVIOUS" ]; then
  echo "[deploy] rolling back to $PREVIOUS"
  IMAGE_TAG="$PREVIOUS" docker compose -f "$COMPOSE" up -d api worker beat
fi
exit 1
