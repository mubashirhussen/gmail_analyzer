#!/usr/bin/env bash
# Redis snapshot backup — Module 12.
# Triggers BGSAVE, copies the resulting dump.rdb, uploads to S3.

set -euo pipefail

: "${REDIS_CONTAINER:=guardianmail-redis-1}"
: "${BACKUP_BUCKET:?}"
: "${BACKUP_PREFIX:=redis}"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "[redis-backup] triggering BGSAVE"
docker exec "$REDIS_CONTAINER" redis-cli BGSAVE
sleep 3
docker cp "$REDIS_CONTAINER":/data/dump.rdb "$WORK/dump.rdb"
gzip "$WORK/dump.rdb"

KEY="${BACKUP_PREFIX}/$(date -u +%Y/%m/%d)/redis-${STAMP}.rdb.gz"
aws s3 cp "$WORK/dump.rdb.gz" "s3://${BACKUP_BUCKET}/${KEY}" --sse AES256
echo "[redis-backup] uploaded s3://${BACKUP_BUCKET}/${KEY}"
