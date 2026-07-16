#!/usr/bin/env bash
# Daily MongoDB Atlas backup — Module 12.
# Runs `mongodump` against $MONGODB_URI and uploads a gzip'd archive to S3.
# Retention is enforced by the S3 lifecycle policy in terraform/main.tf.

set -euo pipefail

: "${MONGODB_URI:?}"
: "${BACKUP_BUCKET:?}"    # e.g. guardianmail-prod-backups
: "${BACKUP_PREFIX:=mongo}"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

ARCHIVE="$WORK/mongo-${STAMP}.gz"
echo "[backup] dumping to ${ARCHIVE}"
mongodump --uri="$MONGODB_URI" --archive="$ARCHIVE" --gzip

SHA="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
echo "[backup] sha256=$SHA"

KEY="${BACKUP_PREFIX}/$(date -u +%Y/%m/%d)/mongo-${STAMP}.gz"
aws s3 cp "$ARCHIVE" "s3://${BACKUP_BUCKET}/${KEY}" \
  --sse AES256 --metadata "sha256=${SHA}"

echo "[backup] uploaded s3://${BACKUP_BUCKET}/${KEY}"

# Quick verification: HEAD and byte size > 0.
SIZE=$(aws s3api head-object --bucket "$BACKUP_BUCKET" --key "$KEY" --query 'ContentLength' --output text)
if [ "$SIZE" -le 0 ]; then
  echo "[backup] verification failed — object has zero bytes" >&2
  exit 1
fi
echo "[backup] verified (size=${SIZE} bytes)"
