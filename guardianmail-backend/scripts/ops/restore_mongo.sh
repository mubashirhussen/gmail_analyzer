#!/usr/bin/env bash
# Restore MongoDB from a backup archive stored in S3 — Module 12.
# Usage: restore_mongo.sh s3://bucket/key.gz [target_uri]

set -euo pipefail

SRC="${1:?s3://bucket/key.gz required}"
TARGET_URI="${2:-${MONGODB_URI:?}}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
LOCAL="$WORK/dump.gz"

echo "[restore] downloading $SRC"
aws s3 cp "$SRC" "$LOCAL"

echo "[restore] restoring into $TARGET_URI"
mongorestore --uri="$TARGET_URI" --archive="$LOCAL" --gzip --drop
echo "[restore] complete"
