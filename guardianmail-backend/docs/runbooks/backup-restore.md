# Runbook — Backup & Restore

## Daily Mongo Backup
Cron on the app host (03:00 UTC):

```
0 3 * * * BACKUP_BUCKET=guardianmail-prod-backups /opt/guardianmail/scripts/ops/backup_mongo.sh >> /var/log/gm-backup.log 2>&1
```

Verifies non-zero object size after upload.

## Redis Snapshot
Every 6 hours: `scripts/ops/backup_redis.sh` (triggers BGSAVE inside the
redis container).

## Restore Drill (monthly, staging)
1. Provision a fresh staging Mongo cluster.
2. `scripts/ops/restore_mongo.sh s3://…/mongo-<latest>.gz "$STAGING_URI"`.
3. Run integration test suite; document runtime.

## Verification
- `aws s3 ls s3://…/mongo/$(date -u +%Y/%m/%d)/` returns today's file.
- Alertmanager rule `BackupMissing` (recommended add-on) can watch the S3
  object age and fire if the newest key is >26h old.
