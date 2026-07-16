# Runbook — Deploy

**Trigger**: GitHub Actions `deploy` workflow (manual dispatch) or SSH.

## Preconditions
- CI green on the target commit.
- Docker image published to GHCR at the requested tag.
- Secrets Manager has current `.env` payload.

## Steps
1. Trigger `.github/workflows/deploy.yml` with `env=staging` (or `prod`) and `image_tag`.
2. Watch the workflow — it SSHes, pulls, and runs `docker compose up -d`.
3. Verify smoke tests: `scripts/ops/smoke.sh https://api.guardianmail.example`.
4. Confirm Grafana dashboards are green for 10 minutes.

## Rollback
Run `scripts/ops/deploy.sh <previous_tag>` on the host, or re-trigger the
deploy workflow with the previous tag. The deploy script keeps
`/opt/guardianmail/.last_tag` and auto-rolls back on health failure.

## Failure signals
- Health loop times out → check `docker compose logs api` and
  `journalctl -u docker`.
- Alerts: `APIDown`, `HighErrorRate`, `HighLatencyP95`.
