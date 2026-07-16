# Runbook — Incident Response

## Severity ladder
- **SEV1** — API down, data-loss risk, security incident. Page on-call.
- **SEV2** — Elevated errors/latency, non-critical dependency failing.
- **SEV3** — Degraded feature; user-visible but bounded.

## First 5 minutes
1. Acknowledge alert in Alertmanager / PagerDuty.
2. Check dashboards: Grafana → Golden Signals.
3. Check dependency health: `curl -sk https://api.…/api/v1/platform/status`.
4. If deploy in flight: run `scripts/ops/deploy.sh <previous_tag>` to roll back.

## Common playbooks
- **APIDown**: `docker ps`, `docker compose logs -n 200 api`, restart if OOM.
- **HighErrorRate**: recent deploy? Rollback. Otherwise inspect Sentry / logs.
- **CircuitOpen**: identify circuit name label → check the upstream provider.
- **Mongo unreachable**: verify Atlas status, IP allow-list, DNS resolution.
- **Redis unreachable**: `docker compose restart redis`; if persistent, promote replica.

## Postmortem
Within 48h: root cause, timeline, corrective actions. Store under
`docs/postmortems/YYYY-MM-DD-slug.md`.
