# Module 12 — Production Deployment, DevOps & Cloud Infrastructure

Additive to Modules 1–11. **No business code was modified.**
This module ships the deployment plane: Docker, Compose, Nginx, GitHub
Actions CI/CD, Terraform, monitoring, backup/restore, and runbooks.

---

## 1. Production Infrastructure Architecture

```
             ┌────────────────────────────┐
Internet ───►│ Route53 / DNS              │
             └──────────────┬─────────────┘
                            ▼
                    ┌───────────────┐
                    │ Nginx (443)   │  TLS, HSTS, gzip, RL backstop
                    └──────┬────────┘
                           ▼
                  ┌────────────────┐
                  │ FastAPI (Gunicorn + UvicornWorker)
                  │  ─ 4 workers × N replicas
                  └───┬───────┬────┘
      ┌───────────────┘       └────────────┐
      ▼                                    ▼
┌───────────┐                        ┌────────────┐
│ Redis     │◄──── Celery ───────────│ Workers    │  (Q: gmail, threat, ai,
│ (broker + │      Celery Beat       │ N replicas │   ocr, analytics, ...)
│  cache)   │                        └──┬─────────┘
└───────────┘                           ▼
                                  ┌────────────┐
                                  │ MongoDB    │  Atlas (multi-AZ replica set)
                                  └────────────┘
   ┌──── Observability ─────────────────────────────┐
   │ Prometheus ─► Alertmanager ─► on-call/webhook  │
   │ Grafana                                        │
   │ Flower (Celery)                                │
   │ CloudWatch Logs (via awslogs driver)           │
   └────────────────────────────────────────────────┘
```

## 2. Docker Architecture

Single multi-stage `Dockerfile` (`base` → `runtime`) already ships in the
repo. Containers per role:

| Container | Image | Purpose |
| --- | --- | --- |
| api | app runtime | Gunicorn + Uvicorn workers |
| worker | app runtime | Celery worker (all queues) |
| beat | app runtime | Celery beat scheduler |
| flower | app runtime | Celery UI (basic-auth) |
| nginx | `nginx:1.27-alpine` | TLS termination + reverse proxy |
| prometheus | `prom/prometheus` | Metrics scrape + rules |
| alertmanager | `prom/alertmanager` | Alert routing |
| grafana | `grafana/grafana` | Dashboards |
| node-exporter | `prom/node-exporter` | Host metrics |

## 3. Docker Compose Structure

| File | Environment | Notes |
| --- | --- | --- |
| `docker-compose.yml` | dev | hot reload + local mongo/redis |
| `docker-compose.prod.yml` (root) | thin prod (existing) | minimal image swap |
| `deploy/docker-compose.prod.yml` | full prod (**new**) | api+workers+monitoring |

## 4. Nginx Configuration Strategy

`deploy/nginx/nginx.prod.conf`:
- TLS 1.2/1.3, HSTS preload, OCSP stapling.
- JSON access log (request-id, upstream time).
- Security headers (CSP owned by FastAPI middleware; nginx adds HSTS/XFO/XCTO/Referrer/Permissions/COOP).
- `limit_req` + `limit_conn` backstop; app-level RL is authoritative.
- Upstream keepalive to Gunicorn.

## 5. GitHub Actions CI/CD Pipeline

- `.github/workflows/ci.yml` — ruff, bandit, pip-audit, pytest w/ Mongo+Redis service containers.
- `.github/workflows/docker-publish.yml` — GHCR build+push, Trivy scan, semver + sha tags, buildx cache.
- `.github/workflows/deploy.yml` — manual dispatch, SSH deploy, health verify, auto rollback.

## 6. Deployment Workflow

```
git push → CI (lint/tests/SAST) → tag → docker-publish (Trivy) → deploy
                                                        │
                                                        ▼
                              ssh host → compose pull → up -d → healthz loop
                                                        │
                                              fail? → rollback previous tag
```

## 7. AWS Infrastructure Design

| Resource | Purpose |
| --- | --- |
| EC2 (t3.large) | Docker host running compose stack |
| Elastic IP | Stable public IP for DNS |
| Security Group | 22 (SSH allow-list), 80/443 (world) |
| IAM Role + Instance Profile | S3 evidence, Secrets Manager, CloudWatch |
| S3 (versioned + SSE-AES256 + public-access-block) | Evidence + backups |
| Secrets Manager | `.env` provisioning |
| CloudWatch Logs | Central log group (`/gm/prod/app`) |

MongoDB is Atlas-managed (multi-AZ) — not provisioned in Terraform.

## 8. Terraform Infrastructure Layout

`terraform/main.tf` provisions the AWS resources above. Customize via
`terraform.tfvars` (see `terraform.tfvars.example`). State should live in
an S3 backend with DynamoDB lock table (per-workspace, add before `apply`).

## 9. Secrets Management Strategy

- **Never in source.** `.env` on host is populated from AWS Secrets Manager
  at boot (`aws secretsmanager get-secret-value ... > .env`).
- CI secrets in GitHub Environments (`staging`, `prod`): `DEPLOY_SSH_KEY`,
  `DEPLOY_HOST`, `DEPLOY_USER`.
- Rotate JWT signing key + `METRICS_TOKEN` per policy — updates flow
  through Secrets Manager, then `deploy.sh` restarts workers.

## 10. SSL & HTTPS Configuration

- TLS certs mounted at `deploy/nginx/certs/{fullchain.pem,privkey.pem}`.
- Recommended issuer: Let's Encrypt via `certbot` sidecar mounting
  `deploy/nginx/certbot` for the ACME HTTP-01 challenge.
- `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.
- Secure cookies enforced by FastAPI auth (Module 2).

## 11. Monitoring Architecture

Prometheus scrapes the API's `/api/v1/platform/metrics` (Module 11) and
`node-exporter`. Alertmanager routes to a FastAPI webhook or PagerDuty.
Grafana auto-provisions the "Golden Signals" dashboard from
`deploy/grafana/dashboards/*.json`.

## 12. Prometheus Integration

Config: `deploy/prometheus/prometheus.yml` — jobs: `prometheus`, `node`,
`guardianmail-api`. Rules: `deploy/prometheus/alerts.yml`.

## 13. Grafana Dashboards

`GuardianMail / Golden Signals` — RPS, error rate, p50/p95/p99 latency,
rate-limit hits, circuit-breaker state. Extend with module-specific rows.

## 14. Flower Integration

Runs under compose (`flower` service), basic-auth via `FLOWER_USER` +
`FLOWER_PASS`. Fronted by nginx if exposed publicly (URL prefix `/flower`).

## 15. CloudWatch Integration

Docker `awslogs` log driver ships container stdout/stderr to log group
`/gm/prod/app`. IAM policy in Terraform grants `logs:PutLogEvents`.

## 16. Backup Strategy

| Asset | Schedule | Location | Retention |
| --- | --- | --- | --- |
| MongoDB | Daily 02:00 UTC (`backup_mongo.sh`) | `s3://…/mongo/YYYY/MM/DD/…gz` | 30d hot + Glacier 180d |
| Redis | 6-hourly (`backup_redis.sh`) | `s3://…/redis/…rdb.gz` | 14d |
| Config (`.env`, terraform state) | Weekly | S3 + Secrets Manager versioning | 90d |

Verification: `head-object` + non-zero size check baked into `backup_mongo.sh`.
Monthly restore drill into `staging` (see runbook).

## 17. Disaster Recovery Plan

RPO: 24h (daily Mongo backup); RTO: 60m for full stack rebuild.

1. Rebuild EC2 + provision via Terraform apply.
2. Populate `.env` from Secrets Manager.
3. `docker compose pull && up -d`.
4. Run `restore_mongo.sh` with latest verified S3 archive.
5. Warm Redis caches (`analytics_platform_tasks.warm_dashboard`).
6. Verify with `scripts/ops/smoke.sh https://api.…`.

## 18. High Availability Design

- Multiple worker replicas via `WORKER_REPLICAS`.
- Multiple api replicas across nodes behind an ALB (extend Terraform).
- MongoDB Atlas multi-AZ replica set.
- Redis: single node for MVP; upgrade to ElastiCache / Redis Sentinel for HA.
- Restart policy `unless-stopped` on every service.

## 19. Scaling Strategy

- Horizontal API scaling: `docker compose up -d --scale api=N`.
- Worker scaling: `WORKER_REPLICAS` env or Auto Scaling Group.
- Redis vertical scale first, then Cluster mode.
- Mongo scale via Atlas tier upgrades + sharding for >100 GB.

## 20. Logging Architecture

- App: structlog JSON → stdout → docker awslogs → CloudWatch.
- Nginx: JSON access + error → mounted volume → CloudWatch agent optional.
- Deployment: GitHub Actions run logs.
- Audit: `platform_audit_log` collection in Mongo (Module 11).

## 21. Security Hardening

- Security groups: least privilege (SSH allow-list).
- IAM: instance role scoped to required S3 prefixes + specific secret ARN.
- S3: versioning + SSE + public-access-block + lifecycle.
- Docker: non-root user, tini init, healthchecks, image pinned by digest.
- Trivy on every build; pip-audit + bandit on every CI run.
- HTTPS enforced (301 redirect from :80).
- Rate limits: Nginx (backstop) + FastAPI RateLimitService (authoritative).

## 22. Operational Runbooks

See `docs/runbooks/` — deployment, rollback, backup/restore, incident
response, on-call.

## 23. Deployment Checklist

- [ ] `terraform apply` clean, outputs captured.
- [ ] Secrets uploaded to Secrets Manager.
- [ ] DNS points to Elastic IP.
- [ ] TLS certs installed in `deploy/nginx/certs/`.
- [ ] `docker compose -f deploy/docker-compose.prod.yml up -d`.
- [ ] `scripts/ops/smoke.sh https://api.…` green.
- [ ] Prometheus scraping API + node-exporter.
- [ ] Grafana reachable, dashboard loaded.
- [ ] Alertmanager webhook confirmed.
- [ ] First backup succeeded and verified.

## 24. Production Readiness Checklist

- [x] Health/readiness/liveness (Module 11).
- [x] Prometheus metrics + Grafana dashboard.
- [x] Rate limits + circuit breakers.
- [x] Structured JSON logs → CloudWatch.
- [x] Backup schedule + verification.
- [x] Restore drill documented.
- [x] Secrets in Secrets Manager only.
- [x] TLS + HSTS + security headers.
- [x] CI (lint, SAST, deps, tests) on every PR.
- [x] Trivy image scan on every build.

## 25. Maintenance Strategy

- Weekly dependency PR (Renovate/Dependabot recommended).
- Monthly restore drill in staging.
- Quarterly IAM + secret rotation.
- Semi-annual DR game-day (full region-loss simulation).

## 26. Future Cloud Migration Strategy

Path to Kubernetes / managed services when scale demands:

1. Move api + workers to **ECS Fargate** or **EKS**; keep compose for dev.
2. Redis → **ElastiCache** (cluster mode) with TLS.
3. Nginx → **ALB** + AWS WAF; TLS via ACM.
4. Object storage stays on **S3** unchanged.
5. Observability → **AMP** (Prometheus) + **AMG** (Grafana), or Datadog.
6. Secrets stay in **Secrets Manager** (IRSA on EKS).
7. Blue/green deploys via ECS/EKS + CodeDeploy.
