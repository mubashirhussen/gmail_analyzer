# Module 8 — Background Processing Platform

Additive infrastructure layer. No previous module is modified beyond three
already-integration-safe files: `app/workers/celery_app.py` (queue set +
signal wiring), `app/workers/scheduler.py` (added maintenance cadences),
and `app/main.py` (router + metrics mount).

## 1. Celery architecture

Single `celery` app, per-queue routing keys, broker-side priorities.
Business tasks (Modules 4-7) keep their own files; Module 8 registers
`notification_tasks`, `analytics_tasks`, `maintenance_tasks`, and imports
`app.workers.hooks` for the signal handlers that persist execution
history and emit Prometheus metrics.

## 2. Redis architecture

Redis serves as broker, result backend, dedup/ratelimit store, and
DLQ transport. Namespaces live in `services/tasks/redis_keys.py`:
`tasks:rate:*`, `tasks:dedup:*`, `tasks:lock:*`, `tasks:depth:*`,
`tasks:dlq` (Redis Stream, capped at 10k entries).

## 3. Worker architecture

One process per queue in production. Each worker subscribes to a single
queue and Beat runs standalone. Recommended `-c` (concurrency): CPU-bound
queues (`ocr`, `ai`) use `min(CPU, 4)`; IO-bound queues (`gmail`,
`threat`, `notifications`) use 8-16.

## 4. Queue design

Constants in `services/tasks/priority.py::ALL_QUEUES`:
`default`, `gmail`, `threat`, `ai`, `ocr`, `analytics`, `notifications`,
`complaints`, `report`, `maintenance`, `high_priority`, `low_priority`,
`dead_letter`. Every queue advertises `x-max-priority=9` so callers can
route Critical work ahead of Background work on the same worker.

## 5. Task lifecycle

```
API/service ─► TaskDispatcherService.dispatch()
                 ├─ rate-limit + dedup (Redis)
                 ├─ insert BackgroundJob (status=queued)
                 └─ celery.send_task(queue, priority, headers.job_id)
                                                  │
        task_prerun ──► BackgroundJob → running
        task_retry   ──► retry_count++
        task_postrun ──► SUCCESS: BackgroundJob → success + duration_ms
        task_failure ──► BackgroundJob → failed + dead_letter.publish()
        task_revoked ──► BackgroundJob → cancelled
```

## 6. Scheduler architecture

Beat entries live in `workers/scheduler.py`. Module 8 adds:
`maintenance.snapshot_queue_depth` (every minute), `maintenance.dlq_size`
(every 5 min), `maintenance.cleanup_background_jobs` (03:15), and
`analytics.daily_rollup` (02:00). Existing feature cadences are untouched.

## 7. Retry strategy

`services/tasks/retry.py::RetryPolicy` — `max_retries=3`, `base=15s`,
`max=600s`, ±20% jitter. Task-owning modules import
`retry_delay_seconds(retry_count)` and pass to `self.retry(countdown=...)`.
When `should_dead_letter` returns True, the failure handler publishes to
the DLQ stream and marks the job `failed`.

## 8. Monitoring strategy

`MonitoringService` exposes:

* `platform_health()` — Redis ping, broker ping, DLQ size.
* `queue_depths()` — `LLEN` per broker queue.
* `workers()` — `celery.control.inspect` stats/active/reserved/registered.
* `history()` / `job()` — reads from `background_jobs`.

## 9. Flower integration

Flower is deployed as a sidecar container and reads the same Redis broker.
Recommended launch:

```
celery -A app.workers.celery_app.celery flower \
  --address=0.0.0.0 --port=5555 \
  --basic_auth=$FLOWER_USER:$FLOWER_PASS \
  --url_prefix=flower
```

## 10. Prometheus metrics

Emitted from `workers/hooks.py`:

* `guardianmail_task_started_total{task,queue}`
* `guardianmail_task_succeeded_total{task,queue}`
* `guardianmail_task_failed_total{task,queue,exception}`
* `guardianmail_task_retried_total{task,queue}`
* `guardianmail_task_duration_seconds{task,queue}` (histogram)
* `guardianmail_queue_depth{queue}` — set by `maintenance.snapshot_queue_depth`
* `guardianmail_dead_letter_size` — set by `maintenance.dlq_size`

Scraped at `GET /metrics` (gated by `X-Metrics-Token` when `METRICS_TOKEN`
is set).

## 11. Grafana dashboard (recommended panels)

* Queue depth (stacked area, per queue)
* Task throughput = `sum(rate(task_started_total[5m])) by (queue)`
* Failure rate = `sum(rate(task_failed_total[5m])) by (queue,exception)`
* P95 duration = `histogram_quantile(0.95, sum(rate(task_duration_seconds_bucket[5m])) by (le,task))`
* Retry rate = `sum(rate(task_retried_total[5m])) by (task)`
* Dead-letter size (single-stat with threshold at 100)

## 12. API endpoints (all authenticated)

```
POST   /api/v1/tasks/run                       dispatch (allow-listed names)
GET    /api/v1/tasks/{job_id}                  read a job
GET    /api/v1/tasks/history/list              paginated history
POST   /api/v1/tasks/{job_id}/retry            requeue a failed job
DELETE /api/v1/tasks/{job_id}                  cancel / revoke
GET    /api/v1/tasks/platform/health           health
GET    /api/v1/tasks/platform/queues           broker queue depths
GET    /api/v1/tasks/platform/workers          worker inspect
GET    /api/v1/tasks/platform/dead-letter      DLQ tail
GET    /metrics                                Prometheus scrape
```

Dispatch is restricted to an allow-list (`ALLOWED_TASKS`) so users can
never trigger internal maintenance tasks.

## 13. Service layer

`services/tasks/`:
* `TaskDispatcherService` — single write path, rate-limit + dedup + job row.
* `MonitoringService` — read-only inspection surface.
* `priority` — enum + queue map.
* `retry` — pure backoff calculator.
* `dead_letter` — Redis-stream DLQ publisher / peek / size.

## 14. Database integration

Existing `background_jobs` collection (Module 3) is the single execution
log. The TTL index on `finished_at` (60d) already handles auto-cleanup;
`maintenance.cleanup_background_jobs` provides a manual pruning knob.

## 15. Logging strategy

Structured logs at every lifecycle boundary via `workers/hooks.py`:
`task_prerun`, `task_success`, `task_retry`, `task_failure`,
`task_revoked`, `task_dispatched`. Every log carries `task`, `task_id`,
`queue`, and (for success) `duration_ms`.

## 16. Security strategy

* All `/api/v1/tasks/*` endpoints require `Principal`.
* Task-name allow-list on `POST /tasks/run`.
* Per-user rate limit (60/min) via Redis `INCR` + `EXPIRE`.
* Optional dedup key with TTL so double-clicks don't duplicate work.
* `/metrics` gated behind `X-Metrics-Token`.
* Cancel/retry endpoints reject if the job's `user_id` doesn't match the caller.

## 17. Testing strategy

`app/tests/test_task_platform.py` covers the pure helpers (queue mapping,
priority enum, backoff monotonicity + cap, DLQ threshold). Integration
tests should run against a live Redis + Mongo via the docker-compose
fixture in Module 1, exercising `dispatch → prerun → success` and
`dispatch → failure → DLQ`.

## 18. Production deployment

Docker-compose services (recommended):

```
api             (uvicorn app.main:app)
worker-gmail    celery -A app.workers.celery_app.celery worker -Q gmail        -c 8
worker-threat   celery -A app.workers.celery_app.celery worker -Q threat       -c 8
worker-ai       celery -A app.workers.celery_app.celery worker -Q ai           -c 4
worker-ocr      celery -A app.workers.celery_app.celery worker -Q ocr          -c 4
worker-general  celery -A app.workers.celery_app.celery worker \
                    -Q default,analytics,notifications,complaints,report,maintenance,high_priority,low_priority
                    -c 8
beat            celery -A app.workers.celery_app.celery beat
flower          celery -A app.workers.celery_app.celery flower --port=5555
redis           redis:7-alpine (with maxmemory-policy=allkeys-lru for cache DB)
prometheus      scrapes api:8000/metrics
grafana         dashboards from panel list above
```

Horizontal scaling: increase replica count per worker service; the broker
handles load distribution. Beat must remain singleton (use a
`redlock`-backed scheduler or Kubernetes `replicas: 1`).
