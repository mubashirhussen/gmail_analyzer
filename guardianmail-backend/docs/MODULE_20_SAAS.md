# Module 20 — Enterprise SaaS Platform

Phase 20 transforms GuardianMail AI into a multi-tenant SaaS platform.
It is strictly **additive**: no prior module's business logic, API, or DB
schema is modified. All new artifacts live under dedicated namespaces:

- `app/services/saas/` — tenant, org, workspace, subscription, billing,
  usage, quota, license, RBAC, retention.
- `app/models/saas.py`, `app/repositories/saas.py`, `app/schemas/saas.py`.
- `app/api/v1/saas.py` — `/api/v1/saas/*` endpoints.
- `app/workers/saas_tasks.py` — six scheduled Celery tasks.
- `app/tests/test_phase20_saas.py` — deterministic unit suite.

---

## 1. Enterprise SaaS Architecture

```
Internet → Auth Gateway → Tenant Resolver → Organization → Workspace
        → GuardianMail Services (Threat, AI, OCR)
        → Data Layer (per-tenant scoped) → Monitoring / Billing / Audit
```

The tenant is the top-level isolation boundary. Every downstream document
carries `tenant_id`, enforced by `TenantService.scope_query` and
`ensure_same_tenant`.

## 2. Multi-Tenant Model

- **Shared** infrastructure, isolated data via `tenant_id` scoping.
- **Dedicated** isolation flag reserved for future physical separation.
- Tenant document tracks plan, status, policies, retention.

## 3. Organizations & Membership

- Types: `individual, team, company, education, government, enterprise`.
- Members carry `roles: List[str]` and status transitions:
  `invited → active`, `suspended`, `removed`.
- Domain allow-lists per organization.

## 4. Workspaces

- Types: `personal, team, enterprise, investigation`.
- Membership list of user_ids; workspaces belong to a single org/tenant.

## 5. RBAC

Built-in roles: `owner, administrator, security_administrator, soc_analyst,
manager, employee, readonly, guest`, plus `register_custom_role`.
Permissions are drawn from a bounded set (`PERMISSIONS`) covering scan,
evidence, complaint, dashboard, analytics, copilot, settings, admin,
billing, user, role, api, soc.

## 6. Authentication Strategy

Compatible with existing GuardianMail auth (Google OAuth, email+JWT).
SaaS endpoints resolve context from `X-Tenant-Id`, `X-Organization-Id`,
`X-User-Id`, `X-Roles`. MFA / passkey / SSO hooks are declared in tenant
settings (`require_mfa`, `sso_enabled`).

## 7. Subscription Management

Six plans (`free, starter, professional, business, enterprise, custom`).
`PlanLimits` covers storage, monthly + daily scans, users, orgs, OCR/AI
budgets, TI requests, complaints, API calls, retention, and features.

## 8. Billing Architecture

`BillingService` is provider-agnostic; a `BillingProvider` protocol lets
Stripe / Razorpay / PayPal / invoicing be wired in later. Invoices support
line items, overages, coupons, payment marking, voiding.

## 9. Usage & Quota Management

- `UsageService` records per-tenant counters for both daily and monthly
  windows.
- `QuotaService.check` enforces daily-then-monthly, and storage as a level.
- `-1` limits mean unlimited (`custom` plan).

## 10. License Management

Keys hashed at rest (`sha256`). Seat pool with assign/release, revoke,
expiry, activation timestamp. `verify_key` for validation.

## 11. Tenant Security Model

- Isolation via `tenant_id` on every query.
- Per-tenant API keys, hashed before persistence.
- Encrypted secrets and separate sessions are inherited from existing
  hardening (Module 11).
- Cross-tenant access rejected in service layer.

## 12. Database

Collections (Mongo):
`saas_tenants, saas_organizations, saas_memberships, saas_workspaces,
saas_subscriptions, saas_licenses, saas_invoices, saas_usage`.

## 13. Celery Workers

`saas.usage_aggregate, saas.quota_recompute, saas.subscription_validate,
saas.billing_process, saas.retention_cleanup, saas.workspace_sync`.

## 14. API Design

`/api/v1/saas/tenants`, `/organizations`, `/workspaces`, `/subscriptions`,
`/usage`, `/quota/check`, `/licenses`, plus membership sub-resources.
Every mutation checks a specific RBAC permission.

## 15. Performance Optimization

- Compound indexes on `(tenant_id, ...)`.
- In-memory `RBACService` avoids DB lookup on hot path.
- Usage counters keyed by `(tenant, period, metric)` for O(1) reads.

## 16. Security Strategy

Tenant-scoped queries, hashed API + license keys, coupon bounds, seat
caps, cross-tenant guardrails, deterministic serializers.

## 17. Testing Strategy

`test_phase20_saas.py` covers tenant isolation, org lifecycle, workspace
membership, RBAC (built-in and custom), subscription lifecycle, quotas
(daily + unlimited), usage snapshots, license seats/keys, billing math,
retention windows.

## 18. Documentation Plan

This file plus in-service docstrings. Runbooks will be added under
`docs/runbooks/` on demand.

## 19. Production Readiness Checklist

- [x] All new modules additive (no changes to prior business logic).
- [x] RBAC gates on every mutation.
- [x] Tenant scoping enforced.
- [x] Celery tasks registered.
- [x] Router mounted in `app/main.py`.
- [x] Unit tests deterministic and self-contained.

## 20. Enterprise SaaS Validation Report

- Multi-tenant boundary: enforced.
- RBAC coverage: 8 built-in roles, custom-role support.
- Plan matrix: 6 plans × 11 quota dimensions.
- Billing: coupon math verified, overage rated per unit.
- License: seat cap + revoke + expiry validated.
- No modification to Modules 1–19; ready for Phase 21 approval.
