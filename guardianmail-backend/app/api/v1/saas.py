"""Phase 20 — Enterprise SaaS API endpoints.

All endpoints require an authenticated context and are tenant-scoped. This
router is additive and does not alter existing GuardianMail endpoints.
"""
from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, Header, HTTPException, status

from app.repositories.saas import (
    InvoiceRepository, LicenseRepository, MembershipRepository,
    OrganizationRepository, SubscriptionRepository, TenantRepository,
    UsageRepository, WorkspaceRepository,
)
from app.schemas.saas import (
    LicenseCreate, LicenseOut, MemberInvite, MemberOut, OrganizationCreate,
    OrganizationOut, QuotaCheckRequest, QuotaCheckResponse,
    SubscriptionCreate, SubscriptionOut, TenantCreate, TenantOut,
    UsageSnapshot, WorkspaceCreate, WorkspaceOut,
)
from app.services.saas import (
    BillingService, LicenseService, OrganizationService, QuotaService,
    RBACService, SubscriptionService, TenantService, UsageService,
    WorkspaceService,
)
from app.services.saas.tenant_service import TenantContext


router = APIRouter(prefix="/saas", tags=["saas"])

# ---- shared singletons ---------------------------------------------------
_usage = UsageService()
_quota = QuotaService(_usage)
_rbac = RBACService()
_tenants = TenantService(TenantRepository())
_orgs = OrganizationService(OrganizationRepository())
_workspaces = WorkspaceService(WorkspaceRepository())
_subs = SubscriptionService(SubscriptionRepository())
_licenses = LicenseService(LicenseRepository())
_billing = BillingService()

_tenant_repo = TenantRepository()
_org_repo = OrganizationRepository()
_member_repo = MembershipRepository()
_workspace_repo = WorkspaceRepository()
_sub_repo = SubscriptionRepository()
_license_repo = LicenseRepository()
_invoice_repo = InvoiceRepository()


# ---- context resolver ----------------------------------------------------
async def get_tenant_context(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-Id"),
    x_user_id: str = Header(..., alias="X-User-Id"),
    x_roles: str | None = Header(default=None, alias="X-Roles"),
) -> TenantContext:
    if not x_tenant_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "tenant required")
    roles = tuple(r.strip() for r in (x_roles or "").split(",") if r.strip())
    return TenantContext(
        tenant_id=x_tenant_id,
        organization_id=x_organization_id,
        workspace_id=None,
        user_id=x_user_id,
        roles=roles,
    )


def require_permission(ctx: TenantContext, permission: str) -> None:
    if not _rbac.has_permission(ctx.roles, permission):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            f"missing permission: {permission}")


# ---- tenants -------------------------------------------------------------
@router.post("/tenants", response_model=TenantOut,
             status_code=status.HTTP_201_CREATED)
async def create_tenant(payload: TenantCreate):
    doc = _tenants.build_tenant(name=payload.name, plan=payload.plan,
                                isolation=payload.isolation)
    await _tenant_repo.create(doc)
    return TenantOut(**doc)


@router.get("/tenants/current", response_model=TenantOut)
async def get_current_tenant(ctx: TenantContext = Depends(get_tenant_context)):
    doc = await _tenant_repo.get(ctx.tenant_id)
    if not doc:
        raise HTTPException(404, "tenant not found")
    return TenantOut(**doc)


# ---- organizations -------------------------------------------------------
@router.post("/organizations", response_model=OrganizationOut,
             status_code=status.HTTP_201_CREATED)
async def create_organization(payload: OrganizationCreate,
                              ctx: TenantContext = Depends(get_tenant_context)):
    require_permission(ctx, "admin.manage")
    doc = _orgs.build_organization(
        tenant_id=ctx.tenant_id, name=payload.name,
        owner_user_id=payload.owner_user_id, org_type=payload.type,
    )
    await _org_repo.create(doc)
    return OrganizationOut(**doc)


@router.get("/organizations", response_model=List[OrganizationOut])
async def list_organizations(ctx: TenantContext = Depends(get_tenant_context)):
    docs = await _org_repo.list(ctx.tenant_id)
    return [OrganizationOut(**d) for d in docs]


@router.post("/organizations/{organization_id}/members",
             response_model=MemberOut, status_code=status.HTTP_201_CREATED)
async def invite_member(organization_id: str, payload: MemberInvite,
                        ctx: TenantContext = Depends(get_tenant_context)):
    require_permission(ctx, "user.manage")
    org = await _org_repo.get(ctx.tenant_id, organization_id)
    if not org:
        raise HTTPException(404, "organization not found")
    if not _orgs.domain_allowed(org, payload.email):
        raise HTTPException(400, "email domain not allowed for this organization")
    doc = _orgs.build_member(
        organization_id=organization_id, tenant_id=ctx.tenant_id,
        user_id=payload.user_id, email=payload.email, roles=payload.roles,
    )
    await _member_repo.create(doc)
    return MemberOut(**doc)


# ---- workspaces ----------------------------------------------------------
@router.post("/workspaces", response_model=WorkspaceOut,
             status_code=status.HTTP_201_CREATED)
async def create_workspace(payload: WorkspaceCreate,
                           ctx: TenantContext = Depends(get_tenant_context)):
    require_permission(ctx, "admin.manage")
    doc = _workspaces.build_workspace(
        tenant_id=ctx.tenant_id, organization_id=payload.organization_id,
        name=payload.name, workspace_type=payload.type,
        owner_user_id=payload.owner_user_id or ctx.user_id or "",
    )
    await _workspace_repo.create(doc)
    return WorkspaceOut(**doc)


@router.get("/workspaces", response_model=List[WorkspaceOut])
async def list_workspaces(organization_id: str,
                          ctx: TenantContext = Depends(get_tenant_context)):
    docs = await _workspace_repo.list(ctx.tenant_id, organization_id)
    return [WorkspaceOut(**d) for d in docs]


# ---- subscriptions -------------------------------------------------------
@router.post("/subscriptions", response_model=SubscriptionOut,
             status_code=status.HTTP_201_CREATED)
async def create_subscription(payload: SubscriptionCreate,
                              ctx: TenantContext = Depends(get_tenant_context)):
    require_permission(ctx, "billing.manage")
    doc = _subs.build(
        tenant_id=ctx.tenant_id, plan=payload.plan,
        billing_cycle=payload.billing_cycle, trial_days=payload.trial_days,
        seats=payload.seats,
    )
    await _sub_repo.create(doc)
    return SubscriptionOut(**doc)


@router.get("/subscriptions/current", response_model=SubscriptionOut)
async def get_current_subscription(ctx: TenantContext = Depends(get_tenant_context)):
    doc = await _sub_repo.get_current(ctx.tenant_id)
    if not doc:
        raise HTTPException(404, "no subscription")
    return SubscriptionOut(**doc)


# ---- usage & quotas ------------------------------------------------------
@router.get("/usage", response_model=UsageSnapshot)
async def get_usage(ctx: TenantContext = Depends(get_tenant_context)):
    return UsageSnapshot(**_usage.snapshot(ctx.tenant_id))


@router.post("/quota/check", response_model=QuotaCheckResponse)
async def check_quota(payload: QuotaCheckRequest,
                      ctx: TenantContext = Depends(get_tenant_context)):
    sub = await _sub_repo.get_current(ctx.tenant_id)
    if not sub:
        raise HTTPException(404, "no subscription")
    result = _quota.check(ctx.tenant_id, payload.metric,
                          _subs.limits(sub), payload.amount)
    return QuotaCheckResponse(
        metric=result.metric, allowed=result.allowed, limit=result.limit,
        used=result.used, remaining=result.remaining, reason=result.reason,
    )


# ---- licenses ------------------------------------------------------------
@router.post("/licenses", response_model=LicenseOut,
             status_code=status.HTTP_201_CREATED)
async def create_license(payload: LicenseCreate,
                         ctx: TenantContext = Depends(get_tenant_context)):
    require_permission(ctx, "admin.manage")
    doc = _licenses.build(
        tenant_id=ctx.tenant_id, subscription_id=payload.subscription_id,
        seats=payload.seats, duration_days=payload.duration_days,
    )
    await _license_repo.create(doc)
    return LicenseOut(**doc)


@router.get("/licenses", response_model=List[LicenseOut])
async def list_licenses(ctx: TenantContext = Depends(get_tenant_context)):
    docs = await _license_repo.list(ctx.tenant_id)
    return [LicenseOut(**d) for d in docs]
