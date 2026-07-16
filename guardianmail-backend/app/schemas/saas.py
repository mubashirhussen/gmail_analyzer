"""Phase 20 — API request/response schemas."""
from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field


# ---- tenants -------------------------------------------------------------
class TenantCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    plan: str = "free"
    isolation: str = "shared"


class TenantOut(BaseModel):
    tenant_id: str
    name: str
    slug: str
    plan: str
    isolation: str
    status: str


# ---- organizations -------------------------------------------------------
class OrganizationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    owner_user_id: str
    type: str = "company"


class OrganizationOut(BaseModel):
    organization_id: str
    tenant_id: str
    name: str
    type: str
    status: str


# ---- memberships ---------------------------------------------------------
class MemberInvite(BaseModel):
    email: EmailStr
    user_id: str
    roles: List[str] = Field(default_factory=lambda: ["employee"])


class MemberOut(BaseModel):
    membership_id: str
    email: EmailStr
    user_id: str
    roles: List[str]
    status: str


# ---- workspaces ----------------------------------------------------------
class WorkspaceCreate(BaseModel):
    organization_id: str
    name: str
    type: str = "team"
    owner_user_id: str = ""


class WorkspaceOut(BaseModel):
    workspace_id: str
    tenant_id: str
    organization_id: str
    name: str
    type: str
    status: str


# ---- subscription --------------------------------------------------------
class SubscriptionCreate(BaseModel):
    plan: str = "free"
    billing_cycle: str = "monthly"
    trial_days: int = 0
    seats: int = 1


class SubscriptionOut(BaseModel):
    subscription_id: str
    tenant_id: str
    plan: str
    billing_cycle: str
    seats: int
    status: str


# ---- usage / quotas ------------------------------------------------------
class UsageSnapshot(BaseModel):
    tenant_id: str
    day: str
    month: str
    daily: dict
    monthly: dict


class QuotaCheckRequest(BaseModel):
    metric: str
    amount: int = 1


class QuotaCheckResponse(BaseModel):
    metric: str
    allowed: bool
    limit: int
    used: int
    remaining: int
    reason: Optional[str] = None


# ---- license -------------------------------------------------------------
class LicenseCreate(BaseModel):
    subscription_id: str
    seats: int = Field(ge=1)
    duration_days: int = 365


class LicenseOut(BaseModel):
    license_id: str
    tenant_id: str
    subscription_id: str
    seats: int
    assigned_user_ids: List[str]
    status: str
