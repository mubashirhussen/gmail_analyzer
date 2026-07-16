"""Phase 20 — SaaS document schemas (Mongo).

Pydantic v2 models kept intentionally close to what the service layer emits
so persistence stays a thin adapter.
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class Tenant(BaseModel):
    tenant_id: str
    name: str
    slug: str
    plan: str = "free"
    isolation: str = "shared"
    status: str = "active"
    settings: dict = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class Organization(BaseModel):
    organization_id: str
    tenant_id: str
    name: str
    type: str
    status: str = "active"
    owner_user_id: str
    branding: dict = Field(default_factory=dict)
    settings: dict = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class Membership(BaseModel):
    membership_id: str
    organization_id: str
    tenant_id: str
    user_id: str
    email: str
    roles: List[str]
    status: str = "invited"
    invited_at: datetime
    joined_at: Optional[datetime] = None


class Workspace(BaseModel):
    workspace_id: str
    tenant_id: str
    organization_id: str
    name: str
    type: str
    owner_user_id: str = ""
    members: List[str] = Field(default_factory=list)
    status: str = "active"
    created_at: datetime
    updated_at: datetime


class Subscription(BaseModel):
    subscription_id: str
    tenant_id: str
    plan: str
    billing_cycle: str
    seats: int
    status: str
    trial_days: int = 0
    current_period_start: datetime
    current_period_end: datetime
    created_at: datetime
    updated_at: datetime


class License(BaseModel):
    license_id: str
    tenant_id: str
    subscription_id: str
    key_hash: str
    seats: int
    assigned_user_ids: List[str] = Field(default_factory=list)
    status: str
    issued_at: datetime
    activated_at: Optional[datetime] = None
    expires_at: datetime


class Invoice(BaseModel):
    invoice_id: str
    tenant_id: str
    subscription_id: str
    currency: str = "USD"
    period_start: datetime
    period_end: datetime
    line_items: list
    subtotal_cents: int
    discount_cents: int = 0
    total_cents: int
    status: str = "open"
    created_at: datetime


class UsageRecord(BaseModel):
    tenant_id: str
    period: str          # "YYYY-MM-DD" or "YYYY-MM"
    metric: str
    value: int
