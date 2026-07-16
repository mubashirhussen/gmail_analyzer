"""Tenant lifecycle and context resolution (Phase 20).

The tenant is the top-level isolation boundary. Every downstream document
in this module is scoped by `tenant_id`; cross-tenant reads are rejected by
`ensure_same_tenant`.
"""
from __future__ import annotations

import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

_SLUG_RE = re.compile(r"[^a-z0-9]+")


@dataclass
class TenantContext:
    tenant_id: str
    organization_id: Optional[str]
    workspace_id: Optional[str]
    user_id: Optional[str]
    roles: tuple = ()

    def require_tenant(self) -> str:
        if not self.tenant_id:
            raise PermissionError("tenant context required")
        return self.tenant_id


def _slugify(name: str) -> str:
    slug = _SLUG_RE.sub("-", (name or "").strip().lower()).strip("-")
    return slug or "tenant"


class TenantService:
    """Deterministic tenant identity + isolation helpers.

    Storage is intentionally injected (repository) so this service stays
    unit-testable without a running Mongo.
    """

    def __init__(self, repository=None):
        self.repo = repository

    # -- identity -------------------------------------------------------
    def new_tenant_id(self) -> str:
        return f"tnt_{uuid.uuid4().hex[:24]}"

    def build_tenant(self, *, name: str, plan: str = "free",
                     isolation: str = "shared") -> dict:
        if not name or len(name) < 2:
            raise ValueError("tenant name too short")
        if isolation not in {"shared", "dedicated"}:
            raise ValueError("isolation must be shared|dedicated")
        now = datetime.now(timezone.utc)
        return {
            "tenant_id": self.new_tenant_id(),
            "name": name.strip(),
            "slug": _slugify(name),
            "plan": plan,
            "isolation": isolation,
            "status": "active",
            "created_at": now,
            "updated_at": now,
            "settings": {
                "password_policy": {
                    "min_length": 12, "require_upper": True,
                    "require_number": True, "require_symbol": True,
                },
                "session_timeout_min": 60,
                "idle_timeout_min": 15,
                "allowed_domains": [],
                "blocked_domains": [],
                "threat_threshold": 70,
                "retention_days": 90,
            },
        }

    # -- isolation helpers ---------------------------------------------
    @staticmethod
    def ensure_same_tenant(ctx: TenantContext, resource_tenant_id: str) -> None:
        if not resource_tenant_id or ctx.tenant_id != resource_tenant_id:
            raise PermissionError("cross-tenant access denied")

    @staticmethod
    def scope_query(ctx: TenantContext, query: Optional[dict] = None) -> dict:
        q = dict(query or {})
        q["tenant_id"] = ctx.require_tenant()
        return q

    # -- api keys -------------------------------------------------------
    def issue_api_key(self, tenant_id: str, *, label: str = "default") -> dict:
        raw = secrets.token_urlsafe(32)
        return {
            "tenant_id": tenant_id,
            "key_id": f"key_{uuid.uuid4().hex[:16]}",
            "label": label,
            "prefix": raw[:8],
            "secret": raw,          # caller MUST hash before persisting
            "created_at": datetime.now(timezone.utc),
            "revoked_at": None,
        }
