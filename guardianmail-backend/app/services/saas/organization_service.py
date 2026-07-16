"""Organization + membership management (Phase 20)."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Iterable, Optional


VALID_MEMBER_STATUS = {"active", "invited", "suspended", "removed"}


class OrganizationService:
    def __init__(self, repository=None):
        self.repo = repository

    def build_organization(self, *, tenant_id: str, name: str,
                           owner_user_id: str, org_type: str = "company") -> dict:
        if not tenant_id:
            raise ValueError("tenant_id required")
        if not name or len(name) < 2:
            raise ValueError("organization name too short")
        if org_type not in {"individual", "team", "company", "education",
                            "government", "enterprise"}:
            raise ValueError(f"invalid org_type: {org_type}")
        now = datetime.now(timezone.utc)
        return {
            "organization_id": f"org_{uuid.uuid4().hex[:20]}",
            "tenant_id": tenant_id,
            "name": name.strip(),
            "type": org_type,
            "status": "active",
            "owner_user_id": owner_user_id,
            "branding": {"logo_url": None, "primary_color": None},
            "settings": {
                "allowed_email_domains": [],
                "require_mfa": False,
                "sso_enabled": False,
            },
            "created_at": now,
            "updated_at": now,
        }

    def build_member(self, *, organization_id: str, tenant_id: str,
                     user_id: str, email: str,
                     roles: Iterable[str] = ("employee",),
                     status: str = "invited") -> dict:
        if status not in VALID_MEMBER_STATUS:
            raise ValueError(f"invalid status: {status}")
        roles_t = tuple(dict.fromkeys(r.lower() for r in roles if r))
        if not roles_t:
            raise ValueError("at least one role required")
        return {
            "membership_id": f"mem_{uuid.uuid4().hex[:20]}",
            "organization_id": organization_id,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "email": (email or "").lower(),
            "roles": list(roles_t),
            "status": status,
            "invited_at": datetime.now(timezone.utc),
            "joined_at": None,
        }

    # -- state transitions ---------------------------------------------
    def suspend(self, member: dict, reason: Optional[str] = None) -> dict:
        member["status"] = "suspended"
        member["suspended_at"] = datetime.now(timezone.utc)
        if reason:
            member["suspension_reason"] = reason
        return member

    def remove(self, member: dict) -> dict:
        member["status"] = "removed"
        member["removed_at"] = datetime.now(timezone.utc)
        return member

    def deactivate_org(self, org: dict) -> dict:
        org["status"] = "deactivated"
        org["deactivated_at"] = datetime.now(timezone.utc)
        return org

    def domain_allowed(self, org: dict, email: str) -> bool:
        allowed = (org.get("settings") or {}).get("allowed_email_domains") or []
        if not allowed:
            return True
        domain = (email or "").split("@")[-1].lower()
        return any(domain == d.lower() for d in allowed)
