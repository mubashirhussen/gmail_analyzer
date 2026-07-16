"""Role-based access control (Phase 20)."""
from __future__ import annotations

from typing import Dict, Iterable, Set

# ---- permissions ---------------------------------------------------------
PERMISSIONS: Set[str] = {
    "threat.scan", "threat.read",
    "evidence.download", "evidence.read",
    "complaint.generate", "complaint.read",
    "dashboard.read", "analytics.read",
    "copilot.use",
    "settings.read", "settings.write",
    "admin.manage", "billing.manage",
    "user.manage", "role.manage",
    "api.use", "api.manage",
    "soc.read", "soc.manage",
}

# ---- built-in roles ------------------------------------------------------
_ALL = frozenset(PERMISSIONS)

ROLES: Dict[str, frozenset] = {
    "owner": _ALL,
    "administrator": _ALL - {"billing.manage"},
    "security_administrator": frozenset({
        "threat.scan", "threat.read", "evidence.download", "evidence.read",
        "complaint.generate", "complaint.read", "dashboard.read",
        "analytics.read", "copilot.use", "soc.read", "soc.manage",
        "settings.read", "settings.write", "user.manage",
    }),
    "soc_analyst": frozenset({
        "threat.scan", "threat.read", "evidence.download", "evidence.read",
        "dashboard.read", "analytics.read", "copilot.use",
        "soc.read", "soc.manage",
    }),
    "manager": frozenset({
        "threat.read", "dashboard.read", "analytics.read", "copilot.use",
        "complaint.read", "user.manage", "settings.read",
    }),
    "employee": frozenset({
        "threat.scan", "threat.read", "complaint.generate", "complaint.read",
        "dashboard.read", "copilot.use", "evidence.download",
    }),
    "readonly": frozenset({
        "threat.read", "dashboard.read", "analytics.read", "complaint.read",
        "evidence.read", "soc.read",
    }),
    "guest": frozenset({"dashboard.read"}),
}


class RBACService:
    """Pure, in-memory RBAC evaluator; safe to unit-test."""

    def __init__(self, custom_roles: Dict[str, Iterable[str]] | None = None):
        self._custom: Dict[str, frozenset] = {}
        for name, perms in (custom_roles or {}).items():
            self.register_custom_role(name, perms)

    # -- role management ------------------------------------------------
    def register_custom_role(self, name: str, permissions: Iterable[str]) -> None:
        name = (name or "").strip().lower()
        if not name:
            raise ValueError("role name required")
        if name in ROLES:
            raise ValueError(f"cannot override built-in role: {name}")
        clean = frozenset(p for p in permissions if p in PERMISSIONS)
        if not clean:
            raise ValueError("custom role must grant at least one permission")
        self._custom[name] = clean

    def role_permissions(self, role: str) -> frozenset:
        role = (role or "").lower()
        return ROLES.get(role) or self._custom.get(role) or frozenset()

    # -- checks ---------------------------------------------------------
    def has_permission(self, roles: Iterable[str], permission: str) -> bool:
        if permission not in PERMISSIONS:
            return False
        for r in roles or ():
            if permission in self.role_permissions(r):
                return True
        return False

    def require(self, roles: Iterable[str], permission: str) -> None:
        if not self.has_permission(roles, permission):
            raise PermissionError(f"missing permission: {permission}")

    def effective_permissions(self, roles: Iterable[str]) -> Set[str]:
        out: Set[str] = set()
        for r in roles or ():
            out |= set(self.role_permissions(r))
        return out
