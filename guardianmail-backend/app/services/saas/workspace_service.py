"""Workspace management (Phase 20)."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Iterable


WORKSPACE_TYPES = {"personal", "team", "enterprise", "investigation"}


class WorkspaceService:
    def __init__(self, repository=None):
        self.repo = repository

    def build_workspace(self, *, tenant_id: str, organization_id: str,
                        name: str, workspace_type: str = "team",
                        owner_user_id: str = "") -> dict:
        if workspace_type not in WORKSPACE_TYPES:
            raise ValueError(f"invalid workspace type: {workspace_type}")
        if not name:
            raise ValueError("workspace name required")
        now = datetime.now(timezone.utc)
        return {
            "workspace_id": f"ws_{uuid.uuid4().hex[:20]}",
            "tenant_id": tenant_id,
            "organization_id": organization_id,
            "name": name.strip(),
            "type": workspace_type,
            "owner_user_id": owner_user_id,
            "members": [owner_user_id] if owner_user_id else [],
            "status": "active",
            "created_at": now,
            "updated_at": now,
        }

    def add_members(self, workspace: dict, user_ids: Iterable[str]) -> dict:
        members = set(workspace.get("members") or [])
        members.update(u for u in user_ids if u)
        workspace["members"] = sorted(members)
        workspace["updated_at"] = datetime.now(timezone.utc)
        return workspace

    def remove_member(self, workspace: dict, user_id: str) -> dict:
        workspace["members"] = [u for u in (workspace.get("members") or []) if u != user_id]
        workspace["updated_at"] = datetime.now(timezone.utc)
        return workspace

    @staticmethod
    def user_in_workspace(workspace: dict, user_id: str) -> bool:
        return user_id in (workspace.get("members") or [])
