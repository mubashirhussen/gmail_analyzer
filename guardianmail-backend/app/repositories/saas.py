"""Phase 20 — SaaS repositories.

Thin Motor adapters. All queries are tenant-scoped; callers must supply a
`tenant_id` (or `TenantContext`) — the repositories never issue an unscoped
query outside of platform-admin aggregation helpers.
"""
from __future__ import annotations

from typing import Iterable, Optional

from app.database.mongodb import mongodb


def _db():
    return mongodb.db


class TenantRepository:
    coll = "saas_tenants"

    async def create(self, doc: dict) -> dict:
        await _db()[self.coll].insert_one(doc)
        return doc

    async def get(self, tenant_id: str) -> Optional[dict]:
        return await _db()[self.coll].find_one({"tenant_id": tenant_id})

    async def by_slug(self, slug: str) -> Optional[dict]:
        return await _db()[self.coll].find_one({"slug": slug})

    async def list(self, *, limit: int = 100) -> list:
        cur = _db()[self.coll].find().limit(limit)
        return [d async for d in cur]


class OrganizationRepository:
    coll = "saas_organizations"

    async def create(self, doc: dict) -> dict:
        await _db()[self.coll].insert_one(doc)
        return doc

    async def get(self, tenant_id: str, organization_id: str) -> Optional[dict]:
        return await _db()[self.coll].find_one({
            "tenant_id": tenant_id, "organization_id": organization_id,
        })

    async def list(self, tenant_id: str) -> list:
        cur = _db()[self.coll].find({"tenant_id": tenant_id})
        return [d async for d in cur]


class MembershipRepository:
    coll = "saas_memberships"

    async def create(self, doc: dict) -> dict:
        await _db()[self.coll].insert_one(doc)
        return doc

    async def list(self, tenant_id: str, organization_id: str) -> list:
        cur = _db()[self.coll].find({
            "tenant_id": tenant_id, "organization_id": organization_id,
        })
        return [d async for d in cur]


class WorkspaceRepository:
    coll = "saas_workspaces"

    async def create(self, doc: dict) -> dict:
        await _db()[self.coll].insert_one(doc)
        return doc

    async def list(self, tenant_id: str, organization_id: str) -> list:
        cur = _db()[self.coll].find({
            "tenant_id": tenant_id, "organization_id": organization_id,
        })
        return [d async for d in cur]


class SubscriptionRepository:
    coll = "saas_subscriptions"

    async def create(self, doc: dict) -> dict:
        await _db()[self.coll].insert_one(doc)
        return doc

    async def get_current(self, tenant_id: str) -> Optional[dict]:
        return await _db()[self.coll].find_one(
            {"tenant_id": tenant_id},
            sort=[("created_at", -1)],
        )


class LicenseRepository:
    coll = "saas_licenses"

    async def create(self, doc: dict) -> dict:
        await _db()[self.coll].insert_one(doc)
        return doc

    async def list(self, tenant_id: str) -> list:
        cur = _db()[self.coll].find({"tenant_id": tenant_id})
        return [d async for d in cur]


class InvoiceRepository:
    coll = "saas_invoices"

    async def create(self, doc: dict) -> dict:
        await _db()[self.coll].insert_one(doc)
        return doc

    async def list(self, tenant_id: str, *, limit: int = 100) -> list:
        cur = _db()[self.coll].find({"tenant_id": tenant_id}) \
            .sort("created_at", -1).limit(limit)
        return [d async for d in cur]


class UsageRepository:
    coll = "saas_usage"

    async def upsert(self, tenant_id: str, period: str, metric: str,
                     value: int) -> None:
        await _db()[self.coll].update_one(
            {"tenant_id": tenant_id, "period": period, "metric": metric},
            {"$set": {"value": value}},
            upsert=True,
        )

    async def get(self, tenant_id: str, period: str, metric: str) -> int:
        doc = await _db()[self.coll].find_one({
            "tenant_id": tenant_id, "period": period, "metric": metric,
        })
        return int((doc or {}).get("value", 0))

    async def snapshot(self, tenant_id: str, periods: Iterable[str]) -> list:
        cur = _db()[self.coll].find({
            "tenant_id": tenant_id, "period": {"$in": list(periods)},
        })
        return [d async for d in cur]
