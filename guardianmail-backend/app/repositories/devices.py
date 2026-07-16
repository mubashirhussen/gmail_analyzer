"""Devices repository."""
from __future__ import annotations

from app.core.clock import now_utc
from app.models.device import Device
from app.repositories.base import BaseRepository


class DevicesRepository(BaseRepository[Device]):
    collection_name = "devices"
    model = Device

    async def get_by_fingerprint(self, user_id: str, fingerprint: str) -> Device | None:
        return await self.find_one({"user_id": user_id, "fingerprint": fingerprint})

    async def upsert(self, device: Device) -> tuple[Device, bool]:
        """Return (device, is_new)."""
        existing = await self.get_by_fingerprint(device.user_id, device.fingerprint)
        if existing:
            await self.col.update_one(
                {"_id": existing.id},
                {"$set": {
                    "browser": device.browser, "os": device.os,
                    "device_type": device.device_type, "ip": device.ip,
                    "location": device.location,
                    "last_seen_at": now_utc(), "updated_at": now_utc(),
                }},
            )
            existing.last_seen_at = now_utc()
            return existing, False
        await self.col.insert_one(device.model_dump(by_alias=True))
        return device, True

    async def list_for_user(self, user_id: str) -> list[Device]:
        return await self.find_many(
            {"user_id": user_id, "revoked_at": None},
            sort=[("last_seen_at", -1)],
            limit=200,
        )

    async def rename(self, user_id: str, device_id: str, label: str) -> int:
        res = await self.col.update_one(
            {"_id": device_id, "user_id": user_id},
            {"$set": {"label": label, "updated_at": now_utc()}},
        )
        return res.modified_count

    async def set_trusted(self, user_id: str, device_id: str, trusted: bool) -> int:
        res = await self.col.update_one(
            {"_id": device_id, "user_id": user_id},
            {"$set": {"trusted": trusted, "updated_at": now_utc()}},
        )
        return res.modified_count

    async def remove(self, user_id: str, device_id: str) -> int:
        res = await self.col.update_one(
            {"_id": device_id, "user_id": user_id, "revoked_at": None},
            {"$set": {"revoked_at": now_utc(), "updated_at": now_utc()}},
        )
        return res.modified_count
