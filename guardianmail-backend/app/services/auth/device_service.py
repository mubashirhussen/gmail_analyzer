"""Device service — registration, trust, unknown-device detection."""
from __future__ import annotations

from app.database.mongodb import get_db
from app.models.device import Device
from app.repositories.devices import DevicesRepository
from app.services.auth.audit_service import audit_service
from app.utils import fingerprint as fp
from app.utils import geoip
from app.utils.user_agent import parse as ua_parse


class DeviceService:
    def _repo(self) -> DevicesRepository:
        return DevicesRepository(get_db())

    async def register_or_touch(self, *, user_id: str, client_fp: str,
                                ip: str, user_agent: str,
                                label: str | None = None) -> tuple[Device, bool]:
        ua = ua_parse(user_agent)
        server_fp = fp.compose(client_fp, ip, ua.browser)
        loc = await geoip.coarse_location(ip)
        device = Device(
            user_id=user_id, fingerprint=server_fp,
            label=label or f"{ua.browser} on {ua.os}",
            browser=ua.browser, os=ua.os, device_type=ua.device_type,
            ip=ip, location=loc,
        )
        saved, is_new = await self._repo().upsert(device)
        if is_new:
            await audit_service.security_event(
                "device_new", user_id=user_id, severity="medium",
                message=f"New sign-in from {ua.browser} on {ua.os} ({loc or ip})",
                ip=ip, device_id=saved.id,
            )
        return saved, is_new

    async def list_for(self, user_id: str) -> list[Device]:
        return await self._repo().list_for_user(user_id)

    async def rename(self, user_id: str, device_id: str, label: str) -> None:
        await self._repo().rename(user_id, device_id, label)
        await audit_service.audit("device.rename", user_id=user_id,
                                   device_id=device_id, meta={"label": label})

    async def set_trusted(self, user_id: str, device_id: str, trusted: bool) -> None:
        await self._repo().set_trusted(user_id, device_id, trusted)
        await audit_service.security_event(
            "device_trusted", user_id=user_id, device_id=device_id,
            message="Device trust changed", meta={"trusted": trusted},
        )

    async def remove(self, user_id: str, device_id: str) -> None:
        await self._repo().remove(user_id, device_id)
        await audit_service.security_event(
            "device_removed", user_id=user_id, device_id=device_id,
            severity="medium", message="Device removed",
        )


device_service = DeviceService()
