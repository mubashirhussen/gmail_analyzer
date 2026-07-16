"""AuthService — orchestrates OAuth → user upsert → device → session → tokens."""
from __future__ import annotations

from app.core.exceptions import AuthError
from app.services.auth.audit_service import audit_service
from app.services.auth.device_service import device_service
from app.services.auth.oauth_service import oauth_service
from app.services.auth.security_service import security_service
from app.services.auth.session_service import session_service


class AuthService:
    async def start_google_login(self, *, redirect_uri: str | None,
                                  remember_me: bool) -> tuple[str, str]:
        return await oauth_service.build_authorize_url(
            redirect_uri=redirect_uri, remember_me=remember_me,
        )

    async def complete_google_login(self, *, code: str, state: str,
                                     ip: str, user_agent: str,
                                     client_fp: str | None) -> dict:
        st = await oauth_service.consume_state(state)
        tok = await oauth_service.exchange_code(code, st["redirect_uri"])
        info = await oauth_service.fetch_userinfo(tok["access_token"])

        email = (info.get("email") or "").lower()
        if not email or not info.get("email_verified", True):
            raise AuthError("unverified google email", code="oauth_unverified")

        await security_service.check_not_locked(email)

        from app.database.mongodb import get_db
        from app.repositories.users import UsersRepository
        users = UsersRepository(get_db())
        user = await users.upsert_from_google(info)

        device, is_new = await device_service.register_or_touch(
            user_id=user.id, client_fp=client_fp or info.get("sub", ""),
            ip=ip, user_agent=user_agent,
        )

        session, access, refresh, expires_in = await session_service.create(
            user_id=user.id, device_id=device.id, email=user.email,
            ip=ip, user_agent=user_agent, remember_me=bool(st.get("remember_me")),
        )
        await users.touch_login(user.id, ip)
        await security_service.clear_failures(email)

        await audit_service.audit("auth.login", user_id=user.id,
                                   session_id=session.id, device_id=device.id,
                                   ip=ip, user_agent=user_agent,
                                   meta={"method": "google", "new_device": is_new})
        await audit_service.login_history(
            user_id=user.id, email=email, ip=ip, user_agent=user_agent,
            device_id=device.id, session_id=session.id,
            method="google", outcome="success",
        )
        await audit_service.security_event(
            "login_success", user_id=user.id, session_id=session.id,
            device_id=device.id, ip=ip,
            message=f"Signed in from {device.location or ip}",
        )
        return {"user": user, "session": session, "device": device,
                "access": access, "refresh": refresh, "expires_in": expires_in,
                "new_device": is_new}


auth_service = AuthService()
