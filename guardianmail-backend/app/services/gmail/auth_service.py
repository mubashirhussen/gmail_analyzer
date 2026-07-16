"""GmailAuthService — OAuth token lifecycle for Gmail connections.

Distinct from the platform's ``AuthService`` (which owns the *user session*).
This service exclusively manages the Gmail-side OAuth material: exchanging
a fresh authorization code for a refresh token, verifying the granted
scope set, persisting the encrypted refresh token, and revoking it.
"""
from __future__ import annotations

from typing import Any

import httpx

from app.core.config import settings
from app.core.encryption import encrypt
from app.core.exceptions import AuthError, ExternalServiceError, ValidationError
from app.core.http import get_client
from app.core.logging import get_logger
from app.database.mongodb import get_db
from app.models.gmail_connection import GmailConnection
from app.repositories.gmail_connections import GmailConnectionsRepository
from app.services.auth.oauth_service import oauth_service
from app.services.base import BaseService
from app.services.gmail.client import (GMAIL_SCOPES, build_service,
                                        get_profile, stop_watch)

log = get_logger(__name__)

REQUIRED_SCOPES: set[str] = {
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
}

REVOKE_URL = "https://oauth2.googleapis.com/revoke"


class GmailAuthService(BaseService):
    # ---------- connect ---------------------------------------------------
    async def build_connect_url(self, *, redirect_uri: str | None = None) -> tuple[str, str]:
        """Reuses the platform OAuth flow to produce a Gmail-consent URL."""
        return await oauth_service.build_authorize_url(
            redirect_uri=redirect_uri, remember_me=True,
        )

    async def complete_connect(
        self,
        *,
        user_id: str,
        code: str,
        state: str,
    ) -> GmailConnection:
        payload = await oauth_service.consume_state(state)
        tokens = await oauth_service.exchange_code(code, payload["redirect_uri"])

        refresh_token = tokens.get("refresh_token")
        if not refresh_token:
            # Google returns no refresh_token if the user previously granted
            # consent from a different device without prompt=consent.
            raise AuthError(
                "google returned no refresh_token — force consent and retry",
                code="oauth_no_refresh_token",
            )

        granted = set((tokens.get("scope") or "").split())
        missing = REQUIRED_SCOPES - granted
        if missing:
            raise ValidationError(
                f"missing required gmail scopes: {sorted(missing)}",
                code="oauth_scope_missing",
                details={"missing": sorted(missing), "granted": sorted(granted)},
            )

        userinfo = await oauth_service.fetch_userinfo(tokens["access_token"])
        email = (userinfo.get("email") or "").lower()
        if not email:
            raise ExternalServiceError("google userinfo missing email", code="oauth_no_email")

        repo = GmailConnectionsRepository(get_db())
        conn = GmailConnection(
            user_id=user_id,
            email=email,
            google_sub=userinfo.get("sub"),
            refresh_token_enc=encrypt(refresh_token),
            scopes=sorted(granted),
        )
        saved = await repo.upsert(conn)
        log.info("gmail_connected", user_id=user_id, email=email,
                 scopes=len(granted), connection_id=saved.id)
        return saved

    # ---------- health ----------------------------------------------------
    async def verify(self, conn: GmailConnection) -> dict[str, Any]:
        """Round-trips ``users.getProfile`` to prove the token still works."""
        service = build_service(conn.refresh_token_enc)
        profile = get_profile(service)
        return {
            "email": profile.get("emailAddress"),
            "messages_total": profile.get("messagesTotal", 0),
            "threads_total": profile.get("threadsTotal", 0),
            "history_id": profile.get("historyId"),
        }

    # ---------- disconnect ------------------------------------------------
    async def disconnect(self, user_id: str, *, revoke_at_google: bool = True) -> bool:
        repo = GmailConnectionsRepository(get_db())
        conn = await repo.get_active_for_user(user_id)
        if not conn:
            return False
        if revoke_at_google:
            await self._revoke_at_google(conn)
        try:
            service = build_service(conn.refresh_token_enc)
            stop_watch(service)
        except Exception:  # noqa: BLE001 - best effort
            self.log.warning("gmail_stop_watch_failed", user_id=user_id)
        await repo.mark_revoked(conn.id)
        log.info("gmail_disconnected", user_id=user_id, connection_id=conn.id)
        return True

    async def _revoke_at_google(self, conn: GmailConnection) -> None:
        try:
            from app.core.encryption import decrypt
            client: httpx.AsyncClient = get_client()
            r = await client.post(
                REVOKE_URL,
                data={"token": decrypt(conn.refresh_token_enc)},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if r.status_code >= 400:
                self.log.warning("google_revoke_non200", status=r.status_code)
        except Exception as e:  # noqa: BLE001
            self.log.warning("google_revoke_failed", err=str(e))


gmail_auth_service = GmailAuthService()
