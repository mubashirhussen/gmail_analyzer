"""Gmail API client wrapper.

Refresh tokens are stored AES-GCM encrypted on the user document. We rebuild
Google Credentials on demand instead of caching them, so a rotated token is
picked up next call.
"""
from __future__ import annotations

from typing import Any

from google.auth.transport.requests import Request as GRequest
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

from app.core.config import settings
from app.core.encryption import decrypt


def credentials_for(refresh_token_encrypted: str) -> Credentials:
    creds = Credentials(
        token=None,
        refresh_token=decrypt(refresh_token_encrypted),
        client_id=settings.GOOGLE_OAUTH_CLIENT_ID,
        client_secret=settings.GOOGLE_OAUTH_CLIENT_SECRET,
        token_uri="https://oauth2.googleapis.com/token",
        scopes=[
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
        ],
    )
    creds.refresh(GRequest())
    return creds


def gmail_service(refresh_token_encrypted: str):
    return build("gmail", "v1", credentials=credentials_for(refresh_token_encrypted), cache_discovery=False)


def list_messages(service, *, query: str = "newer_than:7d", max_results: int = 50) -> list[dict[str, Any]]:
    resp = service.users().messages().list(userId="me", q=query, maxResults=max_results).execute()
    return resp.get("messages", [])


def get_message(service, msg_id: str) -> dict[str, Any]:
    return service.users().messages().get(userId="me", id=msg_id, format="full").execute()
