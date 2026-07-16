"""Low-level Gmail API wrapper.

Only responsibilities:

* build a ``Credentials`` instance from a stored encrypted refresh token,
* wrap common Gmail endpoints (messages.list, messages.get, history.list,
  labels.list, users.getProfile, users.stop),
* apply exponential backoff on 429/5xx.

Everything above this layer (cursor handling, dedup, extraction, retries at
the run level) lives in ``sync_service`` / feature services.
"""
from __future__ import annotations

import random
import time
from typing import Any, Iterable

from google.auth.exceptions import RefreshError
from google.auth.transport.requests import Request as GRequest
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import Resource, build
from googleapiclient.errors import HttpError

from app.core.config import settings
from app.core.encryption import decrypt
from app.core.logging import get_logger

log = get_logger(__name__)

GMAIL_SCOPES: tuple[str, ...] = (
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
)


class GmailReauthRequired(Exception):
    """Refresh token no longer valid — user must reconnect."""


class GmailQuotaExceeded(Exception):
    """Sustained 429 — caller should pause and retry later."""


def _credentials_from_refresh(refresh_token_enc: str, scopes: Iterable[str] = GMAIL_SCOPES) -> Credentials:
    creds = Credentials(
        token=None,
        refresh_token=decrypt(refresh_token_enc),
        client_id=settings.GOOGLE_OAUTH_CLIENT_ID,
        client_secret=settings.GOOGLE_OAUTH_CLIENT_SECRET,
        token_uri="https://oauth2.googleapis.com/token",
        scopes=list(scopes),
    )
    try:
        creds.refresh(GRequest())
    except RefreshError as e:
        raise GmailReauthRequired(str(e)) from e
    return creds


def build_service(refresh_token_enc: str) -> Resource:
    return build(
        "gmail", "v1",
        credentials=_credentials_from_refresh(refresh_token_enc),
        cache_discovery=False,
    )


# --- retry wrapper --------------------------------------------------------
_RETRY_STATUSES = {429, 500, 502, 503, 504}


def _execute_with_backoff(request, *, max_attempts: int = 5, base_delay: float = 0.5) -> Any:
    for attempt in range(1, max_attempts + 1):
        try:
            return request.execute(num_retries=0)
        except HttpError as e:  # noqa: PERF203
            status = getattr(e.resp, "status", None)
            if status not in _RETRY_STATUSES or attempt == max_attempts:
                if status == 429:
                    raise GmailQuotaExceeded(str(e)) from e
                raise
            delay = base_delay * (2 ** (attempt - 1)) + random.uniform(0, 0.25)
            log.warning("gmail_retry", status=status, attempt=attempt, delay_ms=int(delay * 1000))
            time.sleep(delay)
    raise RuntimeError("unreachable")


# --- endpoints ------------------------------------------------------------
def get_profile(service: Resource) -> dict[str, Any]:
    return _execute_with_backoff(service.users().getProfile(userId="me"))


def list_messages(
    service: Resource,
    *,
    query: str | None = None,
    label_ids: list[str] | None = None,
    max_results: int = 100,
    page_token: str | None = None,
) -> dict[str, Any]:
    return _execute_with_backoff(
        service.users().messages().list(
            userId="me",
            q=query,
            labelIds=label_ids,
            maxResults=max_results,
            pageToken=page_token,
            includeSpamTrash=False,
        )
    )


def get_message(service: Resource, msg_id: str, *, fmt: str = "metadata",
                metadata_headers: list[str] | None = None) -> dict[str, Any]:
    kwargs: dict[str, Any] = {"userId": "me", "id": msg_id, "format": fmt}
    if fmt == "metadata" and metadata_headers:
        kwargs["metadataHeaders"] = metadata_headers
    return _execute_with_backoff(service.users().messages().get(**kwargs))


def get_message_full(service: Resource, msg_id: str) -> dict[str, Any]:
    return get_message(service, msg_id, fmt="full")


def list_history(
    service: Resource,
    *,
    start_history_id: str,
    page_token: str | None = None,
    label_id: str | None = None,
) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "userId": "me",
        "startHistoryId": start_history_id,
        "historyTypes": ["messageAdded", "messageDeleted", "labelAdded", "labelRemoved"],
    }
    if page_token:
        kwargs["pageToken"] = page_token
    if label_id:
        kwargs["labelId"] = label_id
    return _execute_with_backoff(service.users().history().list(**kwargs))


def list_labels(service: Resource) -> list[dict[str, Any]]:
    resp = _execute_with_backoff(service.users().labels().list(userId="me"))
    return resp.get("labels", [])


def get_label(service: Resource, label_id: str) -> dict[str, Any]:
    return _execute_with_backoff(service.users().labels().get(userId="me", id=label_id))


def stop_watch(service: Resource) -> None:
    try:
        _execute_with_backoff(service.users().stop(userId="me"))
    except HttpError as e:  # pragma: no cover - best-effort revocation
        log.warning("gmail_stop_failed", err=str(e))


# ---- legacy shim: preserved for older callers still importing these ------
def credentials_for(refresh_token_encrypted: str) -> Credentials:  # pragma: no cover
    return _credentials_from_refresh(refresh_token_encrypted)


def gmail_service(refresh_token_encrypted: str) -> Resource:  # pragma: no cover
    return build_service(refresh_token_encrypted)
