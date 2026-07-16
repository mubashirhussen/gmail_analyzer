"""Authentication API — Google OAuth, JWT lifecycle, profile."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Header, Request

from app.api.dependencies import CurrentUser, Principal
from app.schemas.auth import (AccessTokenOnly, LoginResponse, OAuthCallbackIn,
                              OAuthLoginStart, OAuthLoginStartResponse,
                              RefreshIn, TokenPair, UserProfile)
from app.services.auth.auth_service import auth_service
from app.services.auth.session_service import session_service

router = APIRouter(prefix="/auth", tags=["auth"])


def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else ""


# ---- OAuth --------------------------------------------------------------
@router.post("/google/login", response_model=OAuthLoginStartResponse)
async def google_login_start(body: OAuthLoginStart):
    url, state = await auth_service.start_google_login(
        redirect_uri=body.redirect_uri, remember_me=body.remember_me,
    )
    return OAuthLoginStartResponse(authorize_url=url, state=state)


@router.post("/google/callback", response_model=LoginResponse)
async def google_callback(
    body: OAuthCallbackIn,
    request: Request,
    x_device_fingerprint: str | None = Header(default=None),
):
    result = await auth_service.complete_google_login(
        code=body.code, state=body.state,
        ip=_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        client_fp=x_device_fingerprint,
    )
    user, session, device = result["user"], result["session"], result["device"]
    return LoginResponse(
        user=UserProfile(
            id=user.id, email=user.email, email_verified=user.email_verified,
            name=user.name, picture=user.picture, status=user.status,
            last_login_at=user.last_login_at,
        ),
        session_id=session.id, device_id=device.id,
        tokens=TokenPair(access_token=result["access"],
                          refresh_token=result["refresh"],
                          expires_in=result["expires_in"]),
    )


# ---- tokens -------------------------------------------------------------
@router.post("/refresh", response_model=TokenPair)
async def refresh(body: RefreshIn, request: Request):
    access, refresh_tok, expires_in, _ = await session_service.refresh(
        body.refresh_token, ip=_client_ip(request),
    )
    return TokenPair(access_token=access, refresh_token=refresh_tok, expires_in=expires_in)


@router.post("/logout")
async def logout(p: Principal = CurrentUser):
    await session_service.revoke(p.session_id, user_id=p.user_id,
                                  reason="logout", access_jti=p.access_jti)
    return {"ok": True}


@router.post("/logout-all")
async def logout_all(p: Principal = CurrentUser):
    n = await session_service.revoke_all(p.user_id, except_session=p.session_id)
    return {"ok": True, "revoked": n}


# ---- profile ------------------------------------------------------------
@router.get("/profile", response_model=UserProfile)
@router.get("/me", response_model=UserProfile)          # legacy alias
async def profile(p: Principal = CurrentUser):
    u = p.user
    return UserProfile(id=u.id, email=u.email, email_verified=u.email_verified,
                       name=u.name, picture=u.picture, status=u.status,
                       last_login_at=u.last_login_at)
