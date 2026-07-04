"""Google OAuth 2.0 + JWT (access/refresh) + device trust."""
import uuid
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr

from app.core.config import settings
from app.core.security import create_access_token, create_refresh_token, decode_token, require_user
from app.database.mongodb import get_db

router = APIRouter(prefix="/auth", tags=["auth"])


class GoogleExchange(BaseModel):
    code: str
    redirect_uri: str | None = None


@router.post("/google")
async def google_exchange(body: GoogleExchange, db=Depends(get_db)):
    """Exchange auth code for Google tokens, then mint our own JWTs."""
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post("https://oauth2.googleapis.com/token", data={
            "code": body.code,
            "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
            "client_secret": settings.GOOGLE_OAUTH_CLIENT_SECRET,
            "redirect_uri": body.redirect_uri or settings.GOOGLE_OAUTH_REDIRECT,
            "grant_type": "authorization_code",
        })
        if r.status_code != 200:
            raise HTTPException(400, f"google exchange failed: {r.text}")
        tok = r.json()
        u = await c.get("https://www.googleapis.com/oauth2/v2/userinfo",
                        headers={"Authorization": f"Bearer {tok['access_token']}"})
        u.raise_for_status()
        info = u.json()

    now = datetime.now(timezone.utc)
    await db.users.update_one(
        {"email": info["email"]},
        {"$setOnInsert": {"created_at": now}, "$set": {"name": info.get("name"), "picture": info.get("picture"), "last_login_at": now}},
        upsert=True,
    )
    user = await db.users.find_one({"email": info["email"]})
    jti = uuid.uuid4().hex
    return {
        "access_token": create_access_token(str(user["_id"]), email=user["email"]),
        "refresh_token": create_refresh_token(str(user["_id"]), jti),
        "user": {"id": str(user["_id"]), "email": user["email"], "name": user.get("name")},
    }


class RefreshBody(BaseModel):
    refresh_token: str


@router.post("/refresh")
async def refresh(body: RefreshBody):
    payload = decode_token(body.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(401, "not a refresh token")
    return {"access_token": create_access_token(payload["sub"])}


@router.get("/me")
async def me(user=Depends(require_user), db=Depends(get_db)):
    doc = await db.users.find_one({"_id": user["sub"]}) or await db.users.find_one({"email": user.get("email")})
    if not doc:
        raise HTTPException(404, "user not found")
    return {"id": str(doc["_id"]), "email": doc["email"], "name": doc.get("name")}
