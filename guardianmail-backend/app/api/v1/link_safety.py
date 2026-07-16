"""Post-scan link revalidation endpoint.

The frontend calls this immediately BEFORE opening a URL that was previously
scanned. If `should_warn` is true, the frontend renders an interstitial with
the diff before allowing navigation.
"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel, HttpUrl

from app.core.security import require_user
from app.services.url_scan.revalidator import revalidate

router = APIRouter(prefix="/link-safety", tags=["link-safety"])


class RevalidateIn(BaseModel):
    url: HttpUrl


@router.post("/revalidate")
async def revalidate_link(body: RevalidateIn, user=Depends(require_user)):
    return await revalidate(str(body.url), user_id=user["sub"])
