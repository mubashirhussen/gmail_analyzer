from fastapi import APIRouter, Depends
from pydantic import BaseModel, HttpUrl

from app.core.security import require_user
from app.services.url_scan.scanner import scan_urls

router = APIRouter(prefix="/url", tags=["url"])


class ScanIn(BaseModel):
    urls: list[HttpUrl]


@router.post("/scan")
async def scan(body: ScanIn, user=Depends(require_user)):
    return await scan_urls([str(u) for u in body.urls])
