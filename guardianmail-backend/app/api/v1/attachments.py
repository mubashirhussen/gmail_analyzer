import base64
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.security import require_user
from app.services.ocr.ocr import extract_text

router = APIRouter(prefix="/attachments", tags=["attachments"])


class OcrIn(BaseModel):
    name: str
    mime: str
    data_b64: str


@router.post("/scan")
async def scan(body: OcrIn, user=Depends(require_user)):
    raw = base64.b64decode(body.data_b64)
    text = await extract_text(raw, mime=body.mime)
    return {"name": body.name, "text_length": len(text), "text": text[:20_000]}
