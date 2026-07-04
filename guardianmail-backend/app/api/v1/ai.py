"""Direct AI passthroughs (chat / classify)."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.security import require_user
from app.services.ai.gemini import gemini_json

router = APIRouter(prefix="/ai", tags=["ai"])


class ClassifyIn(BaseModel):
    text: str


@router.post("/classify")
async def classify(body: ClassifyIn, user=Depends(require_user)):
    return await gemini_json(
        system="Classify the following message as one of: safe, suspicious, phishing, fraud. Return JSON {verdict, reason}.",
        user=body.text,
    )
