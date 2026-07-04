"""Full phishing analysis pipeline entry point."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.core.security import require_user
from app.services.phishing.pipeline import analyze_message

router = APIRouter(prefix="/phishing", tags=["phishing"])


class AnalyzeIn(BaseModel):
    channel: str = Field(default="email", pattern="^(email|social)$")
    sender: str = ""
    subject: str = ""
    body: str = ""
    attachments: list[dict] = []  # {name, mime, data_b64}


@router.post("/analyze")
async def analyze(body: AnalyzeIn, user=Depends(require_user)):
    return await analyze_message(user_id=user["sub"], payload=body.model_dump())
