"""Phase 16 — Copilot HTTP surface.

All endpoints require an authenticated principal. Every response is
scoped to the caller's user_id; conversations from other users are never
returned. Rate limits inherit from the shared SlowAPI limiter.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from app.api.dependencies import CurrentUser, Principal
from app.database.mongodb import get_db
from app.repositories.copilot import ConversationRepository, MessageRepository
from app.schemas.copilot import (
    ChatRequest,
    CopilotResponse,
    ExplainRequest,
    SummarizeRequest,
)
from app.services.copilot.conversation_service import conversation_service
from app.services.copilot.copilot_service import copilot_service
from app.services.copilot.educational_service import educational_service
from app.services.copilot.providers import provider_router

router = APIRouter(prefix="/copilot", tags=["copilot"])


@router.post("/chat", response_model=CopilotResponse)
async def chat(body: ChatRequest, principal: Principal = CurrentUser) -> dict:
    return await copilot_service.chat(
        user_id=principal.user_id,
        question=body.question,
        scope=body.scope.model_dump(exclude_none=True),
        conversation_id=body.conversation_id,
        provider=body.provider,
    )


@router.post("/explain", response_model=CopilotResponse)
async def explain(body: ExplainRequest, principal: Principal = CurrentUser) -> dict:
    return await copilot_service.explain(
        user_id=principal.user_id,
        scope=body.scope.model_dump(exclude_none=True),
        aspect=body.aspect,
        provider=body.provider,
    )


@router.post("/summarize", response_model=CopilotResponse)
async def summarize(body: SummarizeRequest, principal: Principal = CurrentUser) -> dict:
    return await copilot_service.summarize(
        user_id=principal.user_id,
        scope=body.scope.model_dump(exclude_none=True),
        style=body.style,
        provider=body.provider,
    )


@router.get("/history")
async def history(
    principal: Principal = CurrentUser,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
) -> dict:
    return await conversation_service.list_conversations(
        principal.user_id, page=page, page_size=page_size
    )


@router.get("/history/{conversation_id}/messages")
async def conversation_messages(
    conversation_id: str, principal: Principal = CurrentUser,
) -> dict:
    db = get_db()
    convs = ConversationRepository(db)
    conv = await convs.find_by_id(conversation_id)
    if not conv or conv.get("user_id") != principal.user_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="conversation_not_found")
    msgs = await MessageRepository(db).list_for_conversation(conversation_id, limit=200)
    return {"items": [m.model_dump(by_alias=True) for m in msgs]}


@router.delete("/history/{conversation_id}")
async def delete_conversation(
    conversation_id: str, principal: Principal = CurrentUser,
) -> dict:
    ok = await conversation_service.delete_conversation(
        user_id=principal.user_id, conversation_id=conversation_id,
    )
    if not ok:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="conversation_not_found")
    return {"deleted": True}


@router.delete("/history")
async def delete_all_history(principal: Principal = CurrentUser) -> dict:
    return await conversation_service.clear_user_history(principal.user_id)


@router.get("/providers")
async def providers() -> dict:
    return {"providers": provider_router.names()}


@router.get("/education/topics")
async def education_topics() -> dict:
    return {"topics": educational_service.topics()}


@router.get("/education/{topic}")
async def education_topic(topic: str) -> dict:
    text = educational_service.lookup(topic)
    if not text:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="topic_not_found")
    return {"topic": topic, "explanation": text}
