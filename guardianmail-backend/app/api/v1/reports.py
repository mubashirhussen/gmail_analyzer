from fastapi import APIRouter, Depends
from app.core.security import require_user
from app.workers.celery_app import celery

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("/export")
async def export(fmt: str = "pdf", user=Depends(require_user)):
    task = celery.send_task("reports.build", args=[user["sub"], fmt], queue="report")
    return {"task_id": task.id}
