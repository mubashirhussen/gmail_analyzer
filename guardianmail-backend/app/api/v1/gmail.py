from fastapi import APIRouter, Depends

from app.core.security import require_user
from app.workers.celery_app import celery

router = APIRouter(prefix="/gmail", tags=["gmail"])


@router.get("/sync")
async def sync(user=Depends(require_user)):
    task = celery.send_task("gmail.sync_user", args=[user["sub"]])
    return {"task_id": task.id, "status": "queued"}
