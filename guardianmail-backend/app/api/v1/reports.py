from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response

from app.core.security import require_user
from app.database.mongodb import get_db
from app.services.reports.generator import generate
from app.workers.celery_app import celery

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("/export")
async def export(fmt: str = Query("pdf", pattern="^(pdf|csv|xlsx)$"),
                 user=Depends(require_user)):
    task = celery.send_task("reports.build", args=[user["sub"], fmt], queue="report")
    return {"task_id": task.id}


@router.get("/download")
async def download(fmt: str = Query("pdf", pattern="^(pdf|csv|xlsx)$"),
                   user=Depends(require_user)):
    """Synchronous fallback — small reports render inline for the frontend."""
    data, mime = await generate(user["sub"], fmt)
    return Response(
        content=data, media_type=mime,
        headers={"content-disposition": f'attachment; filename="guardianmail.{fmt}"'},
    )


@router.get("/{report_id}")
async def get_report(report_id: str, user=Depends(require_user), db=Depends(get_db)):
    from bson import ObjectId
    doc = await db.reports.find_one({"_id": ObjectId(report_id), "user_id": user["sub"]})
    if not doc:
        raise HTTPException(404, "report not found")
    return {**doc, "_id": str(doc["_id"])}
