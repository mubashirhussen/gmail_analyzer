from app.workers.celery_app import celery


@celery.task(name="reports.build")
def build(user_id: str, fmt: str):
    """Render a PDF/CSV/XLSX report for the user from Mongo aggregates."""
    # TODO: implement WeasyPrint / openpyxl output + upload to storage
    return {"user_id": user_id, "fmt": fmt, "url": None}


@celery.task(name="reports.nightly_rollup")
def nightly_rollup():
    """Aggregate per-user metrics into analytics collection."""
    return {"ok": True}
