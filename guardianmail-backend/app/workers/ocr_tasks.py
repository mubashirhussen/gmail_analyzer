import asyncio
import base64
from app.workers.celery_app import celery
from app.services.ocr.ocr import extract_text


@celery.task(name="ocr.extract")
def ocr_extract(data_b64: str, mime: str) -> str:
    return asyncio.run(extract_text(base64.b64decode(data_b64), mime))
