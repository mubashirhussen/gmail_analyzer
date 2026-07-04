import asyncio
from app.workers.celery_app import celery
from app.services.phishing.pipeline import analyze_message


@celery.task(name="threat.analyze_email")
def analyze_email(user_id: str, payload: dict):
    return asyncio.run(analyze_message(user_id, payload))
