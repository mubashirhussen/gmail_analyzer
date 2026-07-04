from app.workers.celery_app import celery


@celery.task(name="gmail.sync_all")
def sync_all():
    """Periodically enumerate users and enqueue per-user sync."""
    # TODO: iterate users with a linked Gmail account
    return {"enqueued": 0}


@celery.task(name="gmail.sync_user")
def sync_user(user_id: str):
    """Fetch new Gmail messages for a user, persist metadata, enqueue phishing analysis."""
    # TODO: googleapiclient discovery, list messages since last cursor, save to Mongo,
    #       then celery.send_task("threat.analyze_email", args=[user_id, email_id])
    return {"user_id": user_id, "processed": 0}
