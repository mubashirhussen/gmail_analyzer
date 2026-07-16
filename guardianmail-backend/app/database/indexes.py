"""Index bootstrap — every collection's read pattern is enumerated here.

Design rules
------------
* Compound indexes always lead with `user_id` for row-owner isolation.
* Time-sorted lists index `(user_id, <time>)` DESC to serve the common
  "latest first" query without a sort stage.
* Every unique constraint is defined as an index (not just app logic).
* TTL indexes back short-lived collections so eviction happens without
  a nightly job.
* `deleted_at` isn't indexed globally; queries scope by user first, so
  the compound index is already selective.
"""
from motor.motor_asyncio import AsyncIOMotorDatabase

# TTL windows (seconds)
NOTIFICATION_TTL = 60 * 60 * 24 * 30       # 30 days
JOB_TTL = 60 * 60 * 24 * 60                # 60 days
LOGIN_HISTORY_TTL = 60 * 60 * 24 * 180     # 180 days
SECURITY_EVENT_TTL = 60 * 60 * 24 * 365    # 365 days


async def ensure_indexes(db: AsyncIOMotorDatabase) -> None:
    # =============================================================
    # AUTH & IDENTITY
    # =============================================================
    await db.users.create_index("email", unique=True)
    await db.users.create_index("google_sub", sparse=True)
    await db.users.create_index("status")

    await db.devices.create_index([("user_id", 1), ("fingerprint", 1)], unique=True)
    await db.devices.create_index([("user_id", 1), ("last_seen_at", -1)])
    await db.devices.create_index([("user_id", 1), ("trusted", 1)])

    await db.sessions.create_index([("user_id", 1), ("status", 1)])
    await db.sessions.create_index([("device_id", 1), ("status", 1)])
    await db.sessions.create_index("expires_at", expireAfterSeconds=0)

    await db.refresh_tokens.create_index("jti", unique=True)
    await db.refresh_tokens.create_index([("session_id", 1), ("status", 1)])
    await db.refresh_tokens.create_index("expires_at", expireAfterSeconds=0)

    await db.login_history.create_index([("user_id", 1), ("at", -1)])
    await db.login_history.create_index([("email", 1), ("at", -1)])
    await db.login_history.create_index("at", expireAfterSeconds=LOGIN_HISTORY_TTL)

    # =============================================================
    # EMAILS & THREAT PIPELINE
    # =============================================================
    await db.emails.create_index("gmail_id", unique=True, sparse=True)
    await db.emails.create_index([("user_id", 1), ("received_at", -1)])
    await db.emails.create_index([("user_id", 1), ("thread_id", 1)])
    await db.emails.create_index([("user_id", 1), ("sender_domain", 1), ("received_at", -1)])
    await db.emails.create_index([("user_id", 1), ("analysis_status", 1)])
    await db.emails.create_index([("user_id", 1), ("labels", 1)])
    await db.emails.create_index([("user_id", 1), ("connection_id", 1), ("received_at", -1)])
    await db.emails.create_index([("user_id", 1), ("history_id", 1)], sparse=True)

    # ---- Gmail integration (Module 4) --------------------------------
    await db.gmail_connections.create_index([("user_id", 1), ("email", 1)], unique=True)
    await db.gmail_connections.create_index([("user_id", 1), ("status", 1)])
    await db.gmail_connections.create_index("google_sub", sparse=True)

    await db.email_threads.create_index([("user_id", 1), ("thread_id", 1)], unique=True)
    await db.email_threads.create_index([("user_id", 1), ("last_message_at", -1)])
    await db.email_threads.create_index([("user_id", 1), ("label_ids", 1)])

    await db.email_labels.create_index([("user_id", 1), ("label_id", 1)], unique=True)
    await db.email_labels.create_index([("user_id", 1), ("type", 1), ("name", 1)])

    await db.sync_logs.create_index([("user_id", 1), ("started_at", -1)])
    await db.sync_logs.create_index([("connection_id", 1), ("started_at", -1)])
    await db.sync_logs.create_index([("status", 1), ("started_at", -1)])
    # sync logs are transient audit records — retain 90 days
    await db.sync_logs.create_index("started_at", expireAfterSeconds=60 * 60 * 24 * 90)

    await db.threats.create_index([("user_id", 1), ("created_at", -1)])
    await db.threats.create_index([("email_id", 1), ("created_at", -1)])
    await db.threats.create_index([("user_id", 1), ("risk_score", -1), ("created_at", -1)])
    await db.threats.create_index([("user_id", 1), ("threat_category", 1), ("created_at", -1)])
    await db.threats.create_index([("review_status", 1), ("created_at", -1)])

    await db.threat_indicators.create_index([("threat_report_id", 1), ("kind", 1)])
    await db.threat_indicators.create_index([("user_id", 1), ("created_at", -1)])
    await db.threat_indicators.create_index([("kind", 1), ("value_hash", 1)])
    await db.threat_indicators.create_index([("kind", 1), ("severity", 1)])

    # ---- Threat Intelligence Engine (Module 5) ------------------
    # provider_results: cache + audit. TTL = 30d.
    await db.provider_results.create_index(
        [("provider", 1), ("artifact_hash", 1), ("created_at", -1)]
    )
    await db.provider_results.create_index(
        [("threat_report_id", 1), ("created_at", 1)]
    )
    await db.provider_results.create_index([("user_id", 1), ("created_at", -1)])
    await db.provider_results.create_index(
        "created_at", expireAfterSeconds=30 * 24 * 3600
    )

    # threat_timeline: per-report event stream. TTL = 30d.
    await db.threat_timeline.create_index(
        [("threat_report_id", 1), ("sequence", 1)]
    )
    await db.threat_timeline.create_index([("user_id", 1), ("created_at", -1)])
    await db.threat_timeline.create_index(
        "created_at", expireAfterSeconds=30 * 24 * 3600
    )

    # =============================================================
    # COMPLAINTS & EVIDENCE
    # =============================================================
    await db.complaints.create_index([("user_id", 1), ("created_at", -1)])
    await db.complaints.create_index([("user_id", 1), ("status", 1)])
    await db.complaints.create_index([("status", 1), ("scheduled_for", 1)])
    await db.complaints.create_index([("threat_report_id", 1), ("created_at", -1)])
    await db.complaint_templates.create_index([("destination", 1), ("category", 1)], unique=True)

    await db.evidence_packs.create_index([("user_id", 1), ("generated_at", -1)])
    await db.evidence_packs.create_index([("threat_report_id", 1), ("created_at", -1)])
    await db.evidence_packs.create_index("sha256")
    await db.evidence_packs.create_index("expires_at", expireAfterSeconds=0)

    # Module 9 — additive collections for the complaint/evidence platform.
    await db.evidence_packs.create_index([("user_id", 1), ("created_at", -1)])
    await db.evidence_custody.create_index([("pack_id", 1), ("at", 1)])
    await db.evidence_downloads.create_index([("user_id", 1), ("at", -1)])
    await db.evidence_downloads.create_index([("pack_id", 1), ("at", -1)])
    await db.complaint_reminders.create_index([("status", 1), ("fire_at", 1)])
    await db.complaint_reminders.create_index([("user_id", 1), ("fire_at", 1)])
    await db.complaint_reminders.create_index([("complaint_id", 1), ("status", 1)])



    # =============================================================
    # NOTIFICATIONS & ANALYTICS
    # =============================================================
    await db.notifications.create_index([("user_id", 1), ("created_at", -1)])
    await db.notifications.create_index([("user_id", 1), ("read", 1), ("created_at", -1)])
    await db.notifications.create_index("created_at", expireAfterSeconds=NOTIFICATION_TTL)

    await db.analytics.create_index([("user_id", 1), ("period", 1), ("at", -1)])
    await db.analytics.create_index([("user_id", 1), ("at", -1)])

    # =============================================================
    # SECURITY / AUDIT / JOBS
    # =============================================================
    await db.security_events.create_index([("user_id", 1), ("created_at", -1)])
    await db.security_events.create_index([("kind", 1), ("severity", 1), ("created_at", -1)])
    await db.security_events.create_index("created_at", expireAfterSeconds=SECURITY_EVENT_TTL)

    await db.audit_logs.create_index([("user_id", 1), ("at", -1)])
    await db.audit_logs.create_index([("action", 1), ("at", -1)])
    await db.audit_logs.create_index([("module", 1), ("at", -1)])

    await db.background_jobs.create_index([("user_id", 1), ("created_at", -1)])
    await db.background_jobs.create_index([("status", 1), ("scheduled_for", 1)])
    await db.background_jobs.create_index([("job_type", 1), ("status", 1)])
    await db.background_jobs.create_index("finished_at", expireAfterSeconds=JOB_TTL, sparse=True)

    # =============================================================
    # LEGACY / EXISTING BUSINESS COLLECTIONS (kept)
    # =============================================================
    await db.community_reports.create_index("hash", unique=True)
    await db.community_reports.create_index([("hash", 1), ("reporters", 1)])
    await db.reports.create_index([("user_id", 1), ("period", 1)])
    await db.automation_rules.create_index([("user_id", 1), ("enabled", 1)])
    await db.artifact_stats.create_index("hash", unique=True)
    await db.artifact_stats.create_index([("kind", 1), ("last_seen", -1)])
    await db.artifact_events.create_index([("hash", 1), ("at", -1)])
    await db.artifact_events.create_index([("user_id", 1), ("at", -1)])
    await db.device_artifacts.create_index(
        [("user_id", 1), ("device_fingerprint", 1), ("at", -1)]
    )
    await db.webhook_deliveries.create_index([("user_id", 1), ("created_at", -1)])
    await db.webhook_deliveries.create_index([("status", 1), ("next_attempt_at", 1)])

    # =============================================================
    # MODULE 6 — AI ANALYSIS ENGINE
    # =============================================================
    await db.ai_reports.create_index([("user_id", 1), ("created_at", -1)])
    await db.ai_reports.create_index([("threat_report_id", 1), ("created_at", -1)])
    await db.ai_reports.create_index([("email_id", 1), ("created_at", -1)], sparse=True)
    await db.ai_reports.create_index([("verdict", 1), ("created_at", -1)])
    await db.ai_reports.create_index([("prompt_hash", 1)])
    await db.ai_prompts.create_index([("name", 1), ("version", 1)], unique=True)
    await db.ai_prompts.create_index([("active", 1)])
    await db.ai_decision_history.create_index([("user_id", 1), ("created_at", -1)])
    await db.ai_decision_history.create_index([("prompt_version", 1), ("created_at", -1)])
    await db.ai_decision_history.create_index([("model_name", 1), ("created_at", -1)])

    # =============================================================
    # MODULE 7 — OCR & ATTACHMENT SECURITY
    # =============================================================
    await db.ocr_reports.create_index([("user_id", 1), ("created_at", -1)])
    await db.ocr_reports.create_index([("user_id", 1), ("status", 1), ("created_at", -1)])
    await db.ocr_reports.create_index([("user_id", 1), ("attachment.sha256", 1)])
    await db.ocr_reports.create_index([("email_id", 1), ("created_at", -1)], sparse=True)
    await db.ocr_reports.create_index([("threat_report_id", 1)], sparse=True)
    await db.ocr_reports.create_index([("ai_report_id", 1)], sparse=True)

    await db.attachment_records.create_index([("user_id", 1), ("sha256", 1)], unique=True)
    await db.attachment_records.create_index([("sha256", 1), ("last_seen_at", -1)])
    await db.attachment_records.create_index([("user_id", 1), ("last_seen_at", -1)])
    await db.attachment_records.create_index([("user_id", 1), ("risk_flags", 1)])

    # =============================================================
    # MODULE 10 — ANALYTICS PLATFORM
    # =============================================================
    await db.trend_series.create_index(
        [("user_id", 1), ("metric", 1), ("granularity", 1), ("bucket_start", 1)],
        unique=True,
    )
    await db.trend_series.create_index(
        [("user_id", 1), ("metric", 1), ("bucket_start", -1)]
    )
    await db.report_records.create_index([("user_id", 1), ("requested_at", -1)])
    await db.report_records.create_index([("user_id", 1), ("kind", 1), ("requested_at", -1)])
    await db.report_records.create_index([("status", 1), ("requested_at", -1)])
    await db.report_records.create_index("download_token", unique=True, sparse=True)
    await db.report_records.create_index("expires_at", expireAfterSeconds=0, sparse=True)
    await db.dashboard_cache.create_index(
        [("user_id", 1), ("scope", 1), ("time_filter", 1)], unique=True
    )
    await db.dashboard_cache.create_index([("computed_at", -1)])
