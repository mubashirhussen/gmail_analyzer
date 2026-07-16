"""Domain-scoped analytics assemblers.

Each `*_analytics` method returns a fully-populated schema object ready
for the dashboard API. Methods are deliberately read-only and idempotent —
safe to run in a Celery worker for cache warming or on-demand from the API.

Collections consumed (all previous modules — never mutated):
    emails, threats, provider_results, ai_reports, ocr_reports,
    attachment_records, complaints, evidence_packs, gmail_connections.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.logging import get_logger
from app.schemas.analytics_platform import (
    AIAnalytics, BarChart, ChartSeries, ComplaintAnalytics, DomainAnalytics,
    EmailAnalytics, Heatmap, HeatmapCell, LineChart, OCRAnalytics, PieChart,
    PieSlice, SecurityAnalytics, SeriesPoint, ThreatAnalytics, TimelineEvent,
    TimelineGraph, TimeRange, UserAnalytics,
)
from app.services.analytics_platform.aggregation_service import AggregationService
from app.services.analytics_platform.security_score_service import SecurityScoreService

_log = get_logger(__name__)
_UTC = timezone.utc

# Severity buckets used across threat & AI analytics
SEVERITIES = ("low", "medium", "high", "critical")


class AnalyticsService:
    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self.db = db
        self.agg = AggregationService(db)
        self.scores = SecurityScoreService()

    # ================================================================== EMAIL
    async def email_analytics(self, user_id: str, tr: TimeRange) -> EmailAnalytics:
        base = {"user_id": user_id, "created_at": {"$gte": tr.since, "$lte": tr.until}}
        pipeline = [
            {"$match": base},
            {"$facet": {
                "total": [{"$count": "n"}],
                "read": [{"$match": {"is_read": True}}, {"$count": "n"}],
                "unread": [{"$match": {"is_read": False}}, {"$count": "n"}],
                "spam": [{"$match": {"labels": "SPAM"}}, {"$count": "n"}],
                "flagged": [{"$match": {"is_starred": True}}, {"$count": "n"}],
                "archived": [{"$match": {"labels": {"$nin": ["INBOX"]}}}, {"$count": "n"}],
                "deleted": [{"$match": {"labels": "TRASH"}}, {"$count": "n"}],
                "attach": [{"$match": {"has_attachments": True}}, {"$count": "n"}],
            }},
        ]
        rows = await self.agg.run("emails", pipeline)
        r = rows[0] if rows else {}

        def _n(k: str) -> int:
            v = r.get(k) or []
            return int(v[0]["n"]) if v else 0

        total = _n("total")
        span_days = max((tr.until - tr.since).days, 1)
        avg_day = total / span_days
        avg_week = avg_day * 7
        avg_month = avg_day * 30

        # growth vs prior period
        prev_since = tr.since - (tr.until - tr.since)
        prev_total = await self.agg.count(
            "emails",
            {"user_id": user_id, "created_at": {"$gte": prev_since, "$lt": tr.since}},
        )
        growth = 0.0 if prev_total == 0 else round(((total - prev_total) / prev_total) * 100, 2)

        # inbox health: penalises spam/deleted heavy inboxes
        spam = _n("spam"); deleted = _n("deleted")
        denom = max(total, 1)
        health = max(0, 100 - int((spam + deleted) / denom * 80))

        return EmailAnalytics(
            total=total, read=_n("read"), unread=_n("unread"),
            spam=spam, flagged=_n("flagged"), archived=_n("archived"),
            deleted=deleted, with_attachments=_n("attach"),
            avg_per_day=round(avg_day, 2), avg_per_week=round(avg_week, 2),
            avg_per_month=round(avg_month, 2), growth_pct=growth, inbox_health=health,
        )

    # ================================================================ THREATS
    async def threat_analytics(self, user_id: str, tr: TimeRange) -> ThreatAnalytics:
        match = {"user_id": user_id, "created_at": {"$gte": tr.since, "$lte": tr.until}}
        pipe = [
            {"$match": match},
            {"$facet": {
                "total": [{"$count": "n"}],
                "by_cat": [
                    {"$group": {"_id": "$attack_category", "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}}, {"$limit": 12},
                ],
                "by_sev": [
                    {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
                ],
                "trend": [
                    {"$group": {
                        "_id": {"$dateTrunc": {"date": "$created_at", "unit": tr.granularity}},
                        "count": {"$sum": 1}}},
                    {"$sort": {"_id": 1}},
                ],
                "domains": [
                    {"$match": {"indicators.domain": {"$ne": None}}},
                    {"$group": {"_id": "$indicators.domain", "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}}, {"$limit": 10},
                ],
                "urls": [
                    {"$match": {"indicators.url": {"$ne": None}}},
                    {"$group": {"_id": "$indicators.url", "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}}, {"$limit": 10},
                ],
                "senders": [
                    {"$group": {"_id": "$sender", "count": {"$sum": 1},
                                "avg_risk": {"$avg": "$risk_score"}}},
                    {"$sort": {"count": -1}}, {"$limit": 10},
                ],
                "conf": [{"$group": {"_id": None, "avg": {"$avg": "$confidence"}}}],
                "attach": [{"$match": {"has_attachment_threat": True}}, {"$count": "n"}],
                "heatmap": [
                    {"$group": {"_id": {
                        "dow": {"$dayOfWeek": "$created_at"},
                        "hod": {"$hour": "$created_at"}},
                        "count": {"$sum": 1}}},
                ],
                "timeline": [
                    {"$sort": {"created_at": -1}},
                    {"$limit": 25},
                    {"$project": {"at": "$created_at", "label": "$title",
                                  "severity": 1, "_id": 1}},
                ],
                "repeat": [
                    {"$group": {"_id": "$sender", "count": {"$sum": 1}}},
                    {"$match": {"count": {"$gte": 2}}},
                    {"$sort": {"count": -1}}, {"$limit": 10},
                ],
            }},
        ]
        rows = await self.agg.run("threats", pipe)
        f = rows[0] if rows else {}

        total = int((f.get("total") or [{}])[0].get("n", 0))
        by_cat = PieChart(slices=[PieSlice(label=str(r["_id"] or "unknown"),
                                           value=r["count"]) for r in f.get("by_cat", [])])
        by_sev = PieChart(slices=[PieSlice(label=str(r["_id"] or "unknown"),
                                           value=r["count"]) for r in f.get("by_sev", [])])
        trend = LineChart(
            x_label="time", y_label="threats",
            series=[ChartSeries(name="threats",
                    points=[SeriesPoint(x=r["_id"], y=r["count"]) for r in f.get("trend", [])])],
        )
        # heatmap 7x24
        cells: list[HeatmapCell] = []
        for r in f.get("heatmap", []):
            _id = r["_id"]; cells.append(HeatmapCell(
                row=str(_id["dow"]), col=str(_id["hod"]), value=r["count"]))
        heat = Heatmap(rows=[str(i) for i in range(1, 8)],
                       cols=[str(i) for i in range(24)], cells=cells)

        timeline = TimelineGraph(events=[
            TimelineEvent(at=t.get("at"), label=str(t.get("label") or "threat"),
                          severity=(t.get("severity") if t.get("severity") in SEVERITIES else "info"),
                          ref=str(t.get("_id"))) for t in f.get("timeline", [])
            if isinstance(t.get("at"), datetime)
        ])
        conf_arr = f.get("conf") or []
        conf_avg = round(float(conf_arr[0]["avg"] or 0), 3) if conf_arr else 0.0
        attach_n = int((f.get("attach") or [{}])[0].get("n", 0))

        return ThreatAnalytics(
            total=total, by_category=by_cat, by_severity=by_sev, trend=trend,
            timeline=timeline, heatmap=heat,
            top_sources=[{"domain": r["_id"], "count": r["count"]} for r in f.get("domains", [])],
            confidence_avg=conf_avg,
            repeated_attackers=[{"sender": r["_id"], "count": r["count"]} for r in f.get("repeat", [])],
            dangerous_domains=[{"domain": r["_id"], "count": r["count"]} for r in f.get("domains", [])],
            dangerous_urls=[{"url": r["_id"], "count": r["count"]} for r in f.get("urls", [])],
            attachment_threats=attach_n,
            top_sender_risks=[{"sender": r["_id"], "count": r["count"],
                               "avg_risk": round(float(r.get("avg_risk") or 0), 2)}
                              for r in f.get("senders", [])],
        )

    # =============================================================== SECURITY
    async def security_analytics(self, user_id: str, tr: TimeRange) -> SecurityAnalytics:
        total = await self.agg.count("emails",
            {"user_id": user_id, "created_at": {"$gte": tr.since, "$lte": tr.until}})
        threats = await self.agg.count("threats",
            {"user_id": user_id, "created_at": {"$gte": tr.since, "$lte": tr.until}})
        blocked = await self.agg.count("threats", {
            "user_id": user_id, "created_at": {"$gte": tr.since, "$lte": tr.until},
            "status": {"$in": ["blocked", "quarantined"]}})
        critical = await self.agg.count("threats", {
            "user_id": user_id, "severity": "critical",
            "created_at": {"$gte": tr.since, "$lte": tr.until}})
        recent_crit = await self.agg.count("threats", {
            "user_id": user_id, "severity": "critical",
            "created_at": {"$gte": datetime.now(_UTC) - timedelta(days=7)}})

        # trust: use sender diversity
        senders_pipe = [
            {"$match": {"user_id": user_id, "created_at": {"$gte": tr.since, "$lte": tr.until}}},
            {"$group": {"_id": "$sender", "risk": {"$max": "$risk_score"}}},
        ]
        senders = await self.agg.run("emails", senders_pipe)
        total_senders = len(senders)
        risky = sum(1 for s in senders if (s.get("risk") or 0) >= 60)
        trusted = total_senders - risky

        auth_pipe = [
            {"$match": {"user_id": user_id, "created_at": {"$gte": tr.since, "$lte": tr.until}}},
            {"$group": {"_id": None,
                        "pass": {"$sum": {"$cond": [{"$eq": ["$auth_verdict", "pass"]}, 1, 0]}},
                        "n": {"$sum": 1}}},
        ]
        arows = await self.agg.run("emails", auth_pipe)
        auth_ratio = 0.0
        if arows and arows[0].get("n"):
            auth_ratio = arows[0]["pass"] / arows[0]["n"]

        sec = self.scores.security_score(total_scanned=total, threats_detected=threats,
                                          blocked=blocked, recent_critical=recent_crit)
        trust = self.scores.trust_score(total_senders=total_senders,
                                        trusted_senders=trusted, risky_senders=risky,
                                        auth_pass_ratio=auth_ratio)
        thr = self.scores.threat_score(total_scanned=total, threats_detected=threats,
                                       critical_count=critical)

        # historical trend from analytics_snapshots
        hist_rows = [d async for d in self.db.analytics.find(
            {"user_id": user_id, "at": {"$gte": tr.since, "$lte": tr.until}},
            sort=[("at", 1)], limit=1000,
        )]
        historical = LineChart(
            x_label="time", y_label="security_score",
            series=[ChartSeries(name="security_score",
                    points=[SeriesPoint(x=r["at"], y=r.get("security_score", 0))
                            for r in hist_rows])],
        )

        return SecurityAnalytics(
            security_score=sec, trust_score=trust, threat_score=thr,
            historical=historical,
            protection_pct=self.scores.protection_pct(threats=threats, blocked=blocked),
            prevention_rate=self.scores.protection_pct(threats=threats, blocked=blocked),
            blocked_count=blocked,
            safe_ratio=self.scores.safe_ratio(total=total, threats=threats),
            suspicious_ratio=round(1 - self.scores.safe_ratio(total=total, threats=threats), 4),
        )

    # =================================================================== USER
    async def user_analytics(self, user_id: str, tr: TimeRange) -> UserAnalytics:
        match = {"user_id": user_id, "created_at": {"$gte": tr.since, "$lte": tr.until}}
        pipe = [
            {"$match": match},
            {"$facet": {
                "senders": [
                    {"$group": {"_id": "$sender", "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}}, {"$limit": 15},
                ],
                "domains": [
                    {"$group": {"_id": "$sender_domain", "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}}, {"$limit": 15},
                ],
                "cats": [
                    {"$group": {"_id": "$category", "count": {"$sum": 1}}},
                ],
                "hours": [
                    {"$group": {"_id": {"$hour": "$created_at"}, "count": {"$sum": 1}}},
                    {"$sort": {"_id": 1}},
                ],
                "dow": [
                    {"$group": {"_id": {"$dayOfWeek": "$created_at"}, "count": {"$sum": 1}}},
                    {"$sort": {"_id": 1}},
                ],
                "month": [
                    {"$group": {"_id": {"$dateTrunc": {"date": "$created_at", "unit": "week"}},
                                "count": {"$sum": 1}}},
                    {"$sort": {"_id": 1}},
                ],
                "labels": [
                    {"$unwind": "$labels"},
                    {"$group": {"_id": "$labels", "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}}, {"$limit": 12},
                ],
            }},
        ]
        rows = await self.agg.run("emails", pipe)
        f = rows[0] if rows else {}

        peak_hours = BarChart(x_label="hour", y_label="emails",
            categories=[str(r["_id"]) for r in f.get("hours", [])],
            series=[ChartSeries(name="emails",
                    points=[SeriesPoint(x=str(r["_id"]), y=r["count"]) for r in f.get("hours", [])])],
        )
        weekly = BarChart(x_label="dow", y_label="emails",
            categories=[str(r["_id"]) for r in f.get("dow", [])],
            series=[ChartSeries(name="emails",
                    points=[SeriesPoint(x=str(r["_id"]), y=r["count"]) for r in f.get("dow", [])])],
        )
        monthly = BarChart(x_label="week", y_label="emails",
            categories=[str(r["_id"]) for r in f.get("month", [])],
            series=[ChartSeries(name="emails",
                    points=[SeriesPoint(x=str(r["_id"]), y=r["count"]) for r in f.get("month", [])])],
        )
        cats = PieChart(slices=[PieSlice(label=str(r["_id"] or "uncategorised"),
                                         value=r["count"]) for r in f.get("cats", [])])
        # productivity heuristics
        total_emails = sum(r["count"] for r in f.get("hours", [])) or 1
        peak = max(f.get("hours", []) or [{"count": 0}], key=lambda r: r["count"])["count"]
        productivity = {
            "total_emails": total_emails,
            "peak_hour_emails": peak,
            "focus_ratio": round(1 - (peak / total_emails), 3),
        }
        return UserAnalytics(
            top_senders=[{"sender": r["_id"], "count": r["count"]} for r in f.get("senders", [])],
            top_domains=[{"domain": r["_id"], "count": r["count"]} for r in f.get("domains", [])],
            categories=cats, peak_hours=peak_hours,
            weekly_usage=weekly, monthly_usage=monthly,
            top_labels=[{"label": r["_id"], "count": r["count"]} for r in f.get("labels", [])],
            productivity=productivity,
        )

    # ================================================================= DOMAIN
    async def domain_analytics(self, user_id: str, tr: TimeRange) -> DomainAnalytics:
        match = {"user_id": user_id, "created_at": {"$gte": tr.since, "$lte": tr.until}}
        pipe = [
            {"$match": match},
            {"$group": {
                "_id": "$sender_domain",
                "count": {"$sum": 1},
                "first_seen": {"$min": "$created_at"},
                "reputation": {"$max": "$sender_reputation"},
                "category": {"$first": "$sender_category"},
                "country": {"$first": "$sender_country"},
            }},
            {"$sort": {"count": -1}},
        ]
        rows = await self.agg.run("emails", pipe)
        top = [{"domain": r["_id"], "count": r["count"]} for r in rows[:20]]
        new_cutoff = datetime.now(_UTC) - timedelta(days=30)
        new = [{"domain": r["_id"], "first_seen": r["first_seen"], "count": r["count"]}
               for r in rows if r.get("first_seen") and r["first_seen"] >= new_cutoff][:20]
        trusted = [{"domain": r["_id"], "reputation": r.get("reputation")}
                   for r in rows if (r.get("reputation") or 0) >= 70][:20]
        suspicious = [{"domain": r["_id"], "reputation": r.get("reputation")}
                      for r in rows if 0 < (r.get("reputation") or 0) < 40][:20]
        blocked = [d async for d in self.db.threats.find(
            {"user_id": user_id, "status": {"$in": ["blocked", "quarantined"]},
             "indicators.domain": {"$ne": None}},
            {"indicators.domain": 1, "_id": 0},
        ).limit(50)]
        newsletters = [{"domain": r["_id"], "count": r["count"]}
                       for r in rows if r.get("category") == "newsletter"][:20]
        corporate = [{"domain": r["_id"], "count": r["count"]}
                     for r in rows if r.get("category") == "corporate"][:20]

        countries: dict[str, int] = defaultdict(int)
        for r in rows:
            c = r.get("country") or "unknown"
            countries[c] += r["count"]
        country_chart = PieChart(slices=[PieSlice(label=k, value=v)
                                         for k, v in sorted(countries.items(),
                                                            key=lambda kv: -kv[1])[:20]])

        return DomainAnalytics(
            top=top, new=new, trusted=trusted, suspicious=suspicious,
            blocked=[{"domain": (b.get("indicators") or {}).get("domain")} for b in blocked],
            newsletters=newsletters, corporate=corporate, countries=country_chart,
        )

    # ==================================================================== AI
    async def ai_analytics(self, user_id: str, tr: TimeRange) -> AIAnalytics:
        match = {"user_id": user_id, "created_at": {"$gte": tr.since, "$lte": tr.until}}
        pipe = [
            {"$match": match},
            {"$facet": {
                "verdicts": [
                    {"$group": {"_id": "$verdict", "count": {"$sum": 1}}},
                ],
                "conf": [
                    {"$bucket": {"groupBy": "$confidence",
                                 "boundaries": [0, 0.25, 0.5, 0.75, 0.9, 1.01],
                                 "default": "other",
                                 "output": {"count": {"$sum": 1}}}},
                ],
                "recs": [
                    {"$unwind": "$recommendations"},
                    {"$group": {"_id": "$recommendations.type", "count": {"$sum": 1}}},
                ],
                "findings": [
                    {"$unwind": "$findings"},
                    {"$group": {"_id": "$findings.label", "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}}, {"$limit": 12},
                ],
                "fp": [{"$match": {"user_feedback": "false_positive"}}, {"$count": "n"}],
            }},
        ]
        rows = await self.agg.run("ai_reports", pipe)
        f = rows[0] if rows else {}
        decisions = PieChart(slices=[PieSlice(label=str(r["_id"] or "unknown"),
                                              value=r["count"]) for r in f.get("verdicts", [])])
        confidence = BarChart(
            x_label="confidence bucket", y_label="count",
            categories=[str(r["_id"]) for r in f.get("conf", [])],
            series=[ChartSeries(name="count",
                    points=[SeriesPoint(x=str(r["_id"]), y=r["count"]) for r in f.get("conf", [])])],
        )
        recs = PieChart(slices=[PieSlice(label=str(r["_id"] or "n/a"), value=r["count"])
                                for r in f.get("recs", [])])
        fp = int((f.get("fp") or [{}])[0].get("n", 0))
        return AIAnalytics(
            decisions=decisions, confidence_distribution=confidence,
            recommendation_types=recs, false_positive_queue=fp,
            common_findings=[{"label": r["_id"], "count": r["count"]}
                             for r in f.get("findings", [])],
        )

    # =================================================================== OCR
    async def ocr_analytics(self, user_id: str, tr: TimeRange) -> OCRAnalytics:
        match = {"user_id": user_id, "created_at": {"$gte": tr.since, "$lte": tr.until}}
        files = await self.agg.count("ocr_reports", match)
        qr = await self.agg.count("ocr_reports",
            {**match, "qr_codes": {"$exists": True, "$ne": []}})
        sens_pipe = [
            {"$match": match},
            {"$project": {"n": {"$sum": "$sensitive_findings.count"}}},
            {"$group": {"_id": None, "total": {"$sum": "$n"}}},
        ]
        sens_rows = await self.agg.run("ocr_reports", sens_pipe)
        sens = int((sens_rows[0].get("total") or 0)) if sens_rows else 0
        types_pipe = [
            {"$match": match},
            {"$group": {"_id": "$document_type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}, {"$limit": 10},
        ]
        types = await self.agg.run("ocr_reports", types_pipe)
        doc_types = PieChart(slices=[PieSlice(label=str(r["_id"] or "unknown"),
                                              value=r["count"]) for r in types])

        att_pipe = [
            {"$match": {"user_id": user_id}},
            {"$group": {"_id": None,
                        "unique": {"$sum": 1},
                        "avg_size": {"$avg": "$size_bytes"},
                        "risky": {"$sum": {"$cond": [{"$gt": [{"$size":
                            {"$ifNull": ["$risk_flags", []]}}, 0]}, 1, 0]}}}},
        ]
        arows = await self.agg.run("attachment_records", att_pipe)
        stats = arows[0] if arows else {}
        return OCRAnalytics(
            files_processed=files, qr_detected=qr, sensitive_findings=sens,
            document_types=doc_types,
            attachment_stats={
                "unique": int(stats.get("unique", 0)),
                "avg_size_bytes": round(float(stats.get("avg_size") or 0), 2),
                "risky": int(stats.get("risky", 0)),
            },
        )

    # ============================================================ COMPLAINTS
    async def complaint_analytics(self, user_id: str, tr: TimeRange) -> ComplaintAnalytics:
        match = {"user_id": user_id, "created_at": {"$gte": tr.since, "$lte": tr.until}}
        trend_pipe = [
            {"$match": match},
            {"$group": {"_id": {"$dateTrunc": {"date": "$created_at", "unit": tr.granularity}},
                        "count": {"$sum": 1}}},
            {"$sort": {"_id": 1}},
        ]
        trend_rows = await self.agg.run("complaints", trend_pipe)
        types_pipe = [
            {"$match": match},
            {"$group": {"_id": "$category", "count": {"$sum": 1}}},
        ]
        types = await self.agg.run("complaints", types_pipe)
        evidence = await self.agg.count("evidence_packs", match)
        reminders_pipe = [
            {"$match": {"user_id": user_id}},
            {"$group": {"_id": "$status", "count": {"$sum": 1}}},
        ]
        rem = {r["_id"]: r["count"] for r in await self.agg.run("complaint_reminders", reminders_pipe)}
        exports_pipe = [
            {"$match": {"user_id": user_id}},
            {"$group": {"_id": "$format", "count": {"$sum": 1}}},
        ]
        exp = {r["_id"]: r["count"] for r in await self.agg.run("evidence_downloads", exports_pipe)}

        history = LineChart(
            x_label="time", y_label="complaints",
            series=[ChartSeries(name="complaints",
                    points=[SeriesPoint(x=r["_id"], y=r["count"]) for r in trend_rows])],
        )
        return ComplaintAnalytics(
            history=history,
            types=PieChart(slices=[PieSlice(label=str(r["_id"] or "other"),
                                            value=r["count"]) for r in types]),
            evidence_packs=evidence, reminders=rem, exports=exp,
        )
