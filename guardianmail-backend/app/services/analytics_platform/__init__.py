"""Analytics, Security Dashboard & Reporting Platform (Module 10).

This package implements the read-side aggregation engine that consumes data
persisted by Modules 4-9 (Gmail, Threat Intel, AI, OCR, Complaints) and
exposes optimized dashboard/report APIs. It is strictly additive: no other
module imports from it, and it never mutates their collections.

Public services:

* `TimeFilterService`         — canonical time-window resolution.
* `AggregationService`        — reusable MongoDB pipeline builders.
* `KPIService`                — KPI card computation with delta vs prior.
* `SecurityScoreService`      — Security / Trust / Threat score formulae.
* `AnalyticsService`          — Domain-scoped analytics assemblers.
* `TrendService`              — Persisted trend series builder + reader.
* `DashboardService`          — Composed dashboard payloads (cached).
* `ReportingService`          — Report lifecycle + generation orchestration.
* `ExportService`             — PDF/DOCX/XLSX/CSV/JSON serialization.
"""
from app.services.analytics_platform.time_filters import TimeFilterService
from app.services.analytics_platform.aggregation_service import AggregationService
from app.services.analytics_platform.kpi_service import KPIService
from app.services.analytics_platform.security_score_service import SecurityScoreService
from app.services.analytics_platform.analytics_service import AnalyticsService
from app.services.analytics_platform.trend_service import TrendService
from app.services.analytics_platform.dashboard_service import DashboardService
from app.services.analytics_platform.reporting_service import ReportingService
from app.services.analytics_platform.export_service import ExportService

__all__ = [
    "TimeFilterService",
    "AggregationService",
    "KPIService",
    "SecurityScoreService",
    "AnalyticsService",
    "TrendService",
    "DashboardService",
    "ReportingService",
    "ExportService",
]
