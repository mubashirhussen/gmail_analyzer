"""Pydantic schemas for the analytics, dashboard, and reporting platform.

These schemas define the contracts the frontend consumes. They are
deliberately independent of the persisted models so that internal storage
shapes can evolve without breaking API consumers.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

# --------------------------------------------------------------------- time
TimeFilter = Literal[
    "today", "yesterday", "last_7_days", "last_30_days", "last_90_days",
    "this_month", "last_month", "custom",
]

Granularity = Literal["hour", "day", "week", "month"]


class TimeRange(BaseModel):
    filter: TimeFilter = "last_30_days"
    since: datetime
    until: datetime
    granularity: Granularity = "day"


class CustomRangeParams(BaseModel):
    since: datetime
    until: datetime
    granularity: Granularity = "day"


# --------------------------------------------------------------------- KPIs
class KPICard(BaseModel):
    key: str
    label: str
    value: float
    unit: str | None = None
    delta_pct: float | None = None
    trend: Literal["up", "down", "flat"] = "flat"
    hint: str | None = None


class ScoreCard(BaseModel):
    key: str
    label: str
    score: int = Field(ge=0, le=100)
    band: Literal["critical", "poor", "fair", "good", "excellent"]
    delta: int = 0
    computed_at: datetime


# --------------------------------------------------------- chart data types
class SeriesPoint(BaseModel):
    x: Any
    y: float


class ChartSeries(BaseModel):
    name: str
    points: list[SeriesPoint]


class LineChart(BaseModel):
    kind: Literal["line", "area"] = "line"
    x_label: str
    y_label: str
    series: list[ChartSeries]


class BarChart(BaseModel):
    kind: Literal["bar"] = "bar"
    x_label: str
    y_label: str
    categories: list[str]
    series: list[ChartSeries]


class PieSlice(BaseModel):
    label: str
    value: float


class PieChart(BaseModel):
    kind: Literal["pie", "donut"] = "pie"
    slices: list[PieSlice]


class ScatterPoint(BaseModel):
    x: float
    y: float
    label: str | None = None


class ScatterChart(BaseModel):
    kind: Literal["scatter"] = "scatter"
    x_label: str
    y_label: str
    points: list[ScatterPoint]


class HeatmapCell(BaseModel):
    row: str
    col: str
    value: float


class Heatmap(BaseModel):
    kind: Literal["heatmap"] = "heatmap"
    rows: list[str]
    cols: list[str]
    cells: list[HeatmapCell]


class TimelineEvent(BaseModel):
    at: datetime
    label: str
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    ref: str | None = None


class TimelineGraph(BaseModel):
    kind: Literal["timeline"] = "timeline"
    events: list[TimelineEvent]


# ----------------------------------------------------------------- payloads
class EmailAnalytics(BaseModel):
    total: int
    read: int
    unread: int
    spam: int
    flagged: int
    archived: int
    deleted: int
    with_attachments: int
    avg_per_day: float
    avg_per_week: float
    avg_per_month: float
    growth_pct: float
    inbox_health: int = Field(ge=0, le=100)


class ThreatAnalytics(BaseModel):
    total: int
    by_category: PieChart
    by_severity: PieChart
    trend: LineChart
    timeline: TimelineGraph
    heatmap: Heatmap
    top_sources: list[dict]
    confidence_avg: float
    repeated_attackers: list[dict]
    dangerous_domains: list[dict]
    dangerous_urls: list[dict]
    attachment_threats: int
    top_sender_risks: list[dict]


class SecurityAnalytics(BaseModel):
    security_score: ScoreCard
    trust_score: ScoreCard
    threat_score: ScoreCard
    historical: LineChart
    protection_pct: float
    prevention_rate: float
    blocked_count: int
    safe_ratio: float
    suspicious_ratio: float


class UserAnalytics(BaseModel):
    top_senders: list[dict]
    top_domains: list[dict]
    categories: PieChart
    peak_hours: BarChart
    weekly_usage: BarChart
    monthly_usage: BarChart
    top_labels: list[dict]
    productivity: dict


class DomainAnalytics(BaseModel):
    top: list[dict]
    new: list[dict]
    trusted: list[dict]
    suspicious: list[dict]
    blocked: list[dict]
    newsletters: list[dict]
    corporate: list[dict]
    countries: PieChart


class AIAnalytics(BaseModel):
    decisions: PieChart
    confidence_distribution: BarChart
    recommendation_types: PieChart
    false_positive_queue: int
    common_findings: list[dict]


class OCRAnalytics(BaseModel):
    files_processed: int
    qr_detected: int
    sensitive_findings: int
    document_types: PieChart
    attachment_stats: dict


class ComplaintAnalytics(BaseModel):
    history: LineChart
    types: PieChart
    evidence_packs: int
    reminders: dict
    exports: dict


class DashboardOverview(BaseModel):
    time_range: TimeRange
    kpis: list[KPICard]
    scores: list[ScoreCard]
    email: EmailAnalytics
    security: SecurityAnalytics
    threats_summary: dict
    recent_events: TimelineGraph
    computed_at: datetime
    from_cache: bool = False


# -------------------------------------------------------------- reports API
ReportKind = Literal[
    "daily", "weekly", "monthly",
    "security", "threat", "executive",
    "email_activity", "analytics_snapshot",
]
ReportFormat = Literal["pdf", "csv", "xlsx", "json", "docx"]


class ReportGenerateRequest(BaseModel):
    kind: ReportKind
    fmt: ReportFormat = "pdf"
    time_filter: TimeFilter = "last_30_days"
    since: datetime | None = None
    until: datetime | None = None
    include_sections: list[str] | None = None


class ReportSummary(BaseModel):
    id: str
    kind: ReportKind
    fmt: ReportFormat
    status: str
    generated_at: datetime | None
    period_start: datetime | None
    period_end: datetime | None
    size_bytes: int | None
    download_url: str | None
    expires_at: datetime | None
