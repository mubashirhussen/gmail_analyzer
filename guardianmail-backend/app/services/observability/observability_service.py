"""Observability facade — one entry-point for other modules.

Any GuardianMail subsystem needing to record telemetry imports
``observability_service`` and calls high-level helpers (``record_scan``,
``record_ai``, ``span``, ...). Keeps the surface area of cross-module
instrumentation as small as possible.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

from app.services.observability.alert_service import ops_alert_service
from app.services.observability.health_service import ops_health_service
from app.services.observability.incident_service import ops_incident_service
from app.services.observability.metrics_service import metrics_service
from app.services.observability.telemetry_service import telemetry_service
from app.services.observability.tracing_service import tracing_service


class ObservabilityService:
    metrics = metrics_service
    tracing = tracing_service
    telemetry = telemetry_service
    health = ops_health_service
    alerts = ops_alert_service
    incidents = ops_incident_service

    @contextmanager
    def instrument(self, name: str, **attrs: Any) -> Iterator[Any]:
        """Combined span + no-op metric wrapper for ad-hoc instrumentation."""
        with tracing_service.span(name, **attrs) as span:
            yield span


observability_service = ObservabilityService()
