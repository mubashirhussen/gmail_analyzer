"""Module 11 — Platform hardening services.

Additive services that harden the backend without touching business logic:
health / readiness, metrics, distributed rate limiting, audit trail,
performance sampling, and a small circuit-breaker / retry toolkit.
"""
from app.services.platform.audit_service import AuditService
from app.services.platform.circuit_breaker import CircuitBreaker, CircuitOpenError
from app.services.platform.health_service import HealthService
from app.services.platform.logging_service import LoggingService
from app.services.platform.metrics_service import MetricsService
from app.services.platform.performance_service import PerformanceService
from app.services.platform.ratelimit_service import RateLimitService, RateLimitPolicy
from app.services.platform.retry import retry_async

__all__ = [
    "AuditService",
    "CircuitBreaker",
    "CircuitOpenError",
    "HealthService",
    "LoggingService",
    "MetricsService",
    "PerformanceService",
    "RateLimitService",
    "RateLimitPolicy",
    "retry_async",
]
