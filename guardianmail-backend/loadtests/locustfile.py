"""Locust load-test suite for GuardianMail — Module 11.

Run: locust -f loadtests/locustfile.py --host https://api.guardianmail.local

Scenarios:
- HealthUser        — hits /api/v1/platform/health|/ready|/live (baseline)
- APIUser           — logged-in API smoke (requires TOKEN env)

Load profile suggestions:
    100 users  -u 100  -r 20  --run-time 5m
    500 users  -u 500  -r 50  --run-time 10m
    1000 users -u 1000 -r 100 --run-time 15m
    5000 users -u 5000 -r 250 --run-time 20m
"""
from __future__ import annotations

import os

from locust import HttpUser, between, task


class HealthUser(HttpUser):
    wait_time = between(0.5, 1.5)

    @task(3)
    def liveness(self) -> None:
        self.client.get("/api/v1/platform/live", name="live")

    @task(2)
    def readiness(self) -> None:
        self.client.get("/api/v1/platform/ready", name="ready")

    @task(1)
    def status(self) -> None:
        self.client.get("/api/v1/platform/status", name="status")


class APIUser(HttpUser):
    wait_time = between(1, 3)

    def on_start(self) -> None:
        self.token = os.getenv("TOKEN", "")
        self.headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}

    @task
    def list_emails(self) -> None:
        self.client.get("/api/v1/emails?limit=25", headers=self.headers, name="emails.list")

    @task
    def dashboard(self) -> None:
        self.client.get("/api/v1/dashboard-platform/overview", headers=self.headers, name="dashboard")
