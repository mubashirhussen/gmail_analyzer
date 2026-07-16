"""Typed application settings.

Single source of truth for all runtime configuration. Values load from
environment / .env, validate at boot, and fail-fast in production if a
security-critical value is missing or weak. All modules import
`settings` from this file and never read `os.environ` directly.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


Environment = Literal["dev", "staging", "prod", "test"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )

    # ---- runtime ---------------------------------------------------------
    APP_ENV: Environment = "dev"
    APP_NAME: str = "GuardianMail AI"
    APP_VERSION: str = "1.0.0"
    LOG_LEVEL: str = "INFO"
    LOG_JSON: bool = True
    REQUEST_MAX_BODY_BYTES: int = 2 * 1024 * 1024  # 2 MiB
    METRICS_TOKEN: str = ""  # required to hit /metrics in non-dev

    # ---- security --------------------------------------------------------
    SECRET_KEY: str = "insecure-dev-secret"
    JWT_ALG: str = "HS256"
    ACCESS_TOKEN_TTL_MIN: int = 15
    REFRESH_TOKEN_TTL_DAYS: int = 30
    FERNET_KEY: str = ""
    PASSWORD_HASH_SCHEME: str = "bcrypt"

    # ---- persistence -----------------------------------------------------
    MONGO_URI: str = "mongodb://localhost:27017"
    MONGO_DB: str = "guardianmail"
    MONGO_MAX_POOL_SIZE: int = 100
    MONGO_MIN_POOL_SIZE: int = 5
    MONGO_SERVER_SELECTION_TIMEOUT_MS: int = 5_000
    MONGO_CONNECT_TIMEOUT_MS: int = 10_000

    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_MAX_CONNECTIONS: int = 64

    # ---- celery ----------------------------------------------------------
    CELERY_BROKER_URL: str = ""
    CELERY_RESULT_BACKEND: str = ""
    CELERY_TASK_SOFT_TIME_LIMIT_S: int = 240
    CELERY_TASK_TIME_LIMIT_S: int = 300
    CELERY_WORKER_PREFETCH_MULTIPLIER: int = 1

    # ---- oauth / external ------------------------------------------------
    GOOGLE_OAUTH_CLIENT_ID: str = ""
    GOOGLE_OAUTH_CLIENT_SECRET: str = ""
    GOOGLE_OAUTH_REDIRECT: str = ""
    GEMINI_API_KEY: str = ""

    VIRUSTOTAL_API_KEY: str = ""
    GOOGLE_SAFE_BROWSING_KEY: str = ""
    URLSCAN_API_KEY: str = ""
    PHISHTANK_APP_KEY: str = ""
    ABUSEIPDB_KEY: str = ""
    WHOISXML_KEY: str = ""

    # ---- http / cors -----------------------------------------------------
    CORS_ORIGINS: str = "http://localhost:5173"
    TRUSTED_HOSTS: str = "*"
    WEBHOOK_SECRET: str = ""

    # ---- rate limits (defaults; per-endpoint overrides live in code) ----
    RATE_LIMIT_DEFAULT: str = "120/minute"

    # ---------------------------------------------------------------------
    @property
    def is_prod(self) -> bool:
        return self.APP_ENV == "prod"

    @property
    def is_test(self) -> bool:
        return self.APP_ENV == "test"

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def trusted_hosts_list(self) -> list[str]:
        return [h.strip() for h in self.TRUSTED_HOSTS.split(",") if h.strip()]

    @property
    def celery_broker(self) -> str:
        return self.CELERY_BROKER_URL or self.REDIS_URL

    @property
    def celery_backend(self) -> str:
        return self.CELERY_RESULT_BACKEND or self.REDIS_URL

    # ---- validators ------------------------------------------------------
    @field_validator("LOG_LEVEL")
    @classmethod
    def _upper(cls, v: str) -> str:
        v = (v or "INFO").upper()
        if v not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"}:
            raise ValueError(f"invalid LOG_LEVEL: {v}")
        return v

    @model_validator(mode="after")
    def _prod_guardrails(self) -> "Settings":
        if self.APP_ENV != "prod":
            return self
        weak: list[str] = []
        if len(self.SECRET_KEY) < 32 or self.SECRET_KEY.startswith("insecure"):
            weak.append("SECRET_KEY")
        if len(self.FERNET_KEY) < 32:
            weak.append("FERNET_KEY")
        if "*" in self.cors_origins_list:
            weak.append("CORS_ORIGINS(*)")
        if "*" in self.trusted_hosts_list:
            weak.append("TRUSTED_HOSTS(*)")
        if not self.METRICS_TOKEN:
            weak.append("METRICS_TOKEN")
        if weak:
            raise ValueError(f"insecure prod configuration: {', '.join(weak)}")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
