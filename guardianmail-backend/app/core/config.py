from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_ENV: str = "dev"
    SECRET_KEY: str = "insecure-dev-secret"
    JWT_ALG: str = "HS256"
    ACCESS_TOKEN_TTL_MIN: int = 15
    REFRESH_TOKEN_TTL_DAYS: int = 30
    FERNET_KEY: str = ""

    MONGO_URI: str = "mongodb://localhost:27017"
    MONGO_DB: str = "guardianmail"
    REDIS_URL: str = "redis://localhost:6379/0"

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

    CORS_ORIGINS: str = "http://localhost:5173"

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


@lru_cache
def _get() -> Settings:
    return Settings()


settings = _get()
