from app.core.config import Settings


def test_defaults():
    s = Settings()
    assert s.APP_NAME == "GuardianMail AI"
    assert s.cors_origins_list
    assert s.celery_broker == s.REDIS_URL


def test_prod_rejects_weak_secret(monkeypatch):
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("SECRET_KEY", "short")
    monkeypatch.setenv("CORS_ORIGINS", "*")
    monkeypatch.setenv("TRUSTED_HOSTS", "*")
    monkeypatch.setenv("FERNET_KEY", "x")
    monkeypatch.setenv("METRICS_TOKEN", "")
    import pytest
    with pytest.raises(Exception):
        Settings()
