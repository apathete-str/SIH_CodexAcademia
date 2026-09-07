"""Application configuration loaded from environment variables."""
from __future__ import annotations
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # App
    app_name: str = "Email Threat Intelligence Platform"
    app_version: str = "0.1.0"
    debug: bool = False
    environment: str = "development"

    # Storage
    database_url: str = "postgresql+psycopg://postgres:postgres@localhost:5432/emailthreat"
    redis_url: str = "redis://localhost:6379/0"
    s3_bucket: str = "email-threat-artifacts"
    s3_endpoint: str = ""  # empty = AWS default

    # Security
    secret_key: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    # Enrichment API keys (empty = use mock providers)
    virustotal_api_key: str = ""
    urlscan_api_key: str = ""
    google_safebrowsing_key: str = ""
    maxmind_db_path: str = ""  # empty = use mock geo

    # Model paths
    classical_model_path: str = "ml/models/classical.joblib"
    nlp_model_path: str = "ml/models/nlp"

    # Queue
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"

    # CORS
    cors_origins: list[str] = ["http://localhost:3000"]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
