from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    """
    Centralized configuration management for the Intelligent API Security Gateway
    and downstream microservices.
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Gateway Reverse Proxy
    gateway_host: str = Field(default="0.0.0.0", alias="GATEWAY_HOST")
    gateway_port: int = Field(default=8000, alias="GATEWAY_PORT")
    gateway_workers: int = Field(default=1, alias="GATEWAY_WORKERS")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    # Downstream Backend Service
    backend_host: str = Field(default="127.0.0.1", alias="BACKEND_HOST")
    backend_port: int = Field(default=8001, alias="BACKEND_PORT")
    backend_service_url: str = Field(default="http://127.0.0.1:8001", alias="BACKEND_SERVICE_URL")

    # Cryptographic Identity & JWT Engine
    jwt_secret_key: str = Field(default="super-secret-production-grade-encryption-key-32chars", alias="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    jwt_expiration_minutes: int = Field(default=60, alias="JWT_EXPIRATION_MINUTES")

    # Redis State, Sliding Window & Token Revocation
    redis_host: str = Field(default="localhost", alias="REDIS_HOST")
    redis_port: int = Field(default=6379, alias="REDIS_PORT")
    redis_db: int = Field(default=0, alias="REDIS_DB")
    redis_password: Optional[str] = Field(default=None, alias="REDIS_PASSWORD")
    use_fake_redis_fallback: bool = Field(default=True, alias="USE_FAKE_REDIS_FALLBACK")

    # PostgreSQL Database Store
    postgres_user: str = Field(default="postgres", alias="POSTGRES_USER")
    postgres_password: str = Field(default="postgres", alias="POSTGRES_PASSWORD")
    postgres_db: str = Field(default="securathon_audit", alias="POSTGRES_DB")
    postgres_host: str = Field(default="localhost", alias="POSTGRES_HOST")
    postgres_port: int = Field(default=5432, alias="POSTGRES_PORT")
    database_url: str = Field(
        default="postgresql+asyncpg://postgres:postgres@localhost:5432/securathon_audit",
        alias="DATABASE_URL"
    )

    # Rate Limiting Configuration
    rate_limit_requests_per_window: int = Field(default=100, alias="RATE_LIMIT_REQUESTS_PER_WINDOW")
    rate_limit_window_seconds: int = Field(default=60, alias="RATE_LIMIT_WINDOW_SECONDS")

    # Behavioral ML & Telemetry
    anomaly_score_threshold: float = Field(default=0.75, alias="ANOMALY_SCORE_THRESHOLD")
    tarpit_delay_seconds: float = Field(default=2.0, alias="TARPIT_DELAY_SECONDS")


settings = Settings()

