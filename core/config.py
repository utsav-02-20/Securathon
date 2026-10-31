from urllib.parse import urlparse
from typing import Optional, Any
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


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

    # --------------------------------------------------------------------------
    # Gateway Reverse Proxy (Source)
    # --------------------------------------------------------------------------
    source_url: Optional[str] = Field(default=None, alias="SOURCE_URL")
    gateway_host: str = Field(default="0.0.0.0", alias="GATEWAY_HOST")
    gateway_port: int = Field(default=8000, alias="GATEWAY_PORT")
    gateway_workers: int = Field(default=1, alias="GATEWAY_WORKERS")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    # --------------------------------------------------------------------------
    # Downstream Backend Service (Destination / Target Application)
    # --------------------------------------------------------------------------
    destination_url: Optional[str] = Field(default=None, alias="DESTINATION_URL")
    target_url: Optional[str] = Field(default=None, alias="TARGET_URL")
    backend_host: str = Field(default="127.0.0.1", alias="BACKEND_HOST")
    backend_port: int = Field(default=8001, alias="BACKEND_PORT")
    backend_service_url: str = Field(default="http://127.0.0.1:8001", alias="BACKEND_SERVICE_URL")

    # --------------------------------------------------------------------------
    # Authentication & Access Control
    # --------------------------------------------------------------------------
    require_auth: bool = Field(default=True, alias="REQUIRE_AUTH")
    jwt_secret_key: str = Field(default="super-secret-production-grade-encryption-key-32chars", alias="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    jwt_expiration_minutes: int = Field(default=60, alias="JWT_EXPIRATION_MINUTES")

    # --------------------------------------------------------------------------
    # Redis State, Sliding Window & Token Revocation
    # --------------------------------------------------------------------------
    redis_host: str = Field(default="localhost", alias="REDIS_HOST")
    redis_port: int = Field(default=6379, alias="REDIS_PORT")
    redis_db: int = Field(default=0, alias="REDIS_DB")
    redis_password: Optional[str] = Field(default=None, alias="REDIS_PASSWORD")
    use_fake_redis_fallback: bool = Field(default=True, alias="USE_FAKE_REDIS_FALLBACK")

    # --------------------------------------------------------------------------
    # Database Configuration (SQLite / PostgreSQL)
    # --------------------------------------------------------------------------
    db_type: str = Field(default="sqlite", alias="DB_TYPE")
    database_url: Optional[str] = Field(default=None, alias="DATABASE_URL")
    postgres_user: str = Field(default="postgres", alias="POSTGRES_USER")
    postgres_password: str = Field(default="postgres", alias="POSTGRES_PASSWORD")
    postgres_db: str = Field(default="securathon_audit", alias="POSTGRES_DB")
    postgres_host: str = Field(default="localhost", alias="POSTGRES_HOST")
    postgres_port: int = Field(default=5432, alias="POSTGRES_PORT")

    # --------------------------------------------------------------------------
    # Rate Limiting Configuration (Atomic Sliding Window)
    # --------------------------------------------------------------------------
    rate_limit_requests_per_window: int = Field(default=100, alias="RATE_LIMIT_REQUESTS_PER_WINDOW")
    rate_limit_window_seconds: int = Field(default=60, alias="RATE_LIMIT_WINDOW_SECONDS")
    rate_limit_customer: int = Field(default=100, alias="RATE_LIMIT_CUSTOMER")
    rate_limit_merchant: int = Field(default=250, alias="RATE_LIMIT_MERCHANT")
    rate_limit_admin: int = Field(default=1000, alias="RATE_LIMIT_ADMIN")
    rate_limit_unauth_ip: int = Field(default=30, alias="RATE_LIMIT_UNAUTH_IP")

    # --------------------------------------------------------------------------
    # Behavioral ML & Telemetry
    # --------------------------------------------------------------------------
    anomaly_score_threshold: float = Field(default=0.75, alias="ANOMALY_SCORE_THRESHOLD")
    tarpit_delay_seconds: float = Field(default=2.0, alias="TARPIT_DELAY_SECONDS")

    def model_post_init(self, __context: Any) -> None:
        """
        Synchronizes Source/Destination URLs, parses ports/hosts,
        and ensures coherent fallbacks.
        """
        # 1. Destination / Target Application URL mapping
        effective_dest = self.destination_url or self.target_url or self.backend_service_url
        if effective_dest:
            clean_dest = str(effective_dest).rstrip("/")
            self.backend_service_url = clean_dest
            self.destination_url = clean_dest
            parsed_dest = urlparse(clean_dest)
            if parsed_dest.hostname:
                self.backend_host = parsed_dest.hostname
            if parsed_dest.port:
                self.backend_port = parsed_dest.port

        # 2. Source / Gateway URL mapping
        if self.source_url:
            parsed_src = urlparse(self.source_url)
            if parsed_src.hostname:
                self.gateway_host = parsed_src.hostname
            if parsed_src.port:
                self.gateway_port = parsed_src.port
        else:
            self.source_url = f"http://{self.gateway_host}:{self.gateway_port}"


settings = Settings()


