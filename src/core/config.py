"""Application configuration using Pydantic Settings"""

from functools import lru_cache
from typing import List, Optional, Literal
import math

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _estimate_entropy(value: str) -> float:
    """
    Estimate Shannon entropy of a string.
    Returns entropy in bits.
    """
    if not value:
        return 0.0

    # Count frequency of each character
    char_counts = {}
    for char in value:
        char_counts[char] = char_counts.get(char, 0) + 1

    # Calculate Shannon entropy
    entropy = 0.0
    length = len(value)
    for count in char_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "PySOAR"
    app_env: str = "development"
    debug: bool = False
    secret_key: str = "change-me-in-production"
    api_v1_prefix: str = "/api/v1"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 1

    # Database
    database_url: str = "sqlite+aiosqlite:///./pysoar.db"
    database_ssl_mode: str = "prefer"

    # Redis
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # JWT Authentication
    jwt_secret_key: str = "jwt-secret-change-in-production"
    jwt_algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # Encryption
    encryption_master_key: Optional[str] = None

    # Account Security
    account_lockout_max_attempts: int = 5
    account_lockout_duration_seconds: int = 900
    password_min_length: int = 12

    # First Admin User
    first_admin_email: str = "admin@pysoar.local"
    first_admin_password: str = "changeme123"

    # CORS
    cors_origins: List[str] = ["http://localhost:3000", "http://localhost:8000"]

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            import json
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return [origin.strip() for origin in v.split(",")]
        return v

    @field_validator("database_ssl_mode")
    @classmethod
    def validate_database_ssl_mode(cls, v, info):
        if info.data.get("app_env") == "production":
            if v not in ["require", "verify-full"]:
                raise ValueError(
                    f"In production, database_ssl_mode must be 'require' or 'verify-full', got '{v}'"
                )
        return v

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"

    # Rate Limiting
    rate_limit_per_minute: int = 60

    # Integrations
    virustotal_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    shodan_api_key: Optional[str] = None
    greynoise_api_key: Optional[str] = None
    urlscan_api_key: Optional[str] = None
    hibp_api_key: Optional[str] = None

    # Email (SMTP)
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from: str = "noreply@pysoar.local"
    smtp_tls: bool = True

    # Notifications
    slack_webhook_url: Optional[str] = None
    teams_webhook_url: Optional[str] = None

    # External Services
    elasticsearch_url: Optional[str] = None
    elasticsearch_api_key: Optional[str] = None
    splunk_host: Optional[str] = None
    splunk_token: Optional[str] = None

    # AWS
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_region: str = "us-east-1"

    @property
    def is_development(self) -> bool:
        return self.app_env == "development"

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    def validate_production_secrets(self) -> list[str]:
        """
        Validate production secret strength and configuration.
        Returns list of warning strings if issues are found.
        """
        warnings = []
        weak_patterns = ["change", "default", "password", "secret", "admin", "test", "example", "placeholder"]

        # Check secret_key entropy
        secret_entropy = _estimate_entropy(self.secret_key)
        if secret_entropy < 3.0:
            warnings.append(
                f"secret_key entropy is {secret_entropy:.2f} bits (< 3.0). Consider using a more random value."
            )

        # Check jwt_secret_key entropy
        jwt_entropy = _estimate_entropy(self.jwt_secret_key)
        if jwt_entropy < 3.0:
            warnings.append(
                f"jwt_secret_key entropy is {jwt_entropy:.2f} bits (< 3.0). Consider using a more random value."
            )

        # Check for weak patterns in secrets
        for secret_name, secret_value in [("secret_key", self.secret_key), ("jwt_secret_key", self.jwt_secret_key)]:
            secret_lower = secret_value.lower()
            for pattern in weak_patterns:
                if pattern in secret_lower:
                    warnings.append(
                        f"{secret_name} contains weak pattern '{pattern}'. Use a cryptographically random secret."
                    )
                    break

        # Check encryption_master_key is set
        if not self.encryption_master_key:
            warnings.append(
                "encryption_master_key is not set. Data encryption will not be available."
            )

        # Check first_admin_password entropy
        first_admin_entropy = _estimate_entropy(self.first_admin_password)
        if first_admin_entropy < 3.0:
            warnings.append(
                f"first_admin_password entropy is {first_admin_entropy:.2f} bits (< 3.0). Set a stronger initial admin password."
            )

        return warnings


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()


settings = get_settings()
