"""
NIDS ARC Configuration Management.

Loads configuration from environment variables with sensible defaults.
Uses pydantic-settings for validation and type coercion.
"""

from __future__ import annotations

import os
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings
from pydantic import Field


class AppMode(str, Enum):
    """Operating mode for the platform."""
    SIMULATION = "simulation"
    REAL = "real"
    REPLAY = "replay"


class LogLevel(str, Enum):
    """Log levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ResponseMode(str, Enum):
    """Default response mode."""
    ALERT_ONLY = "alert_only"
    MANUAL_APPROVAL = "manual_approval"
    AUTOMATIC = "automatic"


class AnomalySensitivity(str, Enum):
    """Anomaly detection sensitivity."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # --- Application ---
    app_name: str = "NIDS ARC"
    app_env: str = "development"
    app_debug: bool = True
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    app_log_level: LogLevel = LogLevel.INFO
    app_secret_key: str = Field(
        default="CHANGE_ME_TO_A_RANDOM_SECRET_AT_LEAST_32_CHARS",
        min_length=16,
    )
    app_mode: AppMode = AppMode.SIMULATION

    # --- Database ---
    database_url: str = "sqlite+aiosqlite:///./nids_arc.db"

    # --- Redis ---
    redis_url: str = "redis://localhost:6379/0"
    redis_password: Optional[str] = None

    # --- JWT ---
    jwt_secret_key: str = Field(
        default="CHANGE_ME_TO_A_RANDOM_JWT_SECRET_AT_LEAST_64_CHARS",
        min_length=16,
    )
    jwt_access_token_expire_minutes: int = 15
    jwt_refresh_token_expire_days: int = 7
    jwt_algorithm: str = "HS256"

    # --- Default Admin ---
    default_admin_username: str = "admin"
    default_admin_password: str = "CHANGE_ME_IMMEDIATELY"
    default_admin_email: str = "admin@nidsarc.local"

    # --- Rate Limiting ---
    rate_limit_auth: str = "100/minute"
    rate_limit_api: str = "1000/minute"

    # --- Detection ---
    detection_signature_enabled: bool = True
    detection_anomaly_enabled: bool = True
    detection_behavioral_enabled: bool = True
    detection_ml_enabled: bool = True
    detection_threat_intel_enabled: bool = True

    # --- Anomaly ---
    anomaly_baseline_learning_period_hours: int = 24
    anomaly_sensitivity: AnomalySensitivity = AnomalySensitivity.MEDIUM
    anomaly_min_samples: int = 100

    # --- ML ---
    ml_model_path: str = "backend/ml/models"
    ml_inference_batch_size: int = 32
    ml_inference_timeout_ms: int = 50

    # --- Simulation ---
    simulation_events_per_second: int = 10
    simulation_attack_probability: float = 0.05
    simulation_seed: int = 42

    # --- Response ---
    response_default_mode: ResponseMode = ResponseMode.ALERT_ONLY
    response_dry_run: bool = True
    response_manual_approval: bool = True

    # --- Retention ---
    retention_events_days: int = 90
    retention_alerts_days: int = 365
    retention_audit_days: int = 365
    retention_pcap_days: int = 30

    # --- CORS ---
    cors_allowed_origins: str = "http://localhost:3000,http://localhost:8000"
    cors_allow_credentials: bool = True

    @property
    def cors_origins_list(self) -> list[str]:
        """Parse CORS origins string into list."""
        return [o.strip() for o in self.cors_allowed_origins.split(",")]

    @property
    def is_production(self) -> bool:
        """Check if running in production."""
        return self.app_env == "production"

    @property
    def base_dir(self) -> Path:
        """Project base directory."""
        return Path(__file__).parent.parent

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }


@lru_cache()
def get_settings() -> Settings:
    """Get cached application settings singleton."""
    return Settings()
