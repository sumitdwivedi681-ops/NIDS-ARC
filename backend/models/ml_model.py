"""ML Model Version ORM model."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, String, JSON
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base, TimestampMixin, UUIDMixin


class ModelVersion(UUIDMixin, TimestampMixin, Base):
    """Versioned ML model metadata."""

    __tablename__ = "ml_models"

    model_name: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="staging")
    algorithm: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    training_data_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    metrics: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    parameters: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    artifact_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    deployed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    deployed_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
