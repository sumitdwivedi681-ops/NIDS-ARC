"""Detection Result ORM model."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, String, JSON
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base, UUIDMixin


class DetectionResult(UUIDMixin, Base):
    """Result from a detection engine with full provenance."""

    __tablename__ = "detection_results"

    event_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    detector: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    detector_version: Mapped[str] = mapped_column(String(20), nullable=False)
    rule_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    model_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    model_version: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    attack_category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False)
    explanation: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    mitre_attack: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    tags: Mapped[Optional[list]] = mapped_column(JSON, nullable=True, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
