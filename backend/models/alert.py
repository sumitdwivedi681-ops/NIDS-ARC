"""Alert ORM model."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base, TimestampMixin, UUIDMixin


class Alert(UUIDMixin, TimestampMixin, Base):
    """Security alert generated from detection results."""

    __tablename__ = "alerts"

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="new", index=True)
    source_type: Mapped[str] = mapped_column(String(20), nullable=False)
    event_ids: Mapped[Optional[list]] = mapped_column(JSON, nullable=True, default=list)
    detection_ids: Mapped[Optional[list]] = mapped_column(JSON, nullable=True, default=list)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    risk_factors: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    src_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    dst_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    assigned_to: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    resolved_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
