"""Threat Intelligence Record ORM model."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, String, JSON
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base, TimestampMixin, UUIDMixin


class ThreatIntelRecord(UUIDMixin, TimestampMixin, Base):
    """Indicator of Compromise (IOC) record."""

    __tablename__ = "threat_intel"

    indicator_type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    severity: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    tags: Mapped[Optional[list]] = mapped_column(JSON, nullable=True, default=list)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expiry: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    extra_metadata: Mapped[Optional[dict]] = mapped_column("metadata", JSON, nullable=True)
