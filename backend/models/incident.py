"""Incident ORM model."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base, TimestampMixin, UUIDMixin


class Incident(UUIDMixin, TimestampMixin, Base):
    """Correlated security incident grouping related alerts."""

    __tablename__ = "incidents"

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active", index=True)
    attack_stage: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    mitre_tactics: Mapped[Optional[list]] = mapped_column(JSON, nullable=True, default=list)
    alert_ids: Mapped[Optional[list]] = mapped_column(JSON, nullable=True, default=list)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    src_entities: Mapped[Optional[list]] = mapped_column(JSON, nullable=True, default=list)
    dst_entities: Mapped[Optional[list]] = mapped_column(JSON, nullable=True, default=list)
    assigned_to: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
