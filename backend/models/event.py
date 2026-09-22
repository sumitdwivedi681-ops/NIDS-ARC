"""Security Event ORM model."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, DateTime, Integer, String, JSON, Float, Index
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base, UUIDMixin


class SecurityEvent(UUIDMixin, Base):
    """Canonical normalized security event."""

    __tablename__ = "security_events"

    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_type: Mapped[str] = mapped_column(String(20), nullable=False)  # real, simulation, replay
    sensor_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Network 5-tuple
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    src_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    # Flow metrics
    bytes_sent: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_received: Mapped[int] = mapped_column(BigInteger, default=0)
    packets_sent: Mapped[int] = mapped_column(Integer, default=0)
    packets_received: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)

    # Classification
    event_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    attack_category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info")

    # Scores
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Metadata
    raw_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    extra_metadata: Mapped[Optional[dict]] = mapped_column("metadata", JSON, nullable=True)
    tags: Mapped[Optional[list]] = mapped_column(JSON, nullable=True, default=list)
    mitre_attack: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    response_state: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    __table_args__ = (
        Index("ix_events_time_severity", "timestamp", "severity"),
        Index("ix_events_src_dst", "src_ip", "dst_ip"),
    )
