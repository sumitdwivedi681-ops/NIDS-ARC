"""Sensor ORM model."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, DateTime, Integer, String, JSON
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base, TimestampMixin, UUIDMixin


class Sensor(UUIDMixin, TimestampMixin, Base):
    """Network sensor or data source."""

    __tablename__ = "sensors"

    name: Mapped[str] = mapped_column(String(100), nullable=False)
    sensor_type: Mapped[str] = mapped_column(String(30), nullable=False)  # simulation, suricata, zeek, pcap, ebpf
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="inactive")  # active, inactive, error, unavailable
    host: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    config: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    events_total: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
