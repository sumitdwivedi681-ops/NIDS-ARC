"""Response Action ORM model."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, String, JSON
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base, TimestampMixin, UUIDMixin


class ResponseAction(UUIDMixin, TimestampMixin, Base):
    """Policy-controlled response action."""

    __tablename__ = "response_actions"

    action_type: Mapped[str] = mapped_column(String(30), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending", index=True)
    requested_by: Mapped[str] = mapped_column(String(50), nullable=False)
    policy_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    alert_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    incident_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    target: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    parameters: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    result: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    approved_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    rollback_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    is_dry_run: Mapped[bool] = mapped_column(Boolean, default=False)
