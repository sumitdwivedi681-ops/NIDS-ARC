"""Audit Log ORM model — append-only."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, String, JSON
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base, UUIDMixin


class AuditLog(UUIDMixin, Base):
    """Immutable audit trail entry. No update or delete operations."""

    __tablename__ = "audit_logs"

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    actor_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    actor_username: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    result: Mapped[str] = mapped_column(String(20), nullable=False, default="success")
