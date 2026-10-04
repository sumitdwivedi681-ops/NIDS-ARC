"""
NIDS ARC Audit Logs API Endpoints.

Provides query endpoints for the immutable security audit log trail.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.models.audit_log import AuditLog

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("")
async def list_audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    action: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Retrieve paginated immutable audit logs."""
    query = select(AuditLog)
    if action:
        query = query.where(AuditLog.action == action)

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    query = query.order_by(desc(AuditLog.timestamp))
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    logs = result.scalars().all()

    items = [
        {
            "id": log.id,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "actor_username": log.actor_username or "system",
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
            "details": log.details,
            "source_ip": log.source_ip,
            "result": log.result,
        }
        for log in logs
    ]

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size if total > 0 else 1,
    }
