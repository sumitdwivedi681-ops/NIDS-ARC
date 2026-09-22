"""
Alerts API Endpoints.

GET    /api/v1/alerts — List alerts with filtering
GET    /api/v1/alerts/{id} — Get alert details
PUT    /api/v1/alerts/{id} — Update alert (status, notes, assignment)
GET    /api/v1/alerts/stats — Alert statistics
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.middleware.auth import CurrentUser, get_current_user
from backend.middleware.error_handler import NotFoundError
from backend.models.alert import Alert
from backend.models.audit_log import AuditLog

router = APIRouter(prefix="/alerts", tags=["Alerts"])


class AlertUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None


@router.get("")
async def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source_type: Optional[str] = None,
    sort_order: str = "desc",
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List alerts with filtering and pagination."""
    query = select(Alert)
    if severity:
        query = query.where(Alert.severity == severity)
    if status:
        query = query.where(Alert.status == status)
    if source_type:
        query = query.where(Alert.source_type == source_type)

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    query = query.order_by(desc(Alert.created_at) if sort_order == "desc" else Alert.created_at)
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    alerts = result.scalars().all()

    return {
        "data": [
            {
                "id": a.id,
                "title": a.title,
                "severity": a.severity,
                "status": a.status,
                "source_type": a.source_type,
                "risk_score": a.risk_score,
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "assigned_to": a.assigned_to,
                "created_at": a.created_at.isoformat(),
                "event_count": len(a.event_ids) if a.event_ids else 0,
            }
            for a in alerts
        ],
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": (total + page_size - 1) // page_size,
        },
        "meta": {
            "request_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    }


@router.get("/stats")
async def alert_stats(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get alert statistics."""
    total_q = select(func.count()).select_from(Alert)
    total = (await db.execute(total_q)).scalar() or 0

    by_sev = await db.execute(
        select(Alert.severity, func.count()).group_by(Alert.severity)
    )
    by_status = await db.execute(
        select(Alert.status, func.count()).group_by(Alert.status)
    )

    return {
        "data": {
            "total": total,
            "by_severity": {r[0]: r[1] for r in by_sev.all()},
            "by_status": {r[0]: r[1] for r in by_status.all()},
        },
        "meta": {
            "request_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    }


@router.get("/{alert_id}")
async def get_alert(
    alert_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get alert details."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if alert is None:
        raise NotFoundError(f"Alert {alert_id} not found")

    return {
        "data": {
            "id": alert.id,
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity,
            "status": alert.status,
            "source_type": alert.source_type,
            "event_ids": alert.event_ids or [],
            "detection_ids": alert.detection_ids or [],
            "risk_score": alert.risk_score,
            "risk_factors": alert.risk_factors,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "assigned_to": alert.assigned_to,
            "resolved_by": alert.resolved_by,
            "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
            "notes": alert.notes,
            "created_at": alert.created_at.isoformat(),
            "updated_at": alert.updated_at.isoformat(),
        },
        "meta": {
            "request_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    }


@router.put("/{alert_id}")
async def update_alert(
    alert_id: str,
    update: AlertUpdate,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update alert status, assignment, or notes. Requires analyst or admin role."""
    if not current_user.has_role("admin", "analyst"):
        from backend.middleware.error_handler import AuthorizationError
        raise AuthorizationError("Analysts and admins can update alerts")

    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if alert is None:
        raise NotFoundError(f"Alert {alert_id} not found")

    old_status = alert.status

    if update.status:
        alert.status = update.status
        if update.status in ("resolved", "false_positive"):
            alert.resolved_by = current_user.user_id
            alert.resolved_at = datetime.now(timezone.utc)
    if update.assigned_to is not None:
        alert.assigned_to = update.assigned_to
    if update.notes is not None:
        alert.notes = update.notes

    alert.updated_at = datetime.now(timezone.utc)

    # Audit
    audit = AuditLog(
        actor_id=current_user.user_id,
        actor_username=current_user.username,
        action="alert_updated",
        resource_type="alert",
        resource_id=alert_id,
        details={"old_status": old_status, "new_status": alert.status, "updates": update.model_dump(exclude_none=True)},
        result="success",
    )
    db.add(audit)

    return {"data": {"id": alert.id, "status": alert.status}, "message": "Alert updated"}
