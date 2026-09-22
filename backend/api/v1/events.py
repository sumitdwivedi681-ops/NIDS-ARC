"""
Events API Endpoints.

GET /api/v1/events — Search and list events with filtering
GET /api/v1/events/{event_id} — Get event details with detections
GET /api/v1/events/stats — Event statistics
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, desc, asc
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.middleware.auth import CurrentUser, get_current_user
from backend.middleware.error_handler import NotFoundError
from backend.models.event import SecurityEvent
from backend.models.detection import DetectionResult
from backend.schemas import Severity, SourceType

router = APIRouter(prefix="/events", tags=["Events"])


@router.get("")
async def list_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    sensor_id: Optional[str] = None,
    source_type: Optional[str] = None,
    sort_by: str = "timestamp",
    sort_order: str = "desc",
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Search and list security events with filtering and pagination."""
    query = select(SecurityEvent)

    # Apply filters
    if start_time:
        query = query.where(SecurityEvent.timestamp >= start_time)
    if end_time:
        query = query.where(SecurityEvent.timestamp <= end_time)
    if src_ip:
        query = query.where(SecurityEvent.src_ip == src_ip)
    if dst_ip:
        query = query.where(SecurityEvent.dst_ip == dst_ip)
    if severity:
        query = query.where(SecurityEvent.severity == severity)
    if event_type:
        query = query.where(SecurityEvent.event_type == event_type)
    if sensor_id:
        query = query.where(SecurityEvent.sensor_id == sensor_id)
    if source_type:
        query = query.where(SecurityEvent.source_type == source_type)

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Sort
    sort_column = getattr(SecurityEvent, sort_by, SecurityEvent.timestamp)
    if sort_order == "asc":
        query = query.order_by(asc(sort_column))
    else:
        query = query.order_by(desc(sort_column))

    # Paginate
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    result = await db.execute(query)
    events = result.scalars().all()

    return {
        "data": [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "source_type": e.source_type,
                "sensor_id": e.sensor_id,
                "src_ip": e.src_ip,
                "src_port": e.src_port,
                "dst_ip": e.dst_ip,
                "dst_port": e.dst_port,
                "protocol": e.protocol,
                "event_type": e.event_type,
                "severity": e.severity,
                "confidence": e.confidence,
                "risk_score": e.risk_score,
                "attack_category": e.attack_category,
                "tags": e.tags or [],
                "response_state": e.response_state,
            }
            for e in events
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
async def event_stats(
    hours: int = Query(24, ge=1, le=720),
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get event statistics for the specified time window."""
    from datetime import timedelta

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    # Total events
    total_q = select(func.count()).select_from(SecurityEvent).where(SecurityEvent.timestamp >= cutoff)
    total = (await db.execute(total_q)).scalar() or 0

    # By severity
    sev_q = (
        select(SecurityEvent.severity, func.count())
        .where(SecurityEvent.timestamp >= cutoff)
        .group_by(SecurityEvent.severity)
    )
    sev_result = await db.execute(sev_q)
    by_severity = {row[0]: row[1] for row in sev_result.all()}

    # By source type
    src_q = (
        select(SecurityEvent.source_type, func.count())
        .where(SecurityEvent.timestamp >= cutoff)
        .group_by(SecurityEvent.source_type)
    )
    src_result = await db.execute(src_q)
    by_source_type = {row[0]: row[1] for row in src_result.all()}

    return {
        "data": {
            "total_events": total,
            "time_window_hours": hours,
            "by_severity": by_severity,
            "by_source_type": by_source_type,
        },
        "meta": {
            "request_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    }


@router.get("/{event_id}")
async def get_event(
    event_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get event details including detection results."""
    result = await db.execute(select(SecurityEvent).where(SecurityEvent.id == event_id))
    event = result.scalar_one_or_none()
    if event is None:
        raise NotFoundError(f"Event {event_id} not found")

    # Get detection results
    det_result = await db.execute(
        select(DetectionResult).where(DetectionResult.event_id == event_id)
    )
    detections = det_result.scalars().all()

    return {
        "data": {
            "id": event.id,
            "timestamp": event.timestamp.isoformat(),
            "ingested_at": event.ingested_at.isoformat(),
            "source_type": event.source_type,
            "sensor_id": event.sensor_id,
            "src_ip": event.src_ip,
            "src_port": event.src_port,
            "dst_ip": event.dst_ip,
            "dst_port": event.dst_port,
            "protocol": event.protocol,
            "bytes_sent": event.bytes_sent,
            "bytes_received": event.bytes_received,
            "packets_sent": event.packets_sent,
            "packets_received": event.packets_received,
            "duration_ms": event.duration_ms,
            "event_type": event.event_type,
            "attack_category": event.attack_category,
            "severity": event.severity,
            "confidence": event.confidence,
            "risk_score": event.risk_score,
            "tags": event.tags or [],
            "mitre_attack": event.mitre_attack,
            "response_state": event.response_state,
            "raw_data": event.raw_data,
            "metadata": event.extra_metadata,
            "detections": [
                {
                    "id": d.id,
                    "detector": d.detector,
                    "detector_version": d.detector_version,
                    "severity": d.severity,
                    "confidence": d.confidence,
                    "attack_category": d.attack_category,
                    "evidence": d.evidence,
                    "explanation": d.explanation,
                    "rule_id": d.rule_id,
                    "model_id": d.model_id,
                    "mitre_attack": d.mitre_attack,
                    "created_at": d.created_at.isoformat(),
                }
                for d in detections
            ],
        },
        "meta": {
            "request_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    }
