"""Event Pydantic schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from backend.schemas import Severity, SourceType


class SecurityEventCreate(BaseModel):
    """Schema for creating a security event."""
    timestamp: datetime
    source_type: SourceType
    sensor_id: str
    src_ip: str
    src_port: Optional[int] = None
    dst_ip: str
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    duration_ms: int = 0
    event_type: str
    attack_category: Optional[str] = None
    severity: Severity = Severity.INFO
    raw_data: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    tags: List[str] = Field(default_factory=list)


class SecurityEventResponse(BaseModel):
    """Schema for security event API response."""
    id: str
    timestamp: datetime
    ingested_at: datetime
    source_type: str
    sensor_id: str
    src_ip: str
    src_port: Optional[int] = None
    dst_ip: str
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    duration_ms: int = 0
    event_type: str
    attack_category: Optional[str] = None
    severity: str
    confidence: Optional[float] = None
    risk_score: Optional[float] = None
    tags: List[str] = Field(default_factory=list)
    mitre_attack: Optional[Dict[str, Any]] = None
    response_state: Optional[str] = None

    model_config = {"from_attributes": True}


class DetectionResultResponse(BaseModel):
    """Schema for detection result in API response."""
    id: str
    event_id: str
    detector: str
    detector_version: str
    rule_id: Optional[str] = None
    model_id: Optional[str] = None
    model_version: Optional[str] = None
    severity: str
    confidence: float
    attack_category: Optional[str] = None
    evidence: Dict[str, Any]
    explanation: Optional[str] = None
    mitre_attack: Optional[Dict[str, Any]] = None
    tags: List[str] = Field(default_factory=list)
    created_at: datetime

    model_config = {"from_attributes": True}


class EventSearchParams(BaseModel):
    """Query parameters for event search."""
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=500)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    severity: Optional[Severity] = None
    event_type: Optional[str] = None
    sensor_id: Optional[str] = None
    source_type: Optional[SourceType] = None
    sort_by: str = "timestamp"
    sort_order: str = "desc"
