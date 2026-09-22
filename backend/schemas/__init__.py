"""Common Pydantic schemas used across the API."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Generic, List, Optional, TypeVar

from pydantic import BaseModel, Field


# --- Enumerations ---

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SourceType(str, Enum):
    REAL = "real"
    SIMULATION = "simulation"
    REPLAY = "replay"


class AlertStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class IncidentStatus(str, Enum):
    ACTIVE = "active"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class SensorStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    UNAVAILABLE = "unavailable"


class ResponseActionType(str, Enum):
    ALERT_ONLY = "alert_only"
    NOTIFY = "notify"
    INCREASE_MONITORING = "increase_monitoring"
    TEMPORARY_BLOCK = "temporary_block"
    FIREWALL_RULE = "firewall_rule"
    HOST_QUARANTINE = "host_quarantine"
    SESSION_TERMINATE = "session_terminate"


class ResponseStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    EXECUTED = "executed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class ModelStatus(str, Enum):
    TRAINING = "training"
    VALIDATING = "validating"
    STAGING = "staging"
    ACTIVE = "active"
    RETIRED = "retired"


class ComponentHealth(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DOWN = "down"
    UNKNOWN = "unknown"


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    SYSTEM = "system"


# --- Base Schemas ---

class Pagination(BaseModel):
    """Pagination metadata."""
    page: int = 1
    page_size: int = 50
    total: int = 0
    total_pages: int = 0


class Meta(BaseModel):
    """Response metadata."""
    request_id: str
    timestamp: datetime
    mode: Optional[str] = None


class ErrorDetail(BaseModel):
    """Single error detail."""
    field: Optional[str] = None
    message: str


class ErrorResponse(BaseModel):
    """Structured error response."""
    code: str
    message: str
    details: List[ErrorDetail] = []


T = TypeVar("T")


class ListResponse(BaseModel, Generic[T]):
    """Paginated list response."""
    data: List[T]
    pagination: Pagination
    meta: Meta


class ItemResponse(BaseModel, Generic[T]):
    """Single item response."""
    data: T
    meta: Meta
