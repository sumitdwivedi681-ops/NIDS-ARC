"""
Detection Engine Interface and Orchestrator.

Defines the abstract Detector interface that all detection engines implement.
The DetectionOrchestrator routes events to appropriate detectors and collects results.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4


@dataclass
class DetectionContext:
    """Context passed to a detector with the event data."""
    event_id: str
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    event_type: str
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    duration_ms: int = 0
    source_type: str = "simulation"
    sensor_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)


@dataclass
class DetectionResultData:
    """
    Normalized detection result returned by every detector.

    Every result carries full provenance per RULES.md DR-02.
    """
    detection_id: str = field(default_factory=lambda: str(uuid4()))
    event_id: str = ""
    detector: str = ""              # e.g. "signature", "anomaly", "behavioral", "ml"
    detector_version: str = "1.0.0"
    rule_id: Optional[str] = None
    model_id: Optional[str] = None
    model_version: Optional[str] = None
    severity: str = "info"          # critical, high, medium, low, info
    confidence: float = 0.0         # 0.0–1.0
    attack_category: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    explanation: Optional[str] = None
    mitre_attack: Optional[Dict[str, Any]] = None
    tags: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class Detector(abc.ABC):
    """
    Abstract base class for all detection engines.

    Every detector implements this interface, ensuring:
    - Consistent result format (DetectionResultData)
    - Full provenance (detector name, version, confidence, evidence)
    - Clean pluggability (add new detectors without modifying core)
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Unique detector name."""
        ...

    @property
    @abc.abstractmethod
    def version(self) -> str:
        """Detector version string."""
        ...

    @property
    def enabled(self) -> bool:
        """Whether this detector is currently enabled."""
        return True

    @abc.abstractmethod
    async def detect(self, context: DetectionContext) -> List[DetectionResultData]:
        """
        Run detection on an event.

        Args:
            context: Normalized event context to analyze.

        Returns:
            List of detection results (empty list if no detections).
        """
        ...

    async def initialize(self) -> None:
        """Initialize detector resources (called on startup)."""
        pass

    async def shutdown(self) -> None:
        """Clean up detector resources (called on shutdown)."""
        pass

    def get_status(self) -> Dict[str, Any]:
        """Return detector health/status information."""
        return {
            "name": self.name,
            "version": self.version,
            "enabled": self.enabled,
            "status": "active" if self.enabled else "disabled",
        }
