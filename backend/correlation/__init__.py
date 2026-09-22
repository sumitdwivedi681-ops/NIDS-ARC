"""
Correlation Engine.

Groups related detection results into incidents with
attack chain abstraction and MITRE ATT&CK mapping.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

import structlog

from backend.detection import DetectionResultData

logger = structlog.get_logger("correlation")


@dataclass
class CorrelationGroup:
    """A group of correlated detections forming a potential incident."""
    group_id: str = field(default_factory=lambda: str(uuid4()))
    detections: List[DetectionResultData] = field(default_factory=list)
    src_entities: set = field(default_factory=set)
    dst_entities: set = field(default_factory=set)
    attack_stages: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    severity: str = "low"

    def add_detection(self, detection: DetectionResultData, src_ip: str = "", dst_ip: str = "") -> None:
        self.detections.append(detection)
        if src_ip:
            self.src_entities.add(src_ip)
        if dst_ip:
            self.dst_entities.add(dst_ip)
        if detection.attack_category and detection.attack_category not in self.attack_stages:
            self.attack_stages.append(detection.attack_category)

        now = detection.timestamp
        if self.first_seen is None or now < self.first_seen:
            self.first_seen = now
        if self.last_seen is None or now > self.last_seen:
            self.last_seen = now

        # Update severity to highest
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        if sev_order.get(detection.severity, 0) > sev_order.get(self.severity, 0):
            self.severity = detection.severity


class CorrelationEngine:
    """
    Correlates detection results into incidents.

    Correlates by:
    - Same source IP
    - Time window
    - Attack pattern similarity
    - Detector agreement
    """

    def __init__(self, window_minutes: int = 30, min_detections: int = 2):
        self._groups: Dict[str, CorrelationGroup] = {}
        self._entity_groups: Dict[str, str] = {}  # entity → group_id
        self._window = timedelta(minutes=window_minutes)
        self._min_detections = min_detections
        self._total_correlated = 0

    def correlate(
        self,
        detections: List[DetectionResultData],
        src_ip: str = "",
        dst_ip: str = "",
    ) -> Optional[CorrelationGroup]:
        """
        Attempt to correlate new detections with existing groups.

        Returns a CorrelationGroup if the detections form or extend
        an incident-level correlation.
        """
        if not detections:
            return None

        # Find existing group for this source entity
        group_id = self._entity_groups.get(src_ip)
        group = self._groups.get(group_id) if group_id else None

        # Check if existing group is stale
        now = datetime.now(timezone.utc)
        if group and group.last_seen and (now - group.last_seen) > self._window:
            group = None  # Start new group

        if group is None:
            group = CorrelationGroup()
            self._groups[group.group_id] = group
            if src_ip:
                self._entity_groups[src_ip] = group.group_id

        for detection in detections:
            group.add_detection(detection, src_ip, dst_ip)

        # Only return groups that meet minimum detection threshold
        if len(group.detections) >= self._min_detections:
            self._total_correlated += 1
            return group

        return None

    def get_incidents(self, min_severity: str = "low") -> List[Dict[str, Any]]:
        """Get all correlation groups that qualify as incidents."""
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        min_sev = sev_order.get(min_severity, 0)

        incidents = []
        for group in self._groups.values():
            if (
                len(group.detections) >= self._min_detections
                and sev_order.get(group.severity, 0) >= min_sev
            ):
                # Count unique detectors
                detectors = set(d.detector for d in group.detections)
                incidents.append({
                    "group_id": group.group_id,
                    "detection_count": len(group.detections),
                    "detector_count": len(detectors),
                    "detectors": list(detectors),
                    "severity": group.severity,
                    "attack_stages": group.attack_stages,
                    "src_entities": list(group.src_entities),
                    "dst_entities": list(group.dst_entities),
                    "first_seen": group.first_seen.isoformat() if group.first_seen else None,
                    "last_seen": group.last_seen.isoformat() if group.last_seen else None,
                })

        return sorted(
            incidents,
            key=lambda x: sev_order.get(x["severity"], 0),
            reverse=True,
        )

    def cleanup_stale(self, max_age_minutes: int = 120) -> int:
        """Remove stale correlation groups."""
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=max_age_minutes)
        stale = [
            gid for gid, g in self._groups.items()
            if g.last_seen and g.last_seen < cutoff
        ]
        for gid in stale:
            del self._groups[gid]
        # Clean entity mappings
        self._entity_groups = {
            e: gid for e, gid in self._entity_groups.items()
            if gid in self._groups
        }
        return len(stale)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "active_groups": len(self._groups),
            "total_correlated": self._total_correlated,
            "entities_tracked": len(self._entity_groups),
        }
