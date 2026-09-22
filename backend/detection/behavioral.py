"""
Behavioral Detection Engine.

Sequence analysis and multi-stage attack pattern detection.
Groups related events by entity and time window.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import structlog

from backend.detection import Detector, DetectionContext, DetectionResultData

logger = structlog.get_logger("behavioral_detector")


@dataclass
class EntityBehavior:
    """Tracks behavioral events for a single entity."""
    events: List[Dict[str, Any]] = field(default_factory=list)
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def add_event(self, event_type: str, context: DetectionContext) -> None:
        self.events.append({
            "event_type": event_type,
            "timestamp": context.timestamp.isoformat() if isinstance(context.timestamp, datetime) else str(context.timestamp),
            "dst_ip": context.dst_ip,
            "dst_port": context.dst_port,
            "protocol": context.protocol,
        })
        self.last_updated = datetime.now(timezone.utc)
        # Keep only last 1000 events per entity
        if len(self.events) > 1000:
            self.events = self.events[-500:]

    def get_event_types(self) -> List[str]:
        return [e["event_type"] for e in self.events]


# Attack stage definitions with event type patterns
ATTACK_PATTERNS = {
    "reconnaissance": {
        "description": "Network reconnaissance and scanning",
        "indicators": ["port_scan", "host_sweep", "service_probe", "dns_query_burst"],
        "mitre_tactic": "TA0043",
        "mitre_technique": "T1595",
    },
    "initial_access": {
        "description": "Attempting initial system access",
        "indicators": ["ssh_attempt", "rdp_attempt", "exploit_attempt", "brute_force"],
        "mitre_tactic": "TA0001",
        "mitre_technique": "T1190",
    },
    "persistence": {
        "description": "Establishing persistent presence",
        "indicators": ["backdoor_install", "scheduled_task", "new_service", "registry_mod"],
        "mitre_tactic": "TA0003",
        "mitre_technique": "T1543",
    },
    "lateral_movement": {
        "description": "Moving through the network",
        "indicators": ["internal_scan", "smb_connection", "wmi_execution", "psexec"],
        "mitre_tactic": "TA0008",
        "mitre_technique": "T1021",
    },
    "exfiltration": {
        "description": "Data exfiltration attempt",
        "indicators": ["large_upload", "dns_tunneling", "encrypted_channel", "unusual_outbound"],
        "mitre_tactic": "TA0010",
        "mitre_technique": "T1048",
    },
}


class BehavioralDetector(Detector):
    """
    Behavioral detection engine using sequence analysis.

    Tracks entity behavior over time, detects multi-stage attack
    patterns, and groups related events into attack chains.
    """

    def __init__(self, window_minutes: int = 60):
        self._entity_behaviors: Dict[str, EntityBehavior] = defaultdict(EntityBehavior)
        self._window = timedelta(minutes=window_minutes)

    @property
    def name(self) -> str:
        return "behavioral"

    @property
    def version(self) -> str:
        return "1.0.0"

    def _classify_event(self, context: DetectionContext) -> List[str]:
        """Classify an event into behavioral indicators."""
        indicators = []

        # Port scan: many different ports from same source
        if context.dst_port and context.duration_ms < 100:
            indicators.append("port_scan")

        # Brute force: repeated connections to auth ports
        if context.dst_port in (22, 23, 3389, 445):
            indicators.append("ssh_attempt" if context.dst_port == 22 else "rdp_attempt")
            indicators.append("brute_force")

        # DNS behavior
        if context.dst_port == 53:
            if context.bytes_sent > 200:
                indicators.append("dns_tunneling")
            indicators.append("dns_query_burst")

        # Large outbound transfer
        if context.bytes_sent > 5000000:
            indicators.append("large_upload")
            indicators.append("unusual_outbound")

        # SMB/lateral movement indicators
        if context.dst_port in (445, 135, 139):
            indicators.append("smb_connection")
            indicators.append("internal_scan")

        # Generic connection
        if not indicators:
            indicators.append("connection")

        return indicators

    def _detect_attack_stages(self, entity: str, behavior: EntityBehavior) -> List[Dict[str, Any]]:
        """Detect multi-stage attack patterns from entity behavior."""
        detected_stages: List[Dict[str, Any]] = []
        event_types = set()

        for event in behavior.events:
            event_types.add(event["event_type"])

        for stage_name, stage_info in ATTACK_PATTERNS.items():
            matched_indicators = event_types.intersection(stage_info["indicators"])
            if matched_indicators:
                confidence = len(matched_indicators) / len(stage_info["indicators"])
                detected_stages.append({
                    "stage": stage_name,
                    "description": stage_info["description"],
                    "matched_indicators": list(matched_indicators),
                    "confidence": round(min(confidence, 1.0), 3),
                    "mitre_tactic": stage_info["mitre_tactic"],
                    "mitre_technique": stage_info["mitre_technique"],
                })

        return detected_stages

    async def detect(self, context: DetectionContext) -> List[DetectionResultData]:
        """Analyze event for behavioral patterns and multi-stage attacks."""
        entity_key = context.src_ip
        behavior = self._entity_behaviors[entity_key]
        results: List[DetectionResultData] = []

        # Classify this event
        indicators = self._classify_event(context)
        for indicator in indicators:
            behavior.add_event(indicator, context)

        # Detect attack stages
        stages = self._detect_attack_stages(entity_key, behavior)

        # Only alert if we see multi-stage patterns (2+ stages)
        if len(stages) >= 2:
            # Calculate overall confidence from stage confidences
            overall_confidence = sum(s["confidence"] for s in stages) / len(stages)

            # Severity based on number of attack stages detected
            if len(stages) >= 4:
                severity = "critical"
            elif len(stages) >= 3:
                severity = "high"
            else:
                severity = "medium"

            stage_names = [s["stage"] for s in stages]
            explanation = (
                f"Multi-stage attack pattern detected from {entity_key}: "
                f"{' → '.join(stage_names)}. "
                f"{len(stages)} attack stages identified."
            )

            results.append(DetectionResultData(
                event_id=context.event_id,
                detector=self.name,
                detector_version=self.version,
                severity=severity,
                confidence=round(overall_confidence, 3),
                attack_category="multi_stage_attack",
                evidence={
                    "entity": entity_key,
                    "attack_stages": stages,
                    "total_events": len(behavior.events),
                    "stage_count": len(stages),
                    "event_summary": dict(
                        (t, sum(1 for e in behavior.events if e["event_type"] == t))
                        for t in set(e["event_type"] for e in behavior.events)
                    ),
                },
                explanation=explanation,
                mitre_attack={
                    "tactics": [s["mitre_tactic"] for s in stages],
                    "techniques": [s["mitre_technique"] for s in stages],
                },
                tags=["behavioral", "multi_stage"] + stage_names,
            ))

        return results

    def cleanup_stale(self, max_age_minutes: int = 120) -> int:
        """Remove stale entity behaviors. Returns count removed."""
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=max_age_minutes)
        stale = [k for k, v in self._entity_behaviors.items() if v.last_updated < cutoff]
        for key in stale:
            del self._entity_behaviors[key]
        return len(stale)
