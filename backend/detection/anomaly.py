"""
Anomaly Detection Engine.

Statistical baseline tracking and deviation analysis.
Produces explainable results with baseline, current value, deviation, and score.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog

from backend.detection import Detector, DetectionContext, DetectionResultData

logger = structlog.get_logger("anomaly_detector")


@dataclass
class BaselineStat:
    """Running statistics for a feature baseline."""
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0  # For Welford's online variance

    @property
    def variance(self) -> float:
        if self.count < 2:
            return 0.0
        return self.m2 / (self.count - 1)

    @property
    def std_dev(self) -> float:
        return math.sqrt(self.variance)

    def update(self, value: float) -> None:
        """Update running statistics using Welford's algorithm."""
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2

    def z_score(self, value: float) -> float:
        """Calculate z-score for a given value."""
        if self.std_dev == 0 or self.count < 10:
            return 0.0
        return (value - self.mean) / self.std_dev


class AnomalyDetector(Detector):
    """
    Statistical anomaly detector using baseline deviation analysis.

    Tracks per-entity baselines for multiple features and flags
    events that deviate significantly from learned baselines.

    Returns explainable results: baseline, current, deviation, score.
    """

    FEATURES = [
        "bytes_sent", "bytes_received", "packets_sent",
        "packets_received", "duration_ms",
    ]

    SENSITIVITY_THRESHOLDS = {
        "low": 4.0,
        "medium": 3.0,
        "high": 2.0,
    }

    def __init__(self, sensitivity: str = "medium", min_samples: int = 100):
        self._baselines: Dict[str, Dict[str, BaselineStat]] = defaultdict(
            lambda: {f: BaselineStat() for f in self.FEATURES}
        )
        self._sensitivity = sensitivity
        self._min_samples = min_samples
        self._z_threshold = self.SENSITIVITY_THRESHOLDS.get(sensitivity, 3.0)
        self._connection_counts: Dict[str, int] = defaultdict(int)
        self._destination_diversity: Dict[str, set] = defaultdict(set)
        self._port_diversity: Dict[str, set] = defaultdict(set)

    @property
    def name(self) -> str:
        return "anomaly"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def detect(self, context: DetectionContext) -> List[DetectionResultData]:
        """Analyze event for statistical anomalies."""
        entity_key = context.src_ip
        results: List[DetectionResultData] = []
        anomalies: List[Dict[str, Any]] = []

        # Track entity behavior
        self._connection_counts[entity_key] += 1
        self._destination_diversity[entity_key].add(context.dst_ip)
        if context.dst_port:
            self._port_diversity[entity_key].add(context.dst_port)

        # Check each feature against baseline
        baselines = self._baselines[entity_key]
        for feature_name in self.FEATURES:
            value = getattr(context, feature_name, 0)
            stat = baselines[feature_name]

            # Only flag if we have enough samples for a meaningful baseline
            if stat.count >= self._min_samples:
                z = stat.z_score(value)
                if abs(z) > self._z_threshold:
                    anomalies.append({
                        "feature": feature_name,
                        "baseline_mean": round(stat.mean, 2),
                        "baseline_std_dev": round(stat.std_dev, 2),
                        "current_value": value,
                        "z_score": round(z, 2),
                        "deviation": f"{abs(z):.1f} standard deviations from baseline",
                    })

            # Update baseline with this value
            stat.update(float(value))

        # Check destination diversity anomaly
        dst_count = len(self._destination_diversity[entity_key])
        if dst_count > 50 and self._connection_counts[entity_key] > self._min_samples:
            anomalies.append({
                "feature": "destination_diversity",
                "baseline_mean": 10,  # Expected normal range
                "current_value": dst_count,
                "z_score": dst_count / 10.0,
                "deviation": f"Contacted {dst_count} unique destinations",
            })

        # Check port diversity anomaly
        port_count = len(self._port_diversity[entity_key])
        if port_count > 20 and self._connection_counts[entity_key] > self._min_samples:
            anomalies.append({
                "feature": "port_diversity",
                "baseline_mean": 5,
                "current_value": port_count,
                "z_score": port_count / 5.0,
                "deviation": f"Scanned {port_count} unique ports",
            })

        if anomalies:
            # Calculate aggregate anomaly score (0.0 to 1.0)
            max_z = max(abs(a.get("z_score", 0)) for a in anomalies)
            anomaly_score = min(1.0, max_z / (self._z_threshold * 2))

            # Determine severity from score
            if anomaly_score >= 0.8:
                severity = "high"
            elif anomaly_score >= 0.5:
                severity = "medium"
            else:
                severity = "low"

            explanation_parts = [a["deviation"] for a in anomalies[:3]]
            explanation = f"Anomalous behavior from {entity_key}: " + "; ".join(explanation_parts)

            results.append(DetectionResultData(
                event_id=context.event_id,
                detector=self.name,
                detector_version=self.version,
                severity=severity,
                confidence=round(anomaly_score, 3),
                attack_category="anomalous_behavior",
                evidence={
                    "anomalies": anomalies,
                    "entity": entity_key,
                    "connection_count": self._connection_counts[entity_key],
                    "sensitivity": self._sensitivity,
                    "threshold": self._z_threshold,
                },
                explanation=explanation,
                tags=["anomaly", "statistical"],
            ))

        return results

    def get_baselines(self, entity: Optional[str] = None) -> Dict[str, Any]:
        """Get current baseline statistics."""
        if entity:
            if entity not in self._baselines:
                return {}
            return {
                feature: {
                    "count": stat.count,
                    "mean": round(stat.mean, 2),
                    "std_dev": round(stat.std_dev, 2),
                }
                for feature, stat in self._baselines[entity].items()
            }
        return {
            "entities_tracked": len(self._baselines),
            "min_samples": self._min_samples,
            "sensitivity": self._sensitivity,
        }

    def reset_baselines(self) -> None:
        """Reset all baselines."""
        self._baselines.clear()
        self._connection_counts.clear()
        self._destination_diversity.clear()
        self._port_diversity.clear()
        logger.info("baselines_reset")
