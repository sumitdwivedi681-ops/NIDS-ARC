"""
Risk Engine.

Multi-factor contextual risk scoring with explainable output.
Risk score is calculated from multiple independent factors, not just severity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import structlog

from backend.detection import DetectionResultData

logger = structlog.get_logger("risk_engine")


@dataclass
class RiskFactor:
    """A single risk factor contributing to the overall score."""
    factor: str
    value: float
    weight: float
    contribution: float
    description: str


@dataclass
class RiskAssessment:
    """Explainable risk assessment."""
    risk_score: float  # 0.0 to 100.0
    risk_level: str    # critical, high, medium, low
    risk_factors: List[RiskFactor]
    risk_explanation: str
    detection_count: int
    detector_agreement: int  # How many unique detectors flagged


class RiskEngine:
    """
    Multi-factor contextual risk calculator.

    Factors:
    - Detection confidence (weighted average across detectors)
    - Detector agreement (more independent detectors = higher risk)
    - Severity of detections
    - Attack stage progression
    - Behavioral indicators
    - Threat intelligence match (future)
    """

    DEFAULT_WEIGHTS = {
        "detection_confidence": 0.25,
        "detector_agreement": 0.20,
        "severity": 0.20,
        "attack_stage": 0.15,
        "event_frequency": 0.10,
        "behavioral_score": 0.10,
    }

    SEVERITY_SCORES = {
        "critical": 1.0,
        "high": 0.8,
        "medium": 0.5,
        "low": 0.2,
        "info": 0.05,
    }

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self._weights = weights or self.DEFAULT_WEIGHTS

    def assess(
        self,
        detections: List[DetectionResultData],
        event_count: int = 1,
        entity_history: Optional[Dict[str, Any]] = None,
    ) -> RiskAssessment:
        """
        Calculate contextual risk from detection results and context.

        Returns an explainable RiskAssessment with factor breakdown.
        """
        factors: List[RiskFactor] = []

        if not detections:
            return RiskAssessment(
                risk_score=0.0,
                risk_level="low",
                risk_factors=[],
                risk_explanation="No detections — no risk factors identified",
                detection_count=0,
                detector_agreement=0,
            )

        # Factor 1: Detection Confidence (weighted average)
        avg_confidence = sum(d.confidence for d in detections) / len(detections)
        weight = self._weights["detection_confidence"]
        contribution = avg_confidence * weight * 100
        factors.append(RiskFactor(
            factor="detection_confidence",
            value=round(avg_confidence, 3),
            weight=weight,
            contribution=round(contribution, 2),
            description=f"Average detection confidence: {avg_confidence:.1%}",
        ))

        # Factor 2: Detector Agreement
        unique_detectors = set(d.detector for d in detections)
        agreement_score = min(len(unique_detectors) / 4.0, 1.0)  # 4 detectors = max
        weight = self._weights["detector_agreement"]
        contribution = agreement_score * weight * 100
        factors.append(RiskFactor(
            factor="detector_agreement",
            value=round(agreement_score, 3),
            weight=weight,
            contribution=round(contribution, 2),
            description=f"{len(unique_detectors)} independent detectors flagged this event",
        ))

        # Factor 3: Severity
        max_severity = max(
            self.SEVERITY_SCORES.get(d.severity, 0) for d in detections
        )
        weight = self._weights["severity"]
        contribution = max_severity * weight * 100
        factors.append(RiskFactor(
            factor="severity",
            value=round(max_severity, 3),
            weight=weight,
            contribution=round(contribution, 2),
            description=f"Highest severity: {max(detections, key=lambda d: self.SEVERITY_SCORES.get(d.severity, 0)).severity}",
        ))

        # Factor 4: Attack Stage
        attack_categories = set(d.attack_category for d in detections if d.attack_category)
        stage_score = min(len(attack_categories) / 5.0, 1.0)
        weight = self._weights["attack_stage"]
        contribution = stage_score * weight * 100
        factors.append(RiskFactor(
            factor="attack_stage",
            value=round(stage_score, 3),
            weight=weight,
            contribution=round(contribution, 2),
            description=f"{len(attack_categories)} attack categories: {', '.join(attack_categories) if attack_categories else 'none'}",
        ))

        # Factor 5: Event Frequency
        freq_score = min(event_count / 100.0, 1.0)
        weight = self._weights["event_frequency"]
        contribution = freq_score * weight * 100
        factors.append(RiskFactor(
            factor="event_frequency",
            value=round(freq_score, 3),
            weight=weight,
            contribution=round(contribution, 2),
            description=f"{event_count} related events observed",
        ))

        # Factor 6: Behavioral Score
        behavioral_detections = [d for d in detections if d.detector == "behavioral"]
        behavioral_score = (
            max(d.confidence for d in behavioral_detections) if behavioral_detections else 0.0
        )
        weight = self._weights["behavioral_score"]
        contribution = behavioral_score * weight * 100
        factors.append(RiskFactor(
            factor="behavioral_score",
            value=round(behavioral_score, 3),
            weight=weight,
            contribution=round(contribution, 2),
            description=f"Behavioral analysis score: {behavioral_score:.1%}",
        ))

        # Calculate total risk score
        total_risk = sum(f.contribution for f in factors)
        total_risk = min(max(total_risk, 0.0), 100.0)

        # Determine risk level
        if total_risk >= 75:
            risk_level = "critical"
        elif total_risk >= 50:
            risk_level = "high"
        elif total_risk >= 25:
            risk_level = "medium"
        else:
            risk_level = "low"

        # Build explanation
        top_factors = sorted(factors, key=lambda f: f.contribution, reverse=True)[:3]
        explanation_parts = [f.description for f in top_factors]
        explanation = (
            f"Risk score {total_risk:.1f}/100 ({risk_level}). "
            f"Key factors: {'; '.join(explanation_parts)}"
        )

        return RiskAssessment(
            risk_score=round(total_risk, 2),
            risk_level=risk_level,
            risk_factors=factors,
            risk_explanation=explanation,
            detection_count=len(detections),
            detector_agreement=len(unique_detectors),
        )
