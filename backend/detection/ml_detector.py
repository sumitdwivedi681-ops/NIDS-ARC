"""
ML Detection Engine.

Machine learning-based network threat detection with pluggable model interface,
versioning, and explainability.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import numpy as np
import structlog

from backend.detection import Detector, DetectionContext, DetectionResultData

logger = structlog.get_logger("ml_detector")

# Feature names for the ML model
FEATURE_NAMES = [
    "bytes_sent", "bytes_received", "packets_sent", "packets_received",
    "duration_ms", "src_port", "dst_port", "protocol_tcp", "protocol_udp",
    "protocol_icmp", "bytes_ratio", "packet_ratio",
]


class MLDetector(Detector):
    """
    Machine learning-based detector.

    Uses a pluggable model interface. Ships with a lightweight
    RandomForest model trained on synthetic data (clearly labeled).
    """

    def __init__(self, model_path: Optional[str] = None):
        self._model = None
        self._model_name = "nids-arc-rf-v1"
        self._model_version = "1.0.0-synthetic"
        self._model_path = model_path
        self._inference_count = 0
        self._total_inference_ms = 0.0

    @property
    def name(self) -> str:
        return "ml"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def initialize(self) -> None:
        """Load or train the ML model."""
        try:
            if self._model_path and os.path.exists(self._model_path):
                import joblib
                self._model = joblib.load(self._model_path)
                logger.info("ml_model_loaded", path=self._model_path)
            else:
                self._train_default_model()
        except Exception as e:
            logger.error("ml_model_init_failed", error=str(e))
            self._train_default_model()

    def _train_default_model(self) -> None:
        """Train a lightweight RandomForest on synthetic data."""
        from sklearn.ensemble import RandomForestClassifier

        logger.info("training_default_ml_model", note="trained on synthetic data only")

        rng = np.random.RandomState(42)

        # Generate synthetic training data
        n_normal = 2000
        n_attack = 500

        # Normal traffic features
        normal = np.column_stack([
            rng.exponential(500, n_normal),          # bytes_sent
            rng.exponential(1000, n_normal),         # bytes_received
            rng.poisson(5, n_normal),                # packets_sent
            rng.poisson(8, n_normal),                # packets_received
            rng.exponential(200, n_normal),          # duration_ms
            rng.randint(1024, 65535, n_normal),      # src_port
            rng.choice([80, 443, 8080, 53, 25], n_normal),  # dst_port
            rng.binomial(1, 0.7, n_normal),          # protocol_tcp
            rng.binomial(1, 0.2, n_normal),          # protocol_udp
            rng.binomial(1, 0.1, n_normal),          # protocol_icmp
            rng.uniform(0.1, 2.0, n_normal),         # bytes_ratio
            rng.uniform(0.3, 1.5, n_normal),         # packet_ratio
        ])

        # Attack traffic features (different distributions)
        attack = np.column_stack([
            rng.exponential(5000, n_attack),         # bytes_sent (higher)
            rng.exponential(200, n_attack),          # bytes_received (lower)
            rng.poisson(50, n_attack),               # packets_sent (higher)
            rng.poisson(2, n_attack),                # packets_received (lower)
            rng.exponential(20, n_attack),           # duration_ms (shorter)
            rng.randint(1024, 65535, n_attack),
            rng.choice([22, 23, 445, 3389, 4444], n_attack),  # suspicious ports
            rng.binomial(1, 0.8, n_attack),
            rng.binomial(1, 0.1, n_attack),
            rng.binomial(1, 0.1, n_attack),
            rng.uniform(5.0, 50.0, n_attack),       # bytes_ratio (skewed)
            rng.uniform(5.0, 30.0, n_attack),       # packet_ratio (skewed)
        ])

        X = np.vstack([normal, attack])
        y = np.array([0] * n_normal + [1] * n_attack)

        # Shuffle
        idx = rng.permutation(len(X))
        X, y = X[idx], y[idx]

        self._model = RandomForestClassifier(
            n_estimators=50,
            max_depth=10,
            random_state=42,
            n_jobs=1,
        )
        self._model.fit(X, y)
        self._model_version = "1.0.0-synthetic"

        logger.info("default_ml_model_trained", samples=len(X), features=X.shape[1])

    def _extract_features(self, context: DetectionContext) -> np.ndarray:
        """Extract feature vector from event context."""
        protocol = (context.protocol or "TCP").upper()
        bytes_ratio = (context.bytes_sent / max(context.bytes_received, 1))
        packet_ratio = (context.packets_sent / max(context.packets_received, 1))

        features = [
            context.bytes_sent,
            context.bytes_received,
            context.packets_sent,
            context.packets_received,
            context.duration_ms,
            context.src_port or 0,
            context.dst_port or 0,
            1.0 if protocol == "TCP" else 0.0,
            1.0 if protocol == "UDP" else 0.0,
            1.0 if protocol == "ICMP" else 0.0,
            bytes_ratio,
            packet_ratio,
        ]

        return np.array(features).reshape(1, -1)

    async def detect(self, context: DetectionContext) -> List[DetectionResultData]:
        """Run ML inference on the event."""
        if self._model is None:
            return []

        import time
        start = time.perf_counter()

        features = self._extract_features(context)
        prediction = self._model.predict(features)[0]
        probabilities = self._model.predict_proba(features)[0]

        inference_ms = (time.perf_counter() - start) * 1000
        self._inference_count += 1
        self._total_inference_ms += inference_ms

        results: List[DetectionResultData] = []

        if prediction == 1:  # Attack predicted
            confidence = float(probabilities[1])

            # Get feature importances
            importances = self._model.feature_importances_
            top_features = sorted(
                zip(FEATURE_NAMES, importances, features[0]),
                key=lambda x: x[1],
                reverse=True,
            )[:5]

            severity = "high" if confidence > 0.8 else "medium" if confidence > 0.5 else "low"

            results.append(DetectionResultData(
                event_id=context.event_id,
                detector=self.name,
                detector_version=self.version,
                model_id=self._model_name,
                model_version=self._model_version,
                severity=severity,
                confidence=round(confidence, 4),
                attack_category="ml_anomaly",
                evidence={
                    "prediction": "attack",
                    "attack_probability": round(confidence, 4),
                    "normal_probability": round(float(probabilities[0]), 4),
                    "feature_importances": [
                        {"feature": name, "importance": round(float(imp), 4), "value": round(float(val), 2)}
                        for name, imp, val in top_features
                    ],
                    "inference_time_ms": round(inference_ms, 2),
                    "model_note": "Model trained on synthetic data — for demonstration purposes",
                },
                explanation=(
                    f"ML model ({self._model_name} v{self._model_version}) predicts attack "
                    f"with {confidence:.1%} confidence. "
                    f"Top feature: {top_features[0][0]}={top_features[0][2]:.1f}"
                ),
                tags=["ml", "random_forest", "synthetic_model"],
            ))

        return results

    def get_status(self) -> Dict[str, Any]:
        """Return ML detector status and performance metrics."""
        avg_inference = (
            self._total_inference_ms / self._inference_count
            if self._inference_count > 0
            else 0
        )
        return {
            "name": self.name,
            "version": self.version,
            "enabled": self.enabled,
            "status": "active" if self._model is not None else "not_loaded",
            "model_name": self._model_name,
            "model_version": self._model_version,
            "inference_count": self._inference_count,
            "avg_inference_ms": round(avg_inference, 2),
        }
