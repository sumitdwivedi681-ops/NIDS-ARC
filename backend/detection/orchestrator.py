"""
Detection Orchestrator.

Routes events to all enabled detectors, collects results, and
stores detection results in the database.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List

import structlog

from backend.detection import Detector, DetectionContext, DetectionResultData
from backend.detection.signature import SignatureDetector
from backend.detection.anomaly import AnomalyDetector
from backend.detection.behavioral import BehavioralDetector
from backend.detection.ml_detector import MLDetector

logger = structlog.get_logger("detection_orchestrator")


class DetectionOrchestrator:
    """
    Orchestrates multiple detection engines.

    Routes events to all enabled detectors in parallel,
    collects and merges results.
    """

    def __init__(self):
        self._detectors: List[Detector] = []
        self._total_events_processed = 0
        self._total_detections = 0

    def register_detector(self, detector: Detector) -> None:
        """Register a detector."""
        self._detectors.append(detector)
        logger.info("detector_registered", name=detector.name, version=detector.version)

    async def initialize_all(self) -> None:
        """Initialize all registered detectors."""
        for detector in self._detectors:
            try:
                await detector.initialize()
                logger.info("detector_initialized", name=detector.name)
            except Exception as e:
                logger.error("detector_init_failed", name=detector.name, error=str(e))

    async def shutdown_all(self) -> None:
        """Shutdown all registered detectors."""
        for detector in self._detectors:
            try:
                await detector.shutdown()
            except Exception as e:
                logger.error("detector_shutdown_failed", name=detector.name, error=str(e))

    async def detect(self, context: DetectionContext) -> List[DetectionResultData]:
        """Run all enabled detectors on an event and collect results."""
        self._total_events_processed += 1
        all_results: List[DetectionResultData] = []

        # Run detectors concurrently
        tasks = []
        for detector in self._detectors:
            if detector.enabled:
                tasks.append(self._run_detector(detector, context))

        if tasks:
            detector_results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in detector_results:
                if isinstance(result, Exception):
                    logger.error("detector_error", error=str(result))
                elif isinstance(result, list):
                    all_results.extend(result)

        self._total_detections += len(all_results)
        return all_results

    async def _run_detector(
        self, detector: Detector, context: DetectionContext
    ) -> List[DetectionResultData]:
        """Run a single detector with error handling."""
        try:
            return await detector.detect(context)
        except Exception as e:
            logger.error(
                "detector_execution_error",
                detector=detector.name,
                event_id=context.event_id,
                error=str(e),
            )
            return []

    def get_status(self) -> Dict[str, Any]:
        """Get orchestrator status and detector statuses."""
        return {
            "total_events_processed": self._total_events_processed,
            "total_detections": self._total_detections,
            "detectors": [d.get_status() for d in self._detectors],
        }

    @classmethod
    def create_default(cls) -> "DetectionOrchestrator":
        """Create an orchestrator with all default detectors."""
        orchestrator = cls()
        orchestrator.register_detector(SignatureDetector())
        orchestrator.register_detector(AnomalyDetector())
        orchestrator.register_detector(BehavioralDetector())
        orchestrator.register_detector(MLDetector())
        return orchestrator
