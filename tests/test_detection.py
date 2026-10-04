"""
Unit tests for NIDS ARC Detection Engines.
"""

import pytest
from datetime import datetime, timezone
from backend.detection import DetectionContext
from backend.detection.signature import SignatureDetector
from backend.detection.anomaly import AnomalyDetector
from backend.detection.behavioral import BehavioralDetector
from backend.detection.ml_detector import MLDetector
from backend.detection.orchestrator import DetectionOrchestrator


@pytest.mark.asyncio
async def test_signature_detector():
    detector = SignatureDetector()
    await detector.initialize()

    # Benign context
    benign_ctx = DetectionContext(
        event_id="test-1",
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.50",
        dst_ip="192.168.1.1",
        src_port=54321,
        dst_port=443,
        protocol="TCP",
        event_type="connection",
        bytes_sent=500,
        bytes_received=2000,
        packets_sent=5,
        packets_received=8,
        duration_ms=120,
    )
    results = await detector.detect(benign_ctx)
    # Benign traffic should not trigger telnet or scan signatures
    assert not any(d.rule_id == "SIG-006" for d in results)

    # Insecure Telnet connection (port 23)
    telnet_ctx = DetectionContext(
        event_id="test-2",
        timestamp=datetime.now(timezone.utc),
        src_ip="10.0.0.99",
        dst_ip="192.168.1.1",
        src_port=44112,
        dst_port=23,
        protocol="TCP",
        event_type="connection",
        bytes_sent=100,
        bytes_received=100,
        packets_sent=2,
        packets_received=2,
        duration_ms=50,
    )
    results_telnet = await detector.detect(telnet_ctx)
    assert any(d.rule_id == "SIG-006" for d in results_telnet)


@pytest.mark.asyncio
async def test_anomaly_detector():
    detector = AnomalyDetector()
    await detector.initialize()

    ctx = DetectionContext(
        event_id="test-anom-1",
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        bytes_sent=5000000,  # abnormally massive outbound flow
        bytes_received=50,
        packets_sent=5000,
        packets_received=2,
        duration_ms=10,
    )
    results = await detector.detect(ctx)
    assert isinstance(results, list)


@pytest.mark.asyncio
async def test_ml_detector():
    detector = MLDetector()
    await detector.initialize()
    assert detector._model is not None

    ctx = DetectionContext(
        event_id="test-ml-1",
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.15",
        dst_ip="192.168.1.1",
        src_port=55123,
        dst_port=80,
        protocol="TCP",
        bytes_sent=6000,
        bytes_received=100,
        packets_sent=80,
        packets_received=2,
        duration_ms=250,
    )
    results = await detector.detect(ctx)
    assert isinstance(results, list)


@pytest.mark.asyncio
async def test_orchestrator():
    orchestrator = DetectionOrchestrator.create_default()
    await orchestrator.initialize_all()

    ctx = DetectionContext(
        event_id="test-orch-1",
        timestamp=datetime.now(timezone.utc),
        src_ip="172.16.0.4",
        dst_ip="192.168.1.1",
        src_port=55000,
        dst_port=23,
        protocol="TCP",
        bytes_sent=120,
        bytes_received=80,
        packets_sent=2,
        packets_received=2,
        duration_ms=30,
    )
    results = await orchestrator.detect(ctx)
    status = orchestrator.get_status()
    assert status["total_events_processed"] >= 1
    assert len(status["detectors"]) == 4

    sig_det = orchestrator.get_detector("signature")
    assert sig_det is not None

    await orchestrator.shutdown_all()
