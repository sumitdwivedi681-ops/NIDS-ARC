"""
NIDS ARC Application Factory.

Creates and configures the FastAPI application with all middleware,
routes, detection engines, and background services.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.config import get_settings
from backend.database import init_db, close_db, get_session_factory
from backend.detection import DetectionContext
from backend.detection.orchestrator import DetectionOrchestrator
from backend.correlation import CorrelationEngine
from backend.risk import RiskEngine
from backend.response import ResponseEngine
from backend.threat_intel import ThreatIntelStore
from backend.simulation import SimulationEngine
from backend.logging_config import setup_logging, get_logger
from backend.middleware.security_headers import SecurityHeadersMiddleware
from backend.middleware.request_logging import RequestLoggingMiddleware
from backend.middleware.error_handler import ErrorHandlerMiddleware
from backend.middleware.auth import hash_password

# API Routers
from backend.api.v1.health import router as health_router
from backend.api.v1.auth import router as auth_router
from backend.api.v1.events import router as events_router
from backend.api.v1.alerts import router as alerts_router
from backend.api.v1.rules import router as rules_router
from backend.api.v1.sensors import router as sensors_router

logger = get_logger("app")

# Global instances (initialized in lifespan)
detection_orchestrator: DetectionOrchestrator = None  # type: ignore
correlation_engine: CorrelationEngine = None  # type: ignore
risk_engine: RiskEngine = None  # type: ignore
response_engine: ResponseEngine = None  # type: ignore
threat_intel_store: ThreatIntelStore = None  # type: ignore
simulation_engine: SimulationEngine = None  # type: ignore
_simulation_task: asyncio.Task = None  # type: ignore


async def _create_default_admin(session_factory) -> None:
    """Create default admin user on first run."""
    from sqlalchemy import select
    from backend.models.user import User

    async with session_factory() as session:
        result = await session.execute(select(User).where(User.username == "admin"))
        existing = result.scalar_one_or_none()
        if existing is None:
            settings = get_settings()
            admin = User(
                username=settings.default_admin_username,
                email=settings.default_admin_email,
                password_hash=hash_password(settings.default_admin_password),
                role="admin",
                is_active=True,
            )
            session.add(admin)
            await session.commit()
            logger.info("default_admin_created", username=settings.default_admin_username)


async def _simulation_loop() -> None:
    """Background loop that generates simulated events and processes them through the detection pipeline."""
    global detection_orchestrator, correlation_engine, risk_engine, response_engine
    global threat_intel_store, simulation_engine

    settings = get_settings()
    session_factory = get_session_factory()
    delay = 1.0 / max(settings.simulation_events_per_second, 1)

    logger.info("simulation_loop_started", events_per_second=settings.simulation_events_per_second)

    while True:
        try:
            # Generate event
            event_data = simulation_engine.generate_event()

            # Create detection context
            context = DetectionContext(
                event_id=event_data["event_id"],
                timestamp=event_data["timestamp"],
                src_ip=event_data["src_ip"],
                dst_ip=event_data["dst_ip"],
                src_port=event_data.get("src_port"),
                dst_port=event_data.get("dst_port"),
                protocol=event_data.get("protocol"),
                event_type=event_data.get("event_type", "connection"),
                bytes_sent=event_data.get("bytes_sent", 0),
                bytes_received=event_data.get("bytes_received", 0),
                packets_sent=event_data.get("packets_sent", 0),
                packets_received=event_data.get("packets_received", 0),
                duration_ms=event_data.get("duration_ms", 0),
                source_type="simulation",
                sensor_id=simulation_engine.sensor_id,
            )

            # Run detection
            detections = await detection_orchestrator.detect(context)

            # TI matching
            ti_matches = threat_intel_store.match_event(context.src_ip, context.dst_ip)

            # Correlation
            correlation_group = correlation_engine.correlate(
                detections, src_ip=context.src_ip, dst_ip=context.dst_ip
            )

            # Risk assessment
            risk = risk_engine.assess(detections, event_count=1)

            # Store event in database
            async with session_factory() as session:
                from backend.models.event import SecurityEvent
                from backend.models.detection import DetectionResult as DetectionResultModel
                from backend.models.alert import Alert

                # Store the event
                db_event = SecurityEvent(
                    id=event_data["event_id"],
                    timestamp=event_data["timestamp"],
                    ingested_at=datetime.now(timezone.utc),
                    source_type="simulation",
                    sensor_id=simulation_engine.sensor_id,
                    src_ip=event_data["src_ip"],
                    src_port=event_data.get("src_port"),
                    dst_ip=event_data["dst_ip"],
                    dst_port=event_data.get("dst_port"),
                    protocol=event_data.get("protocol"),
                    bytes_sent=event_data.get("bytes_sent", 0),
                    bytes_received=event_data.get("bytes_received", 0),
                    packets_sent=event_data.get("packets_sent", 0),
                    packets_received=event_data.get("packets_received", 0),
                    duration_ms=event_data.get("duration_ms", 0),
                    event_type=event_data.get("event_type", "connection"),
                    attack_category=event_data.get("attack_category"),
                    severity=event_data.get("severity", "info"),
                    confidence=risk.risk_score / 100.0 if risk else None,
                    risk_score=risk.risk_score if risk else None,
                    tags=event_data.get("tags", []),
                )
                session.add(db_event)

                # Store detections
                for det in detections:
                    db_det = DetectionResultModel(
                        id=det.detection_id,
                        event_id=det.event_id,
                        detector=det.detector,
                        detector_version=det.detector_version,
                        rule_id=det.rule_id,
                        model_id=det.model_id,
                        model_version=det.model_version,
                        severity=det.severity,
                        confidence=det.confidence,
                        attack_category=det.attack_category,
                        evidence=det.evidence,
                        explanation=det.explanation,
                        mitre_attack=det.mitre_attack,
                        tags=det.tags,
                        created_at=det.timestamp,
                    )
                    session.add(db_det)

                # Create alert if detections found
                if detections:
                    max_sev_det = max(
                        detections,
                        key=lambda d: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(d.severity, 0),
                    )
                    alert = Alert(
                        title=f"[SIMULATION] {max_sev_det.attack_category or 'Detection'} from {context.src_ip}",
                        description=max_sev_det.explanation,
                        severity=max_sev_det.severity,
                        status="new",
                        source_type="simulation",
                        event_ids=[event_data["event_id"]],
                        detection_ids=[d.detection_id for d in detections],
                        risk_score=risk.risk_score,
                        risk_factors=[
                            {"factor": f.factor, "value": f.value, "weight": f.weight,
                             "contribution": f.contribution, "description": f.description}
                            for f in risk.risk_factors
                        ],
                        src_ip=context.src_ip,
                        dst_ip=context.dst_ip,
                    )
                    session.add(alert)

                    # Response evaluation
                    response_engine.evaluate(
                        risk_score=risk.risk_score,
                        risk_level=risk.risk_level,
                        source_entity=context.src_ip,
                        alert_id=alert.id,
                    )

                await session.commit()

            await asyncio.sleep(delay)

        except asyncio.CancelledError:
            logger.info("simulation_loop_stopped")
            break
        except Exception as e:
            logger.error("simulation_error", error=str(e))
            await asyncio.sleep(1)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown."""
    global detection_orchestrator, correlation_engine, risk_engine
    global response_engine, threat_intel_store, simulation_engine, _simulation_task

    settings = get_settings()
    setup_logging(settings.app_log_level.value)
    logger.info("nids_arc_starting", mode=settings.app_mode.value, env=settings.app_env)

    # Initialize database
    await init_db()
    logger.info("database_initialized")

    # Create default admin
    session_factory = get_session_factory()
    await _create_default_admin(session_factory)

    # Initialize detection orchestrator
    detection_orchestrator = DetectionOrchestrator.create_default()
    await detection_orchestrator.initialize_all()

    # Initialize correlation engine
    correlation_engine = CorrelationEngine()

    # Initialize risk engine
    risk_engine = RiskEngine()

    # Initialize response engine
    response_engine = ResponseEngine(
        dry_run=settings.response_dry_run,
        manual_approval=settings.response_manual_approval,
    )

    # Initialize threat intelligence
    threat_intel_store = ThreatIntelStore()
    threat_intel_store.load_mock_data()

    # Initialize simulation engine
    simulation_engine = SimulationEngine(
        events_per_second=settings.simulation_events_per_second,
        attack_probability=settings.simulation_attack_probability,
        seed=settings.simulation_seed,
    )

    # Start simulation if in simulation mode
    if settings.app_mode.value == "simulation":
        _simulation_task = asyncio.create_task(_simulation_loop())
        logger.info("simulation_mode_active")

    logger.info("nids_arc_started")

    yield

    # Shutdown
    if _simulation_task and not _simulation_task.done():
        _simulation_task.cancel()
        try:
            await _simulation_task
        except asyncio.CancelledError:
            pass

    await detection_orchestrator.shutdown_all()
    await close_db()
    logger.info("nids_arc_stopped")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="NIDS ARC",
        description="Autonomous Scalable Hybrid Network Intrusion Detection and Response Platform",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/api/docs" if settings.app_debug else None,
        redoc_url="/api/redoc" if settings.app_debug else None,
    )

    # Middleware (order matters — outermost first)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(ErrorHandlerMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Health routes (no auth required)
    app.include_router(health_router)

    # API v1 routes
    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(events_router, prefix="/api/v1")
    app.include_router(alerts_router, prefix="/api/v1")
    app.include_router(rules_router, prefix="/api/v1")
    app.include_router(sensors_router, prefix="/api/v1")

    # Additional API endpoints
    @app.get("/api/v1/dashboard/overview")
    async def dashboard_overview() -> Dict[str, Any]:
        """Dashboard overview data for frontend."""
        from sqlalchemy import func, select
        from backend.models.event import SecurityEvent
        from backend.models.alert import Alert

        session_factory = get_session_factory()
        async with session_factory() as session:
            from datetime import timedelta
            cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)

            # Event count 24h
            total_events = (await session.execute(
                select(func.count()).select_from(SecurityEvent).where(SecurityEvent.timestamp >= cutoff_24h)
            )).scalar() or 0

            # Alert counts
            total_alerts = (await session.execute(
                select(func.count()).select_from(Alert)
            )).scalar() or 0
            active_alerts = (await session.execute(
                select(func.count()).select_from(Alert).where(Alert.status.in_(["new", "acknowledged", "investigating"]))
            )).scalar() or 0

            # Severity distribution
            sev_q = await session.execute(
                select(Alert.severity, func.count()).group_by(Alert.severity)
            )
            severity_dist = {row[0]: row[1] for row in sev_q.all()}

            # Recent alerts
            recent_q = await session.execute(
                select(Alert).order_by(Alert.created_at.desc()).limit(10)
            )
            recent_alerts = [
                {
                    "id": a.id,
                    "title": a.title,
                    "severity": a.severity,
                    "status": a.status,
                    "source_type": a.source_type,
                    "src_ip": a.src_ip,
                    "dst_ip": a.dst_ip,
                    "risk_score": a.risk_score,
                    "created_at": a.created_at.isoformat(),
                }
                for a in recent_q.scalars().all()
            ]

        return {
            "mode": settings.app_mode.value,
            "total_events_24h": total_events,
            "total_alerts": total_alerts,
            "active_alerts": active_alerts,
            "severity_distribution": severity_dist,
            "recent_alerts": recent_alerts,
            "detection_engines": detection_orchestrator.get_status() if detection_orchestrator else {},
            "threat_intel": threat_intel_store.get_stats() if threat_intel_store else {},
            "correlation": correlation_engine.get_stats() if correlation_engine else {},
            "response": response_engine.get_stats() if response_engine else {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @app.get("/api/v1/detections/engines")
    async def detection_engine_status() -> Dict[str, Any]:
        """Get detection engine statuses."""
        return {
            "data": detection_orchestrator.get_status() if detection_orchestrator else {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @app.get("/api/v1/threat-intel/stats")
    async def threat_intel_stats() -> Dict[str, Any]:
        """Get threat intelligence statistics."""
        return {
            "data": threat_intel_store.get_stats() if threat_intel_store else {},
            "iocs": threat_intel_store.get_all()[:50] if threat_intel_store else [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @app.get("/api/v1/response/actions")
    async def response_actions() -> Dict[str, Any]:
        """Get response actions."""
        return {
            "data": response_engine.get_all_actions()[-50:] if response_engine else [],
            "stats": response_engine.get_stats() if response_engine else {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @app.get("/api/v1/incidents")
    async def list_incidents() -> Dict[str, Any]:
        """Get correlated incidents."""
        return {
            "data": correlation_engine.get_incidents() if correlation_engine else [],
            "stats": correlation_engine.get_stats() if correlation_engine else {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # Serve frontend static files
    import os
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
    if os.path.exists(frontend_dir):
        app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")

    return app


# Application instance
app = create_app()
