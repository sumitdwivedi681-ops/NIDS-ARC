"""
NIDS ARC Application Factory.

Creates and configures the FastAPI application with all middleware,
routes, detection engines, background simulation, live packet capture,
real-time WebSockets, and operational endpoints.
"""

from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from uuid import uuid4

import structlog
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.config import get_settings, AppMode
from backend.database import init_db, close_db, get_session_factory
from backend.detection import DetectionContext
from backend.detection.orchestrator import DetectionOrchestrator
from backend.correlation import CorrelationEngine
from backend.risk import RiskEngine
from backend.response import ResponseEngine
from backend.threat_intel import ThreatIntelStore
from backend.simulation import SimulationEngine
from backend.sensors.manager import SensorManager
from backend.sensors.live_sniffer import LiveSniffer
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
from backend.api.v1.audit import router as audit_router

logger = get_logger("app")

# Global instances (initialized in lifespan)
detection_orchestrator: DetectionOrchestrator = None  # type: ignore
correlation_engine: CorrelationEngine = None  # type: ignore
risk_engine: RiskEngine = None  # type: ignore
response_engine: ResponseEngine = None  # type: ignore
threat_intel_store: ThreatIntelStore = None  # type: ignore
simulation_engine: SimulationEngine = None  # type: ignore
sensor_manager: SensorManager = None  # type: ignore
live_sniffer: LiveSniffer = None  # type: ignore

_simulation_task: Optional[asyncio.Task] = None
_live_sniffer_task: Optional[asyncio.Task] = None


class WebSocketManager:
    """Manages active WebSocket connections for live alert and telemetry streaming."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("ws_client_connected", total_clients=len(self.active_connections))

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("ws_client_disconnected", remaining_clients=len(self.active_connections))

    async def broadcast(self, message: Dict[str, Any]):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)


ws_manager = WebSocketManager()


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


async def _process_normalized_event(event_data: Dict[str, Any], source_type: str = "simulation") -> None:
    """
    Central event processing pipeline.
    Runs Detection -> Threat Intel -> Correlation -> Risk -> DB Store -> Response -> WebSocket Broadcast.
    """
    global detection_orchestrator, correlation_engine, risk_engine, response_engine, threat_intel_store
    session_factory = get_session_factory()

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
        source_type=source_type,
        sensor_id=event_data.get("sensor_id", "sensor-core"),
    )

    # Run detection engines
    detections = await detection_orchestrator.detect(context)

    # Threat Intel matching
    ti_matches = threat_intel_store.match_event(context.src_ip, context.dst_ip)
    if ti_matches and not detections:
        # Generate TI detection result if matching known malicious IOC
        from backend.detection import DetectionResultData
        for ti in ti_matches:
            detections.append(DetectionResultData(
                detection_id=f"ti-{uuid4().hex[:8]}",
                event_id=context.event_id,
                detector="threat_intel",
                detector_version="1.0.0",
                severity=ti.get("severity", "high"),
                confidence=ti.get("confidence", 0.9),
                attack_category="Known Malicious IOC",
                explanation=f"Traffic matched known Threat Intel IOC: {ti.get('value')} ({ti.get('source')})",
                mitre_attack=["T1071"],
                tags=ti.get("tags", []),
            ))

    # Correlation
    correlation_group = correlation_engine.correlate(
        detections, src_ip=context.src_ip, dst_ip=context.dst_ip
    )

    # Risk assessment
    risk = risk_engine.assess(detections, event_count=1)

    created_alert_dict = None

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
            source_type=source_type,
            sensor_id=event_data.get("sensor_id", "sensor-core"),
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
            prefix = "[REAL]" if source_type == "real" else "[SIM]"
            alert = Alert(
                title=f"{prefix} {max_sev_det.attack_category or 'Threat Detected'} from {context.src_ip}",
                description=max_sev_det.explanation,
                severity=max_sev_det.severity,
                status="new",
                source_type=source_type,
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

            created_alert_dict = {
                "id": alert.id,
                "title": alert.title,
                "severity": alert.severity,
                "status": alert.status,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "risk_score": alert.risk_score,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }

        await session.commit()

    # Stream real-time notification to all connected WebSockets
    await ws_manager.broadcast({
        "type": "alert" if created_alert_dict else "telemetry",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": {
            "id": event_data["event_id"],
            "src_ip": event_data["src_ip"],
            "dst_ip": event_data["dst_ip"],
            "protocol": event_data.get("protocol"),
            "event_type": event_data.get("event_type"),
            "severity": event_data.get("severity", "info"),
        },
        "alert": created_alert_dict,
    })


async def _simulation_loop() -> None:
    """Background loop that generates simulated events."""
    global simulation_engine
    settings = get_settings()
    delay = 1.0 / max(settings.simulation_events_per_second, 1)

    logger.info("simulation_loop_started", events_per_second=settings.simulation_events_per_second)

    while True:
        try:
            event_data = simulation_engine.generate_event()
            await _process_normalized_event(event_data, source_type="simulation")
            await asyncio.sleep(delay)
        except asyncio.CancelledError:
            logger.info("simulation_loop_stopped")
            break
        except Exception as e:
            logger.error("simulation_error", error=str(e))
            await asyncio.sleep(1)


async def _live_sniffer_loop() -> None:
    """Background loop polling live packets captured by LiveSniffer."""
    global live_sniffer
    logger.info("live_sniffer_loop_started")

    while True:
        try:
            events = await live_sniffer.poll_events()
            for evt in events:
                await _process_normalized_event(evt, source_type="real")
            await asyncio.sleep(0.5 if not events else 0.05)
        except asyncio.CancelledError:
            logger.info("live_sniffer_loop_stopped")
            break
        except Exception as e:
            logger.error("live_sniffer_loop_error", error=str(e))
            await asyncio.sleep(1)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown."""
    global detection_orchestrator, correlation_engine, risk_engine
    global response_engine, threat_intel_store, simulation_engine
    global sensor_manager, live_sniffer
    global _simulation_task, _live_sniffer_task

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

    # Initialize sensors
    sensor_manager = SensorManager.create_default()
    live_sniffer = LiveSniffer()
    sensor_manager.register_sensor(live_sniffer)

    # Start sensors based on mode
    if settings.app_mode in (AppMode.SIMULATION, "simulation"):
        _simulation_task = asyncio.create_task(_simulation_loop())
        logger.info("simulation_mode_active")
    elif settings.app_mode in (AppMode.REAL, "real"):
        await live_sniffer.start()
        _live_sniffer_task = asyncio.create_task(_live_sniffer_loop())
        logger.info("real_capture_mode_active")

    logger.info("nids_arc_started")

    yield

    # Shutdown
    if _simulation_task and not _simulation_task.done():
        _simulation_task.cancel()
        try:
            await _simulation_task
        except asyncio.CancelledError:
            pass

    if _live_sniffer_task and not _live_sniffer_task.done():
        _live_sniffer_task.cancel()
        try:
            await _live_sniffer_task
        except asyncio.CancelledError:
            pass

    if live_sniffer:
        await live_sniffer.stop()

    await detection_orchestrator.shutdown_all()
    await close_db()
    logger.info("nids_arc_stopped")


class UnblockRequest(BaseModel):
    ip: str


class SettingsUpdateRequest(BaseModel):
    app_mode: Optional[str] = None
    simulation_events_per_second: Optional[int] = None
    response_dry_run: Optional[bool] = None
    response_manual_approval: Optional[bool] = None


class CleanupRequest(BaseModel):
    max_events_to_keep: int = 30000


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="NIDS ARC",
        description="Autonomous Scalable Hybrid Network Intrusion Detection and Response Platform",
        version="0.2.0",
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
    app.include_router(audit_router, prefix="/api/v1")

    # Real-time WebSocket endpoints
    @app.websocket("/ws/live")
    @app.websocket("/api/v1/ws/live")
    async def websocket_live_endpoint(websocket: WebSocket):
        """WebSocket endpoint for real-time telemetry and live alert streaming."""
        await ws_manager.connect(websocket)
        try:
            while True:
                # Keep connection alive, listen for ping/pong
                await websocket.receive_text()
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket)
        except Exception:
            ws_manager.disconnect(websocket)

    # Dashboard overview
    @app.get("/api/v1/dashboard/overview")
    async def dashboard_overview() -> Dict[str, Any]:
        """Dashboard overview data for frontend."""
        from sqlalchemy import func, select
        from backend.models.event import SecurityEvent
        from backend.models.alert import Alert

        session_factory = get_session_factory()
        async with session_factory() as session:
            cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)

            total_events = (await session.execute(
                select(func.count()).select_from(SecurityEvent).where(SecurityEvent.timestamp >= cutoff_24h)
            )).scalar() or 0

            total_alerts = (await session.execute(
                select(func.count()).select_from(Alert)
            )).scalar() or 0
            active_alerts = (await session.execute(
                select(func.count()).select_from(Alert).where(Alert.status.in_(["new", "acknowledged", "investigating"]))
            )).scalar() or 0

            sev_q = await session.execute(
                select(Alert.severity, func.count()).group_by(Alert.severity)
            )
            severity_dist = {row[0]: row[1] for row in sev_q.all()}

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
            "mode": settings.app_mode.value if hasattr(settings.app_mode, "value") else str(settings.app_mode),
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

    # Network Activity API
    @app.get("/api/v1/network/activity")
    async def network_activity(hours: int = 24) -> Dict[str, Any]:
        """Detailed network telemetry breakdown by protocol, top talkers, and traffic."""
        from sqlalchemy import func, select, desc
        from backend.models.event import SecurityEvent

        session_factory = get_session_factory()
        async with session_factory() as session:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

            # Protocols
            proto_q = await session.execute(
                select(SecurityEvent.protocol, func.count(SecurityEvent.id), func.sum(SecurityEvent.bytes_sent))
                .where(SecurityEvent.timestamp >= cutoff)
                .group_by(SecurityEvent.protocol)
            )
            protocols = [
                {"protocol": row[0] or "UNKNOWN", "count": row[1], "bytes": row[2] or 0}
                for row in proto_q.all()
            ]

            # Top Source IPs
            top_src_q = await session.execute(
                select(SecurityEvent.src_ip, func.count(SecurityEvent.id))
                .where(SecurityEvent.timestamp >= cutoff)
                .group_by(SecurityEvent.src_ip)
                .order_by(desc(func.count(SecurityEvent.id)))
                .limit(10)
            )
            top_sources = [{"ip": row[0], "count": row[1]} for row in top_src_q.all()]

            # Top Destination Ports
            top_dst_q = await session.execute(
                select(SecurityEvent.dst_port, func.count(SecurityEvent.id))
                .where(SecurityEvent.timestamp >= cutoff, SecurityEvent.dst_port.isnot(None))
                .group_by(SecurityEvent.dst_port)
                .order_by(desc(func.count(SecurityEvent.id)))
                .limit(10)
            )
            top_ports = [{"port": row[0], "count": row[1]} for row in top_dst_q.all()]

        return {
            "protocols": protocols,
            "top_sources": top_sources,
            "top_ports": top_ports,
            "time_window_hours": hours,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # Detection Engines
    @app.get("/api/v1/detections/engines")
    async def detection_engine_status() -> Dict[str, Any]:
        return {
            "data": detection_orchestrator.get_status() if detection_orchestrator else {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # Threat Intelligence
    @app.get("/api/v1/threat-intel/stats")
    async def threat_intel_stats() -> Dict[str, Any]:
        return {
            "data": threat_intel_store.get_stats() if threat_intel_store else {},
            "iocs": threat_intel_store.get_all()[:50] if threat_intel_store else [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # Response Actions & Firewall Rules
    @app.get("/api/v1/response/actions")
    async def response_actions() -> Dict[str, Any]:
        return {
            "data": response_engine.get_all_actions()[-50:] if response_engine else [],
            "stats": response_engine.get_stats() if response_engine else {},
            "blocked_ips": response_engine.list_blocked_ips() if response_engine else [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @app.post("/api/v1/response/unblock")
    async def unblock_ip_action(req: UnblockRequest) -> Dict[str, Any]:
        """Manually unblock an IP from the host firewall."""
        if not response_engine:
            raise HTTPException(status_code=500, detail="Response engine not initialized")
        res = response_engine.unblock_ip(req.ip)
        return {"result": res, "timestamp": datetime.now(timezone.utc).isoformat()}

    # Incidents
    @app.get("/api/v1/incidents")
    async def list_incidents() -> Dict[str, Any]:
        return {
            "data": correlation_engine.get_incidents() if correlation_engine else [],
            "stats": correlation_engine.get_stats() if correlation_engine else {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # System Settings Management
    @app.get("/api/v1/settings")
    async def get_system_settings() -> Dict[str, Any]:
        """Fetch active system settings."""
        settings = get_settings()
        return {
            "app_mode": settings.app_mode.value if hasattr(settings.app_mode, "value") else str(settings.app_mode),
            "environment": settings.app_env,
            "version": "0.2.0",
            "simulation_events_per_second": settings.simulation_events_per_second,
            "simulation_attack_probability": settings.simulation_attack_probability,
            "response_dry_run": response_engine._dry_run if response_engine else settings.response_dry_run,
            "response_manual_approval": response_engine._manual_approval if response_engine else settings.response_manual_approval,
            "active_sensors": [s.name for s in sensor_manager.get_all_sensors()] if sensor_manager else [],
        }

    @app.put("/api/v1/settings")
    async def update_system_settings(req: SettingsUpdateRequest) -> Dict[str, Any]:
        """Update system runtime settings on the fly."""
        global _simulation_task, _live_sniffer_task
        settings = get_settings()

        if req.simulation_events_per_second is not None:
            settings.simulation_events_per_second = max(1, min(req.simulation_events_per_second, 100))
            if simulation_engine:
                simulation_engine.events_per_second = settings.simulation_events_per_second

        if req.response_dry_run is not None and response_engine:
            response_engine._dry_run = req.response_dry_run
            response_engine.firewall.dry_run = req.response_dry_run

        if req.response_manual_approval is not None and response_engine:
            response_engine._manual_approval = req.response_manual_approval

        # Handle Mode Switch
        if req.app_mode and req.app_mode in ("simulation", "real"):
            if req.app_mode == "real" and (_simulation_task and not _simulation_task.done()):
                _simulation_task.cancel()
                if live_sniffer:
                    await live_sniffer.start()
                    _live_sniffer_task = asyncio.create_task(_live_sniffer_loop())
                settings.app_mode = AppMode.REAL
            elif req.app_mode == "simulation" and (_live_sniffer_task and not _live_sniffer_task.done()):
                _live_sniffer_task.cancel()
                if live_sniffer:
                    await live_sniffer.stop()
                _simulation_task = asyncio.create_task(_simulation_loop())
                settings.app_mode = AppMode.SIMULATION

        return {"message": "Settings updated successfully", "settings": await get_system_settings()}

    # Maintenance DB Cleanup
    @app.post("/api/v1/maintenance/cleanup")
    async def cleanup_database(req: Optional[CleanupRequest] = None) -> Dict[str, Any]:
        """Prune old events to optimize database performance."""
        from sqlalchemy import text
        session_factory = get_session_factory()
        deleted_count = 0
        limit = req.max_events_to_keep if req else 30000

        async with session_factory() as session:
            try:
                # Delete older events beyond limit
                res = await session.execute(text(f"""
                    DELETE FROM security_events 
                    WHERE id NOT IN (
                        SELECT id FROM security_events 
                        ORDER BY timestamp DESC 
                        LIMIT {limit}
                    )
                """))
                await session.commit()
                deleted_count = res.rowcount if hasattr(res, "rowcount") else 0
            except Exception as e:
                logger.warning("cleanup_query_failed", error=str(e))

        return {
            "status": "success",
            "message": f"Cleaned up {deleted_count} stale events. Preserved latest {limit} records.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # Serve frontend static files
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
    if os.path.exists(frontend_dir):
        app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")

    return app


# Application instance
app = create_app()
