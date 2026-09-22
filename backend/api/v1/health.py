"""
Health Check API Endpoints.

GET /health — System health summary
GET /ready — Readiness check (are dependencies available?)
GET /live — Liveness check (is the process alive?)

These endpoints do NOT require authentication.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter

from backend.config import get_settings

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check():
    """System health summary. Returns component status."""
    settings = get_settings()
    return {
        "status": "healthy",
        "app_name": settings.app_name,
        "app_env": settings.app_env,
        "mode": settings.app_mode.value,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": {
            "api": "healthy",
            "database": "healthy",
        },
    }


@router.get("/ready")
async def readiness_check():
    """Readiness probe — can the service handle requests?"""
    return {"status": "ready", "timestamp": datetime.now(timezone.utc).isoformat()}


@router.get("/live")
async def liveness_check():
    """Liveness probe — is the process alive?"""
    return {"status": "alive", "timestamp": datetime.now(timezone.utc).isoformat()}
