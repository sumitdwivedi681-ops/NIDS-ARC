"""
NIDS ARC Sensor API Endpoints.

Provides status, metrics, and configuration for network telemetry sensors.
"""

from __future__ import annotations

from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException

from backend.sensors.manager import SensorManager

router = APIRouter(prefix="/sensors", tags=["Sensors"])

# Global sensor manager instance
sensor_manager = SensorManager.create_default()


@router.get("")
async def list_sensors() -> Dict[str, Any]:
    """List all registered sensors and their current status."""
    await sensor_manager.check_all_health()
    sensors_data = sensor_manager.get_statuses()
    return {
        "sensors": sensors_data,
        "total": len(sensors_data),
        "online_count": sum(1 for s in sensors_data if s["status"] == "online"),
    }


@router.get("/{sensor_id}")
async def get_sensor_detail(sensor_id: str) -> Dict[str, Any]:
    """Get detail and statistics for a specific sensor."""
    sensor = sensor_manager.get_sensor(sensor_id)
    if not sensor:
        raise HTTPException(status_code=404, detail=f"Sensor '{sensor_id}' not found")
    await sensor.health_check()
    return sensor.get_info()


@router.post("/{sensor_id}/toggle")
async def toggle_sensor(sensor_id: str) -> Dict[str, Any]:
    """Toggle sensor enabled/disabled state."""
    sensor = sensor_manager.get_sensor(sensor_id)
    if not sensor:
        raise HTTPException(status_code=404, detail=f"Sensor '{sensor_id}' not found")
    sensor.config.enabled = not sensor.config.enabled
    if sensor.config.enabled:
        await sensor.start()
    else:
        await sensor.stop()
    return {
        "sensor_id": sensor_id,
        "enabled": sensor.config.enabled,
        "status": sensor.status.value,
    }
