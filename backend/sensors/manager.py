"""
NIDS ARC Sensor Manager.

Coordinates all registered network sensors (Simulation, Suricata, Zeek, etc.),
tracks their health states, and collects events.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.sensors.base import BaseSensor, SensorHealthStatus
from backend.sensors.simulation_sensor import SimulationSensor
from backend.sensors.suricata_adapter import SuricataAdapter
from backend.sensors.zeek_adapter import ZeekAdapter


class SensorManager:
    """
    Sensor orchestration manager.
    Maintains the registry of active network telemetry sensors.
    """

    def __init__(self):
        self._sensors: Dict[str, BaseSensor] = {}

    def register_sensor(self, sensor: BaseSensor) -> None:
        """Register a sensor adapter."""
        self._sensors[sensor.sensor_id] = sensor

    def get_sensor(self, sensor_id: str) -> Optional[BaseSensor]:
        """Retrieve sensor by ID."""
        return self._sensors.get(sensor_id)

    def get_all_sensors(self) -> List[BaseSensor]:
        """Return list of all registered sensors."""
        return list(self._sensors.values())

    async def start_all(self) -> None:
        """Start all enabled sensors."""
        for sensor in self._sensors.values():
            if sensor.config.enabled:
                await sensor.start()

    async def stop_all(self) -> None:
        """Stop all running sensors."""
        for sensor in self._sensors.values():
            await sensor.stop()

    async def check_all_health(self) -> Dict[str, str]:
        """Execute health check across all sensors."""
        health = {}
        for s_id, sensor in self._sensors.items():
            status = await sensor.health_check()
            health[s_id] = status.value
        return health

    def get_statuses(self) -> List[Dict[str, Any]]:
        """Return detailed status list for SOC dashboard and API."""
        return [sensor.get_info() for sensor in self._sensors.values()]

    @classmethod
    def create_default(cls) -> SensorManager:
        """Factory creating default sensor set (Simulation + Suricata stub + Zeek stub)."""
        mgr = cls()
        mgr.register_sensor(SimulationSensor())
        mgr.register_sensor(SuricataAdapter())
        mgr.register_sensor(ZeekAdapter())
        return mgr
