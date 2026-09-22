"""
NIDS ARC Simulation Sensor.

Adapter that integrates the internal synthetic traffic generator into the
unified BaseSensor interface.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from backend.sensors.base import BaseSensor, SensorConfig, SensorHealthStatus, SensorType
from backend.simulation import SimulationEngine


class SimulationSensor(BaseSensor):
    """
    Simulation sensor generating synthetic benign and malicious network telemetry.
    Implements full BaseSensor lifecycle and metrics reporting.
    """

    def __init__(
        self,
        config: Optional[SensorConfig] = None,
        simulation_engine: Optional[SimulationEngine] = None,
    ):
        if config is None:
            config = SensorConfig(
                sensor_id="sensor-sim-01",
                name="NIDS ARC Simulation Generator",
                sensor_type=SensorType.SIMULATION,
                enabled=True,
                extra_params={"events_per_second": 10, "attack_probability": 0.05},
            )
        super().__init__(config)

        eps = config.extra_params.get("events_per_second", 10)
        prob = config.extra_params.get("attack_probability", 0.05)
        seed = config.extra_params.get("seed", 42)

        self.engine = simulation_engine or SimulationEngine(
            events_per_second=eps,
            attack_probability=prob,
            seed=seed,
        )
        self._buffer: List[Dict[str, Any]] = []

    async def start(self) -> None:
        """Start the simulation sensor."""
        self._is_running = True
        self.status = SensorHealthStatus.ONLINE
        self.stats.last_heartbeat = datetime.now(timezone.utc)

    async def stop(self) -> None:
        """Stop the simulation sensor."""
        self._is_running = False
        self.status = SensorHealthStatus.OFFLINE

    async def poll_events(self) -> List[Dict[str, Any]]:
        """Generate a batch of simulated events."""
        if not self._is_running or not self.config.enabled:
            return []

        events = []
        batch_size = max(1, self.config.extra_params.get("events_per_second", 5) // 2)
        for _ in range(batch_size):
            evt = self.engine.generate_event()
            events.append(evt)
            self.stats.events_generated += 1
            self.stats.packets_captured += (evt.get("packets_sent", 1) + evt.get("packets_received", 1))
            self.stats.bytes_processed += (evt.get("bytes_sent", 0) + evt.get("bytes_received", 0))

        now = datetime.now(timezone.utc)
        self.stats.last_event_time = now
        self.stats.last_heartbeat = now
        return events

    async def health_check(self) -> SensorHealthStatus:
        """Check status of the simulation generator."""
        if not self.config.enabled:
            self.status = SensorHealthStatus.OFFLINE
        elif self._is_running:
            self.status = SensorHealthStatus.ONLINE
            self.stats.last_heartbeat = datetime.now(timezone.utc)
        else:
            self.status = SensorHealthStatus.OFFLINE
        return self.status
