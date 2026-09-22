"""
NIDS ARC Sensor Adapter Interfaces.

Defines the abstract base class and data structures for all network sensors
(Suricata, Zeek, Simulation, eBPF, PCAP Replay).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncIterator, Dict, List, Optional
from uuid import uuid4


class SensorType(str, Enum):
    """Supported sensor types."""
    SIMULATION = "simulation"
    SURICATA = "suricata"
    ZEEK = "zeek"
    EBPF = "ebpf"
    PCAP_REPLAY = "pcap_replay"


class SensorHealthStatus(str, Enum):
    """Operational health status of a sensor."""
    ONLINE = "online"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    ERROR = "error"
    UNCONFIGURED = "unconfigured"


@dataclass
class SensorConfig:
    """Configuration for a network sensor."""
    sensor_id: str
    name: str
    sensor_type: SensorType
    enabled: bool = True
    interface: Optional[str] = None
    log_path: Optional[str] = None
    socket_path: Optional[str] = None
    buffer_size: int = 1000
    poll_interval_seconds: float = 1.0
    extra_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SensorStats:
    """Runtime statistics for a sensor."""
    packets_captured: int = 0
    packets_dropped: int = 0
    events_generated: int = 0
    bytes_processed: int = 0
    errors_count: int = 0
    last_event_time: Optional[datetime] = None
    last_heartbeat: Optional[datetime] = None
    cpu_percent: float = 0.0
    memory_mb: float = 0.0


class BaseSensor(ABC):
    """
    Abstract base class for all network sensor adapters.
    
    Sensors ingest raw packet, flow, or alert data from network interfaces,
    daemon log files, or replay sources, and yield normalized security events.
    """

    def __init__(self, config: SensorConfig):
        self.config = config
        self.status = SensorHealthStatus.UNCONFIGURED
        self.stats = SensorStats()
        self._is_running = False

    @property
    def sensor_id(self) -> str:
        return self.config.sensor_id

    @property
    def name(self) -> str:
        return self.config.name

    @property
    def sensor_type(self) -> SensorType:
        return self.config.sensor_type

    @abstractmethod
    async def start(self) -> None:
        """Initialize and start the sensor ingestion loop."""
        pass

    @abstractmethod
    async def stop(self) -> None:
        """Gracefully stop sensor ingestion."""
        pass

    @abstractmethod
    async def poll_events(self) -> List[Dict[str, Any]]:
        """Poll the next batch of normalized events from the sensor buffer."""
        pass

    @abstractmethod
    async def health_check(self) -> SensorHealthStatus:
        """Evaluate sensor health and return current status."""
        pass

    def get_info(self) -> Dict[str, Any]:
        """Return sensor status summary for SOC dashboard."""
        return {
            "sensor_id": self.sensor_id,
            "name": self.name,
            "type": self.sensor_type.value,
            "status": self.status.value,
            "enabled": self.config.enabled,
            "interface": self.config.interface,
            "stats": {
                "packets_captured": self.stats.packets_captured,
                "packets_dropped": self.stats.packets_dropped,
                "events_generated": self.stats.events_generated,
                "bytes_processed": self.stats.bytes_processed,
                "errors_count": self.stats.errors_count,
                "last_event_time": self.stats.last_event_time.isoformat() if self.stats.last_event_time else None,
                "last_heartbeat": self.stats.last_heartbeat.isoformat() if self.stats.last_heartbeat else None,
            },
        }
