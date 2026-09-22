"""
NIDS ARC Suricata Adapter.

Ingests and normalizes Suricata EVE JSON telemetry (eve.json / UNIX domain socket).
Converts Suricata alert, flow, and DNS events into canonical NIDS ARC event schemas.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.sensors.base import BaseSensor, SensorConfig, SensorHealthStatus, SensorType


class SuricataAdapter(BaseSensor):
    """
    Adapter for Suricata IDS/IPS.
    Tails eve.json or reads from unix domain socket and normalizes EVE records.
    """

    def __init__(self, config: Optional[SensorConfig] = None):
        if config is None:
            config = SensorConfig(
                sensor_id="sensor-suricata-01",
                name="Suricata Engine",
                sensor_type=SensorType.SURICATA,
                enabled=False,
                log_path="/var/log/suricata/eve.json",
                extra_params={"alert_only": False},
            )
        super().__init__(config)
        self._file_handle = None
        self._file_position = 0

    def _map_severity(self, suricata_severity: int) -> str:
        """Suricata 1=high/crit, 2=med, 3=low, 4=info."""
        mapping = {1: "critical", 2: "high", 3: "medium", 4: "low"}
        return mapping.get(suricata_severity, "medium")

    def normalize_eve_record(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Normalize a Suricata EVE JSON record into NIDS ARC canonical event format."""
        try:
            event_type = record.get("event_type", "flow")
            timestamp_str = record.get("timestamp")
            if timestamp_str:
                try:
                    ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                except ValueError:
                    ts = datetime.now(timezone.utc)
            else:
                ts = datetime.now(timezone.utc)

            event = {
                "event_id": f"suricata-{record.get('flow_id', os.urandom(4).hex())}",
                "timestamp": ts,
                "source_type": "suricata",
                "sensor_id": self.sensor_id,
                "src_ip": record.get("src_ip", "0.0.0.0"),
                "src_port": record.get("src_port"),
                "dst_ip": record.get("dest_ip", "0.0.0.0"),
                "dst_port": record.get("dest_port"),
                "protocol": record.get("proto", "TCP").upper(),
                "event_type": event_type,
            }

            if event_type == "alert":
                alert_data = record.get("alert", {})
                event["attack_category"] = alert_data.get("category", "Intrusion Attempt")
                event["severity"] = self._map_severity(alert_data.get("severity", 3))
                event["signature_id"] = str(alert_data.get("signature_id"))
                event["signature_name"] = alert_data.get("signature")
            elif event_type == "flow":
                flow_data = record.get("flow", {})
                event["bytes_sent"] = flow_data.get("bytes_toserver", 0)
                event["bytes_received"] = flow_data.get("bytes_toclient", 0)
                event["packets_sent"] = flow_data.get("pkts_toserver", 0)
                event["packets_received"] = flow_data.get("pkts_toclient", 0)
                event["severity"] = "info"
            else:
                event["severity"] = "info"

            return event
        except Exception:
            self.stats.errors_count += 1
            return None

    async def start(self) -> None:
        """Start reading from Suricata log file if available."""
        if not self.config.enabled:
            self.status = SensorHealthStatus.UNCONFIGURED
            return

        log_path = self.config.log_path
        if log_path and os.path.exists(log_path):
            try:
                self._file_handle = open(log_path, "r", encoding="utf-8")
                self._file_handle.seek(0, os.SEEK_END)
                self._is_running = True
                self.status = SensorHealthStatus.ONLINE
                self.stats.last_heartbeat = datetime.now(timezone.utc)
            except Exception:
                self.status = SensorHealthStatus.ERROR
        else:
            self.status = SensorHealthStatus.OFFLINE

    async def stop(self) -> None:
        """Close file handles and stop."""
        self._is_running = False
        if self._file_handle:
            try:
                self._file_handle.close()
            except Exception:
                pass
            self._file_handle = None
        self.status = SensorHealthStatus.OFFLINE

    async def poll_events(self) -> List[Dict[str, Any]]:
        """Poll new lines from Suricata eve.json."""
        if not self._is_running or not self._file_handle:
            return []

        events = []
        lines = self._file_handle.readlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                norm = self.normalize_eve_record(record)
                if norm:
                    events.append(norm)
                    self.stats.events_generated += 1
            except json.JSONDecodeError:
                self.stats.errors_count += 1

        if events:
            now = datetime.now(timezone.utc)
            self.stats.last_event_time = now
            self.stats.last_heartbeat = now
        return events

    async def health_check(self) -> SensorHealthStatus:
        """Check if Suricata is active and eve.json is readable."""
        if not self.config.enabled:
            self.status = SensorHealthStatus.UNCONFIGURED
        elif self.config.log_path and os.path.exists(self.config.log_path):
            self.status = SensorHealthStatus.ONLINE
            self.stats.last_heartbeat = datetime.now(timezone.utc)
        else:
            self.status = SensorHealthStatus.OFFLINE
        return self.status
