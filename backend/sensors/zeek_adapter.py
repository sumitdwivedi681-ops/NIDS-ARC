"""
NIDS ARC Zeek (Bro) Adapter.

Ingests and normalizes Zeek connection and protocol logs (conn.log, dns.log).
Maps Zeek flow records into canonical NIDS ARC event schemas.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.sensors.base import BaseSensor, SensorConfig, SensorHealthStatus, SensorType


class ZeekAdapter(BaseSensor):
    """
    Adapter for Zeek network security monitor.
    Parses Zeek JSON logs (conn.log) into canonical events.
    """

    def __init__(self, config: Optional[SensorConfig] = None):
        if config is None:
            config = SensorConfig(
                sensor_id="sensor-zeek-01",
                name="Zeek Sensor",
                sensor_type=SensorType.ZEEK,
                enabled=False,
                log_path="/opt/zeek/logs/current/conn.log",
                extra_params={"json_format": True},
            )
        super().__init__(config)
        self._file_handle = None

    def normalize_zeek_record(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Normalize Zeek JSON conn.log record."""
        try:
            # Zeek ts is unix timestamp float
            ts_val = record.get("ts")
            if isinstance(ts_val, (int, float)):
                ts = datetime.fromtimestamp(ts_val, tz=timezone.utc)
            else:
                ts = datetime.now(timezone.utc)

            uid = record.get("uid", os.urandom(4).hex())
            src_ip = record.get("id.orig_h", record.get("orig_h", "0.0.0.0"))
            src_port = record.get("id.orig_p", record.get("orig_p"))
            dst_ip = record.get("id.resp_h", record.get("resp_h", "0.0.0.0"))
            dst_port = record.get("id.resp_p", record.get("resp_p"))
            proto = record.get("proto", "TCP").upper()

            orig_bytes = record.get("orig_bytes") or record.get("orig_ip_bytes") or 0
            resp_bytes = record.get("resp_bytes") or record.get("resp_ip_bytes") or 0
            orig_pkts = record.get("orig_pkts", 0)
            resp_pkts = record.get("resp_pkts", 0)
            duration_s = record.get("duration", 0.0)

            conn_state = record.get("conn_state", "")
            # S0 = Connection attempt seen, no reply (possible scan)
            severity = "medium" if conn_state in ("S0", "REJ") else "info"

            return {
                "event_id": f"zeek-{uid}",
                "timestamp": ts,
                "source_type": "zeek",
                "sensor_id": self.sensor_id,
                "src_ip": str(src_ip),
                "src_port": int(src_port) if src_port is not None else None,
                "dst_ip": str(dst_ip),
                "dst_port": int(dst_port) if dst_port is not None else None,
                "protocol": proto,
                "bytes_sent": int(orig_bytes) if isinstance(orig_bytes, (int, float)) else 0,
                "bytes_received": int(resp_bytes) if isinstance(resp_bytes, (int, float)) else 0,
                "packets_sent": int(orig_pkts) if orig_pkts else 0,
                "packets_received": int(resp_pkts) if resp_pkts else 0,
                "duration_ms": int(float(duration_s) * 1000) if duration_s else 0,
                "event_type": "flow",
                "severity": severity,
                "tags": [f"zeek_state:{conn_state}"] if conn_state else [],
            }
        except Exception:
            self.stats.errors_count += 1
            return None

    async def start(self) -> None:
        """Initialize Zeek log reader."""
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
        """Stop Zeek reader."""
        self._is_running = False
        if self._file_handle:
            try:
                self._file_handle.close()
            except Exception:
                pass
            self._file_handle = None
        self.status = SensorHealthStatus.OFFLINE

    async def poll_events(self) -> List[Dict[str, Any]]:
        """Read newly appended JSON records from conn.log."""
        if not self._is_running or not self._file_handle:
            return []

        events = []
        lines = self._file_handle.readlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                record = json.loads(line)
                norm = self.normalize_zeek_record(record)
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
        """Check status of Zeek log source."""
        if not self.config.enabled:
            self.status = SensorHealthStatus.UNCONFIGURED
        elif self.config.log_path and os.path.exists(self.config.log_path):
            self.status = SensorHealthStatus.ONLINE
            self.stats.last_heartbeat = datetime.now(timezone.utc)
        else:
            self.status = SensorHealthStatus.OFFLINE
        return self.status
