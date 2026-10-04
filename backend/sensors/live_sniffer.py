"""
NIDS ARC Live Packet Sniffer Adapter.

Captures live network packets from active interfaces (Wi-Fi / Ethernet)
using Scapy, extracts 5-tuple flow metadata and canonical security events,
and feeds the NIDS ARC detection orchestrator in Real Mode.
"""

from __future__ import annotations

import asyncio
import os
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

import structlog

from backend.sensors.base import BaseSensor, SensorConfig, SensorHealthStatus, SensorType

logger = structlog.get_logger("live_sniffer")


class LiveSniffer(BaseSensor):
    """
    Live packet sniffer sensor adapter.
    Captures raw packets, parses protocol layers, and produces canonical events.
    """

    def __init__(self, config: Optional[SensorConfig] = None):
        if config is None:
            config = SensorConfig(
                sensor_id="sensor-live-01",
                name="Live Network Sniffer (Scapy)",
                sensor_type=SensorType.LIVE_SNIFFER,
                enabled=True,
                interface=None,  # None = default active interface
                buffer_size=5000,
                extra_params={"promisc": False, "filter": ""},
            )
        super().__init__(config)

        self._queue: deque[Dict[str, Any]] = deque(maxlen=config.buffer_size)
        self._sniffer_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._diagnostic_info = "Initialized, waiting to start"

    async def start(self) -> None:
        """Start background packet capture."""
        if self._is_running:
            return

        self._is_running = True
        self._stop_event.clear()

        # Run capture in a dedicated background daemon thread
        self._sniffer_thread = threading.Thread(
            target=self._capture_worker,
            name="NIDS-LiveSniffer",
            daemon=True,
        )
        self._sniffer_thread.start()
        self.status = SensorHealthStatus.ONLINE
        self.stats.last_heartbeat = datetime.now(timezone.utc)
        logger.info("live_sniffer_started", interface=self.config.interface or "default")

    async def stop(self) -> None:
        """Stop background packet capture."""
        self._is_running = False
        self._stop_event.set()
        if self._sniffer_thread and self._sniffer_thread.is_alive():
            self._sniffer_thread.join(timeout=2.0)
        self.status = SensorHealthStatus.OFFLINE
        logger.info("live_sniffer_stopped")

    def _capture_worker(self) -> None:
        """Worker thread function executing Scapy packet sniffer."""
        try:
            from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNS, Raw
        except ImportError:
            self.status = SensorHealthStatus.ERROR
            self._diagnostic_info = "Scapy not installed or import error"
            logger.error("scapy_import_failed")
            return

        def process_packet(pkt: Any) -> None:
            if self._stop_event.is_set():
                return

            try:
                self.stats.packets_captured += 1
                pkt_len = len(pkt)
                self.stats.bytes_processed += pkt_len

                if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
                    return

                is_ipv6 = pkt.haslayer(IPv6)
                ip_layer = pkt[IPv6] if is_ipv6 else pkt[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst

                protocol = "OTHER"
                src_port = None
                dst_port = None
                flags = []
                event_type = "connection"
                attack_hint = None

                if pkt.haslayer(TCP):
                    protocol = "TCP"
                    tcp_layer = pkt[TCP]
                    src_port = int(tcp_layer.sport)
                    dst_port = int(tcp_layer.dport)
                    flags_str = str(tcp_layer.flags)
                    flags = [f for f in flags_str]

                    # Basic packet heuristics
                    if "S" in flags_str and "A" not in flags_str:
                        event_type = "tcp_syn"
                    elif "F" in flags_str or "R" in flags_str:
                        event_type = "tcp_close"

                elif pkt.haslayer(UDP):
                    protocol = "UDP"
                    udp_layer = pkt[UDP]
                    src_port = int(udp_layer.sport)
                    dst_port = int(udp_layer.dport)
                    event_type = "udp_flow"

                    if pkt.haslayer(DNS):
                        event_type = "dns_query"

                elif pkt.haslayer(ICMP):
                    protocol = "ICMP"
                    event_type = "icmp_echo"

                # Check for suspicious port signatures
                if dst_port in (22, 2222) and protocol == "TCP":
                    event_type = "ssh_traffic"
                elif dst_port in (23, 2323) and protocol == "TCP":
                    event_type = "telnet_traffic"
                    attack_hint = "Insecure Telnet Connection"
                elif dst_port in (80, 443, 8080, 8443):
                    event_type = "http_traffic"

                event = {
                    "event_id": f"live-{uuid4().hex[:12]}",
                    "timestamp": datetime.now(timezone.utc),
                    "source_type": "real",
                    "sensor_id": self.sensor_id,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "bytes_sent": pkt_len,
                    "bytes_received": 0,
                    "packets_sent": 1,
                    "packets_received": 0,
                    "duration_ms": 1,
                    "event_type": event_type,
                    "attack_category": attack_hint,
                    "severity": "info" if not attack_hint else "medium",
                    "tags": ["live_traffic", protocol.lower()],
                }

                self._queue.append(event)
                self.stats.events_generated += 1
                self.stats.last_event_time = datetime.now(timezone.utc)

            except Exception as err:
                self.stats.errors_count += 1
                logger.debug("packet_parse_error", error=str(err))

        try:
            sniff_kwargs: Dict[str, Any] = {
                "prn": process_packet,
                "store": False,
                "stop_filter": lambda _: self._stop_event.is_set(),
            }
            if self.config.interface:
                sniff_kwargs["iface"] = self.config.interface
            if self.config.extra_params.get("filter"):
                sniff_kwargs["filter"] = self.config.extra_params["filter"]

            self.status = SensorHealthStatus.ONLINE
            self._diagnostic_info = "Actively sniffing packets"
            sniff(**sniff_kwargs)

        except Exception as e:
            self.status = SensorHealthStatus.DEGRADED
            self._diagnostic_info = f"Capture degraded/failed: {str(e)}"
            logger.warning("live_sniffer_exception", error=str(e))

    async def poll_events(self) -> List[Dict[str, Any]]:
        """Drain captured events from internal buffer."""
        events: List[Dict[str, Any]] = []
        while self._queue and len(events) < 100:
            events.append(self._queue.popleft())

        now = datetime.now(timezone.utc)
        self.stats.last_heartbeat = now
        return events

    async def health_check(self) -> SensorHealthStatus:
        """Return operational status."""
        if not self.config.enabled:
            self.status = SensorHealthStatus.OFFLINE
        elif not self._is_running:
            self.status = SensorHealthStatus.OFFLINE
        elif self._sniffer_thread and not self._sniffer_thread.is_alive():
            self.status = SensorHealthStatus.ERROR
        else:
            self.stats.last_heartbeat = datetime.now(timezone.utc)
        return self.status

    def get_info(self) -> Dict[str, Any]:
        info = super().get_info()
        info["diagnostic"] = self._diagnostic_info
        return info
