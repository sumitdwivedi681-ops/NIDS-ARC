"""
Simulation Engine.

Generates controlled synthetic network events for demonstration and testing.
Every simulated event is clearly marked: source_type = "simulation"
"""

from __future__ import annotations

import asyncio
import random
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

import structlog

from backend.detection import DetectionContext

logger = structlog.get_logger("simulation")

# Realistic IP address pools
INTERNAL_IPS = [f"10.0.{subnet}.{host}" for subnet in range(1, 6) for host in range(1, 51)]
EXTERNAL_IPS = [
    "203.0.113.1", "203.0.113.15", "203.0.113.42", "203.0.113.100",
    "198.51.100.5", "198.51.100.23", "198.51.100.77",
    "192.0.2.10", "192.0.2.55", "192.0.2.128",
    "185.220.101.1", "91.219.237.1",  # Known Tor exit nodes (test IPs)
    "45.33.32.156",  # Common scan target IP
]

PROTOCOLS = ["TCP", "UDP", "ICMP"]
NORMAL_PORTS = [80, 443, 8080, 8443, 53, 25, 587, 993, 110, 143, 3306, 5432]
SUSPICIOUS_PORTS = [22, 23, 4444, 5555, 6666, 8888, 9999, 445, 3389, 135, 139]

ATTACK_SCENARIOS = [
    "port_scan",
    "brute_force",
    "data_exfiltration",
    "dns_tunneling",
    "c2_communication",
    "lateral_movement",
]


class SimulationEngine:
    """
    Generates synthetic network events for demonstration.

    Events are clearly marked as simulation data and never
    presented as real network traffic.
    """

    def __init__(
        self,
        events_per_second: int = 10,
        attack_probability: float = 0.05,
        seed: int = 42,
    ):
        self.events_per_second = events_per_second
        self.attack_probability = attack_probability
        self._rng = random.Random(seed)
        self._running = False
        self._sensor_id = str(uuid4())
        self._total_events = 0

    def generate_normal_event(self) -> Dict[str, Any]:
        """Generate a normal network traffic event."""
        src_ip = self._rng.choice(INTERNAL_IPS)
        dst_ip = self._rng.choice(EXTERNAL_IPS + INTERNAL_IPS)
        protocol = self._rng.choices(PROTOCOLS, weights=[0.7, 0.25, 0.05])[0]

        return {
            "event_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc),
            "source_type": "simulation",
            "sensor_id": self._sensor_id,
            "src_ip": src_ip,
            "src_port": self._rng.randint(1024, 65535),
            "dst_ip": dst_ip,
            "dst_port": self._rng.choice(NORMAL_PORTS),
            "protocol": protocol,
            "bytes_sent": int(self._rng.expovariate(1 / 500)),
            "bytes_received": int(self._rng.expovariate(1 / 1000)),
            "packets_sent": self._rng.randint(1, 20),
            "packets_received": self._rng.randint(1, 30),
            "duration_ms": int(self._rng.expovariate(1 / 200)),
            "event_type": "connection",
            "severity": "info",
        }

    def generate_attack_event(self) -> Dict[str, Any]:
        """Generate a simulated attack event."""
        scenario = self._rng.choice(ATTACK_SCENARIOS)

        if scenario == "port_scan":
            return self._gen_port_scan()
        elif scenario == "brute_force":
            return self._gen_brute_force()
        elif scenario == "data_exfiltration":
            return self._gen_data_exfil()
        elif scenario == "dns_tunneling":
            return self._gen_dns_tunnel()
        elif scenario == "c2_communication":
            return self._gen_c2()
        elif scenario == "lateral_movement":
            return self._gen_lateral()
        else:
            return self.generate_normal_event()

    def _gen_port_scan(self) -> Dict[str, Any]:
        attacker = self._rng.choice(EXTERNAL_IPS)
        target = self._rng.choice(INTERNAL_IPS)
        return {
            "event_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc),
            "source_type": "simulation",
            "sensor_id": self._sensor_id,
            "src_ip": attacker,
            "src_port": self._rng.randint(1024, 65535),
            "dst_ip": target,
            "dst_port": self._rng.randint(1, 1024),
            "protocol": "TCP",
            "bytes_sent": self._rng.randint(40, 120),
            "bytes_received": 0,
            "packets_sent": 1,
            "packets_received": 0,
            "duration_ms": self._rng.randint(1, 50),
            "event_type": "connection",
            "attack_category": "reconnaissance",
            "severity": "medium",
        }

    def _gen_brute_force(self) -> Dict[str, Any]:
        attacker = self._rng.choice(EXTERNAL_IPS)
        target = self._rng.choice(INTERNAL_IPS)
        return {
            "event_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc),
            "source_type": "simulation",
            "sensor_id": self._sensor_id,
            "src_ip": attacker,
            "src_port": self._rng.randint(1024, 65535),
            "dst_ip": target,
            "dst_port": 22,
            "protocol": "TCP",
            "bytes_sent": self._rng.randint(100, 500),
            "bytes_received": self._rng.randint(50, 200),
            "packets_sent": self._rng.randint(3, 10),
            "packets_received": self._rng.randint(2, 8),
            "duration_ms": self._rng.randint(100, 3000),
            "event_type": "connection",
            "attack_category": "credential_access",
            "severity": "high",
        }

    def _gen_data_exfil(self) -> Dict[str, Any]:
        source = self._rng.choice(INTERNAL_IPS)
        dest = self._rng.choice(EXTERNAL_IPS)
        return {
            "event_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc),
            "source_type": "simulation",
            "sensor_id": self._sensor_id,
            "src_ip": source,
            "src_port": self._rng.randint(1024, 65535),
            "dst_ip": dest,
            "dst_port": self._rng.choice([443, 8443, 8080]),
            "protocol": "TCP",
            "bytes_sent": self._rng.randint(10_000_000, 100_000_000),
            "bytes_received": self._rng.randint(100, 1000),
            "packets_sent": self._rng.randint(1000, 10000),
            "packets_received": self._rng.randint(100, 500),
            "duration_ms": self._rng.randint(5000, 60000),
            "event_type": "connection",
            "attack_category": "exfiltration",
            "severity": "critical",
        }

    def _gen_dns_tunnel(self) -> Dict[str, Any]:
        source = self._rng.choice(INTERNAL_IPS)
        return {
            "event_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc),
            "source_type": "simulation",
            "sensor_id": self._sensor_id,
            "src_ip": source,
            "src_port": self._rng.randint(1024, 65535),
            "dst_ip": self._rng.choice(EXTERNAL_IPS),
            "dst_port": 53,
            "protocol": "UDP",
            "bytes_sent": self._rng.randint(500, 5000),
            "bytes_received": self._rng.randint(100, 500),
            "packets_sent": self._rng.randint(5, 50),
            "packets_received": self._rng.randint(2, 20),
            "duration_ms": self._rng.randint(10, 500),
            "event_type": "dns_query",
            "attack_category": "exfiltration",
            "severity": "high",
        }

    def _gen_c2(self) -> Dict[str, Any]:
        compromised = self._rng.choice(INTERNAL_IPS)
        c2_server = self._rng.choice(EXTERNAL_IPS[:4])
        return {
            "event_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc),
            "source_type": "simulation",
            "sensor_id": self._sensor_id,
            "src_ip": compromised,
            "src_port": self._rng.randint(1024, 65535),
            "dst_ip": c2_server,
            "dst_port": self._rng.choice(SUSPICIOUS_PORTS),
            "protocol": "TCP",
            "bytes_sent": self._rng.randint(100, 2000),
            "bytes_received": self._rng.randint(500, 5000),
            "packets_sent": self._rng.randint(2, 10),
            "packets_received": self._rng.randint(5, 20),
            "duration_ms": self._rng.randint(1000, 30000),
            "event_type": "connection",
            "attack_category": "command_and_control",
            "severity": "high",
        }

    def _gen_lateral(self) -> Dict[str, Any]:
        source = self._rng.choice(INTERNAL_IPS)
        target = self._rng.choice([ip for ip in INTERNAL_IPS if ip != source])
        return {
            "event_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc),
            "source_type": "simulation",
            "sensor_id": self._sensor_id,
            "src_ip": source,
            "src_port": self._rng.randint(1024, 65535),
            "dst_ip": target,
            "dst_port": self._rng.choice([445, 135, 139, 3389]),
            "protocol": "TCP",
            "bytes_sent": self._rng.randint(200, 5000),
            "bytes_received": self._rng.randint(100, 3000),
            "packets_sent": self._rng.randint(5, 30),
            "packets_received": self._rng.randint(3, 20),
            "duration_ms": self._rng.randint(100, 5000),
            "event_type": "connection",
            "attack_category": "lateral_movement",
            "severity": "high",
        }

    def generate_event(self) -> Dict[str, Any]:
        """Generate a single event (normal or attack based on probability)."""
        self._total_events += 1
        if self._rng.random() < self.attack_probability:
            return self.generate_attack_event()
        return self.generate_normal_event()

    def generate_batch(self, count: int = 10) -> List[Dict[str, Any]]:
        """Generate a batch of events."""
        return [self.generate_event() for _ in range(count)]

    @property
    def sensor_id(self) -> str:
        return self._sensor_id
