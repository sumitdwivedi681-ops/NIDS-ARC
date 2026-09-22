"""
Threat Intelligence Module.

IOC storage, matching, and mock adapter.
Mock data is explicitly labeled as mock.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

import structlog

logger = structlog.get_logger("threat_intel")


class ThreatIntelStore:
    """In-memory IOC store. Production would use database backend."""

    def __init__(self):
        self._iocs: Dict[str, Dict[str, Any]] = {}  # value → IOC record
        self._loaded = False

    def add_ioc(
        self,
        indicator_type: str,
        value: str,
        source: str,
        confidence: float = 0.5,
        severity: str = "medium",
        tags: Optional[List[str]] = None,
    ) -> str:
        """Add an IOC to the store."""
        ioc_id = str(uuid4())
        self._iocs[value] = {
            "id": ioc_id,
            "indicator_type": indicator_type,
            "value": value,
            "source": source,
            "confidence": confidence,
            "severity": severity,
            "tags": tags or [],
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "is_active": True,
        }
        return ioc_id

    def match(self, value: str) -> Optional[Dict[str, Any]]:
        """Check if a value matches any active IOC."""
        ioc = self._iocs.get(value)
        if ioc and ioc["is_active"]:
            ioc["last_seen"] = datetime.now(timezone.utc).isoformat()
            return ioc
        return None

    def match_event(self, src_ip: str, dst_ip: str) -> List[Dict[str, Any]]:
        """Check event IPs against IOC database."""
        matches = []
        for ip in [src_ip, dst_ip]:
            match = self.match(ip)
            if match:
                matches.append(match)
        return matches

    def get_all(self) -> List[Dict[str, Any]]:
        """Get all IOCs."""
        return list(self._iocs.values())

    def load_mock_data(self) -> int:
        """
        Load mock threat intelligence data.

        NOTE: This is MOCK data for development and demonstration.
        It does NOT represent real threat intelligence.
        """
        mock_iocs = [
            ("ip", "185.220.101.1", "mock_feed", 0.9, "high", ["tor_exit", "mock_data"]),
            ("ip", "91.219.237.1", "mock_feed", 0.85, "high", ["known_scanner", "mock_data"]),
            ("ip", "45.33.32.156", "mock_feed", 0.7, "medium", ["suspicious", "mock_data"]),
            ("domain", "evil-c2-server.example.com", "mock_feed", 0.95, "critical", ["c2", "mock_data"]),
            ("domain", "malware-drop.example.net", "mock_feed", 0.9, "critical", ["malware", "mock_data"]),
            ("hash", "e99a18c428cb38d5f260853678922e03", "mock_feed", 0.95, "critical", ["malware_hash", "mock_data"]),
            ("ip", "203.0.113.42", "mock_feed", 0.6, "medium", ["suspicious_scanner", "mock_data"]),
            ("ip", "198.51.100.77", "mock_feed", 0.75, "high", ["brute_force_source", "mock_data"]),
        ]

        count = 0
        for itype, value, source, conf, sev, tags in mock_iocs:
            self.add_ioc(itype, value, source, conf, sev, tags)
            count += 1

        self._loaded = True
        logger.info("mock_ti_loaded", count=count, note="MOCK data — not real threat intelligence")
        return count

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_iocs": len(self._iocs),
            "active_iocs": sum(1 for i in self._iocs.values() if i["is_active"]),
            "data_source": "mock" if self._loaded else "none",
        }
