"""
Signature Detection Engine.

Rule-based pattern matching detector. Loads rules from configuration,
matches events against active rules, returns DetectionResults with
full rule provenance.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog
import yaml

from backend.detection import Detector, DetectionContext, DetectionResultData

logger = structlog.get_logger("signature_detector")


class SignatureRule:
    """A single signature detection rule."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        severity: str,
        conditions: Dict[str, Any],
        attack_category: str = "",
        mitre_attack: Optional[Dict[str, str]] = None,
        description: str = "",
        enabled: bool = True,
        version: int = 1,
    ):
        self.rule_id = rule_id
        self.name = name
        self.severity = severity
        self.conditions = conditions
        self.attack_category = attack_category
        self.mitre_attack = mitre_attack
        self.description = description
        self.enabled = enabled
        self.version = version
        self._compiled_patterns: Dict[str, re.Pattern] = {}
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for performance."""
        for key, value in self.conditions.items():
            if isinstance(value, str) and value.startswith("regex:"):
                self._compiled_patterns[key] = re.compile(value[6:], re.IGNORECASE)

    def matches(self, context: DetectionContext) -> tuple[bool, Dict[str, Any]]:
        """
        Check if the event matches this rule.

        Returns:
            Tuple of (matched: bool, evidence: dict)
        """
        evidence: Dict[str, Any] = {}

        for field_name, condition in self.conditions.items():
            value = getattr(context, field_name, None)
            if value is None:
                value = context.metadata.get(field_name)

            if value is None:
                return False, {}

            if field_name in self._compiled_patterns:
                pattern = self._compiled_patterns[field_name]
                if not pattern.search(str(value)):
                    return False, {}
                evidence[field_name] = f"matched pattern: {condition}"
            elif isinstance(condition, list):
                if value not in condition and str(value) not in [str(c) for c in condition]:
                    return False, {}
                evidence[field_name] = f"{value} in {condition}"
            elif isinstance(condition, dict):
                # Range conditions: {"min": x, "max": y}
                if "min" in condition and value < condition["min"]:
                    return False, {}
                if "max" in condition and value > condition["max"]:
                    return False, {}
                evidence[field_name] = f"{value} in range {condition}"
            else:
                if str(value) != str(condition):
                    return False, {}
                evidence[field_name] = f"{field_name}={value}"

        return True, evidence


class SignatureDetector(Detector):
    """
    Signature-based detection engine.

    Matches events against a configurable ruleset. Rules can be loaded
    from YAML configuration files and managed via API.
    """

    def __init__(self):
        self._rules: List[SignatureRule] = []
        self._rules_loaded = False

    @property
    def name(self) -> str:
        return "signature"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def initialize(self) -> None:
        """Load default rules on startup."""
        if not self._rules_loaded:
            self._load_default_rules()
            self._rules_loaded = True
            logger.info("signature_detector_initialized", rule_count=len(self._rules))

    def _load_default_rules(self) -> None:
        """Load built-in detection rules."""
        default_rules = [
            SignatureRule(
                rule_id="SIG-001",
                name="Port Scan Detection",
                severity="medium",
                conditions={"dst_port": {"min": 1, "max": 1024}, "duration_ms": {"min": 0, "max": 100}},
                attack_category="reconnaissance",
                mitre_attack={"tactic": "Reconnaissance", "technique": "T1046", "name": "Network Service Discovery"},
                description="Detects rapid connections to multiple low ports indicating port scanning",
            ),
            SignatureRule(
                rule_id="SIG-002",
                name="SSH Brute Force",
                severity="high",
                conditions={"dst_port": 22, "protocol": "TCP"},
                attack_category="credential_access",
                mitre_attack={"tactic": "Credential Access", "technique": "T1110", "name": "Brute Force"},
                description="Multiple SSH connection attempts indicating brute force attack",
            ),
            SignatureRule(
                rule_id="SIG-003",
                name="DNS Tunneling Indicator",
                severity="high",
                conditions={"dst_port": 53, "bytes_sent": {"min": 500}},
                attack_category="exfiltration",
                mitre_attack={"tactic": "Exfiltration", "technique": "T1048", "name": "Exfiltration Over Alternative Protocol"},
                description="Large DNS requests may indicate DNS tunneling for data exfiltration",
            ),
            SignatureRule(
                rule_id="SIG-004",
                name="Suspicious Outbound Traffic",
                severity="medium",
                conditions={"dst_port": [4444, 5555, 6666, 8888, 9999], "protocol": "TCP"},
                attack_category="command_and_control",
                mitre_attack={"tactic": "Command and Control", "technique": "T1571", "name": "Non-Standard Port"},
                description="Outbound connection to commonly used C2 ports",
            ),
            SignatureRule(
                rule_id="SIG-005",
                name="Large Data Transfer",
                severity="medium",
                conditions={"bytes_sent": {"min": 10000000}},
                attack_category="exfiltration",
                mitre_attack={"tactic": "Exfiltration", "technique": "T1030", "name": "Data Transfer Size Limits"},
                description="Unusually large outbound data transfer",
            ),
            SignatureRule(
                rule_id="SIG-006",
                name="Telnet Connection",
                severity="high",
                conditions={"dst_port": 23, "protocol": "TCP"},
                attack_category="initial_access",
                mitre_attack={"tactic": "Initial Access", "technique": "T1021", "name": "Remote Services"},
                description="Telnet connection detected — insecure protocol",
            ),
            SignatureRule(
                rule_id="SIG-007",
                name="FTP Data Transfer",
                severity="low",
                conditions={"dst_port": [20, 21], "protocol": "TCP"},
                attack_category="lateral_movement",
                mitre_attack={"tactic": "Lateral Movement", "technique": "T1021", "name": "Remote Services"},
                description="FTP connection detected — unencrypted file transfer",
            ),
            SignatureRule(
                rule_id="SIG-008",
                name="ICMP Flood Indicator",
                severity="medium",
                conditions={"protocol": "ICMP", "packets_sent": {"min": 100}},
                attack_category="impact",
                mitre_attack={"tactic": "Impact", "technique": "T1498", "name": "Network Denial of Service"},
                description="High volume ICMP traffic indicating potential flood attack",
            ),
        ]
        self._rules.extend(default_rules)

    def load_rules_from_yaml(self, yaml_content: str) -> int:
        """Load rules from YAML string. Returns count of rules loaded."""
        try:
            data = yaml.safe_load(yaml_content)
            if not isinstance(data, dict) or "rules" not in data:
                return 0
            count = 0
            for rule_data in data["rules"]:
                rule = SignatureRule(
                    rule_id=rule_data["id"],
                    name=rule_data["name"],
                    severity=rule_data.get("severity", "info"),
                    conditions=rule_data.get("conditions", {}),
                    attack_category=rule_data.get("attack_category", ""),
                    mitre_attack=rule_data.get("mitre_attack"),
                    description=rule_data.get("description", ""),
                    enabled=rule_data.get("enabled", True),
                    version=rule_data.get("version", 1),
                )
                self._rules.append(rule)
                count += 1
            logger.info("rules_loaded_from_yaml", count=count)
            return count
        except Exception as e:
            logger.error("rule_loading_failed", error=str(e))
            return 0

    async def detect(self, context: DetectionContext) -> List[DetectionResultData]:
        """Match event against all enabled rules."""
        results: List[DetectionResultData] = []

        for rule in self._rules:
            if not rule.enabled:
                continue

            matched, evidence = rule.matches(context)
            if matched:
                results.append(DetectionResultData(
                    event_id=context.event_id,
                    detector=self.name,
                    detector_version=self.version,
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    confidence=0.85,  # Signature matches have high confidence
                    attack_category=rule.attack_category,
                    evidence={
                        "rule_name": rule.name,
                        "rule_version": rule.version,
                        "matched_conditions": evidence,
                        "description": rule.description,
                    },
                    explanation=f"Matched signature rule '{rule.name}' ({rule.rule_id})",
                    mitre_attack=rule.mitre_attack,
                    tags=["signature", rule.attack_category] if rule.attack_category else ["signature"],
                ))

        return results

    def get_rules(self) -> List[Dict[str, Any]]:
        """Get all rules with their status."""
        return [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "severity": r.severity,
                "enabled": r.enabled,
                "attack_category": r.attack_category,
                "version": r.version,
            }
            for r in self._rules
        ]

    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule by ID."""
        for rule in self._rules:
            if rule.rule_id == rule_id:
                rule.enabled = True
                return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule by ID."""
        for rule in self._rules:
            if rule.rule_id == rule_id:
                rule.enabled = False
                return True
        return False
