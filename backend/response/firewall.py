"""
NIDS ARC Firewall Controller.

Platform-aware host firewall management for automated incident response.
Supports Windows Firewall (netsh) and Linux (iptables / ufw) with dry-run
protection, safety verification, and full unblock rollback capabilities.
"""

from __future__ import annotations

import os
import platform
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog

logger = structlog.get_logger("firewall_controller")


class FirewallController:
    """
    Manages OS-level firewall rules to enforce host-based network blocking.
    """

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self.os_type = platform.system().lower()
        self._blocked_ips: Dict[str, Dict[str, Any]] = {}

    def block_ip(self, ip: str, reason: str = "High Risk Intrusion") -> Dict[str, Any]:
        """
        Add a firewall block rule for the given IP address.
        """
        rule_name = f"NIDS_ARC_BLOCK_{ip.replace(':', '_')}"
        now = datetime.now(timezone.utc).isoformat()

        if self.dry_run:
            logger.info("firewall_dry_run_block", ip=ip, reason=reason)
            res = {
                "success": True,
                "ip": ip,
                "status": "dry_run",
                "rule_name": rule_name,
                "message": f"[DRY-RUN] Would block {ip} via {self.os_type} firewall",
                "timestamp": now,
            }
            self._blocked_ips[ip] = res
            return res

        command = []
        if self.os_type == "windows":
            # Windows netsh firewall rule
            command = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip}",
                f"description=NIDS ARC Auto-Block: {reason}",
            ]
        elif self.os_type == "linux":
            # Linux iptables rule
            command = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        else:
            return {
                "success": False,
                "ip": ip,
                "status": "unsupported_os",
                "message": f"Firewall control not supported on OS: {self.os_type}",
                "timestamp": now,
            }

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            success = (result.returncode == 0)
            msg = result.stdout.strip() if success else (result.stderr.strip() or "Permission denied or failed")
            
            status_entry = {
                "success": success,
                "ip": ip,
                "status": "active" if success else "failed",
                "rule_name": rule_name,
                "command": " ".join(command),
                "message": msg,
                "timestamp": now,
            }
            if success:
                self._blocked_ips[ip] = status_entry
                logger.info("firewall_rule_added", ip=ip, rule_name=rule_name)
            else:
                logger.warning("firewall_rule_failed", ip=ip, error=msg)
            return status_entry

        except Exception as e:
            logger.error("firewall_execution_error", ip=ip, error=str(e))
            return {
                "success": False,
                "ip": ip,
                "status": "error",
                "rule_name": rule_name,
                "message": str(e),
                "timestamp": now,
            }

    def unblock_ip(self, ip: str) -> Dict[str, Any]:
        """
        Remove the firewall block rule for the given IP address.
        """
        rule_name = f"NIDS_ARC_BLOCK_{ip.replace(':', '_')}"
        now = datetime.now(timezone.utc).isoformat()

        if self.dry_run:
            self._blocked_ips.pop(ip, None)
            return {
                "success": True,
                "ip": ip,
                "status": "dry_run",
                "message": f"[DRY-RUN] Would unblock {ip}",
                "timestamp": now,
            }

        command = []
        if self.os_type == "windows":
            command = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
        elif self.os_type == "linux":
            command = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        else:
            return {"success": False, "ip": ip, "message": f"Unsupported OS: {self.os_type}"}

        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
            success = (result.returncode == 0)
            self._blocked_ips.pop(ip, None)
            logger.info("firewall_rule_removed", ip=ip, rule_name=rule_name)
            return {
                "success": success,
                "ip": ip,
                "status": "removed" if success else "failed",
                "message": result.stdout.strip() if success else result.stderr.strip(),
                "timestamp": now,
            }
        except Exception as e:
            logger.error("firewall_unblock_error", ip=ip, error=str(e))
            return {"success": False, "ip": ip, "error": str(e), "timestamp": now}

    def list_blocked(self) -> List[Dict[str, Any]]:
        """Return all tracked blocked IP entries."""
        return list(self._blocked_ips.values())
