"""
Response Engine.

Policy-controlled response actions with dry-run, manual approval, and audit trail.
Default mode is SAFE (alert_only).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

import structlog

logger = structlog.get_logger("response_engine")


class ResponsePolicy:
    """A response policy mapping risk levels to actions."""

    def __init__(
        self,
        policy_id: str,
        name: str,
        min_risk_score: float,
        action_type: str,
        require_approval: bool = True,
        enabled: bool = True,
    ):
        self.policy_id = policy_id
        self.name = name
        self.min_risk_score = min_risk_score
        self.action_type = action_type
        self.require_approval = require_approval
        self.enabled = enabled


class ResponseEngine:
    """
    Policy-controlled response engine.

    Evaluates risk assessments against policies and generates
    response actions. Defaults to SAFE mode (alert_only).

    Supports:
    - Dry-run mode (log only)
    - Manual approval mode
    - Automatic execution (requires opt-in)
    """

    def __init__(self, dry_run: bool = True, manual_approval: bool = True):
        self._policies: List[ResponsePolicy] = []
        self._actions: List[Dict[str, Any]] = []
        self._dry_run = dry_run
        self._manual_approval = manual_approval
        self._load_default_policies()

    def _load_default_policies(self) -> None:
        """Load safe default policies."""
        self._policies = [
            ResponsePolicy(
                "POL-001", "Critical Risk Alert", 75.0,
                "alert_only", require_approval=False,
            ),
            ResponsePolicy(
                "POL-002", "High Risk Monitoring", 50.0,
                "increase_monitoring", require_approval=True,
            ),
            ResponsePolicy(
                "POL-003", "Critical Risk Block", 85.0,
                "temporary_block", require_approval=True,
            ),
        ]

    def evaluate(
        self,
        risk_score: float,
        risk_level: str,
        source_entity: str,
        alert_id: Optional[str] = None,
        detections_summary: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Evaluate risk against policies and generate response actions.

        Returns list of response actions (pending, executed, or dry-run).
        """
        actions: List[Dict[str, Any]] = []

        for policy in self._policies:
            if not policy.enabled:
                continue
            if risk_score < policy.min_risk_score:
                continue

            action = {
                "action_id": str(uuid4()),
                "action_type": policy.action_type,
                "policy_id": policy.policy_id,
                "policy_name": policy.name,
                "requested_by": "system",
                "target": {"entity": source_entity},
                "confidence": risk_score / 100.0,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "alert_id": alert_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "is_dry_run": self._dry_run,
            }

            if self._dry_run:
                action["status"] = "dry_run"
                action["result"] = {"message": f"DRY RUN: Would execute {policy.action_type}"}
                logger.info(
                    "response_dry_run",
                    action_type=policy.action_type,
                    target=source_entity,
                    risk_score=risk_score,
                )
            elif policy.require_approval or self._manual_approval:
                action["status"] = "pending_approval"
                action["result"] = {"message": "Queued for manual approval"}
                logger.info(
                    "response_pending_approval",
                    action_type=policy.action_type,
                    target=source_entity,
                )
            else:
                action["status"] = "executed"
                action["result"] = self._execute_action(policy.action_type, source_entity)
                logger.info(
                    "response_executed",
                    action_type=policy.action_type,
                    target=source_entity,
                )

            actions.append(action)
            self._actions.append(action)

        return actions

    def _execute_action(self, action_type: str, target: str) -> Dict[str, Any]:
        """Execute a response action. In production, this would integrate with network devices."""
        # This is a placeholder — real implementation would call firewall APIs, etc.
        return {
            "message": f"Action {action_type} executed against {target}",
            "note": "Placeholder — production would integrate with network infrastructure",
            "executed_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_pending_actions(self) -> List[Dict[str, Any]]:
        """Get actions pending approval."""
        return [a for a in self._actions if a.get("status") == "pending_approval"]

    def approve_action(self, action_id: str, approved_by: str) -> Optional[Dict[str, Any]]:
        """Approve a pending action."""
        for action in self._actions:
            if action["action_id"] == action_id and action["status"] == "pending_approval":
                action["status"] = "approved"
                action["approved_by"] = approved_by
                action["approved_at"] = datetime.now(timezone.utc).isoformat()
                logger.info("response_approved", action_id=action_id, approved_by=approved_by)
                return action
        return None

    def reject_action(self, action_id: str, rejected_by: str) -> Optional[Dict[str, Any]]:
        """Reject a pending action."""
        for action in self._actions:
            if action["action_id"] == action_id and action["status"] == "pending_approval":
                action["status"] = "rejected"
                action["rejected_by"] = rejected_by
                logger.info("response_rejected", action_id=action_id, rejected_by=rejected_by)
                return action
        return None

    def get_all_actions(self) -> List[Dict[str, Any]]:
        """Get all response actions."""
        return self._actions

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_actions": len(self._actions),
            "pending": len(self.get_pending_actions()),
            "dry_run_mode": self._dry_run,
            "manual_approval": self._manual_approval,
            "policies": len(self._policies),
        }
