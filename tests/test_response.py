"""
Unit tests for Firewall Controller and Response Engine.
"""

import pytest
from backend.response.firewall import FirewallController
from backend.response import ResponseEngine


def test_firewall_controller_dry_run():
    fw = FirewallController(dry_run=True)
    block_res = fw.block_ip("203.0.113.99", reason="Test Infiltration")
    assert block_res["success"] is True
    assert block_res["status"] == "dry_run"
    assert "203.0.113.99" in [b["ip"] for b in fw.list_blocked()]

    unblock_res = fw.unblock_ip("203.0.113.99")
    assert unblock_res["success"] is True
    assert "203.0.113.99" not in [b["ip"] for b in fw.list_blocked()]


def test_response_engine_policies():
    engine = ResponseEngine(dry_run=False, manual_approval=True)

    # Low risk - no action
    actions_low = engine.evaluate(risk_score=20.0, risk_level="low", source_entity="192.168.1.10")
    assert len(actions_low) == 0

    # High risk - triggers monitoring and alert
    actions_high = engine.evaluate(risk_score=88.0, risk_level="critical", source_entity="198.51.100.5")
    assert len(actions_high) >= 2

    # Check pending approvals
    pending = engine.get_pending_actions()
    assert len(pending) > 0

    # Approve action
    action_to_approve = pending[0]["action_id"]
    approved = engine.approve_action(action_to_approve, approved_by="admin")
    assert approved is not None
    assert approved["status"] == "approved"
