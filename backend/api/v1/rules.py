"""
NIDS ARC Rules API Endpoints.

Provides endpoints to list, inspect, and toggle signature and behavioral detection rules.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.detection.signature import SignatureDetector

router = APIRouter(prefix="/rules", tags=["Rules"])

# Fallback detector if app orchestrator not yet initialized
_fallback_detector: Optional[SignatureDetector] = None


def _get_signature_detector() -> SignatureDetector:
    """Obtain active SignatureDetector from running orchestrator with fallback."""
    try:
        import backend.app as app_module
        if app_module.detection_orchestrator:
            sig = app_module.detection_orchestrator.get_detector("signature")
            if sig and isinstance(sig, SignatureDetector):
                return sig
    except Exception:
        pass

    global _fallback_detector
    if _fallback_detector is None:
        _fallback_detector = SignatureDetector()
    return _fallback_detector


class RuleToggleRequest(BaseModel):
    enabled: bool


@router.get("")
async def list_rules() -> Dict[str, Any]:
    """List all signature detection rules."""
    detector = _get_signature_detector()
    rules_data = []
    for rule in detector._rules:
        rules_data.append({
            "id": rule.rule_id,
            "name": rule.name,
            "severity": rule.severity,
            "category": rule.attack_category,
            "description": rule.description,
            "enabled": rule.enabled,
            "version": rule.version,
            "mitre_attack": rule.mitre_attack,
        })
    return {
        "rules": rules_data,
        "total": len(rules_data),
        "enabled_count": sum(1 for r in rules_data if r["enabled"]),
    }


@router.get("/{rule_id}")
async def get_rule(rule_id: str) -> Dict[str, Any]:
    """Get details for a specific rule."""
    detector = _get_signature_detector()
    for rule in detector._rules:
        if rule.rule_id == rule_id:
            return {
                "id": rule.rule_id,
                "name": rule.name,
                "severity": rule.severity,
                "category": rule.attack_category,
                "description": rule.description,
                "enabled": rule.enabled,
                "version": rule.version,
                "conditions": rule.conditions,
                "mitre_attack": rule.mitre_attack,
            }
    raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")


@router.put("/{rule_id}/toggle")
async def toggle_rule(rule_id: str, req: RuleToggleRequest) -> Dict[str, Any]:
    """Enable or disable a specific detection rule in the live engine."""
    detector = _get_signature_detector()
    for rule in detector._rules:
        if rule.rule_id == rule_id:
            rule.enabled = req.enabled
            return {"rule_id": rule_id, "enabled": rule.enabled}
    raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")
