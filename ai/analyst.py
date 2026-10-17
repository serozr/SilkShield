"""AI Analyst — orchestrates the AI security analysis pipeline."""

from __future__ import annotations

from typing import Any, Dict

from ai.prompts import SECURITY_ANALYST_PROMPT
from ai.providers import get_provider


async def analyze_threat(
    *,
    risk_score: int,
    risk_level: str,
    classification: str,
    confidence: float,
    evidence: list[str],
    intel_data: dict,
    ioc: str,
    ioc_type: str,
) -> Dict[str, Any]:
    """Build structured evidence and delegate to the configured AI provider."""

    structured = {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "classification": classification,
        "confidence": confidence,
        "evidence": evidence,
        "intelligence_summary": {
            "detections": intel_data.get("detections", 0),
            "total_engines": intel_data.get("total_engines", 0),
            "detection_ratio": intel_data.get("detection_ratio", 0),
            "reputation": intel_data.get("reputation", 0),
            "source": intel_data.get("source", "unknown"),
        },
    }

    provider = get_provider()
    return await provider.analyze(structured, SECURITY_ANALYST_PROMPT)
