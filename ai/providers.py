"""AI Providers — abstraction layer for IBM Granite and demo fallback.

Architecture:
    AIProvider (ABC)
    ├── GraniteProvider      — IBM Granite via REST API
    └── DemoFallbackProvider — deterministic, no LLM required
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, Dict

import httpx

from app.config import settings


class AIProvider(ABC):
    """Abstract base for all AI providers."""

    @abstractmethod
    async def analyze(
        self,
        evidence: Dict[str, Any],
        system_prompt: str,
    ) -> Dict[str, Any]:
        ...


# ─── Granite ────────────────────────────────────────────────── #

class GraniteProvider(AIProvider):
    """IBM Granite provider via an OpenAI-compatible chat endpoint."""

    def __init__(self) -> None:
        self.api_url = settings.granite_api_url
        self.api_key = settings.granite_api_key
        self.model_id = settings.granite_model_id

    @property
    def is_available(self) -> bool:
        return bool(self.api_url and self.api_key)

    async def analyze(
        self,
        evidence: Dict[str, Any],
        system_prompt: str,
    ) -> Dict[str, Any]:
        user_msg = (
            "Analyze the following threat evidence and provide a "
            "security assessment:\n\n"
            + json.dumps(evidence, indent=2)
        )

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self.api_url,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model_id,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_msg},
                    ],
                    "temperature": 0.3,
                    "max_tokens": 1024,
                },
                timeout=60,
            )
            resp.raise_for_status()
            body = resp.json()

        content = (
            body.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        )
        parsed = _try_parse_json(content)
        parsed["provider"] = "granite"
        return parsed


# ─── Demo Fallback ──────────────────────────────────────────── #

class DemoFallbackProvider(AIProvider):
    """Deterministic fallback — no LLM required."""

    async def analyze(
        self,
        evidence: Dict[str, Any],
        system_prompt: str,
    ) -> Dict[str, Any]:

        score = evidence.get("risk_score", 0)
        classification = evidence.get("classification", "UNKNOWN")
        evidence_list = evidence.get("evidence", [])

        if score >= 75:
            summary = (
                f"Critical-risk {classification.lower()} indicator "
                f"requiring immediate action."
            )
            rec = "BLOCK"
            reasoning = [
                "Multiple independent threat intelligence sources "
                "flagged this indicator.",
                "The risk score significantly exceeds the high-risk "
                "threshold.",
                "Immediate blocking is recommended to prevent "
                "potential compromise.",
            ]
        elif score >= 50:
            summary = (
                f"High-risk indicator with {classification.lower()} "
                f"characteristics."
            )
            rec = "BLOCK"
            reasoning = [
                "Threat intelligence detections suggest elevated risk.",
                "The indicator exhibits patterns consistent with "
                "known threats.",
                "Blocking is recommended pending further investigation.",
            ]
        elif score >= 25:
            summary = "Medium-risk indicator — monitoring advised."
            rec = "MONITOR"
            reasoning = [
                "Some threat indicators are present but inconclusive.",
                "Continued monitoring is recommended.",
                "Additional context may clarify the risk level.",
            ]
        else:
            summary = "Low-risk indicator — no significant threats detected."
            rec = "ALLOW"
            reasoning = [
                "No significant threat intelligence detections.",
                "The indicator appears benign based on available evidence.",
                "Standard monitoring policies apply.",
            ]

        # Append up to 3 evidence items as reasoning
        for item in evidence_list[:3]:
            reasoning.append(f"Evidence: {item}")

        retrieved_mitre = evidence.get("retrieved_mitre", {})
        mitre_ids = retrieved_mitre.get("technique_ids") or (_estimate_mitre(classification) if score >= 50 else [])
        mitigations = retrieved_mitre.get("suggested_mitigations", [])

        return {
            "summary": summary,
            "reasoning": reasoning,
            "recommendation": rec,
            "mitre": mitre_ids,
            "mitigations": mitigations,
            "provider": "demo_fallback",
        }


# ─── Helpers ────────────────────────────────────────────────── #

_MITRE_MAP: dict[str, list[str]] = {
    "PHISHING": ["T1566.002", "T1598"],
    "MALWARE": ["T1204.002", "T1059"],
    "COMMAND_AND_CONTROL": ["T1071.001", "T1573"],
    "SUSPICIOUS": ["T1595"],
}


def _estimate_mitre(classification: str) -> list[str]:
    return _MITRE_MAP.get(classification, [])


def _try_parse_json(text: str) -> Dict[str, Any]:
    """Try to extract a JSON object from LLM output."""
    try:
        start = text.index("{")
        end = text.rindex("}") + 1
        data = json.loads(text[start:end])
        return {
            "summary": data.get("summary", text[:500]),
            "reasoning": data.get("reasoning", [text]),
            "recommendation": data.get("recommendation", "MONITOR"),
            "mitre": data.get("mitre", []),
            "mitigations": data.get("mitigations", []),
        }
    except (ValueError, json.JSONDecodeError):
        return {
            "summary": text[:500],
            "reasoning": [text],
            "recommendation": "MONITOR",
            "mitre": [],
            "mitigations": [],
        }


def get_provider() -> AIProvider:
    """Return the configured AI provider instance."""
    if settings.ai_provider == "granite":
        gp = GraniteProvider()
        if gp.is_available:
            return gp
    return DemoFallbackProvider()
