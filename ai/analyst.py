"""AI Analyst — orchestrates grounded explanations and validates security decisions."""

from __future__ import annotations

from typing import Any, Dict

from ai.prompts import SECURITY_ANALYST_PROMPT
from ai.providers import get_provider
from ai.rag import retrieve_mitre_context

BASELINE_MITIGATION = (
    "Continue standard baseline monitoring. No high-confidence ATT&CK techniques indicated."
)


def enforce_analysis_contract(
    result: Dict[str, Any],
    *,
    risk_score: int,
    classification: str,
    mitre_rag: Dict[str, Any],
) -> Dict[str, Any]:
    """Keep the model's output consistent with validated score and retrieved context.

    The LLM explains evidence; it cannot override the score-based action policy,
    invent ATT&CK techniques, or substitute unrelated mitigations.
    """
    validated = dict(result)

    # Deterministic action policy keeps recommendation values valid and aligned
    # with the platform's risk-score bands.
    if risk_score >= 50:
        recommendation = "BLOCK"
    elif risk_score >= 25:
        recommendation = "MONITOR"
    else:
        recommendation = "ALLOW"
    validated["recommendation"] = recommendation

    # MITRE mapping is grounded exclusively in the retrieved local ATT&CK KB.
    # Benign/low-risk indicators should not acquire techniques from LLM guesses.
    if risk_score < 30 or classification.strip().upper() == "BENIGN":
        validated["mitre"] = []
        validated["mitigations"] = [BASELINE_MITIGATION]
    else:
        validated["mitre"] = list(mitre_rag.get("technique_ids") or [])
        validated["mitigations"] = list(
            mitre_rag.get("mitigations") or [BASELINE_MITIGATION]
        )

    # Defend the API contract against malformed provider adapters.
    if not isinstance(validated.get("summary"), str) or not validated["summary"].strip():
        validated["summary"] = (
            "The risk-scoring pipeline completed; review the evidence and risk score."
        )
    if not isinstance(validated.get("reasoning"), list):
        validated["reasoning"] = []
    validated["reasoning"] = [str(item) for item in validated["reasoning"][:5]]
    return validated


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
    """Retrieve grounded MITRE ATT&CK context and delegate to configured AI provider."""

    # 1. RAG retrieval of relevant techniques & defensive mitigations
    mitre_rag = retrieve_mitre_context(
        classification=classification,
        ioc_type=ioc_type,
        risk_score=risk_score,
        evidence=evidence,
    )

    # 2. Build structured evidence payload with RAG grounding
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
        "retrieved_mitre": {
            "technique_ids": mitre_rag["technique_ids"],
            "suggested_mitigations": mitre_rag["mitigations"],
        },
    }

    # 3. Augment system prompt with retrieved context
    grounded_prompt = f"{SECURITY_ANALYST_PROMPT}\n{mitre_rag['context_prompt']}"

    # 4. Delegate to AI provider for explanation
    provider = get_provider()
    result = await provider.analyze(structured, grounded_prompt)

    # 5. Apply deterministic safety/consistency checks to generated output
    return enforce_analysis_contract(
        result,
        risk_score=risk_score,
        classification=classification,
        mitre_rag=mitre_rag,
    )
