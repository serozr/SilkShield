"""Smoke-test the configured IBM watsonx.ai Granite connection.

Run from the repository root with the project's virtualenv activated:
    python -m scripts.test_granite

The script never prints credentials or IAM tokens.
"""
from __future__ import annotations

import asyncio
import json

import httpx

from ai.providers import GraniteProvider


async def _run() -> int:
    provider = GraniteProvider()
    missing = []
    if not provider.base_url:
        missing.append("GRANITE_API_URL")
    if not provider.api_key:
        missing.append("GRANITE_API_KEY")
    if not provider.project_id:
        missing.append("WATSONX_PROJECT_ID")
    if missing:
        print("[NOT CONFIGURED] Missing .env values: " + ", ".join(missing))
        return 2

    print("[*] Calling IBM watsonx.ai Granite (credentials are hidden)...")
    prompt = (
        "You are SilkShield's SOC analyst. Return a JSON object with keys "
        "summary, reasoning (array), recommendation, mitre (array), "
        "mitigations (array). Use recommendation MONITOR for this connectivity test."
    )
    evidence = {
        "test": "granite_connectivity",
        "ioc": "example.com",
        "ioc_type": "domain",
        "risk_score": 15,
        "risk_level": "LOW",
        "classification": "BENIGN",
        "evidence": ["Connectivity smoke test only; no threat conclusion requested."],
        "retrieved_mitre": {"technique_ids": [], "suggested_mitigations": []},
    }
    try:
        result = await provider.analyze(evidence, prompt)
    except httpx.HTTPStatusError as exc:
        print(f"[FAILED] watsonx.ai returned HTTP {exc.response.status_code}.")
        print("Check the regional URL, model availability, API-key permissions, and project ID.")
        return 1
    except httpx.RequestError as exc:
        print(f"[FAILED] Network error while calling watsonx.ai: {type(exc).__name__}")
        print("Check outbound HTTPS access from LinuxONE and the regional endpoint.")
        return 1
    except Exception as exc:
        print(f"[FAILED] {type(exc).__name__}: {exc}")
        return 1

    print("[SUCCESS] Response received from provider:", result.get("provider", "unknown"))
    print(json.dumps({
        "provider": result.get("provider"),
        "summary": result.get("summary"),
        "recommendation": result.get("recommendation"),
        "mitre_count": len(result.get("mitre", [])),
        "mitigation_count": len(result.get("mitigations", [])),
    }, indent=2))
    return 0


def main() -> None:
    raise SystemExit(asyncio.run(_run()))


if __name__ == "__main__":
    main()
