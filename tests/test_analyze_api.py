"""API decision-band tests using reserved example domains and mocked inputs."""

import unittest
from unittest.mock import PropertyMock, patch

from fastapi.testclient import TestClient

import app.main as main


class _UnreliableProvider:
    async def analyze(self, evidence, system_prompt):
        # Deliberately conflicting output verifies the deterministic guardrail.
        return {
            "summary": "Model generated summary.",
            "reasoning": [],
            "recommendation": "ALLOW",
            "mitre": ["T9999"],
            "mitigations": ["Unverified mitigation."],
            "provider": "test_mock",
        }


class AnalyzeApiDecisionTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main.app)
        self.patches = [
            patch("app.main.get_cached", return_value=None),
            patch("app.main.set_cached"),
            patch("app.main.get_fixture", return_value=None),
            patch.object(
                type(main.vt), "is_configured", new_callable=PropertyMock,
                return_value=False,
            ),
            patch("ai.analyst.get_provider", return_value=_UnreliableProvider()),
        ]
        for mocked in self.patches:
            mocked.start()
            self.addCleanup(mocked.stop)

    def _analyze_at_score(self, score, classification, level):
        prediction = {
            "risk_score": score,
            "risk_level": level,
            "classification": classification,
            "confidence": 0.75,
            "evidence": ["Synthetic test evidence (no live intelligence queried)."],
            "model_available": False,
        }
        with patch("app.main.predict", return_value=prediction):
            return self.client.post(
                "/analyze",
                json={"ioc": f"risk-{score}.example", "type": "domain"},
            )

    def test_low_risk_returns_allow_and_grounded_summary(self):
        response = self._analyze_at_score(10, "BENIGN", "LOW")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["recommendation"], "ALLOW")
        self.assertEqual(body["mitre"], [])
        self.assertIn("risk-10.example is classified as BENIGN", body["ai_analysis"])
        self.assertEqual(body["metadata"]["intelligence_source"], "local_fallback")

    def test_medium_risk_returns_monitor_and_retrieved_mitre(self):
        response = self._analyze_at_score(35, "SUSPICIOUS", "MEDIUM")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["recommendation"], "MONITOR")
        self.assertEqual(body["mitre"], ["T1595"])
        self.assertNotIn("T9999", body["mitre"])

    def test_high_risk_returns_block_and_retrieved_mitre(self):
        response = self._analyze_at_score(65, "MALWARE", "HIGH")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["recommendation"], "BLOCK")
        self.assertEqual(body["mitre"], ["T1204.002", "T1059"])
        self.assertNotIn("T9999", body["mitre"])


if __name__ == "__main__":
    unittest.main()
