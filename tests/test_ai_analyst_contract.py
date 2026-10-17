"""Regression tests for deterministic validation of generated security analysis."""

import unittest

from ai.analyst import BASELINE_MITIGATION, enforce_analysis_contract


class AnalysisContractTests(unittest.TestCase):
    def test_low_risk_benign_drops_hallucinated_mitre_and_allows(self):
        result = enforce_analysis_contract(
            {
                "summary": "Looks benign.",
                "reasoning": ["One low-confidence signal."],
                "recommendation": "MONITOR",
                "mitre": ["T1566.002: Phishing"],
                "mitigations": ["Block all phishing links."],
            },
            risk_score=0,
            classification="BENIGN",
            mitre_rag={"technique_ids": [], "mitigations": []},
        )

        self.assertEqual(result["recommendation"], "ALLOW")
        self.assertEqual(result["mitre"], [])
        self.assertEqual(result["mitigations"], [BASELINE_MITIGATION])

    def test_medium_risk_uses_retrieved_mitre_and_monitor(self):
        result = enforce_analysis_contract(
            {
                "summary": "Potential reconnaissance.",
                "reasoning": [],
                "recommendation": "ALLOW",
                "mitre": ["T9999"],
                "mitigations": ["Invented mitigation."],
            },
            risk_score=35,
            classification="SUSPICIOUS",
            mitre_rag={
                "technique_ids": ["T1595"],
                "mitigations": ["M1037: Filter Network Traffic."],
            },
        )

        self.assertEqual(result["recommendation"], "MONITOR")
        self.assertEqual(result["mitre"], ["T1595"])
        self.assertEqual(result["mitigations"], ["M1037: Filter Network Traffic."])

    def test_high_risk_cannot_be_overridden_to_allow_by_llm(self):
        result = enforce_analysis_contract(
            {
                "summary": "High risk.",
                "reasoning": [],
                "recommendation": "ALLOW",
                "mitre": [],
                "mitigations": [],
            },
            risk_score=80,
            classification="MALWARE",
            mitre_rag={
                "technique_ids": ["T1204.002", "T1059"],
                "mitigations": ["M1038: Execution Prevention."],
            },
        )

        self.assertEqual(result["recommendation"], "BLOCK")
        self.assertEqual(result["mitre"], ["T1204.002", "T1059"])
        self.assertEqual(result["mitigations"], ["M1038: Execution Prevention."])


if __name__ == "__main__":
    unittest.main()
