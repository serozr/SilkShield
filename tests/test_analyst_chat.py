"""Contract tests for the evidence-grounded analyst chat endpoint."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException
from pydantic import ValidationError

import app.main as main
from app.schemas import AnalystChatRequest


class _MockGranite:
    async def analyze(self, evidence, system_prompt):
        self.evidence = evidence
        self.system_prompt = system_prompt
        return {
            "summary": "Rapora göre risk puanı mevcut kanıtlara dayanıyor.",
            "provider": "local_granite",
        }


def _run_without_asyncio_loop(coroutine):
    """Run these fully mocked coroutines without opening OS sockets."""
    try:
        coroutine.send(None)
    except StopIteration as completed:
        return completed.value
    raise AssertionError("Mocked chat unexpectedly suspended on external I/O")


class AnalystChatApiTests(unittest.TestCase):
    def setUp(self):
        self.report = {
            "ioc": "example.test",
            "type": "domain",
            "risk_score": 35,
            "risk_level": "MEDIUM",
            "classification": "SUSPICIOUS",
            "confidence": 0.75,
            "evidence": ["Synthetic evidence; no live intelligence queried."],
            "ai_analysis": "Synthetic test summary.",
            "recommendation": "MONITOR",
            "mitre": ["T1595"],
            "mitigations": ["M1037: Filter Network Traffic."],
            "intelligence_source": "local_fallback",
        }

    def test_chat_uses_granite_and_includes_report_context(self):
        provider = _MockGranite()
        with (
            patch("app.main.settings", SimpleNamespace(ai_provider="local")),
            patch("app.main.get_provider", return_value=provider),
        ):
            response = _run_without_asyncio_loop(main.chat_about_analysis(
                AnalystChatRequest.model_validate({
                    "analysis": self.report,
                    "question": "Bu risk puanı neden 35?",
                    "history": [],
                })
            ))

        self.assertEqual(response.provider, "local_granite")
        self.assertEqual(response.answer, "Rapora göre risk puanı mevcut kanıtlara dayanıyor.")
        self.assertEqual(provider.evidence["current_report"]["risk_score"], 35)
        self.assertEqual(provider.evidence["question"], "Bu risk puanı neden 35?")
        self.assertIn("Do not invent VirusTotal results", provider.system_prompt)

    def test_chat_is_unavailable_in_demo_mode(self):
        with (
            patch("app.main.settings", SimpleNamespace(ai_provider="demo")),
            patch("app.main.get_provider") as provider_factory,
        ):
            with self.assertRaises(HTTPException) as raised:
                _run_without_asyncio_loop(main.chat_about_analysis(AnalystChatRequest.model_validate(
                    {"analysis": self.report, "question": "Explain this result"}
                )))

        self.assertEqual(raised.exception.status_code, 503)
        provider_factory.assert_not_called()

    def test_chat_rejects_questions_over_the_limit(self):
        with self.assertRaises(ValidationError):
            AnalystChatRequest.model_validate(
                {"analysis": self.report, "question": "x" * 601}
            )


if __name__ == "__main__":
    unittest.main()
