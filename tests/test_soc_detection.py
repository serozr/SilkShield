"""Tests for the SOC detection package using harmless synthetic telemetry."""

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from soc.engine import DetectionEngine
from soc.models import event_from_sysmon
from soc.sysmon import parse_json_records


RULES = Path(__file__).parents[1] / "soc" / "rules"


class SocDetectionTests(unittest.TestCase):
    def test_encoded_powershell_is_detected_and_mapped(self):
        event = event_from_sysmon({
            "UtcTime": "2026-10-21T00:00:00Z",
            "EventID": 1,
            "Computer": "LAB-PC",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
            "User": "LAB\\analyst",
        })
        engine = DetectionEngine.from_directory(RULES)
        matches = engine.detect([event])
        self.assertEqual([m.rule_id for m in matches], ["SILK-PS-001"])
        self.assertEqual(matches[0].mitre, ("T1059.001",))

    def test_benign_process_does_not_match(self):
        event = event_from_sysmon({
            "UtcTime": "2026-10-21T00:00:00Z",
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\notepad.exe",
            "CommandLine": "notepad.exe C:\\temp\\notes.txt",
        })
        engine = DetectionEngine.from_directory(RULES)
        self.assertEqual(engine.detect([event]), [])

    def test_json_records_are_normalized(self):
        events = parse_json_records([{"EventID": 3, "DestinationPort": "443", "DestinationIp": "1.2.3.4"}])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].destination_port, 443)
        self.assertEqual(events[0].destination_ip, "1.2.3.4")

    def test_timeline_is_sorted(self):
        engine = DetectionEngine.from_directory(RULES)
        later = event_from_sysmon({"UtcTime": "2026-10-21T00:02:00Z", "Image": "wmic.exe", "CommandLine": "wmic process list"})
        earlier = event_from_sysmon({"UtcTime": "2026-10-21T00:01:00Z", "Image": "powershell.exe", "CommandLine": "powershell.exe -enc AAAA"})
        timeline = engine.build_timeline(engine.detect([later, earlier]))
        self.assertEqual([item.timestamp.minute for item in timeline], [1, 2])


if __name__ == "__main__":
    unittest.main()
