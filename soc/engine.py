"""Detection engine combining Sigma-style rules and incident timelines."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .models import DetectionEvent, DetectionMatch, TimelineEvent
from .sigma import SigmaRule, match_rule


class DetectionEngine:
    """Run deterministic detection rules against normalized telemetry."""

    def __init__(self, rules: Iterable[SigmaRule] = ()) -> None:
        self.rules = list(rules)

    @classmethod
    def from_directory(cls, directory: str | Path) -> "DetectionEngine":
        path = Path(directory)
        rules: list[SigmaRule] = []
        for rule_path in sorted(path.glob("*.json")):
            payload = json.loads(rule_path.read_text(encoding="utf-8"))
            rules.append(SigmaRule.from_dict(payload))
        return cls(rules)

    def detect(self, events: Iterable[DetectionEvent]) -> list[DetectionMatch]:
        matches: list[DetectionMatch] = []
        for event in events:
            for rule in self.rules:
                match = match_rule(rule, event)
                if match:
                    matches.append(match)
        return sorted(matches, key=lambda item: item.event.timestamp)

    @staticmethod
    def build_timeline(matches: Iterable[DetectionMatch]) -> list[TimelineEvent]:
        timeline: list[TimelineEvent] = []
        for match in matches:
            timeline.append(
                TimelineEvent(
                    timestamp=match.event.timestamp,
                    kind="detection",
                    title=match.title,
                    detail="; ".join(match.evidence) or match.description,
                    severity=match.level.upper(),
                    rule_id=match.rule_id,
                    mitre=match.mitre,
                )
            )
        return sorted(timeline, key=lambda item: item.timestamp)
