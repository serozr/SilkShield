"""Small, dependency-free Sigma subset used for deterministic detections."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Any

from .models import DetectionEvent, DetectionMatch


@dataclass(frozen=True)
class SigmaRule:
    id: str
    title: str
    level: str
    description: str
    logsource: dict[str, Any]
    selection: dict[str, Any]
    mitre: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SigmaRule":
        detection = data.get("detection", {})
        condition = str(detection.get("condition", "selection")).strip()
        if condition != "selection":
            raise ValueError(f"Unsupported Sigma condition: {condition}")
        selection = detection.get("selection")
        if not isinstance(selection, dict):
            raise ValueError("Rule must contain detection.selection as an object")
        return cls(
            id=str(data["id"]),
            title=str(data["title"]),
            level=str(data.get("level", "medium")).lower(),
            description=str(data.get("description", "")),
            logsource=dict(data.get("logsource", {})),
            selection=selection,
            mitre=tuple(data.get("tags", [])),
        )


def _field_value(event: DetectionEvent, field: str) -> Any:
    aliases = {
        "Image": event.image,
        "CommandLine": event.command_line,
        "ParentImage": event.parent_image,
        "ParentCommandLine": event.parent_command_line,
        "DestinationIp": event.destination_ip,
        "DestinationPort": event.destination_port,
        "User": event.user,
        "Computer": event.host,
        "EventID": event.event_id,
    }
    return aliases.get(field, event.raw.get(field, ""))


def _matches(value: Any, expected: Any) -> bool:
    if isinstance(expected, list):
        return any(_matches(value, item) for item in expected)
    actual = str(value or "").lower()
    target = str(expected).lower()
    if target.startswith("*") or target.endswith("*"):
        return fnmatch(actual, target)
    return actual == target or target in actual


def _selection_matches(event: DetectionEvent, selection: dict[str, Any]) -> bool:
    return all(
        _matches(_field_value(event, field), expected)
        for field, expected in selection.items()
    )


def match_rule(rule: SigmaRule, event: DetectionEvent) -> DetectionMatch | None:
    """Evaluate the intentionally constrained `condition: selection` form."""
    if not _selection_matches(event, rule.selection):
        return None
    evidence = tuple(
        f"{field}={_field_value(event, field)}"
        for field in rule.selection
    )
    return DetectionMatch(
        rule_id=rule.id,
        title=rule.title,
        level=rule.level,
        description=rule.description,
        mitre=rule.mitre,
        evidence=evidence,
        event=event,
    )
