"""Small, dependency-free Sigma subset used for deterministic detections.

The engine intentionally supports a constrained rule vocabulary instead of
pretending to implement the complete Sigma specification. Rules are YAML-like
Python dictionaries loaded from JSON-compatible files, making the core
portable to LinuxONE without another runtime dependency.
"""

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
    selections: dict[str, dict[str, Any]]
    mitre: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SigmaRule":
        detection = data.get("detection", {})
        selections = {
            key: value for key, value in detection.items() if key != "condition"
        }
        return cls(
            id=str(data["id"]),
            title=str(data["title"]),
            level=str(data.get("level", "medium")).lower(),
            description=str(data.get("description", "")),
            logsource=dict(data.get("logsource", {})),
            selections=selections,
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
    return all(_matches(_field_value(event, field), expected) for field, expected in selection.items())


def match_rule(rule: SigmaRule, event: DetectionEvent) -> DetectionMatch | None:
    """Evaluate the supported `selection`/`condition: selection` form."""
    condition = str(rule.selections.get("condition", "selection"))
    selections = {
        key: value for key, value in rule.selections.items() if key != "condition"
    }
    if condition == "selection" and selections:
        # The common Sigma shape is one selection map.
        selection = selections.get("selection", next(iter(selections.values())))
        if not _selection_matches(event, selection):
            return None
    else:
        return None

    evidence = tuple(
        f"{field}={_field_value(event, field)}" for field in selections.get("selection", {}).keys()
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
