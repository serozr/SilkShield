"""Typed models for normalized SOC telemetry and detection results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def parse_timestamp(value: Any) -> datetime:
    """Parse common ISO-8601 timestamps and normalize them to UTC."""
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value or "").strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class DetectionEvent:
    """Normalized telemetry event consumed by the Sigma-like engine."""

    timestamp: datetime
    event_id: int | None
    channel: str
    host: str
    user: str
    image: str
    command_line: str
    parent_image: str
    parent_command_line: str
    destination_ip: str
    destination_port: int | None
    source_ip: str
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DetectionMatch:
    """A deterministic detection result with evidence and ATT&CK mapping."""

    rule_id: str
    title: str
    level: str
    description: str
    mitre: tuple[str, ...]
    evidence: tuple[str, ...]
    event: DetectionEvent


@dataclass(frozen=True)
class TimelineEvent:
    """Human-readable incident timeline item."""

    timestamp: datetime
    kind: str
    title: str
    detail: str
    severity: str = "INFO"
    rule_id: str | None = None
    mitre: tuple[str, ...] = ()


def event_from_sysmon(record: dict[str, Any]) -> DetectionEvent:
    """Build a DetectionEvent from a normalized or raw Sysmon-style mapping."""
    def first(*keys: str) -> Any:
        for key in keys:
            if key in record and record[key] not in (None, ""):
                return record[key]
        return ""

    port = first("DestinationPort", "destination_port")
    try:
        port = int(port) if port != "" else None
    except (TypeError, ValueError):
        port = None

    return DetectionEvent(
        timestamp=parse_timestamp(first("UtcTime", "Timestamp", "timestamp")),
        event_id=int(first("EventID", "event_id") or 0) or None,
        channel=str(first("Channel", "channel") or "Microsoft-Windows-Sysmon/Operational"),
        host=str(first("Computer", "Host", "host")),
        user=str(first("User", "user")),
        image=str(first("Image", "image")),
        command_line=str(first("CommandLine", "command_line")),
        parent_image=str(first("ParentImage", "parent_image")),
        parent_command_line=str(first("ParentCommandLine", "parent_command_line")),
        destination_ip=str(first("DestinationIp", "DestinationIP", "destination_ip")),
        destination_port=port,
        source_ip=str(first("SourceIp", "SourceIP", "source_ip")),
        raw=dict(record),
    )
