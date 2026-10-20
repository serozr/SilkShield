"""Safe Sysmon XML/JSON normalization for SOC investigations.

This module only parses telemetry. It never executes a process, downloads a
file, or resolves an IOC over the network.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable

from .models import DetectionEvent, event_from_sysmon


def _flatten_xml_event(event: ET.Element) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for child in event.iter():
        tag = child.tag.rsplit("}", 1)[-1]
        name = child.attrib.get("Name") or tag
        if child is event:
            continue
        data[name] = child.text or ""
    return data


def parse_sysmon_xml(text: str) -> list[DetectionEvent]:
    """Parse Sysmon Event XML into normalized DetectionEvent objects."""
    root = ET.fromstring(text)
    events: list[DetectionEvent] = []
    for event in root.iter():
        tag = event.tag.rsplit("}", 1)[-1]
        if tag != "Event":
            continue
        data = _flatten_xml_event(event)
        events.append(event_from_sysmon(data))
    return events


def parse_json_records(records: Iterable[dict[str, Any]]) -> list[DetectionEvent]:
    """Parse a JSON array/iterator of Sysmon-style records."""
    return [event_from_sysmon(record) for record in records]


def load_telemetry(path: str | Path) -> list[DetectionEvent]:
    """Load .json/.jsonl/.xml telemetry from disk without executing payloads."""
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    suffix = file_path.suffix.lower()

    if suffix == ".xml":
        return parse_sysmon_xml(text)
    if suffix == ".jsonl":
        records = [json.loads(line) for line in text.splitlines() if line.strip()]
        return parse_json_records(records)
    if suffix == ".json":
        payload = json.loads(text)
        records = payload if isinstance(payload, list) else payload.get("events", [])
        return parse_json_records(records)
    raise ValueError("Unsupported telemetry format; expected .xml, .json, or .jsonl")
