"""Identity / inputs / target separation.

A raw EMBER2024 line is split into:
- `id`: SHA-256 (or an explicit `synthetic:` id for fixtures), used only for alignment and tracking;
- `target`: label and every metadata field derived from AV scans, VirusTotal, collection time or the split;
- `inputs`: static-analysis fields that would also be available at prediction time.

Metadata field names come from thrember's `ORDERED_COLUMNS` (EMBER2024 repo,
commit 0ef753e). The behaviour/family/packer/... tags are ClarAVy outputs of AV
labels and therefore targets, never inputs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Mapping

from silkscan.errors import DataValidationError

TARGET_FIELDS = frozenset({
    "label", "first_submission_date", "last_analysis_date", "detection_ratio", "file_type",
    "family", "family_confidence", "behavior", "file_property", "packer", "exploit", "group",
    "subset", "split", "week_id",
})
IDENTITY_FIELDS = frozenset({"sha256", "sha1", "md5", "tlsh"})
# Extractors may never request these (enforced by the registry).
FORBIDDEN_INPUT_FIELDS = TARGET_FIELDS | IDENTITY_FIELDS

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class Record:
    id: str
    inputs: Mapping[str, Any]
    target: Mapping[str, Any]


def validate_id(value: Any) -> str:
    if isinstance(value, str) and (_SHA256.match(value) or value.startswith("synthetic:")):
        return value
    raise DataValidationError(
        f"Invalid record id {value!r}: expected a lowercase SHA-256 hex digest or a `synthetic:` id."
    )


def split_record(raw: Mapping[str, Any], id_field: str = "sha256") -> Record:
    if id_field not in raw:
        raise DataValidationError(f"Record has no id field `{id_field}` (keys: {sorted(raw)[:12]}...).")
    rid = validate_id(raw[id_field])
    target = {k: v for k, v in raw.items() if k in TARGET_FIELDS}
    inputs = {k: v for k, v in raw.items() if k not in TARGET_FIELDS and k not in IDENTITY_FIELDS and k != id_field}
    return Record(rid, MappingProxyType(inputs), MappingProxyType(target))


def input_view(record: Record, fields: tuple[str, ...]) -> Mapping[str, Any]:
    """Read-only view exposing only the fields an extractor declared."""
    return MappingProxyType({k: record.inputs[k] for k in fields if k in record.inputs})


def parse_label(value: Any) -> int:
    """1 = malicious, 0 = benign, -1 = unlabeled (EMBER uses null for unknown)."""
    if value is None:
        return -1
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value not in (-1, 0, 1):
        raise DataValidationError(f"Invalid label {value!r}: expected 0, 1, -1 or null.")
    return int(value)


def parse_date(value: Any) -> int | None:
    """Return Unix seconds (UTC). Accepts epoch numbers and ISO-8601 strings."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise DataValidationError(f"Invalid date {value!r}.")
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            raise DataValidationError(f"Invalid date {value!r}: expected epoch seconds or ISO-8601.") from None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    raise DataValidationError(f"Invalid date {value!r}.")
