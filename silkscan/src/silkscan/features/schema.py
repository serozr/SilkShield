"""Versioned feature schema. Prediction refuses to run on a mismatch."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from silkscan.errors import SchemaMismatchError
from silkscan.utils.hashing import sha256_json

SCHEMA_FORMAT = 1


@dataclass
class GroupSchema:
    name: str
    version: str
    feature_names: list[str]
    dtype: str
    missing_policy: str
    state_fingerprint: str
    config: dict[str, Any]
    tool_versions: dict[str, str]
    categorical: list[str] = field(default_factory=list)


@dataclass
class FeatureSchema:
    groups: list[GroupSchema]
    format: int = SCHEMA_FORMAT

    @property
    def feature_names(self) -> list[str]:
        return [n for g in self.groups for n in g.feature_names]

    @property
    def categorical(self) -> list[str]:
        return [n for g in self.groups for n in g.categorical]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint()
        return d

    def fingerprint(self) -> str:
        return sha256_json(asdict(self))

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "FeatureSchema":
        schema = cls([GroupSchema(**g) for g in d["groups"]], d.get("format", SCHEMA_FORMAT))
        if "fingerprint" in d and d["fingerprint"] != schema.fingerprint():
            raise SchemaMismatchError("Stored feature schema is corrupted (fingerprint does not match content).")
        return schema

    def differences(self, other: "FeatureSchema") -> list[str]:
        """Human-readable differences between `self` (expected) and `other` (produced)."""
        diffs: list[str] = []
        exp = [g.name for g in self.groups]
        got = [g.name for g in other.groups]
        if exp != got:
            diffs.append(f"group order/set differs: model expects {exp}, pipeline produced {got}")
        by_name = {g.name: g for g in other.groups}
        for g in self.groups:
            o = by_name.get(g.name)
            if o is None:
                continue
            for attr in ("version", "dtype", "missing_policy", "state_fingerprint", "config", "tool_versions",
                         "categorical"):
                if getattr(g, attr) != getattr(o, attr):
                    diffs.append(f"group `{g.name}` {attr}: expected {getattr(g, attr)!r}, got {getattr(o, attr)!r}")
            if g.feature_names != o.feature_names:
                idx = next((i for i, (a, b) in enumerate(zip(g.feature_names, o.feature_names)) if a != b),
                           min(len(g.feature_names), len(o.feature_names)))
                diffs.append(
                    f"group `{g.name}` feature names differ at position {idx} "
                    f"({len(g.feature_names)} expected, {len(o.feature_names)} produced)"
                )
        return diffs

    def require_match(self, other: "FeatureSchema") -> None:
        diffs = self.differences(other)
        if diffs:
            raise SchemaMismatchError(
                "Feature schema of the model and of the current pipeline differ; refusing to predict.\n  - "
                + "\n  - ".join(diffs)
                + "\nRetrain the model, or use the code/config/data files the model was trained with."
            )
