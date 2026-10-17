"""Explicit feature-group registry. No module scanning, no plugin framework.

Adding a group: write the extractor module, call `register()` for it in
`silkscan/features/groups/__init__.py`, enable it under `features.groups` in YAML.
"""

from __future__ import annotations

from typing import Any

from silkscan.data.records import FORBIDDEN_INPUT_FIELDS
from silkscan.errors import ConfigError, LeakageError
from silkscan.features.base import FeatureExtractor

REGISTRY: dict[str, type[FeatureExtractor]] = {}


def register(cls: type[FeatureExtractor]) -> type[FeatureExtractor]:
    for attr in ("name", "version", "required_inputs"):
        if not hasattr(cls, attr):
            raise TypeError(f"{cls.__name__} must define class attribute `{attr}`.")
    if not cls.name or "." in cls.name:
        raise TypeError(f"{cls.__name__}: group name must be non-empty and contain no '.'.")
    forbidden = sorted(set(cls.required_inputs) & FORBIDDEN_INPUT_FIELDS)
    if forbidden:
        raise LeakageError(
            f"Feature group `{cls.name}` requests target/identity field(s) {forbidden}. Labels, AV results, "
            "family/behavior tags, dates and hashes may never be used as features."
        )
    existing = REGISTRY.get(cls.name)
    if existing is not None and existing is not cls:
        raise TypeError(f"Feature group name `{cls.name}` is already registered by {existing.__name__}.")
    REGISTRY[cls.name] = cls
    return cls


def create_extractor(name: str, params: dict[str, Any]) -> FeatureExtractor:
    # Importing the package registers the built-in groups.
    import silkscan.features.groups  # noqa: F401

    if name not in REGISTRY:
        raise ConfigError(f"Unknown feature group `{name}`. Registered: {sorted(REGISTRY)}.")
    try:
        return REGISTRY[name](**params)
    except TypeError as e:
        raise ConfigError(f"Invalid params for feature group `{name}`: {e}") from None
