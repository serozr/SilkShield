"""Deterministic counts and ratios of imported APIs per behaviour category.

The mapping lives in a versioned YAML data file; its sha256 is part of the
cache key and schema. This group exists mainly for explainability: its columns
read as "network API share" instead of a hashed bucket.
"""

from __future__ import annotations

import hashlib
import math
import re
from importlib import resources
from pathlib import Path
from typing import Any, Mapping

import yaml

from silkscan.errors import ConfigError
from silkscan.features.base import Extraction, FeatureExtractor

DEFAULT_MAPPING = "api_groups.v1.yaml"
_ORDINAL = re.compile(r":ordinal\d+$")


def load_mapping(name_or_path: str) -> tuple[dict[str, Any], str]:
    p = Path(name_or_path)
    if p.is_file():
        data = p.read_bytes()
    else:
        try:
            data = resources.files("silkscan.features.data").joinpath(name_or_path).read_bytes()
        except FileNotFoundError:
            raise ConfigError(f"import_semantics mapping `{name_or_path}` not found.") from None
    mapping = yaml.safe_load(data)
    if not isinstance(mapping, dict) or "categories" not in mapping or "version" not in mapping:
        raise ConfigError(f"Mapping `{name_or_path}` must define `version` and `categories`.")
    return mapping, hashlib.sha256(data).hexdigest()


class ImportSemantics(FeatureExtractor):
    name = "import_semantics"
    version = "1"
    required_inputs = ("imports", "general")
    default_missing_policy = "impute_with_indicator"

    def __init__(self, mapping: str = DEFAULT_MAPPING) -> None:
        super().__init__(mapping=mapping)
        raw, self._sha = load_mapping(mapping)
        self._mapping_version = str(raw["version"])
        self.categories = sorted(raw["categories"])
        self._funcs = {c: {f.lower() for f in raw["categories"][c].get("functions", [])} for c in self.categories}
        self._dlls = {c: {d.lower() for d in raw["categories"][c].get("dlls", [])} for c in self.categories}

    def config_dict(self) -> dict[str, Any]:
        # The file content (sha256), not its name, determines the output.
        return {"mapping_version": self._mapping_version}

    def tool_versions(self) -> dict[str, str]:
        return {"mapping_sha256": self._sha}

    def get_feature_names(self) -> list[str]:
        local = ["total_imports", "n_dlls", "n_ordinal_imports", "frac_ordinal_imports", "n_categories_present"]
        for c in self.categories:
            local += [f"{c}_count", f"{c}_ratio"]
        return self.prefixed(local)

    def extract_one(self, view: Mapping[str, Any]) -> Extraction:
        if "imports" not in view or "general" not in view:
            return Extraction.missing("`imports` or `general` field absent")
        imports, general = view["imports"], view["general"]
        if not isinstance(imports, dict) or not isinstance(general, dict):
            return Extraction.parse_error("`imports`/`general` is not an object")
        if general.get("is_pe") == 0:
            return Extraction.not_applicable("file could not be parsed as PE; no import table")

        total = ordinals = 0
        counts = dict.fromkeys(self.categories, 0)
        for dll, funcs in imports.items():
            if not isinstance(funcs, list):
                return Extraction.parse_error(f"imports of {dll!r} is not a list")
            dll_l = str(dll).lower()
            for fn in funcs:
                total += 1
                fn = str(fn)
                if _ORDINAL.search(fn):
                    ordinals += 1
                base = _strip_suffix(fn)
                for c in self.categories:
                    if dll_l in self._dlls[c] or base in self._funcs[c]:
                        counts[c] += 1
        values: list[float] = [total, len(imports), ordinals, ordinals / total if total else math.nan,
                               sum(1 for c in self.categories if counts[c])]
        for c in self.categories:
            values += [counts[c], counts[c] / total if total else math.nan]
        return Extraction(values)


def _strip_suffix(name: str) -> str:
    """CreateFileW -> createfile, CreateFileA -> createfile; keeps names like `send` intact."""
    if len(name) > 2 and name[-1] in "AW" and name[-2].islower():
        name = name[:-1]
    return name.lower()
