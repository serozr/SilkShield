"""Stage 2 inference: threat category (multi-label) and family for files the detector flags."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import yaml

from silkscan.errors import ConfigError, SilkScanError, SchemaMismatchError
from silkscan.utils.io import read_json

DEFAULT_TAXONOMY = "taxonomy.v1.yaml"
META_FILE = "stage2.json"


@dataclass
class Taxonomy:
    version: str
    categories: dict[str, dict[str, Any]]   # name -> {"impact": high|medium|low, "tags": [...]}
    sha256: str

    @property
    def names(self) -> list[str]:
        return list(self.categories)

    def categories_of(self, tags: Iterable[str]) -> set[str]:
        tags = {t.lower() for t in tags or ()}
        return {c for c, spec in self.categories.items() if tags & set(spec["tags"])}

    def impact(self, category: str) -> str:
        return self.categories[category]["impact"]


def load_taxonomy(name_or_path: str = DEFAULT_TAXONOMY) -> Taxonomy:
    p = Path(name_or_path)
    data = p.read_bytes() if p.is_file() else resources.files("silkscan.stage2").joinpath(name_or_path).read_bytes()
    raw = yaml.safe_load(data)
    cats = raw.get("categories") if isinstance(raw, dict) else None
    if not cats or "version" not in raw:
        raise ConfigError(f"Taxonomy {name_or_path} must define `version` and `categories`.")
    seen: dict[str, str] = {}
    for name, spec in cats.items():
        if spec.get("impact") not in ("high", "medium", "low"):
            raise ConfigError(f"Taxonomy category `{name}`: impact must be high, medium or low.")
        spec["tags"] = [t.lower() for t in spec.get("tags", [])]
        for t in spec["tags"]:
            if t in seen:
                raise ConfigError(f"Taxonomy tag `{t}` is in both `{seen[t]}` and `{name}`.")
            seen[t] = name
    return Taxonomy(str(raw["version"]), cats, hashlib.sha256(data).hexdigest())


class Stage2Model:
    """Loads a stage-2 directory written by `silkscan train-type` (silkscan.stage2.train)."""

    def __init__(self, directory: Path):
        import lightgbm as lgb

        self.dir = Path(directory)
        if not (self.dir / META_FILE).exists():
            raise SilkScanError(f"{self.dir} is not a stage-2 model directory (no {META_FILE}).")
        self.meta = read_json(self.dir / META_FILE)
        self.id = self.meta["id"]
        self.categories = {name: spec for name, spec in self.meta["categories"].items() if spec["enabled"]}
        self._cat_models = {name: lgb.Booster(model_file=str(self.dir / spec["model"]))
                            for name, spec in self.categories.items()}
        fam = self.meta.get("family") or {}
        self.family = fam if fam.get("enabled") else None
        self._fam_model = lgb.Booster(model_file=str(self.dir / fam["model"])) if self.family else None

    def require_compatible(self, base_schema_fingerprint: str) -> None:
        if self.meta["base_schema_fingerprint"] != base_schema_fingerprint:
            raise SchemaMismatchError(
                f"Stage-2 model {self.dir} was trained on features of another model "
                f"(schema {self.meta['base_schema_fingerprint'][:12]}, serving {base_schema_fingerprint[:12]})."
            )

    def classify(self, X: np.ndarray) -> list[dict[str, Any]]:
        """Categories whose score passes their precision-targeted threshold, and the family if confident."""
        n = X.shape[0]
        out: list[dict[str, Any]] = [{"categories": [], "family": None, "stage2": self.id} for _ in range(n)]
        if n == 0:
            return out
        for name, model in self._cat_models.items():
            spec = self.categories[name]
            scores = np.asarray(model.predict(X), dtype=np.float64)
            for i in np.flatnonzero(scores >= spec["threshold"]):
                out[i]["categories"].append({"name": name, "score": round(float(scores[i]), 5),
                                             "impact": spec["impact"]})
        for o in out:
            o["categories"].sort(key=lambda c: -c["score"])
        if self._fam_model is not None:
            probs = np.asarray(self._fam_model.predict(X), dtype=np.float64).reshape(n, -1)
            classes = self.family["classes"]
            top = probs.argmax(axis=1)
            conf = probs.max(axis=1)
            for i in range(n):
                name = classes[top[i]]
                if name != "other" and conf[i] >= self.family["threshold"]:
                    out[i]["family"] = {"name": name, "confidence": round(float(conf[i]), 5)}
        return out
