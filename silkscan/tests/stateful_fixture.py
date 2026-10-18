"""A small stateful feature group used only by tests: section-name vocabulary learned on train."""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, Mapping

import numpy as np

from silkscan.features.base import Extraction, FeatureExtractor
from silkscan.features.registry import REGISTRY, register


class SectionVocab(FeatureExtractor):
    name = "test_section_vocab"
    version = "1"
    required_inputs = ("section",)
    is_stateful = True
    default_missing_policy = "impute_with_indicator"

    def __init__(self, min_count: int = 2) -> None:
        super().__init__(min_count=int(min_count))
        self.min_count = int(min_count)
        self.vocab: list[str] = []

    def fit(self, views: Iterable[Mapping[str, Any]]) -> None:
        counts: Counter[str] = Counter()
        for v in views:
            sec = v.get("section") or {}
            if isinstance(sec, dict) and isinstance(sec.get("sections"), list):
                counts.update({s["name"] for s in sec["sections"]})
        self.set_state({"vocab": sorted(n for n, c in counts.items() if c >= self.min_count)})

    def get_state(self) -> dict[str, Any]:
        return {"vocab": list(self.vocab)}

    def set_state(self, state: Mapping[str, Any]) -> None:
        self.vocab = list(state["vocab"])
        self._fitted = True

    def get_feature_names(self) -> list[str]:
        return self.prefixed([f"has_{i}" for i in range(len(self.vocab))] + ["n_unknown"])

    def extract_one(self, view: Mapping[str, Any]) -> Extraction:
        sec = view.get("section")
        if not sec:
            return Extraction.missing("`section` absent")
        names = {s["name"] for s in sec["sections"]}
        row = [float(n in names) for n in self.vocab]
        return Extraction(np.array(row + [float(len(names - set(self.vocab)))], dtype=np.float32))


if SectionVocab.name not in REGISTRY:
    register(SectionVocab)
