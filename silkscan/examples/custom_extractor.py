"""Adding a feature group: write the extractor, register it, enable it in YAML.

Run:  python examples/custom_extractor.py

In the project itself, step 2 is one line in src/silkscan/features/groups/__init__.py
and step 3 is an entry under `features.groups` in the YAML config. Training,
evaluation, caching, schema checks and prediction need no change.
"""

from __future__ import annotations

from typing import Any, Mapping

from silkscan.config import GroupConfig
from silkscan.features.base import Extraction, FeatureExtractor
from silkscan.features.pipeline import FeaturePipeline
from silkscan.features.registry import register


# 1. The extractor: presence flags for a configurable list of DLLs.
class DllPresence(FeatureExtractor):
    name = "dll_presence"
    version = "1"                                  # bump when the output changes; invalidates the cache
    required_inputs = ("imports",)                 # only these fields are visible; labels never are
    default_missing_policy = "impute_with_indicator"

    def __init__(self, dlls: tuple[str, ...] = ("ws2_32.dll", "wininet.dll", "advapi32.dll")) -> None:
        super().__init__(dlls=list(dlls))
        self.dlls = [d.lower() for d in dlls]

    def get_feature_names(self) -> list[str]:
        return self.prefixed(d.replace(".dll", "") for d in self.dlls)

    def extract_one(self, view: Mapping[str, Any]) -> Extraction:
        if "imports" not in view:
            return Extraction.missing("`imports` field absent")
        imported = {str(d).lower() for d in view["imports"]}
        return Extraction([float(d in imported) for d in self.dlls])


# 2. Register it.
register(DllPresence)

if __name__ == "__main__":
    from silkscan.synthetic import BANNER, make_records

    # 3. Enable it next to the existing groups (in YAML this is a `- name: dll_presence` entry).
    pipe = FeaturePipeline([
        GroupConfig("section_summary", missing_policy="impute_with_indicator"),
        GroupConfig("dll_presence", params={"dlls": ["ws2_32.dll", "wininet.dll"]}),
    ])
    feats = pipe.transform_records(make_records(5))
    cols = feats.group_slices["dll_presence"]
    print(BANNER)
    print("new columns:", feats.feature_names[cols])
    print(feats.X[:, cols])
    print("status:", {g: s.tolist() for g, s in feats.status.items()})
