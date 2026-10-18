"""Interpretable section statistics derived from EMBER's raw `section` field.

Undefined ratios (zero denominator) are NaN, not 0 or inf; LightGBM treats NaN
as missing.
"""

from __future__ import annotations

import math
from typing import Any, Mapping

from silkscan.features.base import Extraction, FeatureExtractor

STANDARD_SECTION_NAMES = frozenset({
    ".text", ".data", ".rdata", ".rsrc", ".reloc", ".pdata", ".idata", ".edata", ".tls", ".bss", ".crt",
    ".didat", ".gfids", ".00cfg", ".xdata", ".debug", ".textbss", ".sdata", ".itext", ".code", ".orpc",
})
HIGH_ENTROPY = 7.0

LOCAL_NAMES = (
    "n_sections", "entropy_mean", "entropy_std", "entropy_size_weighted", "n_high_entropy", "frac_high_entropy",
    "n_executable", "n_writable", "n_write_execute", "frac_write_execute", "n_exec_zero_raw_size",
    "n_nonstandard_name", "frac_nonstandard_name", "raw_size_coverage", "virtual_to_raw_ratio",
    "entry_found", "entry_entropy", "entry_is_writable", "entry_is_last_section", "entry_size_ratio",
    "overlay_present", "overlay_size_ratio", "overlay_entropy",
)


def _ratio(num: float, den: float) -> float:
    return num / den if den else math.nan


class SectionSummary(FeatureExtractor):
    name = "section_summary"
    version = "1"
    required_inputs = ("section", "general")
    default_missing_policy = "impute_with_indicator"

    def __init__(self, high_entropy: float = HIGH_ENTROPY) -> None:
        super().__init__(high_entropy=high_entropy)
        self.high_entropy = float(high_entropy)

    def get_feature_names(self) -> list[str]:
        return self.prefixed(LOCAL_NAMES)

    def extract_one(self, view: Mapping[str, Any]) -> Extraction:
        if "section" not in view or "general" not in view:
            return Extraction.missing("`section` or `general` field absent")
        general, section = view["general"], view["section"]
        if not isinstance(general, dict) or not isinstance(section, dict):
            return Extraction.parse_error("`section`/`general` is not an object")
        if general.get("is_pe") == 0 or not section:
            return Extraction.not_applicable("file could not be parsed as PE; no section table")
        sections = section["sections"]
        if not isinstance(sections, list):
            return Extraction.parse_error("`section.sections` is not a list")

        n = len(sections)
        ent = [float(s["entropy"]) for s in sections]
        size = [float(s["size"]) for s in sections]
        vsize = [float(s["vsize"]) for s in sections]
        props = [set(s["props"]) for s in sections]
        names = [str(s["name"]) for s in sections]
        execu = ["MEM_EXECUTE" in p for p in props]
        write = ["MEM_WRITE" in p for p in props]
        wx = [e and w for e, w in zip(execu, write)]
        high = [e > self.high_entropy for e in ent]
        nonstd = [nm not in STANDARD_SECTION_NAMES for nm in names]
        mean = sum(ent) / n if n else math.nan
        std = math.sqrt(sum((e - mean) ** 2 for e in ent) / n) if n else math.nan

        entry = section.get("entry", "")
        entry_idx = next((i for i, nm in enumerate(names) if nm == entry), None) if entry else None
        found = entry_idx is not None
        overlay = section.get("overlay") or {}
        ov_size = float(overlay.get("size", 0) or 0)

        values = [
            n, mean, std, _ratio(sum(e * s for e, s in zip(ent, size)), sum(size)),
            sum(high), _ratio(sum(high), n),
            sum(execu), sum(write), sum(wx), _ratio(sum(wx), n),
            sum(1 for e, s in zip(execu, size) if e and s == 0),
            sum(nonstd), _ratio(sum(nonstd), n),
            sum(float(s["size_ratio"]) for s in sections), _ratio(sum(vsize), sum(size)),
            float(found),
            ent[entry_idx] if found else math.nan,
            float(write[entry_idx]) if found else math.nan,
            float(entry_idx == n - 1) if found else math.nan,
            float(sections[entry_idx]["size_ratio"]) if found else math.nan,
            float(ov_size > 0), float(overlay.get("size_ratio", 0) or 0), float(overlay.get("entropy", 0) or 0),
        ]
        return Extraction(values)
