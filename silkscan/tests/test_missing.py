"""Missing data states stay distinct; zero denominators give NaN, not inf."""

import math

import numpy as np
import pytest

from silkscan.config import GroupConfig
from silkscan.data.records import split_record
from silkscan.errors import ExtractionError
from silkscan.features.base import Status
from silkscan.features.groups.import_semantics import ImportSemantics
from silkscan.features.groups.section_summary import SectionSummary
from silkscan.features.pipeline import FeaturePipeline, MemorySource
from silkscan.inference.bundle import ModelBundle
from silkscan.inference.predict import predict_records

from silkscan.synthetic import make_records

GEN = {"is_pe": 1, "size": 10, "entropy": 1.0, "start_bytes": [77, 90, 0, 0]}


def _status(ex, view):
    return ex.transform(np.array([b"x"], "S"), [view]).status[0]


def test_four_states_are_distinguished():
    s = SectionSummary()
    sec = {"entry": ".text", "sections": [], "overlay": {"size": 0, "size_ratio": 0, "entropy": 0}}
    assert _status(s, {"general": GEN, "section": sec}) == Status.OK
    assert _status(s, {"general": GEN}) == Status.MISSING_INPUT
    assert _status(s, {"general": GEN, "section": {"sections": "bad"}}) == Status.PARSE_ERROR
    assert _status(s, {"general": {**GEN, "is_pe": 0}, "section": {}}) == Status.NOT_APPLICABLE
    i = ImportSemantics()
    assert _status(i, {"general": GEN, "imports": {}}) == Status.OK
    assert _status(i, {"general": GEN}) == Status.MISSING_INPUT
    assert _status(i, {"general": GEN, "imports": []}) == Status.PARSE_ERROR
    assert _status(i, {"general": {**GEN, "is_pe": 0}, "imports": {}}) == Status.NOT_APPLICABLE


def test_zero_denominators_give_nan_not_inf():
    s = SectionSummary()
    sec = {"entry": "", "sections": [], "overlay": {"size": 0, "size_ratio": 0, "entropy": 0}}
    b = s.transform(np.array([b"x"], "S"), [{"general": GEN, "section": sec}])
    row = dict(zip(b.feature_names, b.matrix[0]))
    assert row["section_summary.n_sections"] == 0
    assert math.isnan(row["section_summary.entropy_mean"])
    assert math.isnan(row["section_summary.virtual_to_raw_ratio"])
    assert not np.isinf(b.matrix).any()
    imp = ImportSemantics().transform(np.array([b"x"], "S"), [{"general": GEN, "imports": {}}])
    r = dict(zip(imp.feature_names, imp.matrix[0]))
    assert r["import_semantics.total_imports"] == 0 and math.isnan(r["import_semantics.network_ratio"])


def _records_with_problem():
    recs = make_records(5, seed=9)
    raw = {"sha256": "synthetic:broken", "label": 0, "general": GEN}  # no section, no imports
    return recs + [split_record(raw)]


def test_error_policy_raises_and_impute_policy_adds_indicators():
    recs = _records_with_problem()
    strict = FeaturePipeline([GroupConfig("section_summary", missing_policy="error")])
    with pytest.raises(ExtractionError, match="MISSING_INPUT"):
        strict.build(MemorySource(recs), _cache(), strict=True)

    imp = FeaturePipeline([GroupConfig("section_summary", missing_policy="impute_with_indicator")])
    f = imp.transform_records(recs, strict=True)
    col = f.feature_names.index("section_summary.__status_missing_input")
    assert f.X[-1, col] == 1 and f.X[:-1, col].sum() == 0
    assert np.isnan(f.X[-1, f.feature_names.index("section_summary.n_sections")])
    assert f.status["section_summary"][-1] == Status.MISSING_INPUT


def _cache():
    import tempfile

    from silkscan.features.cache import FeatureCache

    return FeatureCache(tempfile.mkdtemp())


def test_failed_extraction_is_never_reported_clean(trained_run, monkeypatch):
    run, _ = trained_run
    bundle = ModelBundle(run)
    broken = split_record({"sha256": "synthetic:broken", "label": 0, "general": GEN, "caps": [], "ttps": [], "mbc": []})
    [p] = predict_records(bundle, bundle.backend(), [broken])
    assert p["decision"] in ("inconclusive", "malicious")
    assert p["feature_status"]["section_summary"] == "MISSING_INPUT"

    for g in bundle.config.features.groups:
        if g.name == "section_summary":
            g.missing_policy = "error"
    bundle.schema.groups[0].missing_policy = "error"  # keep schema consistent with the edited config
    bundle.schema.groups[0].feature_names = [n for n in bundle.schema.groups[0].feature_names if "__status" not in n]
    monkeypatch.setattr(type(bundle), "backend", lambda self, *a, **k: _FakeBackend())
    [p] = predict_records(bundle, bundle.backend(), [broken])
    assert p["decision"] == "error" and p["score"] is None


class _FakeBackend:
    name = "lightgbm"

    def predict(self, X):
        return np.zeros(X.shape[0])
