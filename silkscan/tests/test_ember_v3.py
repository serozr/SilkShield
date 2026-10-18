"""Ember_v3 adapter against the real thrember extractor, using a benign Win64 PE
(pip's bundled distlib launcher w64.exe). Skipped if thrember is not installed."""

import importlib
from pathlib import Path

import numpy as np
import pytest

from silkscan.errors import DependencyError
from silkscan.features.base import Status
from silkscan.features.groups import ember_v3 as E


def _launcher() -> Path:
    import pip

    p = Path(pip.__file__).parent / "_vendor" / "distlib" / "w64.exe"
    if not p.exists():
        pytest.skip("pip's w64.exe launcher not available")
    return p


@pytest.fixture
def thrember_features():
    try:
        return E.load_thrember_features()
    except DependencyError as e:
        pytest.skip(str(e))


def test_adapter_matches_official_vectorizer(thrember_features):
    from silkscan.inference.predict import record_from_pe

    rec = record_from_pe(_launcher())
    ex = E.EmberV3()
    names = ex.get_feature_names()
    assert len(names) == thrember_features.PEFeatureExtractor().dim == 2568
    assert ex.categorical_feature_names() == [names[i] for i in E.OFFICIAL_CATEGORICAL]
    block = ex.transform(np.array([rec.id.encode()], "S"), [{k: rec.inputs[k] for k in E.RAW_FIELDS}])
    official = thrember_features.PEFeatureExtractor().process_raw_features(dict(rec.inputs))
    np.testing.assert_array_equal(block.matrix[0], official)
    assert block.status[0] == Status.OK


def test_derived_groups_work_on_real_thrember_output(thrember_features):
    """section_summary/import_semantics written against thrember's raw format, checked on a real PE."""
    from silkscan.features.groups.import_semantics import ImportSemantics
    from silkscan.features.groups.section_summary import SectionSummary
    from silkscan.inference.predict import record_from_pe

    rec = record_from_pe(_launcher())
    for ex in (SectionSummary(), ImportSemantics()):
        view = {k: rec.inputs[k] for k in ex.required_inputs}
        b = ex.transform(np.array([b"x"], "S"), [view])
        assert b.status[0] == Status.OK, b.messages
        row = dict(zip(b.feature_names, b.matrix[0]))
        if isinstance(ex, SectionSummary):
            assert row["section_summary.n_sections"] >= 3 and row["section_summary.entry_found"] == 1
        else:
            assert row["import_semantics.total_imports"] > 50 and row["import_semantics.file_count"] > 0


def test_missing_raw_field_is_missing_input(thrember_features):
    ex = E.EmberV3()
    b = ex.transform(np.array([b"x"], "S"), [{"general": {}}])
    assert b.status[0] == Status.MISSING_INPUT


def test_missing_thrember_gives_actionable_error(monkeypatch):
    monkeypatch.setattr(E, "_MODULE", None)

    def fail(name, *a, **k):
        raise ModuleNotFoundError("No module named 'thrember'", name="thrember")

    monkeypatch.setattr(importlib, "import_module", fail)
    with pytest.raises(DependencyError, match="pip install"):
        E.load_thrember_features()


def test_falls_back_to_features_module_when_package_import_fails(monkeypatch, thrember_features):
    """On s390x polars may be missing: `import thrember` fails but thrember/features.py still loads."""
    monkeypatch.setattr(E, "_MODULE", None)

    def fail(name, *a, **k):
        raise ModuleNotFoundError("No module named 'polars'", name="polars")

    monkeypatch.setattr(importlib, "import_module", fail)
    mod = E.load_thrember_features()
    assert mod.PEFeatureExtractor().dim == 2568


def test_display_names_cover_every_column(thrember_features):
    ex = E.EmberV3()
    d = ex.display_names()
    assert list(d) == ex.get_feature_names()
    assert d["ember_v3.general_0002"] == "is PE (parsed)"
    assert d["ember_v3.datadirectories_0000"] == "data directory EXPORT size"
    assert not any(v.startswith(("header[", "strings[", "pefilewarnings[")) for v in d.values())
