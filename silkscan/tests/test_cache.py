"""Cache keys change with everything that changes the output; partial writes are ignored."""

from pathlib import Path

import numpy as np
import pytest
import yaml

from silkscan.config import GroupConfig
from silkscan.features.base import FeatureBlock
from silkscan.features.cache import FeatureCache, cache_key
from silkscan.features.groups.import_semantics import ImportSemantics
from silkscan.features.groups.section_summary import SectionSummary
from silkscan.features.pipeline import FeaturePipeline, MemorySource
from silkscan.utils.io import atomic_directory

from silkscan.synthetic import make_records


def test_key_depends_on_split_version_config_state_and_tools(monkeypatch, tmp_path):
    base = cache_key("split-a", SectionSummary())
    assert cache_key("split-a", SectionSummary()) == base
    assert cache_key("split-b", SectionSummary()) != base
    assert cache_key("split-a", SectionSummary(high_entropy=6.5)) != base
    monkeypatch.setattr(SectionSummary, "version", "2")
    assert cache_key("split-a", SectionSummary()) != base

    from stateful_fixture import SectionVocab
    a, b = SectionVocab(), SectionVocab()
    a.set_state({"vocab": [".x"]})
    b.set_state({"vocab": [".y"]})
    assert cache_key("s", a) != cache_key("s", b)

    from importlib import resources
    mapping = yaml.safe_load(resources.files("silkscan.features.data").joinpath("api_groups.v1.yaml").read_text())
    mapping["categories"]["file"]["functions"].append("somethingnew")
    custom = tmp_path / "m.yaml"
    custom.write_text(yaml.safe_dump(mapping))
    assert ImportSemantics(mapping=str(custom)).tool_versions() != ImportSemantics().tool_versions()
    assert cache_key("s", ImportSemantics(mapping=str(custom))) != cache_key("s", ImportSemantics())


def test_incomplete_entry_is_not_used(tmp_path):
    cache = FeatureCache(tmp_path)
    block = FeatureBlock(np.array([b"a"], "S"), np.ones((1, 1), np.float32), ("g.x",), "g", "1", np.zeros(1, np.uint8))
    (tmp_path / "g" / "k1").mkdir(parents=True)  # e.g. a crash left a directory without _COMPLETE.json
    assert not cache.has("g", "k1") and cache.load("g", "k1") is None
    cache.save("k2", block)
    assert cache.has("g", "k2")
    np.testing.assert_array_equal(cache.load("g", "k2").matrix, block.matrix)


def test_crash_during_write_leaves_nothing(tmp_path):
    with pytest.raises(RuntimeError):
        with atomic_directory(tmp_path / "entry") as d:
            (d / "matrix.npy").write_bytes(b"partial")
            raise RuntimeError("crash")
    assert not (tmp_path / "entry").exists()
    assert list(tmp_path.iterdir()) == []


def test_second_materialize_uses_cache_and_new_group_only_computes_itself(tmp_path, monkeypatch):
    recs = make_records(40)
    cache = FeatureCache(tmp_path)
    g1 = GroupConfig("section_summary", missing_policy="impute_with_indicator")
    first = FeaturePipeline([g1]).build(MemorySource(recs), cache)

    calls = []
    orig = ImportSemantics.transform
    monkeypatch.setattr(SectionSummary, "transform", lambda *a, **k: (_ for _ in ()).throw(AssertionError("recomputed")))
    monkeypatch.setattr(ImportSemantics, "transform", lambda self, *a: calls.append(1) or orig(self, *a))
    g2 = GroupConfig("import_semantics", missing_policy="impute_with_indicator")
    second = FeaturePipeline([g1, g2]).build(MemorySource(recs), cache)
    assert calls  # only the new group was computed
    np.testing.assert_array_equal(second.X[:, : first.X.shape[1]], first.X)
