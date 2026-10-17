"""Deterministic columns, duplicate names, schema mismatch."""

import numpy as np
import pytest

from silkscan.config import GroupConfig, config_from_dict
from silkscan.errors import ConfigError, ExtractionError, SchemaMismatchError
from silkscan.features.base import FeatureBlock
from silkscan.features.groups.section_summary import SectionSummary
from silkscan.features.pipeline import FeaturePipeline
from silkscan.inference.bundle import ModelBundle


G1 = GroupConfig("section_summary", missing_policy="impute_with_indicator")
G2 = GroupConfig("import_semantics", missing_policy="impute_with_indicator")


def test_column_order_is_deterministic_and_follows_config():
    a, b = FeaturePipeline([G1, G2]).schema(), FeaturePipeline([G1, G2]).schema()
    assert a.feature_names == b.feature_names
    assert a.fingerprint() == b.fingerprint()
    swapped = FeaturePipeline([G2, G1]).schema()
    assert swapped.feature_names[0].startswith("import_semantics.")
    assert sorted(swapped.feature_names) == sorted(a.feature_names)
    assert len(set(a.feature_names)) == len(a.feature_names)


def test_duplicate_or_unprefixed_feature_names_are_rejected():
    ids = np.array([b"a"], dtype="S")
    with pytest.raises(ExtractionError, match="duplicated"):
        FeatureBlock(ids, np.zeros((1, 2), np.float32), ("g.x", "g.x"), "g", "1", np.zeros(1, np.uint8))
    with pytest.raises(ExtractionError, match="must start with"):
        FeatureBlock(ids, np.zeros((1, 1), np.float32), ("other.x",), "g", "1", np.zeros(1, np.uint8))


def test_same_group_twice_in_config_is_rejected(cfg_dict):
    raw = cfg_dict
    raw["features"]["groups"].append({"name": "section_summary"})
    with pytest.raises(ConfigError, match="more than once"):
        config_from_dict(raw)


def test_unknown_config_key_is_rejected(cfg_dict):
    raw = cfg_dict
    raw["model"]["num_boost_rounds"] = 5
    with pytest.raises(ConfigError, match="Unknown key"):
        config_from_dict(raw)


def test_schema_mismatch_on_extractor_version_change(trained_run, monkeypatch):
    run, _ = trained_run
    ModelBundle(run).pipeline()  # matches as trained
    monkeypatch.setattr(SectionSummary, "version", "999")
    with pytest.raises(SchemaMismatchError, match="section_summary.*version"):
        ModelBundle(run).pipeline()


def test_schema_mismatch_on_mapping_file_change(trained_run, tmp_path):
    from silkscan.features.groups.import_semantics import DEFAULT_MAPPING
    from importlib import resources
    import yaml

    run, _ = trained_run
    bundle = ModelBundle(run)
    mapping = yaml.safe_load(resources.files("silkscan.features.data").joinpath(DEFAULT_MAPPING).read_text())
    mapping["categories"]["network"]["functions"].append("newapi")
    custom = tmp_path / "api.yaml"
    custom.write_text(yaml.safe_dump(mapping))
    for g in bundle.config.features.groups:
        if g.name == "import_semantics":
            g.params["mapping"] = str(custom)
    with pytest.raises(SchemaMismatchError, match="import_semantics.*tool_versions"):
        bundle.pipeline()
