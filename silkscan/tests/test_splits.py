"""Split disjointness, temporal validation, filtering."""

import json
from pathlib import Path

import numpy as np
import pytest

from silkscan.config import config_from_dict
from silkscan.data.manifest import Manifest, build_manifest
from silkscan.data.records import parse_date
from silkscan.errors import DataValidationError, LeakageError


def test_manifest_splits_are_disjoint_and_temporal(cfg):
    m = build_manifest(cfg.data)
    assert list(m.splits) == ["train", "validation", "test", "challenge"]
    names = list(m.splits)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            assert not np.isin(m.splits[a].ids, m.splits[b].ids).any(), (a, b)
    boundary = parse_date(cfg.data.validation_start)
    assert (m.splits["train"].dates < boundary).all()
    assert (m.splits["validation"].dates >= boundary).all()
    # unlabeled train record excluded, Win32 challenge records filtered out
    assert m.stats["train"]["unlabeled"] == 1
    assert m.stats["challenge"]["other_file_type"] > 0
    assert (m.splits["challenge"].labels == 1).all()


def test_manifest_roundtrip(cfg, tmp_path):
    m = build_manifest(cfg.data)
    m.save(tmp_path / "man")
    loaded = Manifest.load(tmp_path / "man")
    assert loaded.fingerprint == m.fingerprint
    with pytest.raises(DataValidationError, match="already exists"):
        m.save(tmp_path / "man")


def _copy_train_line_to_test(root: Path) -> None:
    train = (root / "synthetic_Win64_train.jsonl").read_text().splitlines()
    with open(root / "synthetic_Win64_test.jsonl", "a") as f:
        f.write(train[0] + "\n")


def test_id_in_two_splits_is_an_error(cfg_dict):
    _copy_train_line_to_test(Path(cfg_dict["data"]["root"]))
    with pytest.raises(LeakageError, match="earlier split"):
        build_manifest(config_from_dict(cfg_dict).data)


def test_overlap_can_be_dropped_from_later_split(cfg_dict):
    _copy_train_line_to_test(Path(cfg_dict["data"]["root"]))
    cfg_dict["data"]["overlap_policy"] = "drop_from_later"
    m = build_manifest(config_from_dict(cfg_dict).data)
    assert m.stats["test"]["dropped_overlap"] == 1


def test_duplicate_id_within_split_is_an_error(cfg_dict):
    p = Path(cfg_dict["data"]["root"]) / "synthetic_Win64_test.jsonl"
    first = p.read_text().splitlines()[0]
    with open(p, "a") as f:
        f.write(first + "\n")
    with pytest.raises(DataValidationError, match="duplicated"):
        build_manifest(config_from_dict(cfg_dict).data)


def test_data_change_is_detected(cfg, tmp_path):
    m = build_manifest(cfg.data)
    m.save(tmp_path / "man")
    p = Path(cfg.data.root) / "synthetic_Win64_test.jsonl"
    rec = json.loads(p.read_text().splitlines()[0])
    with open(p, "a") as f:
        f.write(json.dumps(rec | {"sha256": "synthetic:new"}) + "\n")
    with pytest.raises(DataValidationError, match="changed"):
        Manifest.load(tmp_path / "man")


def test_train_fraction_is_deterministic_and_leaves_other_splits(cfg_dict):
    full = build_manifest(config_from_dict(cfg_dict).data)
    cfg_dict["data"]["train_fraction"] = 0.5
    a = build_manifest(config_from_dict(cfg_dict).data)
    b = build_manifest(config_from_dict(cfg_dict).data)
    np.testing.assert_array_equal(a.splits["train"].ids, b.splits["train"].ids)
    assert 0.3 < len(a.splits["train"]) / len(full.splits["train"]) < 0.7
    assert np.isin(a.splits["train"].ids, full.splits["train"].ids).all()
    for name in ("validation", "test", "challenge"):
        np.testing.assert_array_equal(a.splits[name].ids, full.splits[name].ids)
    assert a.fingerprint != full.fingerprint


def _append_copy(root: Path, change: dict) -> None:
    p = root / "synthetic_Win64_test.jsonl"
    rec = json.loads(p.read_text().splitlines()[3])
    with open(p, "a") as f:
        f.write(json.dumps(rec | change) + "\n")


def test_duplicate_differing_only_in_ignored_fields_is_dropped(cfg_dict):
    """EMBER2024's weekly files hold each record twice; the copies differ only in capa lists."""
    _append_copy(Path(cfg_dict["data"]["root"]), {"caps": [{"Capability": "x", "Namespace": "y"}], "ttps": []})
    with pytest.raises(DataValidationError, match="duplicate_policy"):
        build_manifest(config_from_dict(cfg_dict).data)
    cfg_dict["data"]["duplicate_policy"] = "keep_first"
    m = build_manifest(config_from_dict(cfg_dict).data)
    assert m.stats["test"]["duplicates_dropped"] == 1
    assert len(np.unique(m.splits["test"].ids)) == len(m.splits["test"])


@pytest.mark.parametrize("change", [{"label": 1 - 0}, {"general": {"size": 1, "entropy": 0.0, "is_pe": 1}}])
def test_duplicate_with_different_label_or_features_is_an_error(cfg_dict, change):
    root = Path(cfg_dict["data"]["root"])
    rec = json.loads((root / "synthetic_Win64_test.jsonl").read_text().splitlines()[3])
    if "label" in change:
        change = {"label": 1 - rec["label"]}
    _append_copy(root, change)
    cfg_dict["data"]["duplicate_policy"] = "keep_first"
    with pytest.raises(DataValidationError, match="different"):
        build_manifest(config_from_dict(cfg_dict).data)
