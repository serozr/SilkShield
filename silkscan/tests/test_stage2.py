"""Stage 2: threat category and family on top of a detection run (synthetic fixture)."""

from pathlib import Path

import numpy as np
import pytest

from silkscan.checks.decision import combine
from silkscan.config import config_from_dict
from silkscan.errors import ConfigError, SchemaMismatchError
from silkscan.inference.bundle import ModelBundle
from silkscan.inference.predict import Submission, scan
from silkscan.stage2 import Stage2Model, load_taxonomy
from silkscan.stage2.train import threshold_for_precision, train_stage2
from silkscan.synthetic import make_records


def test_taxonomy_maps_tags_and_rejects_duplicates(tmp_path):
    tax = load_taxonomy()
    assert tax.categories_of(["Ransom"]) == {"ransomware"}
    assert tax.categories_of(["passwordstealer", "stealer"]) == {"stealer"}
    assert tax.categories_of(["encoder", "selfdel"]) == set()      # traits, not categories
    assert tax.impact("ransomware") == "high" and tax.impact("pua") == "low"
    bad = tmp_path / "t.yaml"
    bad.write_text("version: 1\ncategories:\n  a: {impact: high, tags: [x]}\n  b: {impact: low, tags: [x]}\n")
    with pytest.raises(ConfigError, match="both"):
        load_taxonomy(str(bad))


def test_threshold_for_precision():
    y = np.array([1, 1, 1, 0, 1, 0, 0, 0])
    s = np.array([.9, .8, .7, .6, .5, .4, .3, .2])
    assert threshold_for_precision(y, s, 0.8, min_tp=1) == 0.5      # 4/5 = 0.8 at the 0.5 cut
    assert threshold_for_precision(y, s, 1.0, min_tp=1) == 0.7
    assert threshold_for_precision(y, s, 1.0, min_tp=4) is None


def test_suspicious_with_high_impact_type_is_escalated():
    assert combine("suspicious", [], ["ransomware"])["priority"] == "P2"
    assert combine("suspicious", [], ["coinminer"])["priority"] == "P3"
    assert combine("malicious", [], ["backdoor"])["priority"] == "P1"


def test_train_stage2_and_classify(trained_run):
    run, cfg = trained_run
    out = train_stage2(run, precision=0.5, family_top=8, family_min=5, min_pos=5, rounds=30)
    model = Stage2Model(out)
    assert model.categories, "at least one category should be learnable on the fixture"
    assert model.meta["label_coverage"]["train"]["with_category"] < model.meta["label_coverage"]["train"]["malware"]
    assert "end_to_end_test" in model.meta and (out / "report.md").exists()
    model.require_compatible(ModelBundle(run).schema.fingerprint())
    with pytest.raises(SchemaMismatchError):
        model.require_compatible("0" * 64)

    bundle = ModelBundle(run)
    recs = make_records(40, seed=11, label=1)
    verdicts = scan(bundle, bundle.backend(), [Submission(None, r) for r in recs], stage2=model)
    flagged = [v for v in verdicts if v["model_decision"] in ("malicious", "suspicious")]
    assert flagged and all(v["classification"] is not None for v in flagged)
    assert all(v["classification"] is None for v in verdicts if v["model_decision"] == "clean")
    typed = [v for v in flagged if v["classification"]["categories"]]
    assert all(set(c["name"] for c in v["classification"]["categories"]) <= set(v["tags"]) for v in typed)
