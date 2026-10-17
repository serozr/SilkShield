"""Metrics match scikit-learn; undefined metrics are null with a reason."""

import numpy as np
import pytest

from silkscan.evaluation.metrics import average_precision, evaluate_scores, roc_auc


def test_metrics_match_sklearn():
    sk = pytest.importorskip("sklearn.metrics")
    rng = np.random.default_rng(0)
    for _ in range(50):
        n = int(rng.integers(20, 400))
        y = (rng.random(n) < rng.uniform(0.1, 0.9)).astype(int)
        if y.min() == y.max():
            continue
        s = np.round(rng.random(n) + 0.3 * y, int(rng.integers(1, 4)))  # ties included
        assert roc_auc(y, s) == pytest.approx(sk.roc_auc_score(y, s), abs=1e-9)
        assert average_precision(y, s) == pytest.approx(sk.average_precision_score(y, s), abs=1e-9)


def test_single_class_metrics_are_null_with_reason():
    r = evaluate_scores(np.ones(10, int), np.linspace(0, 1, 10), 0.5, [0.01])
    assert r["roc_auc"] is None and r["average_precision"] is None
    assert "one class" in r["undefined"]["roc_auc"]
    assert r["at_threshold"]["fpr"] is None and "no benign" in r["undefined"]["fpr"]
    assert r["at_threshold"]["recall"] == 0.5
    r = evaluate_scores(np.zeros(10, int), np.linspace(0, 1, 10), 0.5, [0.01])
    assert r["roc_auc"] is None and r["at_threshold"]["recall"] is None
