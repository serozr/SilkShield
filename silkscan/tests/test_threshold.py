"""FPR-target threshold with ties and the >= rule."""

import numpy as np
import pytest

from silkscan.errors import DataValidationError
from silkscan.evaluation.threshold import select_threshold


def _fpr(benign, t):
    return float((np.asarray(benign) >= t).mean())


def test_tied_scores_move_together():
    benign = np.array([0.9, 0.9, 0.9] + [0.1] * 97)
    sel = select_threshold(benign, 0.02)  # including the tie would give FPR 0.03
    assert sel.threshold > 0.9
    assert sel.achieved_fpr == 0.0 == _fpr(benign, sel.threshold)
    sel = select_threshold(benign, 0.03)  # now the whole tie fits the budget
    assert sel.threshold == 0.9 and sel.achieved_fpr == pytest.approx(0.03)
    assert sel.n_false_positives == 3


def test_ge_rule_is_consistent_and_never_exceeds_target():
    rng = np.random.default_rng(0)
    for _ in range(200):
        benign = np.round(rng.random(int(rng.integers(50, 500))), int(rng.integers(1, 4)))  # many ties
        target = float(rng.choice([0.001, 0.01, 0.05, 0.2]))
        sel = select_threshold(benign, target)
        assert sel.achieved_fpr <= target + 1e-12
        assert sel.achieved_fpr == _fpr(benign, sel.threshold)
        assert sel.n_false_positives == int((benign >= sel.threshold).sum())
        # The threshold is the lowest possible: one distinct score lower would exceed the target.
        lower = benign[benign < sel.threshold]
        if len(lower):
            assert _fpr(benign, lower.max()) > target


def test_resolution_and_degenerate_cases():
    sel = select_threshold(np.linspace(0, 1, 100), 0.001)
    assert sel.below_resolution and sel.achieved_fpr == 0.0 and sel.threshold > 1.0
    sel = select_threshold(np.full(10, 0.5), 0.1)
    assert sel.threshold > 0.5 and sel.achieved_fpr == 0.0
    with pytest.raises(DataValidationError):
        select_threshold(np.array([]), 0.01)
