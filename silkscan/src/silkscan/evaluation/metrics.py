"""Metrics implemented with numpy/scipy only (no scikit-learn needed on s390x).

Metrics that are undefined for the given data are reported as None together
with a reason, never computed anyway.
"""

from __future__ import annotations

from typing import Any, Sequence

import numpy as np
from scipy.stats import rankdata


def roc_auc(y: np.ndarray, s: np.ndarray) -> float:
    """Area under the ROC curve via the Mann-Whitney U statistic (ties averaged)."""
    y = np.asarray(y)
    pos = y == 1
    n_pos, n_neg = int(pos.sum()), int((~pos).sum())
    ranks = rankdata(s)
    return float((ranks[pos].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg))


def average_precision(y: np.ndarray, s: np.ndarray) -> float:
    """Average precision = sum_k (R_k - R_{k-1}) P_k over distinct score thresholds
    (same definition as scikit-learn's average_precision_score)."""
    y = np.asarray(y)
    order = np.argsort(-np.asarray(s, dtype=np.float64), kind="mergesort")
    s_sorted, y_sorted = np.asarray(s, dtype=np.float64)[order], y[order]
    last_of_tie = np.r_[np.flatnonzero(np.diff(s_sorted)), len(s_sorted) - 1]
    tp = np.cumsum(y_sorted == 1)[last_of_tie]
    fp = (last_of_tie + 1) - tp
    precision = tp / (tp + fp)
    recall = tp / tp[-1]
    return float(np.sum(np.diff(np.r_[0.0, recall]) * precision))


def tpr_at_fpr(y: np.ndarray, s: np.ndarray, fpr: float) -> float:
    """Best TPR with FPR <= fpr when the threshold is chosen on these same labels.
    Optimistic ("oracle"); reported only for comparison with the literature."""
    from silkscan.evaluation.threshold import select_threshold

    y = np.asarray(y)
    t = select_threshold(np.asarray(s)[y == 0], fpr).threshold
    return float((np.asarray(s)[y == 1] >= t).mean())


def _threshold_repr(t: float | np.ndarray) -> float | str:
    if np.ndim(t) == 0:
        return float(t)
    t = np.asarray(t)
    if len(t) and (t == t.flat[0]).all():
        return float(t.flat[0])
    return "per-record (threshold policy)"


def at_threshold(y: np.ndarray, s: np.ndarray, t: float | np.ndarray) -> dict[str, Any]:
    """Metrics for the rule score >= t; `t` may be one value or one value per record."""
    y = np.asarray(y)
    pred = np.asarray(s) >= np.asarray(t)
    tp = int((pred & (y == 1)).sum())
    fp = int((pred & (y == 0)).sum())
    tn = int((~pred & (y == 0)).sum())
    fn = int((~pred & (y == 1)).sum())
    return {
        "threshold": _threshold_repr(t),
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "fpr": fp / (fp + tn) if fp + tn else None,
    }


def evaluate_scores(y: np.ndarray, s: np.ndarray, threshold: float | np.ndarray, report_fprs: Sequence[float]
                    ) -> dict[str, Any]:
    y = np.asarray(y)
    n_pos, n_neg = int((y == 1).sum()), int((y == 0).sum())
    out: dict[str, Any] = {"n": int(len(y)), "n_malicious": n_pos, "n_benign": n_neg, "undefined": {}}
    if n_pos and n_neg:
        out["roc_auc"] = roc_auc(y, s)
        out["average_precision"] = average_precision(y, s)
        out["oracle_tpr_at_fpr"] = {str(f): tpr_at_fpr(y, s, f) for f in report_fprs}
    else:
        reason = "only one class present (%s)" % ("malicious" if n_pos else "benign" if n_neg else "empty")
        out["roc_auc"] = out["average_precision"] = out["oracle_tpr_at_fpr"] = None
        out["undefined"].update({"roc_auc": reason, "average_precision": reason, "oracle_tpr_at_fpr": reason})
    out["at_threshold"] = at_threshold(y, s, threshold)
    if not n_neg:
        out["undefined"]["fpr"] = "no benign samples; FPR is not reported for this split"
        out["undefined"]["precision"] = "no benign samples; precision is trivially 1 and not meaningful"
        out["at_threshold"]["precision"] = None
    return out


def bootstrap_ci(y: np.ndarray, s: np.ndarray, threshold: float | np.ndarray, n_boot: int, seed: int
                 ) -> dict[str, Any]:
    """95% intervals from class-stratified bootstrap resamples (class counts held fixed)."""
    y, s = np.asarray(y), np.asarray(s, dtype=np.float64)
    t = np.broadcast_to(np.asarray(threshold, dtype=np.float64), s.shape)
    pos, neg = s[y == 1], s[y == 0]
    tpos, tneg = t[y == 1], t[y == 0]
    rng = np.random.default_rng(seed)
    recall, fpr, auc = [], [], []
    for _ in range(n_boot):
        ip = rng.integers(0, len(pos), len(pos)) if len(pos) else np.zeros(0, int)
        ineg = rng.integers(0, len(neg), len(neg)) if len(neg) else np.zeros(0, int)
        bp, bn = pos[ip], neg[ineg]
        if len(bp):
            recall.append(float((bp >= tpos[ip]).mean()))
        if len(bn):
            fpr.append(float((bn >= tneg[ineg]).mean()))
        if len(bp) and len(bn):
            auc.append(roc_auc(np.r_[np.ones(len(bp)), np.zeros(len(bn))], np.r_[bp, bn]))

    def ci(v: list[float]) -> list[float] | None:
        return [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))] if v else None

    return {"recall": ci(recall), "fpr": ci(fpr), "roc_auc": ci(auc), "n_boot": int(n_boot),
            "method": "class-stratified bootstrap, 2.5/97.5 percentiles"}


def evaluate_by_group(y: np.ndarray, s: np.ndarray, threshold: float | np.ndarray, groups: np.ndarray
                      ) -> dict[str, Any]:
    """Recall/FPR at the fixed threshold(s) per subgroup (e.g. month of first submission)."""
    out = {}
    t = np.broadcast_to(np.asarray(threshold, dtype=np.float64), np.shape(s))
    for g in np.unique(groups):
        m = groups == g
        r = at_threshold(y[m], s[m], t[m])
        out[str(g)] = {"n": int(m.sum()), "n_malicious": int((y[m] == 1).sum()), "n_benign": int((y[m] == 0).sum()),
                       "recall": r["recall"], "fpr": r["fpr"]}
    return out
