"""Decision threshold for a target false-positive rate.

Decision rule: malicious iff score >= t.
The threshold is chosen on benign validation scores only: t is the smallest
benign score such that the fraction of benign scores >= t is <= target.
Tied scores move together, so the realised FPR never exceeds the target. If no
benign score satisfies this (target below 1/n_benign, or a large tie at the
top), t is placed just above the highest benign score and FPR is 0.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

import numpy as np

from silkscan.errors import DataValidationError


@dataclass
class ThresholdSelection:
    threshold: float
    target_fpr: float
    achieved_fpr: float
    n_benign: int
    n_false_positives: int
    below_resolution: bool  # target * n_benign < 1: a single FP already exceeds the target
    rule: str = "score >= threshold"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def select_threshold(benign_scores: np.ndarray, target_fpr: float) -> ThresholdSelection:
    s = np.asarray(benign_scores, dtype=np.float64)
    n = len(s)
    if n == 0:
        raise DataValidationError("Cannot select a threshold: the validation split has no benign samples.")
    if np.isnan(s).any():
        raise DataValidationError("Benign validation scores contain NaN.")
    uniq = np.unique(s)[::-1]                         # descending distinct scores
    n_at_or_above = np.searchsorted(np.sort(s), uniq, side="left")
    n_at_or_above = n - n_at_or_above                 # count of scores >= each distinct score
    ok = n_at_or_above <= target_fpr * n
    if ok.any():
        k = int(np.flatnonzero(ok)[-1])               # lowest distinct score still within budget
        t = float(uniq[k])
        fp = int(n_at_or_above[k])
    else:
        t = float(np.nextafter(uniq[0], np.inf))
        fp = 0
    return ThresholdSelection(t, float(target_fpr), fp / n, n, fp, target_fpr * n < 1)


POLICY_MODES = ("global", "per_group", "strictest")


def select_policy(benign_scores: np.ndarray, benign_flags: np.ndarray, target_fpr: float, mode: str,
                  flag_name: str, column: str) -> dict[str, Any]:
    """Threshold policy over a binary file-kind flag (e.g. DLL vs EXE).

    - global: one threshold from all benign scores (FPR target holds on average only);
    - per_group: a threshold per flag value, each meeting the target on its own benign files;
    - strictest: one threshold, the larger of the two per-group ones, so every group meets the target.
    """
    if mode not in POLICY_MODES:
        raise DataValidationError(f"Unknown threshold policy `{mode}`; choose one of {POLICY_MODES}.")
    s, f = np.asarray(benign_scores, dtype=np.float64), np.asarray(benign_flags, dtype=bool)
    if f.all() or not f.any():
        raise DataValidationError(f"Flag `{flag_name}` ({column}) has a single value on validation benign files.")
    glob = select_threshold(s, target_fpr)
    yes, no = select_threshold(s[f], target_fpr), select_threshold(s[~f], target_fpr)
    thresholds = {"global": {"yes": glob.threshold, "no": glob.threshold},
                  "per_group": {"yes": yes.threshold, "no": no.threshold},
                  "strictest": {"yes": max(yes.threshold, no.threshold), "no": max(yes.threshold, no.threshold)}}
    return {"mode": mode, "flag": flag_name, "column": column, "target_fpr": float(target_fpr),
            "thresholds": thresholds[mode],
            "group_selections": {"yes": yes.to_dict(), "no": no.to_dict()}, "rule": "score >= threshold[flag]"}


def row_thresholds(policy: dict[str, Any] | None, global_threshold: float | None, flags: np.ndarray | None,
                   n: int) -> np.ndarray:
    if not policy:
        return np.full(n, float(global_threshold))
    t = policy.get("thresholds")
    if policy["mode"] == "global" or flags is None:
        return np.full(n, float(t["yes"] if t else global_threshold))
    return np.where(np.asarray(flags, dtype=bool), float(t["yes"]), float(t["no"]))


def select_review(benign_scores: np.ndarray, benign_flags: np.ndarray | None, review_fpr: float,
                  main_policy: dict[str, Any] | None, main_global: float) -> dict[str, Any]:
    """Lower ("review") thresholds for a three-zone decision: clean < low <= suspicious < high <= malicious.

    Uses the same grouping as the active malicious-threshold policy, at a looser FPR target, and is
    capped at the malicious threshold of each group so the zones never overlap.
    """
    mode = (main_policy or {}).get("mode", "global")
    s = np.asarray(benign_scores, dtype=np.float64)
    if mode == "global" or benign_flags is None:
        low = select_threshold(s, review_fpr).threshold
        lows = {"yes": low, "no": low}
    else:
        f = np.asarray(benign_flags, dtype=bool)
        lows = {"yes": select_threshold(s[f], review_fpr).threshold,
                "no": select_threshold(s[~f], review_fpr).threshold}
        if mode == "strictest":
            lows = dict.fromkeys(lows, max(lows.values()))
    highs = (main_policy or {}).get("thresholds") or {"yes": main_global, "no": main_global}
    out = {"mode": mode, "target_fpr": float(review_fpr),
           "thresholds": {g: min(lows[g], float(highs[g])) for g in ("yes", "no")}}
    if main_policy and mode != "global":
        out.update(flag=main_policy["flag"], column=main_policy["column"])
    return out


def three_zone(y: np.ndarray, s: np.ndarray, high: np.ndarray, low: np.ndarray) -> dict[str, Any]:
    """Counts and rates for clean / suspicious / malicious zones."""
    y, s = np.asarray(y), np.asarray(s)
    mal = s >= high
    sus = (s >= low) & ~mal
    cln = ~(mal | sus)
    n0, n1 = int((y == 0).sum()), int((y == 1).sum())

    def rate(m: np.ndarray, label: int, n: int) -> float | None:
        return float((m & (y == label)).sum() / n) if n else None

    return {
        "zones": {z: {"benign": int((m & (y == 0)).sum()), "malicious": int((m & (y == 1)).sum())}
                  for z, m in (("malicious", mal), ("suspicious", sus), ("clean", cln))},
        "review_load": float(sus.mean()) if len(s) else None,                 # share of all files sent to review
        "recall_auto": rate(mal, 1, n1),                                      # malware decided automatically
        "recall_auto_or_review": rate(mal | sus, 1, n1),                      # malware not let through
        "missed_rate": rate(cln, 1, n1),                                      # malware in the clean zone
        "fpr_auto": rate(mal, 0, n0),                                         # benign auto-blocked
        "benign_review_rate": rate(sus, 0, n0),                               # benign sent to review
    }


def threshold_stability(benign_scores: np.ndarray, target_fpr: float, n_boot: int, seed: int
                        ) -> dict[str, float]:
    """Quantiles of the threshold re-selected on bootstrap resamples of the benign scores.

    A wide spread means the validation split has too few benign samples to pin
    down the threshold for this target FPR.
    """
    s = np.asarray(benign_scores, dtype=np.float64)
    rng = np.random.default_rng(seed)
    ts = np.array([select_threshold(s[rng.integers(0, len(s), len(s))], target_fpr).threshold
                   for _ in range(n_boot)])
    return {"p2.5": float(np.percentile(ts, 2.5)), "p50": float(np.percentile(ts, 50)),
            "p97.5": float(np.percentile(ts, 97.5)), "n_boot": int(n_boot)}
