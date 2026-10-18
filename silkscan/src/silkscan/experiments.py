"""Research tools: feature-group ablation and explanation reports."""

from __future__ import annotations

import logging
from dataclasses import replace
from pathlib import Path
from typing import Any, Sequence

import numpy as np

from silkscan.config import Config
from silkscan.errors import ConfigError
from silkscan.features.cache import FeatureCache
from silkscan.inference.bundle import ModelBundle
from silkscan.runs import create_run_dir
from silkscan.utils.io import read_json, write_json
from silkscan.workflow import (_features, _with_data_paths, evaluate, load_manifest, source,
                             train)

log = logging.getLogger(__name__)

METRICS = ("roc_auc", "average_precision", "recall", "fpr")


# ---------------------------------------------------------------------------
# ablation
# ---------------------------------------------------------------------------
def default_variants(cfg: Config) -> list[list[str]]:
    """First enabled group alone, plus each other group added to it, plus all of them."""
    enabled = [g.name for g in cfg.enabled_groups()]
    base = enabled[0]
    variants = [[base]] + [[base, g] for g in enabled[1:]]
    if len(enabled) > 2:
        variants.append(enabled)
    return variants


def _variant_config(cfg: Config, groups: Sequence[str], seed: int) -> Config:
    known = {g.name for g in cfg.features.groups}
    unknown = sorted(set(groups) - known)
    if unknown:
        raise ConfigError(f"Ablation variant uses groups not listed in the config: {unknown}.")
    feats = replace(cfg.features, groups=[replace(g, enabled=g.name in groups) for g in cfg.features.groups])
    return replace(cfg, seed=seed, features=feats)


def _flat(m: dict[str, Any]) -> dict[str, Any]:
    t = m["at_threshold"]
    return {"roc_auc": m["roc_auc"], "average_precision": m["average_precision"], "recall": t["recall"],
            "fpr": t["fpr"]}


def ablation(cfg: Config, variants: list[list[str]] | None, seeds: Sequence[int], evaluate_test: bool) -> Path:
    variants = variants or default_variants(cfg)
    out = create_run_dir(Path(cfg.runs_dir), cfg.fingerprint(), prefix="ablation-")
    rows = []
    for groups in variants:
        ordered = [g.name for g in cfg.features.groups if g.name in groups]
        name = "+".join(ordered)
        for seed in seeds:
            log.info("Ablation: %s, seed %d", name, seed)
            run = train(_variant_config(cfg, ordered, seed))
            row: dict[str, Any] = {"variant": name, "seed": seed, "run_dir": str(run),
                                   "validation": _flat(read_json(run / "metrics_validation.json"))}
            if evaluate_test:
                ev = evaluate(run, ["test"])
                row["test"] = _flat(read_json(ev / "test.json"))
            rows.append(row)
            write_json(out / "rows.json", rows)  # keep partial results if a later run fails

    summary = summarize(rows)
    write_json(out / "summary.json", summary)
    (out / "summary.md").write_text(summary_markdown(summary), encoding="utf-8")
    return out


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for variant in dict.fromkeys(r["variant"] for r in rows):
        rs = [r for r in rows if r["variant"] == variant]
        entry: dict[str, Any] = {"n_seeds": len(rs)}
        for split in ("validation", "test"):
            if split not in rs[0]:
                continue
            entry[split] = {}
            for m in METRICS:
                vals = [r[split][m] for r in rs if r[split][m] is not None]
                entry[split][m] = {"mean": float(np.mean(vals)) if vals else None,
                                   "std": float(np.std(vals, ddof=1)) if len(vals) > 1 else None}
        out[variant] = entry
    return out


def summary_markdown(summary: dict[str, Any]) -> str:
    def fmt(d: dict[str, Any]) -> str:
        if d["mean"] is None:
            return "—"
        return f"{d['mean']:.4f}" + (f" ± {d['std']:.4f}" if d["std"] is not None else "")

    splits = [s for s in ("validation", "test") if any(s in e for e in summary.values())]
    head = ["Variant", "Seeds"] + [f"{s} {m}" for s in splits for m in METRICS]
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for variant, e in summary.items():
        cells = [variant, str(e["n_seeds"])] + [fmt(e[s][m]) for s in splits for m in METRICS]
        lines.append("| " + " | ".join(cells) + " |")
    note = ("\nChoose on validation; test is reported, not used for choosing. "
            "Recall/FPR are at the validation-selected threshold.\n")
    return "\n".join(lines) + "\n" + note


# ---------------------------------------------------------------------------
# explanation report
# ---------------------------------------------------------------------------
def explain_report(run_dir: Path, splits: Sequence[str], n: int, examples: int, override: Config | None = None
                   ) -> Path:
    bundle = ModelBundle(run_dir)
    cfg = _with_data_paths(bundle.config, override)
    manifest = load_manifest(cfg)
    cache = FeatureCache(Path(cfg.features.cache_dir))
    pipe = bundle.pipeline()
    for split in splits:  # extract before LightGBM threads exist
        pipe.materialize(source(cfg, manifest, split), cache)
    lgbm = bundle.backend("lightgbm")
    t = bundle.threshold("lightgbm")
    display = pipe.display_names()
    rng = np.random.default_rng(cfg.seed)
    report: dict[str, Any] = {"threshold": t, "unit": "log-odds contribution (LightGBM pred_contrib)", "splits": {}}
    malware_group_means: dict[str, np.ndarray] = {}
    malware_feature_means: dict[str, np.ndarray] = {}
    names: list[str] = []
    groups: list[str] = []

    for split in splits:
        feats, src = _features(pipe, cfg, manifest, cache, split)
        idx = np.sort(rng.choice(len(src.ids), size=min(n, len(src.ids)), replace=False))
        X, y, ids = feats.X[idx], src.labels[idx], src.ids[idx]
        scores = lgbm.predict(X)
        contrib = lgbm.contributions(X)[:, :-1]
        names, groups = feats.feature_names, list(feats.group_slices)
        G = np.stack([contrib[:, feats.group_slices[g]].sum(axis=1) for g in groups], axis=1)
        pred = scores >= t
        outcome = np.where(y == 1, np.where(pred, "TP", "FN"), np.where(pred, "FP", "TN"))
        top = np.argsort(-np.abs(contrib).mean(axis=0))[:20]
        rep: dict[str, Any] = {
            "n_sampled": int(len(idx)),
            "mean_abs_group_contribution": dict(zip(groups, np.abs(G).mean(axis=0).round(5).tolist())),
            "top_features_by_mean_abs_contribution": [
                {"feature": names[j], "meaning": display.get(names[j], names[j]),
                 "mean_abs": float(np.abs(contrib[:, j]).mean())} for j in top],
            "by_outcome": {},
            "examples": {},
        }
        for o in ("TP", "FP", "TN", "FN"):
            m = outcome == o
            if m.any():
                rep["by_outcome"][o] = {"n": int(m.sum()),
                                        "mean_group_contribution": dict(zip(groups, G[m].mean(axis=0).round(5).tolist()))}
        for o in ("FP", "FN"):
            sel = np.flatnonzero(outcome == o)[:examples]
            rep["examples"][o] = [{
                "id": ids[i].decode(), "score": float(scores[i]),
                "group_contribution": dict(zip(groups, G[i].round(4).tolist())),
                "top_features": [{"feature": names[j], "meaning": display.get(names[j], names[j]),
                                  "contribution": float(contrib[i, j])}
                                 for j in np.argsort(-np.abs(contrib[i]))[:5]],
            } for i in sel]
        if (y == 1).any():
            malware_group_means[split] = G[y == 1].mean(axis=0)
            malware_feature_means[split] = contrib[y == 1].mean(axis=0)
        report["splits"][split] = rep

    if "challenge" in malware_group_means and "test" in malware_group_means:
        # Which evidence is weaker on evasive (challenge) malware than on ordinary test malware?
        dg = malware_group_means["challenge"] - malware_group_means["test"]
        df = malware_feature_means["challenge"] - malware_feature_means["test"]
        order = np.argsort(df)[:20]
        report["challenge_vs_test_malware"] = {
            "group_mean_contribution_difference": dict(zip(groups, dg.round(5).tolist())),
            "features_most_weakened_on_challenge": [{"feature": names[j], "meaning": display.get(names[j], names[j]),
                                                     "difference": float(df[j])} for j in order],
            "note": "Negative = pushes challenge malware less towards 'malicious' than test malware.",
        }
    out = create_run_dir(Path(run_dir) / "explanations", cfg.fingerprint(), prefix="explain-")
    write_json(out / "explain_report.json", report)
    return out
