"""Train and evaluate stage 2 (threat category + family) on top of a detection run.

Labels: EMBER2024 `behavior` tags (mapped to taxonomy categories) and `family`, both AV-consensus
targets. Only malware is used. A malware record with no mapped tag is UNLABELLED for categories (not a
negative); a record without a family is unlabelled for the family model.

- categories: one binary LightGBM per category (multi-label), trained on labelled malware; threshold
  chosen on validation for a precision target; a category that cannot reach it is disabled.
- family: multiclass over the most frequent families + "other"; a confidence threshold chosen on
  validation for the same precision target; below it the family is "unknown".
- end to end: test files the detector flags (malicious or suspicious zone), false positives included.
Features are the detection run's own (same pipeline, same cache); nothing is re-extracted.
"""

from __future__ import annotations

import logging
import time
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np

from silkscan.config import Config
from silkscan.data.jsonl import iter_selected_records
from silkscan.data.manifest import Manifest
from silkscan.errors import DataValidationError
from silkscan.features.cache import FeatureCache
from silkscan.inference.bundle import ModelBundle
from silkscan.models.lgbm import resolve_params, train_lightgbm
from silkscan.runs import create_subdir
from silkscan.stage2.model import META_FILE, Stage2Model, load_taxonomy
from silkscan.utils.hashing import sha256_json
from silkscan.utils.io import write_json

log = logging.getLogger(__name__)

CATEGORY_PARAMS = {"num_leaves": 63, "learning_rate": 0.1, "min_data_in_leaf": 20, "is_unbalance": True,
                   "metric": ["average_precision"], "first_metric_only": True}
FAMILY_PARAMS = {"objective": "multiclass", "num_leaves": 63, "learning_rate": 0.1, "min_data_in_leaf": 20,
                 "metric": ["multi_logloss"], "is_unbalance": False}


def collect_targets(manifest: Manifest, split: str, id_field: str, mask: np.ndarray
                    ) -> tuple[list[list[str]], list[str | None]]:
    """Behaviour tags and family for the split rows selected by `mask`, in manifest order."""
    s = manifest.split(split)
    rows = np.flatnonzero(mask)
    tags, fams = [], []
    expected = iter(s.ids[rows])
    for chunk in iter_selected_records(manifest.paths, s.file_idx[rows], s.line_no[rows], id_field, 4096):
        for rec in chunk:
            if rec.id.encode() != next(expected):
                raise DataValidationError("Record order does not match the manifest; rebuild it.")
            tags.append([str(t).lower() for t in (rec.target.get("behavior") or [])])
            fams.append(rec.target.get("family") or None)
    return tags, fams


def threshold_for_precision(y: np.ndarray, s: np.ndarray, target: float, min_tp: int = 5) -> float | None:
    """Lowest score cut whose precision on (y, s) is >= target (max recall at that precision)."""
    order = np.argsort(-s, kind="mergesort")
    ys, ss = y[order], s[order]
    last = np.r_[np.flatnonzero(np.diff(ss)), len(ss) - 1]       # cut after each distinct score
    tp = np.cumsum(ys)[last]
    prec = tp / (last + 1)
    ok = (prec >= target) & (tp >= min_tp)
    if not ok.any():
        return None
    return float(ss[last[np.flatnonzero(ok)[-1]]])


def _binary_metrics(y: np.ndarray, s: np.ndarray, t: float | None) -> dict[str, Any]:
    from silkscan.evaluation.metrics import average_precision

    out: dict[str, Any] = {"n": int(len(y)), "n_pos": int(y.sum())}
    out["average_precision"] = average_precision(y, s) if 0 < y.sum() < len(y) else None
    if t is not None:
        pred = s >= t
        tp = int((pred & (y == 1)).sum())
        out.update({"precision": tp / int(pred.sum()) if pred.any() else None,
                    "recall": tp / int(y.sum()) if y.sum() else None, "n_flagged": int(pred.sum())})
    return out


def train_stage2(run_dir: Path, override: Config | None = None, precision: float = 0.8, family_top: int = 25,
                 family_min: int = 50, min_pos: int = 50, rounds: int = 300, taxonomy: str | None = None,
                 min_threshold: float = 0.5) -> Path:
    from silkscan.workflow import _features, _with_data_paths, load_manifest, n_jobs, source

    bundle = ModelBundle(run_dir)
    cfg = _with_data_paths(bundle.config, override)
    tax = load_taxonomy(taxonomy) if taxonomy else load_taxonomy()
    manifest = load_manifest(cfg)
    cache = FeatureCache(Path(cfg.features.cache_dir))
    pipe = bundle.pipeline()
    for split in ("train", "validation", "test"):  # extract before any LightGBM call (forked workers)
        pipe.materialize(source(cfg, manifest, split), cache, n_jobs(cfg))

    data: dict[str, dict[str, Any]] = {}
    e2e: dict[str, Any] = {}
    names = None
    for split in ("train", "validation", "test"):
        feats, src = _features(pipe, cfg, manifest, cache, split)
        names = feats.feature_names
        mal = src.labels == 1
        if split == "test":
            # end to end: what the detector flags, with the run's thresholds and review zone
            backend = bundle.backend("lightgbm")
            scores = backend.predict(feats.X)
            high = bundle.row_thresholds("lightgbm", names, feats.X)
            low = bundle.row_review_thresholds("lightgbm", names, feats.X)
            flagged = scores >= (high if low is None else low)
            e2e = {"X": feats.X[flagged], "labels": src.labels[flagged], "ids": src.ids[flagged],
                   "zone": np.where(scores[flagged] >= high[flagged], "malicious", "suspicious")}
        log.info("Stage 2: collecting tags/families for %d %s malware records", int(mal.sum()), split)
        tags, fams = collect_targets(manifest, split, cfg.data.id_field, mal)
        data[split] = {"X": feats.X[mal], "tags": tags, "fams": fams, "ids": src.ids[mal]}
        del feats

    cats = tax.names
    for d in data.values():
        d["Y"] = np.array([[c in tax.categories_of(t) for c in cats] for t in d["tags"]], dtype=bool).reshape(-1, len(cats))
        d["labelled"] = d["Y"].any(axis=1)
    test_by_id = {i: k for k, i in enumerate(data["test"]["ids"].tolist())}

    out_dir = create_subdir(Path(run_dir) / "stage2", time.strftime("%Y%m%d-%H%M%S"))
    meta: dict[str, Any] = {
        "id": f"{Path(run_dir).name}/stage2/{out_dir.name}", "base_run": Path(run_dir).name,
        "base_schema_fingerprint": bundle.schema.fingerprint(),
        "taxonomy": {"version": tax.version, "sha256": tax.sha256, "categories": tax.categories},
        "precision_target": precision, "min_threshold": min_threshold,
        "label_fingerprint": sha256_json({s: {"tags": d["tags"], "fams": d["fams"]} for s, d in data.items()}),
        "label_coverage": {s: {"malware": int(len(d["tags"])), "with_category": int(d["labelled"].sum()),
                               "with_family": int(sum(f is not None for f in d["fams"]))}
                           for s, d in data.items()},
        "categories": {}, "family": None,
    }

    # -- categories ------------------------------------------------------------------------
    for j, c in enumerate(cats):
        tr, va, te = (data[s] for s in ("train", "validation", "test"))
        ytr = tr["Y"][tr["labelled"], j]
        spec: dict[str, Any] = {"impact": tax.impact(c), "n_train_pos": int(ytr.sum()),
                                "n_train_labelled": int(len(ytr)), "enabled": False}
        if ytr.sum() < min_pos or ytr.sum() == len(ytr):
            spec["reason"] = f"too few positives in train ({int(ytr.sum())} < {min_pos})"
            meta["categories"][c] = spec
            continue
        params = resolve_params({**CATEGORY_PARAMS, "num_threads": 0}, cfg.seed)
        yva = va["Y"][va["labelled"], j]
        res = train_lightgbm(tr["X"][tr["labelled"]], ytr.astype(int), va["X"][va["labelled"]], yva.astype(int),
                             feature_names=names, categorical=[], params=params, num_boost_round=rounds,
                             early_stopping_rounds=30)
        model_file = f"category_{c}.txt"
        res.booster.save_model(str(out_dir / model_file), num_iteration=res.best_iteration)
        s_va = res.booster.predict(va["X"][va["labelled"]], num_iteration=res.best_iteration)
        t = threshold_for_precision(yva.astype(int), s_va, precision)
        if t is not None:
            # Floor: the lowest cut meeting the target sits on the precision boundary; for common categories
            # that is a tiny score and precision collapses when category frequencies shift between periods.
            t = max(t, min_threshold)
        s_te = res.booster.predict(te["X"][te["labelled"]], num_iteration=res.best_iteration)
        yte = te["Y"][te["labelled"], j].astype(int)
        spec.update({"model": model_file, "best_iteration": res.best_iteration, "threshold": t,
                     "validation": _binary_metrics(yva.astype(int), s_va, t),
                     "test": _binary_metrics(yte, s_te, t)})
        if t is None:
            spec["reason"] = f"precision {precision} not reachable on validation"
        else:
            spec["enabled"] = True
        meta["categories"][c] = spec
        log.info("Stage 2 category %s: %s", c, "enabled" if spec["enabled"] else spec["reason"])

    # -- family ----------------------------------------------------------------------------
    tr, va, te = (data[s] for s in ("train", "validation", "test"))
    counts = Counter(f for f in tr["fams"] if f)
    classes = [f for f, n in counts.most_common(family_top) if n >= family_min]
    fam_meta: dict[str, Any] = {"enabled": False, "n_train_with_family": int(sum(counts.values()))}
    if len(classes) >= 2:
        classes.append("other")
        index = {f: i for i, f in enumerate(classes)}

        def encode(fams: list[str | None]) -> tuple[np.ndarray, np.ndarray]:
            m = np.array([f is not None for f in fams])
            y = np.array([index.get(f, len(classes) - 1) for f in fams if f is not None], dtype=int)
            return m, y

        mtr, ytr = encode(tr["fams"])
        mva, yva = encode(va["fams"])
        mte, yte = encode(te["fams"])
        params = resolve_params({**FAMILY_PARAMS, "num_class": len(classes), "num_threads": 0}, cfg.seed)
        params.pop("is_unbalance", None)
        res = train_lightgbm(tr["X"][mtr], ytr, va["X"][mva], yva, feature_names=names, categorical=[],
                             params=params, num_boost_round=rounds, early_stopping_rounds=30)
        res.booster.save_model(str(out_dir / "family.txt"), num_iteration=res.best_iteration)
        p_va = res.booster.predict(va["X"][mva], num_iteration=res.best_iteration).reshape(-1, len(classes))
        p_te = res.booster.predict(te["X"][mte], num_iteration=res.best_iteration).reshape(-1, len(classes))
        other = len(classes) - 1

        def emitted(p: np.ndarray, y: np.ndarray, thr: float) -> dict[str, Any]:
            pred, conf = p.argmax(1), p.max(1)
            em = (pred != other) & (conf >= thr)
            correct = em & (pred == y)
            known = y != other
            return {"n": int(len(y)), "coverage": float(em.mean()) if len(y) else None,
                    "precision": float(correct.sum() / em.sum()) if em.any() else None,
                    "top1_accuracy_known_families": float((pred[known] == y[known]).mean()) if known.any() else None,
                    "share_other_or_unseen": float((~known).mean()) if len(y) else None}

        # confidence threshold: precision of emitted (non-"other") predictions on validation >= target
        pred_va, conf_va = p_va.argmax(1), p_va.max(1)
        cand = (pred_va != other)
        thr = threshold_for_precision((pred_va == yva)[cand].astype(int), conf_va[cand], precision)
        fam_meta.update({"classes": classes, "model": "family.txt", "best_iteration": res.best_iteration,
                         "threshold": thr, "enabled": thr is not None})
        if thr is not None:
            fam_meta["validation"] = emitted(p_va, yva, thr)
            fam_meta["test"] = emitted(p_te, yte, thr)
        else:
            fam_meta["reason"] = f"precision {precision} not reachable on validation"
    else:
        fam_meta["reason"] = "fewer than two families with enough train samples"
    meta["family"] = fam_meta

    write_json(out_dir / META_FILE, meta)

    # -- end to end on detector-flagged test files -----------------------------------------------
    model = Stage2Model(out_dir)
    cls = model.classify(e2e["X"]) if len(e2e["labels"]) else []
    lab = e2e["labels"]
    any_cat = np.array([bool(c["categories"]) for c in cls], dtype=bool)
    fam_emit = np.array([c["family"] is not None for c in cls], dtype=bool)
    correct = []
    for k, i in enumerate(e2e["ids"].tolist()):
        if lab[k] != 1 or i not in test_by_id or not cls[k]["categories"]:
            continue
        r = test_by_id[i]
        if data["test"]["labelled"][r]:
            truth = {c for c, v in zip(cats, data["test"]["Y"][r]) if v}
            correct.append(all(c["name"] in truth for c in cls[k]["categories"]))
    meta["end_to_end_test"] = {
        "flagged": int(len(lab)), "flagged_malware": int((lab == 1).sum()), "flagged_benign": int((lab == 0).sum()),
        "by_zone": dict(Counter(e2e["zone"].tolist())),
        "malware_with_category": float(any_cat[lab == 1].mean()) if (lab == 1).any() else None,
        "benign_with_category": int(any_cat[lab == 0].sum()),
        "malware_with_family": float(fam_emit[lab == 1].mean()) if (lab == 1).any() else None,
        "category_precision_on_labelled_flagged": float(np.mean(correct)) if correct else None,
        "note": "benign_with_category counts false positives that would also get a threat type.",
    }
    write_json(out_dir / META_FILE, meta)
    (out_dir / "report.md").write_text(render_report(meta), encoding="utf-8")
    return out_dir


def _p(x: float | None) -> str:
    return "—" if x is None else f"{100 * x:.1f}%"


def _f(x: float | None) -> str:
    return "—" if x is None else f"{x:.3f}"


def render_report(meta: dict[str, Any]) -> str:
    cov = meta["label_coverage"]
    lines = [f"# Stage 2: threat category and family · `{meta['id']}`", "",
             f"Taxonomy v{meta['taxonomy']['version']}, precision target {meta['precision_target']}. "
             "Labels are AV consensus (ClarAVy).", "",
             "| Split | Malware | With category | With family |", "|---|---|---|---|"]
    lines += [f"| {s} | {c['malware']:,} | {c['with_category']:,} | {c['with_family']:,} |" for s, c in cov.items()]
    lines += ["", "## Categories (test, labelled malware)", "",
              "| Category | Impact | Train positives | Status | Threshold | Test AP | Test precision | Test recall |",
              "|---|---|---|---|---|---|---|---|"]
    for c, spec in meta["categories"].items():
        te = spec.get("test", {})
        status = "enabled" if spec["enabled"] else "disabled: " + spec.get("reason", "")
        lines.append(f"| {c} | {spec['impact']} | {spec['n_train_pos']:,} | {status} | "
                     f"{_f(spec.get('threshold'))} | {_f(te.get('average_precision'))} | "
                     f"{_p(te.get('precision'))} | {_p(te.get('recall'))} |")
    f = meta["family"]
    lines += ["", "## Family", ""]
    if f.get("enabled"):
        te = f["test"]
        lines += [f"{len(f['classes']) - 1} families + other; confidence threshold {f['threshold']:.3f}.", "",
                  f"Test: coverage {_p(te['coverage'])}, precision of emitted families {_p(te['precision'])}, "
                  f"top-1 accuracy on known families {_p(te['top1_accuracy_known_families'])}, "
                  f"other/unseen families {_p(te['share_other_or_unseen'])}."]
    else:
        lines += [f"Disabled: {f.get('reason')}"]
    e = meta.get("end_to_end_test")
    if e:
        lines += ["", "## End to end (test files the detector flags)", "",
                  f"{e['flagged']:,} flagged files (malicious {e['flagged_malware']:,}, benign {e['flagged_benign']:,}; "
                  f"zones {e['by_zone']}). Category assigned to {_p(e['malware_with_category'])} of flagged malware, "
                  f"family to {_p(e['malware_with_family'])}; {e['benign_with_category']} false positives also get a "
                  f"category. Category precision on labelled flagged malware: "
                  f"{_p(e['category_precision_on_labelled_flagged'])}."]
    return "\n".join(lines) + "\n"
