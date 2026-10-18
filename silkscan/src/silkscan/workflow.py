"""End-to-end steps used by the CLI."""

from __future__ import annotations

import logging
import os
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Sequence

import numpy as np
import yaml

from silkscan import __version__
from silkscan.config import Config, resolve_data_root
from silkscan.data.manifest import Manifest, build_manifest
from silkscan.errors import DataValidationError
from silkscan.evaluation.metrics import at_threshold, bootstrap_ci, evaluate_by_group, evaluate_scores
from silkscan.evaluation.threshold import select_threshold, threshold_stability
from silkscan.features.cache import FeatureCache
from silkscan.features.pipeline import AssembledFeatures, FeaturePipeline, ManifestSource
from silkscan.inference import bundle as B
from silkscan.inference.bundle import ModelBundle
from silkscan.models.lgbm import resolve_params, save_model, train_lightgbm
from silkscan.runs import create_run_dir, create_subdir
from silkscan.utils.env import runtime_info
from silkscan.utils.io import save_array, write_json

log = logging.getLogger(__name__)


def n_jobs(cfg: Config) -> int:
    return cfg.features.n_jobs if cfg.features.n_jobs > 0 else (os.cpu_count() or 1)


def make_manifest(cfg: Config, force: bool = False) -> Manifest:
    m = build_manifest(cfg.data)
    m.save(cfg.manifest_dir, force=force)
    return m


def load_manifest(cfg: Config) -> Manifest:
    return Manifest.load(cfg.manifest_dir)


def source(cfg: Config, manifest: Manifest, split: str) -> ManifestSource:
    return ManifestSource(manifest, split, cfg.data.id_field, cfg.data.chunk_size)


def fitted_pipeline(cfg: Config, manifest: Manifest, cache: FeatureCache) -> FeaturePipeline:
    pipe = FeaturePipeline(cfg.features.groups)
    pipe.fit(source(cfg, manifest, "train"), cache)
    return pipe


def build_features(cfg: Config, splits: Sequence[str] | None = None) -> dict[str, Any]:
    manifest = load_manifest(cfg)
    cache = FeatureCache(Path(cfg.features.cache_dir))
    pipe = fitted_pipeline(cfg, manifest, cache)
    report = {}
    for split in splits or list(manifest.splits):
        blocks = pipe.materialize(source(cfg, manifest, split), cache, n_jobs(cfg))
        report[split] = {"status": {g: b.status_counts() for g, b in blocks.items()}}
    return report


def _features(pipe: FeaturePipeline, cfg: Config, manifest: Manifest, cache: FeatureCache, split: str
              ) -> tuple[AssembledFeatures, ManifestSource]:
    src = source(cfg, manifest, split)
    return pipe.build(src, cache, n_jobs(cfg), strict=True), src


def parity(reference: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, Any]:
    """Score agreement of another backend with LightGBM (e.g. reduced-precision accelerator arithmetic)."""
    diff = np.abs(reference - scores)
    return {"max_abs_score_diff": float(diff.max()) if len(diff) else 0.0,
            "decision_disagreements": int(((reference >= threshold) != (scores >= threshold)).sum()),
            "n": int(len(scores))}


def train(cfg: Config) -> Path:
    manifest = load_manifest(cfg)
    if "validation" not in manifest.splits:
        raise DataValidationError("Training needs a validation split: set `data.validation_start` and rebuild "
                                  "the manifest (`silkscan manifest --force`).")
    cache = FeatureCache(Path(cfg.features.cache_dir))
    pipe = fitted_pipeline(cfg, manifest, cache)
    schema = pipe.schema()
    tr, tr_src = _features(pipe, cfg, manifest, cache, "train")
    va, va_src = _features(pipe, cfg, manifest, cache, "validation")

    params = resolve_params(cfg.model.params, cfg.seed)
    result = train_lightgbm(tr.X, tr_src.labels, va.X, va_src.labels, feature_names=tr.feature_names,
                            categorical=tr.categorical, params=params, num_boost_round=cfg.model.num_boost_round,
                            early_stopping_rounds=cfg.model.early_stopping_rounds)

    run = create_run_dir(Path(cfg.runs_dir), cfg.fingerprint())
    log.info("Writing run to %s", run)
    resolved = cfg.to_dict()
    if cfg.data.root_template:
        resolved["data"]["root"] = cfg.data.root_template  # no machine-specific path in the run directory
    with open(run / B.CONFIG_FILE, "w", encoding="utf-8") as f:
        yaml.safe_dump(resolved, f, sort_keys=False, allow_unicode=True)
    write_json(run / "runtime.json", {**runtime_info(), "silkscan_version": __version__, "seed": cfg.seed,
                                      "config_fingerprint": cfg.fingerprint()})
    write_json(run / "manifest.json", {"fingerprint": manifest.fingerprint,
                                       "split_fingerprints": manifest.split_fingerprints,
                                       "splits": {n: s.summary() for n, s in manifest.splits.items()}})
    save_model(result.booster, run / B.MODEL_FILE, result.best_iteration)
    write_json(run / B.SCHEMA_FILE, schema.to_dict())
    write_json(run / B.STATES_FILE, pipe.get_states())

    va_scores = B.make_backend("lightgbm", run / B.MODEL_FILE).predict(va.X)
    benign_va = va_scores[va_src.labels == 0]
    sel = select_threshold(benign_va, cfg.evaluation.target_fpr)
    entry = {**sel.to_dict(), "selected_on": "validation"}
    if cfg.evaluation.bootstrap:
        entry["bootstrap_threshold"] = threshold_stability(benign_va, cfg.evaluation.target_fpr,
                                                           cfg.evaluation.bootstrap, cfg.seed)
    write_json(run / B.THRESHOLD_FILE, {"lightgbm": entry})
    metrics = evaluate_scores(va_src.labels, va_scores, sel.threshold, cfg.evaluation.report_fprs)
    metrics["note"] = ("Validation is also used for early stopping and threshold selection; "
                       "report test metrics as the result.")
    write_json(run / "metrics_validation.json", metrics)
    write_json(run / "training.json", {
        "best_iteration": result.best_iteration, "num_trees_trained": result.num_trees, "params": result.params,
        "n_train": int(len(tr_src.ids)), "n_validation": int(len(va_src.ids)), "n_features": len(tr.feature_names),
        "status_counts": {"train": _status_counts(tr), "validation": _status_counts(va)},
    })
    _save_predictions(run / "predictions_validation.npz", va_src, va_scores)
    ModelBundle(run)  # fail now, not at prediction time, if the bundle is incomplete
    return run


def _status_counts(f: AssembledFeatures) -> dict[str, dict[str, int]]:
    return {g: {str(k): int(v) for k, v in zip(*np.unique(s, return_counts=True))} for g, s in f.status.items()}


def _save_predictions(path: Path, src: ManifestSource, scores: np.ndarray) -> None:
    np.savez(path, ids=src.ids, labels=src.labels, scores=scores.astype("<f8"))


def _month(dates: np.ndarray) -> np.ndarray:
    out = np.full(len(dates), "unknown", dtype=object)
    known = dates >= 0
    out[known] = dates[known].astype("datetime64[s]").astype("datetime64[M]").astype(str)
    return out


def _with_data_paths(bundle_cfg: Config, override: Config | None) -> Config:
    """Bundle config with data/work/cache paths (and subgroup reports) taken from `override`, e.g. to
    evaluate a run on another machine. Feature groups always come from the bundle."""
    if override is None:
        return resolve_data_root(bundle_cfg)
    feats = replace(bundle_cfg.features, cache_dir=override.features.cache_dir, n_jobs=override.features.n_jobs)
    ev = replace(bundle_cfg.evaluation,
                 subgroup_flags=override.evaluation.subgroup_flags or bundle_cfg.evaluation.subgroup_flags)
    return replace(bundle_cfg, data=override.data, work_dir=override.work_dir, features=feats, evaluation=ev)


def _flag_arrays(cfg: Config, feature_names: list[str], X: Any) -> dict[str, np.ndarray | str]:
    from silkscan.inference.bundle import column_flag

    out: dict[str, np.ndarray | str] = {}
    for name, column in cfg.evaluation.subgroup_flags.items():
        out[name] = (column_flag(X, feature_names.index(column)) if column in feature_names
                     else f"column {column} not in the feature set")
    return out


def _split_report(bundle: ModelBundle, cfg: Config, backend_name: str, labels: np.ndarray, scores: np.ndarray,
                  tvec: np.ndarray, dates: np.ndarray, flags: dict[str, np.ndarray | str],
                  status: dict[str, Any], low: np.ndarray | None = None) -> dict[str, Any]:
    """Every metric section for one set of scored, labelled records."""
    from silkscan.evaluation.threshold import three_zone

    r = evaluate_scores(labels, scores, tvec, cfg.evaluation.report_fprs)
    if low is not None:
        r["three_zone"] = {**three_zone(labels, scores, tvec, low),
                           "review_policy": bundle.review(backend_name)}
        for name, f in flags.items():
            if not isinstance(f, str):
                r["three_zone"][f"by_{name}"] = {f"{name}={v}": three_zone(labels[m], scores[m], tvec[m], low[m])
                                                 for v, m in (("yes", f), ("no", ~f))}
    r["threshold_policy"] = bundle.policy(backend_name) or {"mode": "global",
                                                            "threshold": bundle.threshold(backend_name)}
    r["by_month"] = evaluate_by_group(labels, scores, tvec, _month(dates))
    if cfg.evaluation.bootstrap:
        r["ci95"] = bootstrap_ci(labels, scores, tvec, cfg.evaluation.bootstrap, cfg.seed)
        boot_t = bundle.thresholds[backend_name].get("bootstrap_threshold")
        if boot_t:
            # How FPR/recall move if the global threshold had come out at the 2.5th/97.5th percentile
            # of its bootstrap distribution.
            r["threshold_stability"] = {
                q: {k: at_threshold(labels, scores, boot_t[q])[k] for k in ("threshold", "recall", "fpr")}
                for q in ("p2.5", "p50", "p97.5")}
    r["feature_status"] = status
    if flags:
        r["subgroups"] = {}
        for name, f in flags.items():
            if isinstance(f, str):
                r["subgroups"][name] = {"error": f}
                continue
            r["subgroups"][name] = {}
            for v, m in (("yes", f), ("no", ~f)):
                sub = evaluate_scores(labels[m], scores[m], tvec[m], cfg.evaluation.report_fprs)
                if cfg.evaluation.bootstrap and m.any():
                    sub["ci95"] = bootstrap_ci(labels[m], scores[m], tvec[m], cfg.evaluation.bootstrap, cfg.seed)
                r["subgroups"][name][f"{name}={v}"] = sub
    return r


def _eval_dir(run_dir: Path, backend_name: str, name: str = "") -> Path:
    return create_subdir(Path(run_dir) / "evaluations",
                         time.strftime("%Y%m%d-%H%M%S") + f"-{backend_name}" + (f"-{name}" if name else ""))


def evaluate(run_dir: Path, splits: Sequence[str], override: Config | None = None, backend_name: str = "lightgbm"
             ) -> Path:
    bundle = ModelBundle(run_dir)
    cfg = _with_data_paths(bundle.config, override)
    manifest = load_manifest(cfg)
    cache = FeatureCache(Path(cfg.features.cache_dir))
    pipe = bundle.pipeline()
    # Extract every split before the first LightGBM call: worker processes are forked, and forking
    # after OpenMP threads exist is best avoided.
    for split in splits:
        pipe.materialize(source(cfg, manifest, split), cache, n_jobs(cfg))
    backend = bundle.backend(backend_name)
    out_dir = _eval_dir(run_dir, backend_name)
    benign_test: tuple[np.ndarray, np.ndarray] | None = None
    for split in splits:
        feats, src = _features(pipe, cfg, manifest, cache, split)
        scores = backend.predict(feats.X)
        tvec = bundle.row_thresholds(backend_name, feats.feature_names, feats.X)
        low = bundle.row_review_thresholds(backend_name, feats.feature_names, feats.X)
        r = _split_report(bundle, cfg, backend_name, src.labels, scores, tvec, src.dates,
                          _flag_arrays(cfg, feats.feature_names, feats.X), _status_counts(feats), low)
        if split == "test":
            benign_test = (scores[src.labels == 0], tvec[src.labels == 0])
        if split == "challenge" and benign_test is not None:
            # EMBER2024 paper protocol: challenge malware + test benign files.
            y = np.r_[np.zeros(len(benign_test[0]), np.int8), src.labels]
            r["with_test_benign"] = evaluate_scores(y, np.r_[benign_test[0], scores], np.r_[benign_test[1], tvec],
                                                    cfg.evaluation.report_fprs)
        write_json(out_dir / f"{split}.json", r)
        _save_predictions(out_dir / f"predictions_{split}.npz", src, scores)
    write_json(out_dir / "summary.json", {"backend": backend_name, "threshold": bundle.threshold(backend_name),
                                          "threshold_policy": bundle.policy(backend_name), "splits": list(splits)})
    return out_dir


def evaluate_jsonl(run_dir: Path, paths: Sequence[Path], name: str, backend_name: str = "lightgbm",
                   limit: int | None = None, chunk_size: int = 2048, override: Config | None = None) -> Path:
    """Evaluate labelled EMBER-format JSONL files that are not part of the manifest (e.g. your own test set).

    Records are processed in chunks; records without a label are skipped and counted.
    """
    from silkscan.data.jsonl import iter_raw
    from silkscan.data.records import parse_date, parse_label, split_record

    bundle = ModelBundle(run_dir)
    cfg = _with_data_paths(bundle.config, override) if override else bundle.config  # no dataset needed
    pipe = bundle.pipeline()
    backend = bundle.backend(backend_name)
    cols: dict[str, list] = {"ids": [], "labels": [], "dates": [], "scores": [], "t": [], "low": []}
    flag_parts: dict[str, list] = {}
    status: dict[str, dict[str, int]] = {}
    skipped = {"unlabeled": 0, "extraction_failed": 0}
    n_read = 0

    def flush(batch: list) -> None:
        if not batch:
            return
        feats = pipe.transform_records([b[0] for b in batch], strict=False)
        ok = ~feats.failed
        skipped["extraction_failed"] += int((~ok).sum())
        for g, st in feats.status.items():
            for k, v in zip(*np.unique(st, return_counts=True)):
                status.setdefault(g, {})[str(k)] = status.get(g, {}).get(str(k), 0) + int(v)
        if not ok.any():
            return
        X = feats.X[ok]
        cols["scores"].append(backend.predict(X))
        cols["t"].append(bundle.row_thresholds(backend_name, feats.feature_names, X))
        low_part = bundle.row_review_thresholds(backend_name, feats.feature_names, X)
        if low_part is not None:
            cols["low"].append(low_part)
        sel = [b for b, keep in zip(batch, ok) if keep]
        cols["ids"] += [b[0].id.encode() for b in sel]
        cols["labels"] += [b[1] for b in sel]
        cols["dates"] += [b[2] for b in sel]
        for k, f in _flag_arrays(cfg, feats.feature_names, X).items():
            flag_parts.setdefault(k, []).append(f)

    batch: list = []
    for _, _, obj in iter_raw([Path(p) for p in paths]):
        n_read += 1
        rec = split_record(obj, cfg.data.id_field)
        label = parse_label(obj.get(cfg.data.label_field))
        if label < 0:
            skipped["unlabeled"] += 1
        else:
            d = parse_date(obj.get(cfg.data.date_field))
            batch.append((rec, label, -1 if d is None else d))
        if len(batch) >= chunk_size:
            flush(batch)
            batch = []
        if limit and n_read >= limit:
            break
    flush(batch)
    if not cols["ids"]:
        raise DataValidationError(f"No labelled, extractable records in {list(map(str, paths))} ({skipped}).")

    labels = np.array(cols["labels"], dtype=np.int8)
    scores, tvec = np.concatenate(cols["scores"]), np.concatenate(cols["t"])
    flags = {k: (v[0] if isinstance(v[0], str) else np.concatenate(v)) for k, v in flag_parts.items()}
    r = _split_report(bundle, cfg, backend_name, labels, scores, tvec, np.array(cols["dates"], dtype=np.int64),
                      flags, status, np.concatenate(cols["low"]) if cols["low"] else None)
    r["source"] = {"files": [str(p) for p in paths], "records_read": n_read, "skipped": skipped}
    out_dir = _eval_dir(run_dir, backend_name, name)
    write_json(out_dir / f"{name}.json", r)
    np.savez(out_dir / f"predictions_{name}.npz", ids=np.array(cols["ids"], dtype="S"), labels=labels,
             scores=scores.astype("<f8"))
    write_json(out_dir / "summary.json", {"backend": backend_name, "threshold": bundle.threshold(backend_name),
                                          "threshold_policy": bundle.policy(backend_name), "splits": [name]})
    return out_dir


def select_backend_threshold(run_dir: Path, backend_name: str, override: Config | None = None,
                             force: bool = False) -> dict[str, Any]:
    bundle = ModelBundle(run_dir)
    cfg = _with_data_paths(bundle.config, override)
    manifest = load_manifest(cfg)
    feats, src = _features(bundle.pipeline(), cfg, manifest, FeatureCache(Path(cfg.features.cache_dir)),
                              "validation")
    scores = bundle.backend(backend_name).predict(feats.X)
    sel = select_threshold(scores[src.labels == 0], bundle.config.evaluation.target_fpr)
    entry = {**sel.to_dict(), "selected_on": "validation"}
    if backend_name != "lightgbm":
        ref = bundle.backend("lightgbm").predict(feats.X)
        entry["parity_vs_lightgbm"] = parity(ref, scores, bundle.threshold("lightgbm"))
    bundle.add_threshold(backend_name, entry, force=force)
    return entry


def select_threshold_policy(run_dir: Path, backend_name: str, mode: str, flag_name: str, column: str,
                            override: Config | None = None, force: bool = False,
                            min_fp_budget: float = 10.0) -> dict[str, Any]:
    """Choose a file-kind threshold policy on validation.

    Both per_group and strictest meet the FPR target in every group; per_group never has lower recall
    (identical threshold for the strictest group, a looser one for the other). It is chosen by `auto`
    when each group has enough benign validation files to estimate its own threshold, i.e. the FP
    budget target_fpr * n_benign(group) is at least `min_fp_budget`; otherwise strictest.
    """
    from silkscan.evaluation.threshold import POLICY_MODES, row_thresholds, select_policy
    from silkscan.inference.bundle import column_flag

    bundle = ModelBundle(run_dir)
    cfg = _with_data_paths(bundle.config, override)
    manifest = load_manifest(cfg)
    pipe = bundle.pipeline()
    feats, src = _features(pipe, cfg, manifest, FeatureCache(Path(cfg.features.cache_dir)), "validation")
    if column not in feats.feature_names:
        raise DataValidationError(f"Column {column} is not among the model's features.")
    flags = column_flag(feats.X, feats.feature_names.index(column))
    scores = bundle.backend(backend_name).predict(feats.X)
    y, benign = src.labels, src.labels == 0
    target = bundle.config.evaluation.target_fpr

    comparison: dict[str, Any] = {}
    policies = {}
    for m in POLICY_MODES:
        pol = select_policy(scores[benign], flags[benign], target, m, flag_name, column)
        policies[m] = pol
        t = row_thresholds(pol, bundle.threshold(backend_name), flags, len(scores))
        comparison[m] = {"thresholds": pol["thresholds"],
                         "overall": at_threshold(y, scores, t),
                         f"{flag_name}=yes": at_threshold(y[flags], scores[flags], t[flags]),
                         f"{flag_name}=no": at_threshold(y[~flags], scores[~flags], t[~flags])}
    if mode == "auto":
        budgets = {g: target * int(((y == 0) & (flags if g == "yes" else ~flags)).sum()) for g in ("yes", "no")}
        mode = "per_group" if min(budgets.values()) >= min_fp_budget else "strictest"
        comparison["auto_rule"] = (f"per_group if target_fpr x benign count >= {min_fp_budget} in every group; "
                                   f"budgets = {budgets} -> {mode}")
    elif mode not in POLICY_MODES:
        raise DataValidationError(f"Unknown mode `{mode}`; choose auto or one of {POLICY_MODES}.")
    bundle.set_policy(backend_name, policies[mode], comparison, force)
    return {"active": mode, "comparison_on_validation": comparison}


def select_review_zone(run_dir: Path, backend_name: str, review_fpr: float, override: Config | None = None,
                       force: bool = False) -> dict[str, Any]:
    """Three-zone decision: pick the lower (review) threshold(s) on validation at `review_fpr`."""
    from silkscan.evaluation.threshold import select_review, three_zone
    from silkscan.inference.bundle import column_flag

    bundle = ModelBundle(run_dir)
    if not 0 < review_fpr < 1 or review_fpr <= bundle.config.evaluation.target_fpr:
        raise DataValidationError(f"--review-fpr must be in (target_fpr={bundle.config.evaluation.target_fpr}, 1).")
    cfg = _with_data_paths(bundle.config, override)
    manifest = load_manifest(cfg)
    feats, src = _features(bundle.pipeline(), cfg, manifest, FeatureCache(Path(cfg.features.cache_dir)),
                              "validation")
    scores = bundle.backend(backend_name).predict(feats.X)
    policy = bundle.policy(backend_name)
    flags = None
    if policy and policy["mode"] != "global":
        flags = column_flag(feats.X, feats.feature_names.index(policy["column"]))
    benign = src.labels == 0
    review = select_review(scores[benign], None if flags is None else flags[benign], review_fpr, policy,
                           bundle.threshold(backend_name))
    high = bundle.row_thresholds(backend_name, feats.feature_names, feats.X)
    from silkscan.evaluation.threshold import row_thresholds
    low = row_thresholds(review, None, flags, len(scores))
    review["validation"] = three_zone(src.labels, scores, high, low)
    review["selected_on"] = "validation"
    bundle.set_review(backend_name, review, force)
    return review
