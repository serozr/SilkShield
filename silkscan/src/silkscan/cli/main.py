"""Command line interface: `silkscan <command> ...`."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from silkscan.errors import SilkScanError

log = logging.getLogger("silkscan")


def _print(obj: Any) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def _cfg(args: argparse.Namespace):
    from silkscan.config import load_config

    return load_config(args.config) if getattr(args, "config", None) else None


def _brief(m: dict[str, Any]) -> dict[str, Any]:
    t = m["at_threshold"]
    return {"n": m["n"], "n_malicious": m["n_malicious"], "n_benign": m["n_benign"], "roc_auc": m["roc_auc"],
            "average_precision": m["average_precision"], "threshold": t["threshold"], "recall": t["recall"],
            "fpr": t["fpr"], "precision": t["precision"], "undefined": m.get("undefined", {})}


# -- data and training ---------------------------------------------------------------------------
def cmd_manifest(args: argparse.Namespace) -> None:
    from silkscan.workflow import make_manifest

    cfg = _cfg(args)
    m = make_manifest(cfg, force=args.force)
    _print({"manifest_dir": str(cfg.manifest_dir), "fingerprint": m.fingerprint,
            "splits": {n: s.summary() for n, s in m.splits.items()}, "stats": m.stats})


def cmd_features(args: argparse.Namespace) -> None:
    from silkscan.workflow import build_features

    _print(build_features(_cfg(args), args.splits))


def cmd_train(args: argparse.Namespace) -> None:
    from silkscan.utils.io import read_json
    from silkscan.workflow import train

    run = train(_cfg(args))
    _print({"run_dir": str(run), "validation": _brief(read_json(run / "metrics_validation.json")),
            "threshold": read_json(run / "threshold.json")["lightgbm"]})


def cmd_threshold(args: argparse.Namespace) -> None:
    from silkscan.workflow import select_backend_threshold, select_review_zone, select_threshold_policy

    if args.review_fpr is not None:
        _print(select_review_zone(Path(args.run), args.backend, args.review_fpr, _cfg(args), args.force))
    elif args.policy:
        _print(select_threshold_policy(Path(args.run), args.backend, args.policy, args.flag_name, args.flag_column,
                                       _cfg(args), args.force, args.min_fp_budget))
    else:
        _print(select_backend_threshold(Path(args.run), args.backend, _cfg(args), args.force))


def cmd_train_type(args: argparse.Namespace) -> None:
    from silkscan.stage2.train import train_stage2

    out = train_stage2(Path(args.run), _cfg(args), args.precision, args.family_top, args.family_min, args.min_pos,
                       args.rounds, args.taxonomy, args.min_threshold)
    print((out / "report.md").read_text(encoding="utf-8"))
    print(f"Stage-2 model: {out}  (set `stage2: {out}` in the serving config)", file=sys.stderr)


def cmd_hashlist(args: argparse.Namespace) -> None:
    from silkscan.hashlist import write_hash_list
    from silkscan.workflow import load_manifest

    n = write_hash_list(load_manifest(_cfg(args)), args.splits, 1 if args.label == "malicious" else 0, Path(args.out))
    _print({"out": args.out, "hashes": n, "splits": args.splits, "label": args.label})


# -- evaluation ------------------------------------------------------------------------------------
def cmd_evaluate(args: argparse.Namespace) -> None:
    from silkscan.report import render
    from silkscan.workflow import evaluate, evaluate_jsonl

    if args.jsonl:
        out = evaluate_jsonl(Path(args.run), [Path(p) for p in args.jsonl], args.name, args.backend, args.limit,
                             override=_cfg(args))
    else:
        out = evaluate(Path(args.run), args.splits, _cfg(args), args.backend)
    if args.json:
        from silkscan.utils.io import read_json

        names = [args.name] if args.jsonl else args.splits
        _print({"evaluation_dir": str(out), **{s: _brief(read_json(out / f"{s}.json")) for s in names}})
    else:
        print(render(Path(args.run), out))
        print(f"Detailed JSON: {out}", file=sys.stderr)


def cmd_report(args: argparse.Namespace) -> None:
    from silkscan.report import render

    text = render(Path(args.run), Path(args.evaluation) if args.evaluation else None)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"Report written: {args.out}", file=sys.stderr)
    else:
        print(text)


def cmd_ablation(args: argparse.Namespace) -> None:
    from silkscan.experiments import ablation

    variants = [v.split(",") for v in args.variants] if args.variants else None
    out = ablation(_cfg(args), variants, args.seeds, args.test)
    print((out / "summary.md").read_text(encoding="utf-8"))
    print(f"Results: {out}", file=sys.stderr)


def cmd_explain_report(args: argparse.Namespace) -> None:
    from silkscan.experiments import explain_report

    out = explain_report(Path(args.run), args.splits, args.n, args.examples, _cfg(args))
    print(out / "explain_report.json")


# -- prediction -------------------------------------------------------------------------------------
def cmd_predict(args: argparse.Namespace) -> None:
    from silkscan.checks import create_checks
    from silkscan.config import load_serving_config
    from silkscan.inference.bundle import ModelBundle
    from silkscan.inference.predict import Submission, records_from_jsonl, scan

    serving = load_serving_config(args.serving) if args.serving else None
    run = args.run or (serving.run if serving else None)
    if not run:
        raise SilkScanError("Give --run, or a --serving config that names the model run.")
    bundle = ModelBundle(Path(run))
    backend = args.backend or (serving.backend if serving else "lightgbm")
    checks = create_checks(serving.checks) if serving else []
    if args.pe:
        # Bytes only: parsing happens inside scan(), after the cheap checks, and only if needed.
        items = [Submission(Path(p).read_bytes(), None, Path(p).name) for p in args.pe]
    else:
        items = [Submission(None, r)
                 for r in records_from_jsonl(Path(args.jsonl), bundle.config.data.id_field, args.limit)]
    explain = args.explain if args.explain is not None else (serving.explain_top if serving else 0)
    short = (serving.short_circuit if serving else True) and not args.no_short_circuit
    stage2 = None
    if serving and serving.stage2:
        from silkscan.stage2 import Stage2Model

        stage2 = Stage2Model(Path(serving.stage2))
        stage2.require_compatible(bundle.schema.fingerprint())
    for r in scan(bundle, bundle.backend(backend), items, checks, explain, short, stage2=stage2):
        print(json.dumps(r, ensure_ascii=False))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="silkscan", description="Static PE malware detection (EMBER2024 + LightGBM).")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    sub = p.add_subparsers(dest="command", required=True)

    def add(name: str, fn, help_: str, config: str | None = "required") -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=help_, description=help_)
        if config == "required":
            sp.add_argument("-c", "--config", required=True, help="YAML config")
        elif config == "optional":
            sp.add_argument("-c", "--config", help="YAML config whose data/work/cache paths override the run's")
        sp.set_defaults(fn=fn)
        return sp

    sp = add("manifest", cmd_manifest, "Build the split manifest (ids, labels, dates, fingerprints).")
    sp.add_argument("--force", action="store_true", help="replace an existing manifest")
    sp = add("features", cmd_features, "Fit stateful groups on train and fill the per-group feature cache.")
    sp.add_argument("--splits", nargs="*", default=None)
    add("train", cmd_train, "Train LightGBM, select the FPR threshold on validation, write a run directory.")

    sp = add("threshold", cmd_threshold, "On validation: a backend threshold, a file-kind policy (--policy) or a "
             "review zone (--review-fpr).", config="optional")
    sp.add_argument("--run", required=True)
    sp.add_argument("--backend", default="lightgbm")
    sp.add_argument("--policy", choices=["auto", "global", "per_group", "strictest"],
                    help="file-kind policy; auto = per_group if every group has enough benign files")
    sp.add_argument("--flag-name", default="dll")
    sp.add_argument("--flag-column", default="ember_v3.header_0043", help="binary feature defining the groups")
    sp.add_argument("--review-fpr", type=float, default=None,
                    help="lower threshold at this validation FPR; scores between it and the malicious threshold "
                         "are `suspicious`")
    sp.add_argument("--min-fp-budget", type=float, default=10.0,
                    help="auto: per_group needs target_fpr x benign files >= this in every group")
    sp.add_argument("--force", action="store_true")

    sp = add("train-type", cmd_train_type, "Train threat-category and family models on a run's features.",
             config="optional")
    sp.add_argument("--run", required=True)
    sp.add_argument("--precision", type=float, default=0.8, help="per-category / family precision target")
    sp.add_argument("--family-top", type=int, default=25)
    sp.add_argument("--family-min", type=int, default=50, help="min train samples for a family class")
    sp.add_argument("--min-pos", type=int, default=50, help="min train positives to train a category")
    sp.add_argument("--rounds", type=int, default=300)
    sp.add_argument("--taxonomy", default=None, help="taxonomy YAML (default: packaged taxonomy.v1.yaml)")
    sp.add_argument("--min-threshold", type=float, default=0.5, help="floor for category thresholds")

    sp = add("hashlist", cmd_hashlist, "Write a SHA-256 list from manifest splits for the hash_list check.")
    sp.add_argument("--splits", nargs="+", default=["train"])
    sp.add_argument("--label", choices=["malicious", "benign"], default="malicious")
    sp.add_argument("--out", required=True)

    sp = add("evaluate", cmd_evaluate, "Evaluate a run on manifest splits or labelled JSONL files.",
             config="optional")
    sp.add_argument("--run", required=True)
    sp.add_argument("--splits", nargs="+", default=["test", "challenge"])
    sp.add_argument("--jsonl", nargs="+", help="labelled EMBER-format JSONL files instead of manifest splits")
    sp.add_argument("--name", default="custom", help="name for the --jsonl evaluation")
    sp.add_argument("--limit", type=int, default=None, help="max records to read from --jsonl")
    sp.add_argument("--backend", default="lightgbm")
    sp.add_argument("--json", action="store_true", help="print a JSON summary instead of the report")
    sp = add("report", cmd_report, "Render the report of an evaluation (latest by default).", config=None)
    sp.add_argument("--run", required=True)
    sp.add_argument("--evaluation", help="evaluation directory")
    sp.add_argument("--out", help="write Markdown to this file instead of stdout")
    sp = add("ablation", cmd_ablation, "Train feature-group variants over several seeds and tabulate.")
    sp.add_argument("--variants", nargs="+", metavar="G1,G2",
                    help="comma-separated group lists (default: first group, +each other group, all)")
    sp.add_argument("--seeds", nargs="+", type=int, default=[0, 1, 2])
    sp.add_argument("--test", action="store_true", help="also evaluate each run on test (reporting only)")
    sp = add("explain-report", cmd_explain_report, "Feature-group contributions by outcome; challenge vs test.",
             config="optional")
    sp.add_argument("--run", required=True)
    sp.add_argument("--splits", nargs="+", default=["test", "challenge"])
    sp.add_argument("--n", type=int, default=5000, help="samples per split")
    sp.add_argument("--examples", type=int, default=5, help="FP/FN examples to list")

    sp = add("predict", cmd_predict, "Scan PE files or EMBER JSONL records; one verdict JSON per line.", config=None)
    sp.add_argument("--run", help="model run directory (or take it from --serving)")
    sp.add_argument("--serving", help="serving config: run, backend, checks, stage 2")
    src = sp.add_mutually_exclusive_group(required=True)
    src.add_argument("--jsonl", help="EMBER-format raw feature records")
    src.add_argument("--pe", nargs="+", help="PE files (static analysis only, never executed)")
    sp.add_argument("--limit", type=int, default=None)
    sp.add_argument("--backend", default=None, help="default: from --serving, else lightgbm")
    sp.add_argument("--explain", type=int, default=None, metavar="K", help="top-K feature contributions")
    sp.add_argument("--no-short-circuit", action="store_true",
                    help="run static analysis and the model even when a pre-check already decided")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=args.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        args.fn(args)
    except SilkScanError as e:
        log.error("%s", e)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
