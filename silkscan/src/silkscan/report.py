"""Human-readable evaluation report (Markdown; also readable as plain terminal text)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np

from silkscan.errors import SilkScanError
from silkscan.utils.io import read_json

SPLIT_ORDER = ("validation", "test", "challenge")
STATUS_NAMES = {"1": "MISSING_INPUT", "2": "PARSE_ERROR", "3": "NOT_APPLICABLE"}


def latest_evaluation(run_dir: Path) -> Path:
    ev = Path(run_dir) / "evaluations"
    dirs = sorted(d for d in ev.iterdir() if d.is_dir()) if ev.exists() else []
    if not dirs:
        raise SilkScanError(f"No evaluations in {run_dir}. Run `silkscan evaluate --run {run_dir}` first.")
    return dirs[-1]


def _pct(x: float | None, digits: int = 2) -> str:
    return "—" if x is None else f"{100 * x:.{digits}f}%"


def _num(x: float | None, digits: int = 4) -> str:
    return "—" if x is None else f"{x:.{digits}f}"


def _ci(ci: dict[str, Any] | None, key: str, pct: bool = True, digits: int = 2) -> str:
    if not ci or not ci.get(key):
        return ""
    lo, hi = ci[key]
    f = (lambda v: f"{100 * v:.{digits}f}") if pct else (lambda v: f"{v:.4f}")
    return f" [{f(lo)}–{f(hi)}]"


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    return ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)] + ["| " + " | ".join(r) + " |" for r in rows]


def _split_section(name: str, r: dict[str, Any]) -> list[str]:
    a, ci = r["at_threshold"], r.get("ci95")
    cm = a["confusion_matrix"]
    out = [f"## {name}", "", f"Records: **{r['n']:,}** (malicious {r['n_malicious']:,}, benign {r['n_benign']:,})", ""]
    if r.get("source"):
        sk = r["source"]["skipped"]
        out += [f"Source: {', '.join(r['source']['files'])} · read {r['source']['records_read']:,} · "
                f"unlabeled {sk['unlabeled']:,} · extraction failed {sk['extraction_failed']:,}", ""]
    rows = [
        ["ROC-AUC", _num(r["roc_auc"], 5) + _ci(ci, "roc_auc", pct=False)],
        ["Average precision", _num(r["average_precision"], 5)],
        ["Recall", _pct(a["recall"]) + _ci(ci, "recall")],
        ["FPR", _pct(a["fpr"], 3) + _ci(ci, "fpr", digits=3)],
        ["Precision", _pct(a["precision"], 3)],
        ["Threshold", str(a["threshold"]) if isinstance(a["threshold"], str) else _num(a["threshold"], 6)],
    ]
    out += _table(["Metric", "Value [95% CI]"], rows) + [""]
    out += _table(["", "Predicted malicious", "Predicted benign"],
                  [["Actual malicious", f"{cm['tp']:,} (TP)", f"{cm['fn']:,} (FN)"],
                   ["Actual benign", f"{cm['fp']:,} (FP)", f"{cm['tn']:,} (TN)"]]) + [""]
    if r.get("undefined"):
        out += ["Undefined metrics: " + "; ".join(f"{k}: {v}" for k, v in r["undefined"].items()), ""]
    tz = r.get("three_zone")
    if tz:
        z = tz["zones"]
        out += ["### Three-zone decision", ""]
        out += _table(["Zone", "Malicious", "Benign"],
                      [[k, f"{z[k]['malicious']:,}", f"{z[k]['benign']:,}"] for k in ("malicious", "suspicious", "clean")])
        out += ["", f"Review load {_pct(tz['review_load'])} · malware decided automatically "
                f"{_pct(tz['recall_auto'])} · malware not let through {_pct(tz['recall_auto_or_review'])} · "
                f"benign sent to review {_pct(tz['benign_review_rate'], 3)}", ""]
    for flag, groups in (r.get("subgroups") or {}).items():
        if "error" in groups:
            out += [f"Subgroup `{flag}`: {groups['error']}", ""]
            continue
        out += [f"### Subgroups: {flag}", ""]
        out += _table(["Group", "n", "Malicious / benign", "AUC", "Recall", "FPR", "FP"],
                      [[g, f"{m['n']:,}", f"{m['n_malicious']:,} / {m['n_benign']:,}", _num(m["roc_auc"], 4),
                        _pct(m["at_threshold"]["recall"]) + _ci(m.get("ci95"), "recall"),
                        _pct(m["at_threshold"]["fpr"], 3) + _ci(m.get("ci95"), "fpr", digits=3),
                        str(m["at_threshold"]["confusion_matrix"]["fp"])] for g, m in groups.items()]) + [""]
    if r.get("by_month") and len(r["by_month"]) > 1:
        out += ["### By month", ""]
        out += _table(["Month", "n", "Recall", "FPR"],
                      [[mo, f"{v['n']:,}", _pct(v["recall"]), _pct(v["fpr"], 3)] for mo, v in r["by_month"].items()])
        out += [""]
    w = r.get("with_test_benign")
    if w:
        out += [f"Challenge + test benign files: ROC-AUC {_num(w['roc_auc'], 4)}, recall "
                f"{_pct(w['at_threshold']['recall'])}, FPR {_pct(w['at_threshold']['fpr'], 3)}", ""]
    issues = {g: {k: v for k, v in c.items() if k not in ("0", "OK")} for g, c in (r.get("feature_status") or {}).items()}
    issues = {g: c for g, c in issues.items() if c}
    if issues:
        out += ["Feature extraction issues: " + "; ".join(
            f"{g}: " + ", ".join(f"{STATUS_NAMES.get(k, k)}={v:,}" for k, v in c.items()) for g, c in issues.items()),
            ""]
    return out


def render(run_dir: Path, evaluation_dir: Path | None = None) -> str:
    run_dir = Path(run_dir)
    ev = Path(evaluation_dir) if evaluation_dir else latest_evaluation(run_dir)
    summary = read_json(ev / "summary.json")
    training = read_json(run_dir / "training.json")
    thresholds = read_json(run_dir / "threshold.json")
    backend = summary["backend"]
    policy = summary.get("threshold_policy") or {"mode": "global"}
    sel = thresholds.get(backend, {})

    out = ["# silkscan evaluation report", "",
           f"- Run: `{run_dir}`", f"- Evaluation: `{ev}`",
           f"- Model: {training['n_features']:,} features, {training['best_iteration']} trees, "
           f"{training['n_train']:,} training records",
           f"- Backend: `{backend}` · outputs are model scores, not calibrated probabilities", "",
           "## Decision rule", "",
           f"`score >= threshold` → malicious. Target FPR {sel.get('target_fpr')}, selected on benign validation "
           f"files (achieved {sel.get('achieved_fpr')}, {sel.get('n_benign', 0):,} benign files)."]
    if policy.get("mode", "global") != "global":
        t = policy["thresholds"]
        out += [f"Policy: **{policy['mode']}** on `{policy['flag']}` ({policy['column']}): "
                f"{policy['flag']}=yes {t['yes']:.6f}, {policy['flag']}=no {t['no']:.6f}."]
    else:
        out += [f"Policy: **global**, threshold {sel.get('threshold', float('nan')):.6f}."]
    out += [""]

    files = {p.stem: p for p in ev.glob("*.json") if p.stem != "summary"}
    order = [s for s in SPLIT_ORDER if s in files] + sorted(s for s in files if s not in SPLIT_ORDER)
    if not order:
        raise SilkScanError(f"No split results in {ev}.")
    titles = {"validation": "Validation", "test": "Test", "challenge": "Challenge (malware only)"}
    for s in order:
        out += _split_section(titles.get(s, s), read_json(files[s]))
    if _is_synthetic(ev):
        out[:0] = ["> **SYNTHETIC DATA: these numbers only show that the pipeline runs.**", ""]
    return "\n".join(out).rstrip() + "\n"


def _is_synthetic(ev: Path) -> bool:
    for p in ev.glob("predictions_*.npz"):
        with np.load(p, allow_pickle=False) as z:
            if len(z["ids"]) and bytes(z["ids"][0]).startswith(b"synthetic:"):
                return True
    return False
