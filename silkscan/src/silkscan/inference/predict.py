"""Scanning: cheap checks first, then static analysis and the model only when needed.

Order for every submission:
1. pre-checks    - checks that need only the hash or file bytes (hash lists, YARA);
2. short-circuit - a pre-check hit that forces a decision (deny/allow list, forcing YARA rule)
                   skips steps 3-5 unless short_circuit is off (audit / shadow mode);
3. parse         - static PE analysis with thrember (the expensive step; skipped if raw features
                   were submitted);
4. post-checks   - checks that read the parsed raw features (Check.needs_raw);
5. model         - feature pipeline + scoring backend, decision at the run's threshold policy;
6. combine       - final decision, reasons and priority (silkscan.checks.decision).

The output field is `score` (a model score, not a calibrated probability).
A submission whose analysis failed is never reported as `clean`.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

import numpy as np

from silkscan.checks import Check, CheckContext, CheckResult, Effect, Outcome
from silkscan.checks.decision import combine
from silkscan.data.jsonl import iter_raw
from silkscan.data.records import Record, split_record
from silkscan.inference.backends import LightGBMBackend, ScoringBackend
from silkscan.inference.bundle import ModelBundle

VERDICT_SCHEMA_VERSION = "1"
FILE_KIND_COLUMN = "ember_v3.header_0043"  # COFF characteristic IMAGE_FILE_DLL


@dataclass
class Submission:
    """One thing to scan: file bytes, already-extracted EMBER raw features, or both."""

    data: bytes | None = None
    record: Record | None = None
    filename: str | None = None        # as submitted; untrusted, informational only

    @property
    def sha256(self) -> str:
        if self.record is not None:
            return self.record.id
        if self.data is None:
            raise ValueError("A submission needs file bytes or a record.")
        return hashlib.sha256(self.data).hexdigest()


def records_from_jsonl(path: Path, id_field: str, limit: int | None = None) -> list[Record]:
    out = []
    for _, _, obj in iter_raw([Path(path)]):
        out.append(split_record(obj, id_field))
        if limit and len(out) >= limit:
            break
    return out


def record_from_bytes(data: bytes) -> Record:
    """Static analysis of file bytes with thrember (never executed)."""
    from silkscan.features.groups.ember_v3 import load_thrember_features

    return split_record(load_thrember_features().PEFeatureExtractor().raw_features(data), "sha256")


def record_from_pe(path: Path) -> Record:
    return record_from_bytes(Path(path).read_bytes())


def _forced(results: list[CheckResult]) -> bool:
    return any(r.outcome == Outcome.HIT and r.effect in (Effect.FORCE_MALICIOUS, Effect.FORCE_CLEAN,
                                                         Effect.FORCE_REVIEW)
               for r in results)


def scan(bundle: ModelBundle, backend: ScoringBackend, items: Sequence[Submission], checks: Sequence[Check] = (),
         explain_top: int = 0, short_circuit: bool = True,
         parse: Callable[[bytes], Record] | None = None, stage2: Any = None) -> list[dict[str, Any]]:
    """Return one verdict per submission, in input order.

    `parse` turns file bytes into a Record; default: thrember in this process. A service should pass
    a parser that runs in an isolated subprocess with time/memory limits and raises on failure
    (the submission then gets an `error` verdict).
    """
    parse = parse or record_from_bytes
    n = len(items)
    pre = [c for c in checks if not getattr(c, "needs_raw", False)]
    post = [c for c in checks if getattr(c, "needs_raw", False)]
    timing = [dict.fromkeys(("pre_checks", "parse", "post_checks", "model"), 0.0) for _ in range(n)]
    ids = [it.sha256 for it in items]

    # 1-2: cheap checks on hash/bytes, before any parsing
    pre_results: list[list[CheckResult]] = []
    for i, it in enumerate(items):
        t0 = time.perf_counter()
        raw = it.record.inputs if it.record is not None else {}
        ctx = CheckContext.from_record(ids[i], raw, it.data, it.filename)
        pre_results.append([c(ctx) for c in pre])
        timing[i]["pre_checks"] = 1e3 * (time.perf_counter() - t0)
    todo = [i for i in range(n) if not (short_circuit and _forced(pre_results[i]))]

    # 3: static analysis only for submissions that still need the model
    records: dict[int, Record] = {}
    parse_errors: dict[int, str] = {}
    for i in todo:
        it = items[i]
        if it.record is not None:
            records[i] = it.record
            continue
        t0 = time.perf_counter()
        try:
            records[i] = parse(it.data)
        except Exception as e:  # malformed input must yield an `error` verdict, not a crash
            parse_errors[i] = f"{type(e).__name__}: {e}"
        timing[i]["parse"] = 1e3 * (time.perf_counter() - t0)

    # 4: checks that read raw features
    post_results: dict[int, list[CheckResult]] = {}
    for i, rec in records.items():
        t0 = time.perf_counter()
        ctx = CheckContext.from_record(ids[i], rec.inputs, items[i].data, items[i].filename)
        post_results[i] = [c(ctx) for c in post]
        timing[i]["post_checks"] = 1e3 * (time.perf_counter() - t0)

    # 5: model, batched over everything that was parsed
    order = sorted(records)
    model_out = _score(bundle, backend, [records[i] for i in order], explain_top, stage2)
    per_item = model_out["seconds"] * 1e3 / len(order) if order else 0.0
    model_rows = {i: k for k, i in enumerate(order)}
    policy = (bundle.policy(backend.name) or {}).get("mode", "global")
    model_info = {"run": bundle.run_dir.name, "schema_fingerprint": bundle.schema.fingerprint(),
                  "backend": backend.name, "threshold_policy": policy}
    check_versions = {c.name: {"version": c.version, **c.tool_versions()} for c in checks}
    empty = {"score": None, "threshold": None, "review_threshold": None, "file_kind": None, "feature_status": {}}

    # 6: combine
    verdicts = []
    for i in range(n):
        results = pre_results[i] + post_results.get(i, [])
        if i in model_rows:
            m = model_out["rows"][model_rows[i]]
            timing[i]["model"] = per_item
            model_decision = m["decision"]
        else:
            m = empty
            model_decision = "error" if i in parse_errors else "skipped"
        cls = m.get("classification")
        extra = ([c["name"] for c in cls["categories"]] + ([f"family:{cls['family']['name']}"] if cls["family"]
                                                           else [])) if cls else []
        final = combine(model_decision, results, extra)
        reasons = list(final["reasons"])
        if model_decision == "skipped":
            reasons.append("short-circuit: a pre-check decided; static analysis and model skipped")
        if i in parse_errors:
            reasons.append(f"static analysis failed: {parse_errors[i]}")
        v: dict[str, Any] = {
            "schema_version": VERDICT_SCHEMA_VERSION, "id": ids[i],
            "decision": final["decision"], "priority": final["priority"], "action": final["action"],
            "reasons": reasons,
            "model_decision": model_decision, "score": m["score"], "threshold": m["threshold"],
            "review_threshold": m["review_threshold"],
            "threshold_policy": policy, "file_kind": m["file_kind"], "backend": backend.name,
            "feature_status": m["feature_status"], "checks": [r.to_dict() for r in results],
            "tags": final["tags"], "classification": cls,  # stage 2: categories + family (None if not run)
            "model": model_info, "check_versions": check_versions,
            "timing_ms": {k: round(t, 3) for k, t in timing[i].items()},
        }
        rec = records.get(i) or items[i].record
        if rec is not None and "label" in rec.target:
            v["label_in_file_not_used"] = rec.target["label"]
        if "explanation" in m:
            v["explanation"] = m["explanation"]
        verdicts.append(v)
    return verdicts


def _score(bundle: ModelBundle, backend: ScoringBackend, records: list[Record], explain_top: int,
           stage2: Any = None) -> dict[str, Any]:
    """Feature pipeline + model for parsed records; decision per row at the run's threshold policy."""
    if not records:
        return {"rows": [], "seconds": 0.0}
    t0 = time.perf_counter()
    pipe = bundle.pipeline()
    feats = pipe.transform_records(records, strict=False)
    ok = ~feats.failed
    scores = np.full(len(records), np.nan)
    if ok.any():
        scores[ok] = backend.predict(feats.X[ok])
    tvec = bundle.row_thresholds(backend.name, feats.feature_names, feats.X)
    low = bundle.row_review_thresholds(backend.name, feats.feature_names, feats.X)
    seconds = time.perf_counter() - t0
    inconclusive = bundle.config.evaluation.inconclusive_on_status

    contrib = None
    display = pipe.display_names() if explain_top else {}
    if explain_top and ok.any():
        lgbm = backend if isinstance(backend, LightGBMBackend) else bundle.backend("lightgbm")
        contrib = np.full((len(records), len(feats.feature_names) + 1), np.nan)
        contrib[ok] = lgbm.contributions(feats.X[ok])
    kind = None
    if FILE_KIND_COLUMN in feats.feature_names:
        from silkscan.inference.bundle import column_flag

        kind = np.where(column_flag(feats.X, feats.feature_names.index(FILE_KIND_COLUMN)), "dll", "exe")

    rows = []
    for i in range(len(records)):
        status = feats.record_status(i)
        problems = {g: s for g, s in status.items() if s != "OK"}
        if not ok[i]:
            decision, score = "error", None
        else:
            score = float(scores[i])
            if score >= tvec[i]:
                decision = "malicious"
            elif problems and inconclusive:
                decision = "inconclusive"
            elif low is not None and score >= low[i]:
                decision = "suspicious"
            else:
                decision = "clean"
        row = {"decision": decision, "score": score, "threshold": float(tvec[i]),
               "review_threshold": None if low is None else float(low[i]),
               "file_kind": None if kind is None else str(kind[i]), "feature_status": status}
        if contrib is not None and ok[i]:
            row["explanation"] = _explain(contrib[i], feats.feature_names, feats.group_slices, explain_top, display)
        rows.append(row)
    if stage2 is not None:
        # threat type only for files the detector flags (malicious or suspicious)
        flagged = [i for i, r in enumerate(rows) if r["decision"] in ("malicious", "suspicious")]
        if flagged:
            for i, c in zip(flagged, stage2.classify(feats.X[flagged])):
                rows[i]["classification"] = c
    return {"rows": rows, "seconds": seconds}


def predict_records(bundle: ModelBundle, backend: ScoringBackend, records: Sequence[Record],
                    explain_top: int = 0, checks: Sequence[Check] = (),
                    data: Sequence[bytes | None] | None = None,
                    filenames: Sequence[str | None] | None = None,
                    short_circuit: bool = True) -> list[dict[str, Any]]:
    """`scan` for already-parsed records (optionally with their file bytes for byte-level checks)."""
    items = [Submission(data[i] if data else None, rec, filenames[i] if filenames else None)
             for i, rec in enumerate(records)]
    return scan(bundle, backend, items, checks, explain_top, short_circuit)


def _explain(c: np.ndarray, names: list[str], slices: dict[str, slice], top: int,
             display: dict[str, str] | None = None) -> dict[str, Any]:
    display = display or {}
    feat = c[:-1]
    order = np.argsort(-np.abs(feat))[:top]
    return {
        "unit": "log-odds contribution",
        "bias": float(c[-1]),
        "by_group": {g: float(feat[s].sum()) for g, s in slices.items()},
        "top_features": [{"feature": names[j], "meaning": display.get(names[j], names[j]),
                          "contribution": float(feat[j])} for j in order if feat[j] != 0],
    }
