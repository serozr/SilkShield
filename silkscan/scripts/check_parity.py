"""Check that a model gives the same verdicts on another machine (e.g. after moving it to IBM Z).

    # on the source machine: write expected verdicts for a set of EMBER-format records
    python scripts/check_parity.py --serving configs/serving.yaml --records parity/records.jsonl --write parity/expected.jsonl
    # on the target machine:
    python scripts/check_parity.py --serving configs/serving.yaml --records parity/records.jsonl --expected parity/expected.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

COMPARED = ("decision", "priority", "action", "model_decision", "threshold", "review_threshold", "file_kind")


def _verdicts(serving_path: str, records_path: str) -> list[dict]:
    from silkscan.checks import create_checks
    from silkscan.config import load_serving_config
    from silkscan.inference.bundle import ModelBundle
    from silkscan.inference.predict import Submission, records_from_jsonl, scan

    serving = load_serving_config(serving_path)
    bundle = ModelBundle(Path(serving.run))
    stage2 = None
    if serving.stage2:
        from silkscan.stage2 import Stage2Model

        stage2 = Stage2Model(Path(serving.stage2))
        stage2.require_compatible(bundle.schema.fingerprint())
    records = records_from_jsonl(Path(records_path), bundle.config.data.id_field)
    return scan(bundle, bundle.backend(serving.backend), [Submission(None, r) for r in records],
                create_checks(serving.checks), 0, serving.short_circuit, stage2=stage2)


def _key(v: dict) -> dict:
    cls = v.get("classification") or {}
    return {**{k: v.get(k) for k in COMPARED},
            "categories": [c["name"] for c in cls.get("categories", [])],
            "family": (cls.get("family") or {}).get("name")}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--serving", required=True)
    ap.add_argument("--records", required=True)
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", help="write expected verdicts here")
    group.add_argument("--expected", help="compare against these expected verdicts")
    ap.add_argument("--tol", type=float, default=1e-6, help="max absolute score difference")
    args = ap.parse_args()

    got = _verdicts(args.serving, args.records)
    if args.write:
        with open(args.write, "w", encoding="utf-8") as f:
            for v in got:
                f.write(json.dumps({"id": v["id"], "score": v["score"], **_key(v)}) + "\n")
        print(f"wrote {len(got)} expected verdicts to {args.write}")
        return

    expected = [json.loads(line) for line in open(args.expected, encoding="utf-8")]
    if len(expected) != len(got):
        sys.exit(f"record count differs: expected {len(expected)}, got {len(got)}")
    max_diff, mismatches = 0.0, []
    for e, v in zip(expected, got):
        if e["id"] != v["id"]:
            sys.exit(f"record order differs at {e['id']}")
        if e["score"] is not None and v["score"] is not None:
            max_diff = max(max_diff, abs(e["score"] - v["score"]))
        if _key(v) != {k: e[k] for k in _key(v)}:
            mismatches.append(e["id"])
    print(f"records {len(got)} | max score difference {max_diff:.2e} | verdict mismatches {len(mismatches)}")
    if mismatches or max_diff > args.tol:
        print("PARITY FAILED", mismatches[:5])
        sys.exit(1)
    print("PARITY OK")


if __name__ == "__main__":
    main()
