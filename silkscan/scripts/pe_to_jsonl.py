"""Convert labelled PE files into EMBER2024-format JSONL for `silkscan evaluate --jsonl`.

Files are only read and statically parsed (thrember); they are never executed.

    python scripts/pe_to_jsonl.py --malicious samples/mal --benign samples/clean --out my_test.jsonl
    silkscan evaluate --run <run> --jsonl my_test.jsonl --name my_test
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--malicious", nargs="*", default=[], help="directories with malicious files (label 1)")
    ap.add_argument("--benign", nargs="*", default=[], help="directories with benign files (label 0)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-mb", type=float, default=100, help="skip larger files")
    args = ap.parse_args()

    from silkscan.features.groups.ember_v3 import load_thrember_features

    extractor = load_thrember_features().PEFeatureExtractor()
    n = {0: 0, 1: 0}
    skipped = 0
    with open(args.out, "w", encoding="utf-8") as out:
        for label, dirs in ((1, args.malicious), (0, args.benign)):
            for d in dirs:
                for p in sorted(Path(d).rglob("*")):
                    if not p.is_file() or p.stat().st_size > args.max_mb * 2**20:
                        skipped += p.is_file()
                        continue
                    try:
                        raw = extractor.raw_features(p.read_bytes())
                    except Exception as e:  # unparseable input: report and continue
                        print(f"skip {p}: {type(e).__name__}", file=sys.stderr)
                        skipped += 1
                        continue
                    raw.update(label=label, file_type="Win64")
                    out.write(json.dumps(raw) + "\n")
                    n[label] += 1
    print(f"{args.out}: {n[1]} malicious, {n[0]} benign, {skipped} skipped")


if __name__ == "__main__":
    main()
