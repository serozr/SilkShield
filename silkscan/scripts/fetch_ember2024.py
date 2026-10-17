"""Download and extract EMBER2024 (Win64 train/test and the challenge set) from HuggingFace.

Uses huggingface_hub only, so it also works where the full thrember package cannot be installed.

    python scripts/fetch_ember2024.py --out /data/ember2024
"""

from __future__ import annotations

import argparse
import zipfile
from pathlib import Path

REPO = "joyce8/EMBER2024"
FILES = {"train": "Win64_train.zip", "test": "Win64_test.zip", "challenge": "challenge.zip"}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, help="target directory (set EMBER2024_DIR to it)")
    ap.add_argument("--splits", nargs="+", choices=sorted(FILES), default=sorted(FILES))
    ap.add_argument("--keep-zip", action="store_true", help="keep the downloaded archives in the HF cache")
    args = ap.parse_args()

    from huggingface_hub import hf_hub_download

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for split in args.splits:
        name = FILES[split]
        print(f"downloading {name} ...", flush=True)
        path = Path(hf_hub_download(repo_id=REPO, filename=name, repo_type="dataset"))
        with zipfile.ZipFile(path) as z:
            for member in z.infolist():
                target = (out / member.filename).resolve()
                if out.resolve() not in target.parents and target != out.resolve():
                    raise SystemExit(f"unsafe path in archive: {member.filename}")
            z.extractall(out)
            print(f"  extracted {len(z.infolist())} files")
        if not args.keep_zip:
            path.unlink(missing_ok=True)
    n = len(list(out.glob("*.jsonl")))
    print(f"done: {n} JSONL files in {out}\nexport EMBER2024_DIR={out.resolve()}")


if __name__ == "__main__":
    main()
