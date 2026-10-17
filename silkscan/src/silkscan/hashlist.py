"""Known-hash lists built from the manifest (no data files are read).

Build the deny-list from the training period only: train/validation and test ids are disjoint
(manifest checks), so test samples are never "known" and still reach the model. That keeps
"known threat" (hash hit) and "new threat" (model) separable in the pipeline metrics.

Default format: sorted, unique 32-byte digests in a `.npy` file (dtype S32), memory-mapped by the
hash_list check (fast load, 32 B/hash, shared across worker processes), plus a `.json` sidecar.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from silkscan.data.manifest import Manifest
from silkscan.errors import DataValidationError
from silkscan.utils.io import write_json


def write_hash_list(manifest: Manifest, splits: list[str], label: int, out: Path) -> int:
    ids = [manifest.split(n).ids[manifest.split(n).labels == label] for n in splits]
    hexes = np.unique(np.concatenate(ids)) if ids else np.array([], "S64")
    # Validate on the hex strings: S32 elements read back without trailing NUL bytes, so their length lies.
    if any(len(h) != 64 for h in hexes.tolist()):
        raise DataValidationError("Ids are not SHA-256 values (synthetic data cannot be listed).")
    try:
        digests = np.array([bytes.fromhex(h.decode()) for h in hexes], dtype="S32")
    except ValueError:
        raise DataValidationError("Ids are not SHA-256 values (synthetic data cannot be listed).") from None
    order = np.argsort(digests, kind="stable")
    digests, hexes = digests[order], hexes[order]     # sorted (np.unique on hexes already made them unique)
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    meta = {"label": {1: "malicious", 0: "benign"}[label], "splits": splits, "count": int(len(digests)),
            "manifest_fingerprint": manifest.fingerprint, "created": datetime.now(timezone.utc).isoformat()}
    if out.suffix == ".npy":
        np.save(out, digests, allow_pickle=False)
        write_json(out.with_suffix(".json"), meta)
    else:
        with open(out, "w") as f:
            f.write(f"# {meta}\n")
            # Write the original hex ids: S32 elements read back without trailing NUL bytes.
            f.writelines(h.decode() + "\n" for h in hexes)
    return int(len(digests))
