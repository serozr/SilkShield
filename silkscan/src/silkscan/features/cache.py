"""Per-group feature cache.

Layout: <cache_dir>/<group>/<key>/{ids.npy, status.npy, matrix.npy | csr_*.npy, meta.json, _COMPLETE.json}

The key covers the split fingerprint, group name/version/config, learned
state and tool versions. Entries are written in a temp directory and renamed
into place after `_COMPLETE.json` exists, so a partial write is never read.
Arrays are little-endian on disk on every platform.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import numpy as np
import scipy.sparse as sp

from silkscan.features.base import FeatureBlock, FeatureExtractor
from silkscan.utils.hashing import sha256_json
from silkscan.utils.io import atomic_directory, load_array, read_json, save_array, write_json

log = logging.getLogger(__name__)

CACHE_FORMAT = 1
COMPLETE = "_COMPLETE.json"


def cache_key(split_fingerprint: str, extractor: FeatureExtractor) -> str:
    return sha256_json({
        "format": CACHE_FORMAT,
        "split": split_fingerprint,
        "group": extractor.name,
        "version": extractor.version,
        "config": extractor.config_dict(),
        "state": extractor.state_fingerprint(),
        "tools": extractor.tool_versions(),
    })


def state_key(train_fingerprint: str, extractor: FeatureExtractor) -> str:
    return sha256_json({
        "format": CACHE_FORMAT,
        "train": train_fingerprint,
        "group": extractor.name,
        "version": extractor.version,
        "config": extractor.config_dict(),
        "tools": extractor.tool_versions(),
    })


class FeatureCache:
    def __init__(self, root: Path):
        self.root = Path(root)

    def entry_dir(self, group: str, key: str) -> Path:
        return self.root / group / key

    def has(self, group: str, key: str) -> bool:
        return (self.entry_dir(group, key) / COMPLETE).exists()

    def load(self, group: str, key: str, mmap: bool = True) -> FeatureBlock | None:
        d = self.entry_dir(group, key)
        if not (d / COMPLETE).exists():
            return None
        meta = read_json(d / "meta.json")
        ids = load_array(d / "ids.npy")
        status = load_array(d / "status.npy")
        if meta["sparse"]:
            matrix = sp.csr_matrix(
                (load_array(d / "csr_data.npy"), load_array(d / "csr_indices.npy"), load_array(d / "csr_indptr.npy")),
                shape=tuple(meta["shape"]),
            )
        else:
            matrix = load_array(d / "matrix.npy", mmap=mmap)
        return FeatureBlock(ids, matrix, tuple(meta["feature_names"]), meta["group"], meta["version"], status,
                            [tuple(m) for m in meta["messages"]])

    def save(self, key: str, block: FeatureBlock, extra_meta: dict[str, Any] | None = None) -> None:
        final = self.entry_dir(block.group, key)
        with atomic_directory(final) as tmp:
            save_array(tmp / "ids.npy", block.ids)
            save_array(tmp / "status.npy", block.status)
            if block.is_sparse:
                m = block.matrix.tocsr()
                save_array(tmp / "csr_data.npy", m.data.astype(np.float32))
                save_array(tmp / "csr_indices.npy", m.indices.astype(np.int64))
                save_array(tmp / "csr_indptr.npy", m.indptr.astype(np.int64))
            else:
                save_array(tmp / "matrix.npy", block.matrix)
            self._write_meta(tmp, block, extra_meta)

    def save_streamed(self, key: str, group: str, writer) -> None:
        """`writer(tmp_dir)` writes ids/status/matrix and returns the FeatureBlock it wrote."""
        final = self.entry_dir(group, key)
        with atomic_directory(final) as tmp:
            block, extra = writer(tmp)
            self._write_meta(tmp, block, extra)

    @staticmethod
    def _write_meta(tmp: Path, block: FeatureBlock, extra_meta: dict[str, Any] | None) -> None:
        write_json(tmp / "meta.json", {
            "group": block.group,
            "version": block.version,
            "feature_names": list(block.feature_names),
            "shape": list(block.matrix.shape),
            "sparse": block.is_sparse,
            "status_counts": block.status_counts(),
            "messages": [list(m) for m in block.messages],
            **(extra_meta or {}),
        })
        write_json(tmp / COMPLETE, {"format": CACHE_FORMAT})

    # -- learned extractor state ----------------------------------------------
    def load_state(self, group: str, key: str) -> dict[str, Any] | None:
        p = self.root / group / "states" / f"{key}.json"
        return read_json(p) if p.exists() else None

    def save_state(self, group: str, key: str, state: dict[str, Any]) -> None:
        d = self.root / group / "states"
        d.mkdir(parents=True, exist_ok=True)
        write_json(d / f"{key}.json", state)
