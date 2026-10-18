"""Platform-independent fingerprints.

Hashes are taken over canonical JSON or over little-endian bytes, never over
native memory, so x86_64 and s390x produce the same fingerprints.
"""

from __future__ import annotations

import enum
import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np

from silkscan.utils.io import to_little_endian


def _json_default(obj: Any) -> Any:
    if isinstance(obj, np.generic):
        return obj.item()
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    raise TypeError(f"Not JSON serializable: {type(obj).__name__}")


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=_json_default)


def sha256_json(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def array_fingerprint(a: np.ndarray) -> str:
    le = np.ascontiguousarray(to_little_endian(np.asarray(a)))
    h = hashlib.sha256()
    h.update(f"{le.dtype.str}|{le.shape}".encode())
    h.update(le.tobytes())
    return h.hexdigest()
