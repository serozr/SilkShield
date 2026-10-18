"""Byte-order-safe array IO and atomic writes.

s390x is big-endian. Everything written to disk is explicitly little-endian
and everything handed to native code (LightGBM) is converted to native order
first.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import uuid
from pathlib import Path
from typing import Any, Iterator

import numpy as np


def to_little_endian(a: np.ndarray) -> np.ndarray:
    """Return `a` with an explicit little-endian dtype (no copy if already LE)."""
    if a.dtype.byteorder == "|":  # bytes, bool, int8: no byte order
        return a
    return a.astype(a.dtype.newbyteorder("<"), copy=False)


def to_native(a: np.ndarray) -> np.ndarray:
    """Return `a` in native byte order. C libraries read raw memory and cannot
    interpret a non-native dtype correctly."""
    if a.dtype.isnative:
        return a
    return a.astype(a.dtype.newbyteorder("="))


def save_array(path: Path, a: np.ndarray) -> None:
    np.save(path, to_little_endian(np.asarray(a)), allow_pickle=False)


def load_array(path: Path, mmap: bool = False) -> np.ndarray:
    """Load an .npy file. The dtype in the file header carries the byte order,
    so the result is correct on any platform; it may be non-native."""
    return np.load(path, mmap_mode="r" if mmap else None, allow_pickle=False)


def open_le_memmap(path: Path, shape: tuple[int, ...], dtype: str = "<f4") -> np.memmap:
    """Create a writable .npy memmap with an explicit little-endian dtype."""
    return np.lib.format.open_memmap(path, mode="w+", dtype=np.dtype(dtype), shape=shape)


def write_json(path: Path, obj: Any) -> None:
    path = Path(path)
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True, ensure_ascii=False, default=_default)
        f.write("\n")
    os.replace(tmp, path)


def read_json(path: Path) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _default(obj: Any) -> Any:
    from silkscan.utils.hashing import _json_default

    return _json_default(obj)


@contextlib.contextmanager
def atomic_directory(final: Path) -> Iterator[Path]:
    """Yield a temp directory that is renamed to `final` only if the block
    completes. A crash leaves no directory at `final`, so partial output is never
    mistaken for a finished one."""
    final = Path(final)
    final.parent.mkdir(parents=True, exist_ok=True)
    tmp = final.parent / f".tmp-{final.name}-{uuid.uuid4().hex[:8]}"
    tmp.mkdir()
    try:
        yield tmp
        if final.exists():
            # Another process finished the same work first; keep theirs.
            shutil.rmtree(tmp)
        else:
            os.rename(tmp, final)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
