"""Byte-order-independent feature hashing for thrember.

scikit-learn's MurmurHash3 reads 4-byte blocks in the machine's byte order, so `FeatureHasher` puts
the same string into a different column on big-endian machines (IBM Z) and a model trained on x86
sees shuffled features. Where that happens, each block is byte-swapped before hashing, which
reproduces the little-endian hash exactly.
"""
from __future__ import annotations

from functools import lru_cache

import numpy as np

# murmurhash3_32(key, seed=0) on a little-endian machine; covers whole blocks and a tail.
_REFERENCE = {b"abcd": 1139631978, b".text": -2097954141, b"kernel32.dll:CreateFileW": -523189509}


def swap_blocks(key: bytes) -> bytes:
    n = len(key) - len(key) % 4
    return b"".join(key[i:i + 4][::-1] for i in range(0, n, 4)) + key[n:]


@lru_cache(maxsize=1)
def native_hash_is_portable() -> bool:
    """True if scikit-learn already hashes like a little-endian machine; False if blocks need swapping."""
    from sklearn.utils import murmurhash3_32

    if all(murmurhash3_32(k, seed=0) == v for k, v in _REFERENCE.items()):
        return True
    if all(murmurhash3_32(swap_blocks(k), seed=0) == v for k, v in _REFERENCE.items()):
        return False
    raise RuntimeError("MurmurHash3 matches neither byte order; hashed features would not match the model")


def _key(feature) -> bytes:
    return swap_blocks(feature.encode("utf-8") if isinstance(feature, str) else feature)


class PortableFeatureHasher:
    """Drop-in for `sklearn.feature_extraction.FeatureHasher` that hashes like a little-endian machine."""

    def __init__(self, n_features: int = 2**20, *, input_type: str = "dict", dtype=np.float64,
                 alternate_sign: bool = True):
        from sklearn.feature_extraction import FeatureHasher

        self.input_type = input_type
        self._hasher = FeatureHasher(n_features, input_type="string" if input_type == "string" else "pair",
                                     dtype=dtype, alternate_sign=alternate_sign)

    def transform(self, raw_X):
        if self.input_type == "string":
            rows = []
            for x in raw_X:
                if isinstance(x, str):
                    raise ValueError("Samples can not be a single string; the input must be an iterable of strings")
                rows.append([_key(f) for f in x])
            return self._hasher.transform(rows)
        rows = []
        for x in raw_X:
            pairs = x.items() if self.input_type == "dict" else x
            # Same as scikit-learn: a string value becomes the feature "name=value" with value 1.
            rows.append([(_key(f"{f}={v}"), 1) if isinstance(v, str) else (_key(f), v) for f, v in pairs])
        return self._hasher.transform(rows)


def make_portable(module) -> None:
    """Replace a module's `FeatureHasher` when scikit-learn's hash depends on byte order here."""
    if not native_hash_is_portable():
        module.FeatureHasher = PortableFeatureHasher
