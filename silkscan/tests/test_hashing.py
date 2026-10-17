import random

import numpy as np
import pytest

from silkscan.features import hashing

M = 0xFFFFFFFF


def _rotl(x, r):
    return ((x << r) | (x >> (32 - r))) & M


def murmur3(key: bytes, byteorder: str) -> int:
    """Reference MurmurHash3_x86_32 (seed 0) reading blocks in the given byte order."""
    c1, c2, h, n = 0xCC9E2D51, 0x1B873593, 0, len(key) - len(key) % 4
    for i in range(0, n, 4):
        k = _rotl(int.from_bytes(key[i:i + 4], byteorder) * c1 & M, 15) * c2 & M
        h = (_rotl(h ^ k, 13) * 5 + 0xE6546B64) & M
    tail, k = key[n:], 0
    for j in reversed(range(len(tail))):
        k ^= tail[j] << (8 * j)
    if tail:
        h ^= _rotl(k * c1 & M, 15) * c2 & M
    h ^= len(key)
    h = (h ^ (h >> 16)) * 0x85EBCA6B & M
    h = (h ^ (h >> 13)) * 0xC2B2AE35 & M
    h ^= h >> 16
    return h - (1 << 32) if h & 0x80000000 else h


def test_reference_values_are_little_endian_murmur3():
    for key, value in hashing._REFERENCE.items():
        assert murmur3(key, "little") == value


def test_block_swap_makes_big_endian_hash_match_little_endian():
    rng = random.Random(0)
    for _ in range(300):
        key = bytes(rng.randrange(256) for _ in range(rng.randrange(40)))
        assert murmur3(hashing.swap_blocks(key), "big") == murmur3(key, "little")


def test_this_machine_hashes_portably():
    hashing.native_hash_is_portable()  # raises if neither byte order matches


@pytest.mark.skipif(not hashing.native_hash_is_portable(), reason="checks the wrapper against native hashing")
def test_portable_hasher_matches_sklearn_inputs(monkeypatch):
    from sklearn.feature_extraction import FeatureHasher

    # On a little-endian machine, swapping must be a no-op for the comparison to make sense.
    monkeypatch.setattr(hashing, "swap_blocks", lambda key: key)
    strings = [["kernel32.dll:CreateFileW", ".text", "x", "x"], []]
    pairs = [[(".text", 3.5), (".rsrc", 0), ("name", "value")]]
    for kind, data, kw in (("string", strings, {}), ("string", strings, {"alternate_sign": False}),
                           ("pair", pairs, {}), ("dict", [dict(pairs[0])], {})):
        ours = hashing.PortableFeatureHasher(64, input_type=kind, **kw).transform(data).toarray()
        ref = FeatureHasher(64, input_type=kind, **kw).transform(data).toarray()
        np.testing.assert_array_equal(ours, ref)
