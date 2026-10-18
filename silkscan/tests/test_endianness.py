"""Big-endian data is read correctly; disk format is always little-endian.

These tests run on x86 by constructing explicit big-endian ('>f4') arrays, which
is what native float32 data looks like on s390x. Under s390x emulation the same
tests exercise the native big-endian path.
"""

import numpy as np

from silkscan.config import GroupConfig
from silkscan.features.base import FeatureBlock
from silkscan.features.cache import FeatureCache
from silkscan.features.pipeline import FeaturePipeline, MemorySource
from silkscan.utils.hashing import array_fingerprint
from silkscan.utils.io import load_array, save_array, to_little_endian, to_native

from silkscan.synthetic import make_records

VALUES = np.array([[1.5, -2.25, 3e-8], [np.nan, 1e30, 0.0]], dtype=np.float32)


def test_saved_arrays_are_little_endian_on_disk(tmp_path):
    be = VALUES.astype(">f4")
    save_array(tmp_path / "a.npy", be)
    loaded = load_array(tmp_path / "a.npy")
    assert loaded.dtype.str == "<f4"
    np.testing.assert_array_equal(loaded, VALUES)
    raw = (tmp_path / "a.npy").read_bytes()
    assert raw.endswith(VALUES.astype("<f4").tobytes())


def test_raw_memmap_needs_explicit_dtype(tmp_path):
    """The thrember .dat pitfall: raw float32 files have no header."""
    p = tmp_path / "x.dat"
    VALUES.astype("<f4").tofile(p)
    right = np.memmap(p, dtype="<f4", mode="r").reshape(VALUES.shape)
    wrong = np.memmap(p, dtype=">f4", mode="r").reshape(VALUES.shape)
    np.testing.assert_array_equal(right, VALUES)
    assert not np.array_equal(np.nan_to_num(wrong), np.nan_to_num(VALUES))  # silently garbage, no error


def test_conversions_preserve_values():
    be = VALUES.astype(">f4")
    np.testing.assert_array_equal(to_native(be), VALUES)
    assert to_native(be).dtype.isnative
    assert to_little_endian(be).dtype.str == "<f4"
    assert array_fingerprint(be) == array_fingerprint(VALUES) == array_fingerprint(VALUES.astype("<f4"))


def test_cache_and_assembly_with_big_endian_blocks(tmp_path):
    recs = make_records(30)
    pipe = FeaturePipeline([GroupConfig("section_summary", missing_policy="impute_with_indicator")])
    src = MemorySource(recs)
    block = pipe.compute_blocks(src)["section_summary"]
    expected = pipe.assemble({"section_summary": block}, src.ids).X

    be_block = FeatureBlock(block.ids, np.asarray(block.matrix).astype(">f4"), block.feature_names, block.group,
                            block.version, block.status.astype(">u1"), block.messages)
    got = pipe.assemble({"section_summary": be_block}, src.ids).X
    assert got.dtype.isnative
    np.testing.assert_array_equal(got, expected)

    cache = FeatureCache(tmp_path)
    cache.save("k", be_block)
    loaded = cache.load("section_summary", "k")
    assert loaded.matrix.dtype.str == "<f4"
    np.testing.assert_array_equal(pipe.assemble({"section_summary": loaded}, src.ids).X, expected)


def test_lightgbm_scores_identical_from_le_and_be_sources():
    import lightgbm as lgb

    rng = np.random.default_rng(0)
    X = rng.random((300, 5)).astype(np.float32)
    y = (X[:, 0] + 0.2 * rng.random(300) > 0.6).astype(int)
    booster = lgb.train({"objective": "binary", "verbosity": -1, "num_threads": 1}, lgb.Dataset(X, y), 10)
    from_be = to_native(X.astype(">f4"))
    from_le = to_native(X.astype("<f4"))
    np.testing.assert_array_equal(booster.predict(from_be), booster.predict(from_le))
