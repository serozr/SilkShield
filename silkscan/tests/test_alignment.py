"""Groups are joined by record id, never by row number."""

import numpy as np
import pytest

from silkscan.config import GroupConfig
from silkscan.errors import ExtractionError
from silkscan.features.base import FeatureBlock
from silkscan.features.pipeline import FeaturePipeline, MemorySource, align_index

from silkscan.synthetic import make_records

GROUPS = [GroupConfig("section_summary", missing_policy="impute_with_indicator"),
          GroupConfig("import_semantics", missing_policy="impute_with_indicator")]


def _shuffled(block: FeatureBlock, perm: np.ndarray) -> FeatureBlock:
    return FeatureBlock(block.ids[perm], np.asarray(block.matrix)[perm], block.feature_names, block.group,
                        block.version, block.status[perm], block.messages)


def test_blocks_in_different_order_are_aligned_by_id():
    recs = make_records(50)
    pipe = FeaturePipeline(GROUPS)
    src = MemorySource(recs)
    blocks = pipe.compute_blocks(src)
    reference = pipe.assemble(blocks, src.ids)
    perm = np.random.default_rng(0).permutation(len(recs))
    shuffled = dict(blocks, import_semantics=_shuffled(blocks["import_semantics"], perm))
    got = pipe.assemble(shuffled, src.ids)
    np.testing.assert_array_equal(got.X, reference.X)
    for g in reference.status:
        np.testing.assert_array_equal(got.status[g], reference.status[g])


def test_assembled_rows_follow_reference_id_order():
    recs = make_records(20)
    pipe = FeaturePipeline(GROUPS)
    src = MemorySource(recs)
    blocks = pipe.compute_blocks(src)
    reversed_ids = src.ids[::-1]
    got = pipe.assemble(blocks, reversed_ids)
    direct = pipe.assemble(blocks, src.ids)
    np.testing.assert_array_equal(got.X, direct.X[::-1])


def test_duplicate_missing_and_extra_ids_are_rejected():
    ids = np.array([b"a", b"b", b"c"], dtype="S")
    with pytest.raises(ExtractionError, match="duplicated"):
        align_index("g", np.array([b"a", b"a", b"c"], dtype="S"), ids)
    with pytest.raises(ExtractionError, match="missing"):
        align_index("g", np.array([b"a", b"b", b"x"], dtype="S"), ids)
    with pytest.raises(ExtractionError, match="not in the record set"):
        align_index("g", np.array([b"c", b"a", b"b", b"z"], dtype="S"), ids)
    assert align_index("g", ids.copy(), ids) is None
