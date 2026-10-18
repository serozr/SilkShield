"""Worker-process extraction gives exactly the single-process result (used for real data, n_jobs > 1)."""

import numpy as np
import pytest

from silkscan.config import GroupConfig
from silkscan.features.cache import FeatureCache
from silkscan.features.pipeline import FeaturePipeline, MemorySource

from silkscan.synthetic import make_records
import stateful_fixture  # noqa: F401  (registers the stateful test group)


# Earlier tests leave LightGBM/OpenMP threads alive in this process; the CLI forks before training.
@pytest.mark.filterwarnings("ignore:This process .* is multi-threaded:DeprecationWarning")
def test_parallel_extraction_matches_serial(tmp_path):
    groups = [GroupConfig("section_summary", missing_policy="impute_with_indicator"),
              GroupConfig("test_section_vocab", params={"min_count": 3})]
    train = MemorySource(make_records(120, seed=5), name="train")
    recs = make_records(300, seed=6)
    pipe = FeaturePipeline(groups)
    pipe.fit(train)
    serial = pipe.transform_records(recs, n_jobs=1)
    parallel = pipe.build(MemorySource(recs, chunk_size=128), FeatureCache(tmp_path), n_jobs=2)
    np.testing.assert_array_equal(serial.X, parallel.X)
    for g in serial.status:
        np.testing.assert_array_equal(serial.status[g], parallel.status[g])
