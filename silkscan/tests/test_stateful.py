"""A vocabulary learned on train never grows on test/prediction data."""

import copy

import numpy as np
import pytest

from silkscan.config import GroupConfig
from silkscan.data.records import input_view
from silkscan.errors import ExtractionError
from silkscan.features.pipeline import FeaturePipeline, MemorySource
from silkscan.synthetic import make_records
from stateful_fixture import SectionVocab


def _views(recs):
    return [input_view(r, SectionVocab.required_inputs) for r in recs]


def test_vocabulary_frozen_after_fit_and_unknowns_counted():
    ex = SectionVocab(min_count=3)
    ex.fit(_views(make_records(200, seed=1)))
    state_before = copy.deepcopy(ex.get_state())
    names_before = ex.get_feature_names()
    assert state_before["vocab"]

    test = make_records(30, seed=2)
    novel = dict(test[0].inputs)
    novel["section"] = {"entry": ".new", "sections": [{"name": "never_seen_before"}]}
    test[0] = type(test[0])(test[0].id, novel, test[0].target)
    block = ex.transform(np.array([r.id.encode() for r in test], dtype="S"), _views(test))

    assert ex.get_state() == state_before and ex.get_feature_names() == names_before
    assert block.matrix[0, names_before.index("test_section_vocab.n_unknown")] == 1


def test_stateful_group_must_be_fitted_first():
    with pytest.raises(ExtractionError, match="fitted"):
        SectionVocab().transform(np.array([b"a"], dtype="S"), [{}])


def test_pipeline_fits_only_on_train_split():
    pipe = FeaturePipeline([GroupConfig("test_section_vocab", params={"min_count": 2})])
    with pytest.raises(ExtractionError, match="train split"):
        pipe.fit(MemorySource(make_records(10), name="test"))
    pipe.fit(MemorySource(make_records(50), name="train"))
    assert pipe.get_states()["test_section_vocab"]["vocab"]
