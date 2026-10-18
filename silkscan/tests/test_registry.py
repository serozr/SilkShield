"""Target and identity fields can never reach feature extraction."""

import pytest

from silkscan.data.records import FORBIDDEN_INPUT_FIELDS, input_view, split_record
from silkscan.errors import LeakageError
from silkscan.features.base import Extraction, FeatureExtractor
from silkscan.features.registry import REGISTRY, register


@pytest.mark.parametrize("field", ["label", "detection_ratio", "family", "behavior", "sha256", "tlsh",
                                   "first_submission_date", "packer"])
def test_extractor_requesting_target_field_cannot_be_registered(field):
    class Leaky(FeatureExtractor):
        name = f"leaky_{field}"
        version = "1"
        required_inputs = ("section", field)

        def get_feature_names(self):
            return [f"{self.name}.x"]

        def extract_one(self, view):
            return Extraction([0.0])

    with pytest.raises(LeakageError):
        register(Leaky)
    assert Leaky.name not in REGISTRY


def test_split_record_separates_inputs_and_targets():
    raw = {"sha256": "a" * 64, "label": 1, "family": "x", "detection_ratio": [5, 70], "tlsh": "T1",
           "section": {"sections": []}, "imports": {}}
    rec = split_record(raw)
    assert rec.id == "a" * 64
    assert set(rec.inputs) == {"section", "imports"}
    assert not FORBIDDEN_INPUT_FIELDS & set(rec.inputs)
    assert rec.target["label"] == 1
    view = input_view(rec, ("section", "label"))
    assert set(view) == {"section"}
    with pytest.raises(TypeError):
        view["label"] = 1  # read-only
