"""Save/load gives identical features and scores."""

import numpy as np

from silkscan.features.cache import FeatureCache
from silkscan.inference.bundle import ModelBundle
from silkscan.inference.predict import predict_records
from silkscan.workflow import load_manifest, source


def test_reloaded_bundle_reproduces_features_and_scores(trained_run):
    run, cfg = trained_run
    manifest = load_manifest(cfg)
    val = source(cfg, manifest, "validation")
    records = [r for chunk in val.iter_chunks() for r in chunk]

    saved = np.load(run / "predictions_validation.npz")
    bundle = ModelBundle(run)
    pipe = bundle.pipeline()

    in_memory = pipe.transform_records(records, strict=True)
    cached = pipe.build(val, FeatureCache(cfg.features.cache_dir))
    np.testing.assert_array_equal(in_memory.X, cached.X)  # NaN == NaN for assert_array_equal

    scores = bundle.backend("lightgbm").predict(in_memory.X)
    np.testing.assert_array_equal(scores, saved["scores"])
    np.testing.assert_array_equal(saved["ids"], val.ids)

    preds = predict_records(ModelBundle(run), ModelBundle(run).backend(), records[:10])
    np.testing.assert_array_equal([p["score"] for p in preds], saved["scores"][:10])
