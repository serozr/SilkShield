"""The API serves stage-2 classification exactly like the core scan()/CLI does."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml
from starlette.testclient import TestClient

from silkscan.api.app import create_app
from silkscan.api.config import APIConfig
from silkscan.data.records import split_record
from silkscan.inference.bundle import ModelBundle
from silkscan.inference.predict import Submission, scan
from silkscan.stage2 import Stage2Model
from silkscan.stage2.train import train_stage2


def _strip(v: dict) -> dict:
    return {k: x for k, x in v.items() if k != "timing_ms"}


def test_api_returns_stage2_classification_like_core(trained_run, tmp_path):
    run, cfg = trained_run
    stage2_dir = train_stage2(run, precision=0.5, family_top=8, family_min=5, min_pos=5, rounds=30, min_threshold=0.0)
    serving = tmp_path / "serving.yaml"
    serving.write_text(yaml.safe_dump({"run": str(run), "checks": [], "explain_top": 0, "max_file_mb": 1,
                                       "stage2": str(stage2_dir)}))
    rows = [json.loads(x) for x in (Path(cfg.data.root) / "synthetic_Win64_test.jsonl").read_text().splitlines()]
    rows = [r for r in rows if r["label"] == 1][:30]

    bundle = ModelBundle(run)
    expected = scan(bundle, bundle.backend(), [Submission(None, split_record(r)) for r in rows],
                    stage2=Stage2Model(stage2_dir))
    assert any(v["classification"] for v in expected)

    previous = os.environ.get("SILKSCAN_API_KEYS")
    os.environ["SILKSCAN_API_KEYS"] = "k"
    try:
        app = create_app(APIConfig(serving=str(serving), workers=1, store_url=f"sqlite:///{tmp_path / 'v.db'}",
                                   batch_window_ms=1, rate_limit_per_min=10000))
        with TestClient(app, headers={"Authorization": "Bearer k"}) as client:
            assert client.get("/v1/model").json()["stage2"] == Stage2Model(stage2_dir).id
            body = "\n".join(json.dumps(r) for r in rows).encode()
            got = client.post("/v1/scan/features", content=body,
                              headers={"Content-Type": "application/x-ndjson"}).json()
    finally:
        if previous is None:
            os.environ.pop("SILKSCAN_API_KEYS", None)
        else:
            os.environ["SILKSCAN_API_KEYS"] = previous
    got = got if isinstance(got, list) else got.get("verdicts", got)
    assert [_strip(v) for v in got] == [_strip(v) for v in expected]
