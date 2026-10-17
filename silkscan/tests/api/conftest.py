from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest
import yaml

pytest.importorskip("starlette")
pytest.importorskip("httpx")
pytest.importorskip("python_multipart")

from starlette.testclient import TestClient
from silkscan.api.app import create_app
from silkscan.api.config import APIConfig

ROOT = Path(__file__).resolve().parents[2]
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.fixture(scope="module")
def api_setup(trained_run, tmp_path_factory):
    run, cfg = trained_run
    root = tmp_path_factory.mktemp("api")
    serving = root / "serving.yaml"
    checks = [{"name": "hash_list"}]
    if importlib.util.find_spec("yara"):
        checks.append({"name": "yara", "params": {"rules_dir": str(ROOT / "rules/yara"), "allow_force": True}})
    serving.write_text(yaml.safe_dump({"run": str(run), "checks": checks, "explain_top": 0, "max_file_mb": 1}))
    rows = [json.loads(line) for line in (Path(cfg.data.root) / "synthetic_Win64_test.jsonl").read_text().splitlines()]
    return root, serving, rows


@pytest.fixture(scope="module")
def api_client(api_setup):
    root, serving, _ = api_setup
    previous = os.environ.get("SILKSCAN_API_KEYS")
    os.environ["SILKSCAN_API_KEYS"] = "test-secret,second-key"
    config = APIConfig(serving=str(serving), workers=2, store_url=f"sqlite:///{root / 'verdicts.db'}",
                       heartbeat_s=0.02, batch_window_ms=1, rate_limit_per_min=10000,
                       sync_timeout_s=60)  # slow machines (e.g. emulated s390x) still answer synchronously
    app = create_app(config)
    try:
        with TestClient(app, headers={"Authorization": "Bearer test-secret"}) as client:
            yield client
    finally:
        if previous is None:
            os.environ.pop("SILKSCAN_API_KEYS", None)
        else:
            os.environ["SILKSCAN_API_KEYS"] = previous


@pytest.fixture
def pe_bytes():
    try:
        from silkscan.features.groups.ember_v3 import load_thrember_features
        load_thrember_features()
    except Exception:
        pytest.skip("thrember not installed")
    import pip
    path = Path(pip.__file__).parent / "_vendor/distlib/w64.exe"
    if not path.is_file():
        pytest.skip("pip's clean PE fixture is unavailable")
    return path.read_bytes()
