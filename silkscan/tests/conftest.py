from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from silkscan.config import config_from_dict
from silkscan.synthetic import make_records, write_fixture  # noqa: F401  (re-exported for tests)

ROOT = Path(__file__).resolve().parents[1]


def demo_dict(tmp: Path) -> dict[str, Any]:
    with open(ROOT / "tests" / "data" / "demo.yaml", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    raw["work_dir"] = str(tmp / "work")
    raw["runs_dir"] = str(tmp / "runs")
    raw["data"]["root"] = str(tmp / "data")
    raw["features"]["cache_dir"] = str(tmp / "cache")
    raw["model"]["num_boost_round"] = 20
    return raw


@pytest.fixture
def cfg_dict(tmp_path: Path) -> dict[str, Any]:
    raw = demo_dict(tmp_path)
    write_fixture(Path(raw["data"]["root"]), n_train=400, n_test=120, n_challenge=24, seed=1)
    return raw


@pytest.fixture
def cfg(cfg_dict: dict[str, Any]):
    return config_from_dict(cfg_dict)


@pytest.fixture(scope="session")
def trained_run(tmp_path_factory: pytest.TempPathFactory):
    """One trained demo run shared by tests that only read it."""
    from silkscan.workflow import build_features, make_manifest, train

    tmp = tmp_path_factory.mktemp("trained")
    raw = demo_dict(tmp)
    write_fixture(Path(raw["data"]["root"]), n_train=400, n_test=120, n_challenge=24, seed=2)
    c = config_from_dict(raw)
    make_manifest(c)
    build_features(c)
    return train(c), c
