"""The whole CLI flow on the synthetic fixture."""

import json
from pathlib import Path

import yaml

from silkscan.cli.main import main


def test_cli_end_to_end(cfg_dict, tmp_path, capsys):
    cfg_path = tmp_path / "cfg.yaml"
    cfg_path.write_text(yaml.safe_dump(cfg_dict))
    c = ["-c", str(cfg_path)]

    assert main(["manifest", *c]) == 0
    assert main(["manifest", *c]) == 2  # refuses to overwrite without --force
    capsys.readouterr()
    assert main(["features", *c]) == 0
    capsys.readouterr()
    assert main(["train", *c]) == 0
    run = Path(json.loads(capsys.readouterr().out)["run_dir"])
    for f in ("model.txt", "feature_schema.json", "extractor_states.json", "threshold.json", "config.resolved.yaml",
              "runtime.json", "metrics_validation.json", "training.json", "predictions_validation.npz", "manifest.json"):
        assert (run / f).exists(), f

    assert main(["evaluate", "--run", str(run), "--json"]) == 0
    ev = json.loads(capsys.readouterr().out)
    assert ev["challenge"]["roc_auc"] is None and ev["challenge"]["fpr"] is None
    assert ev["test"]["roc_auc"] is not None

    data = Path(cfg_dict["data"]["root"]) / "synthetic_Win64_test.jsonl"
    assert main(["predict", "--run", str(run), "--jsonl", str(data), "--limit", "3", "--explain", "2"]) == 0
    lines = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert len(lines) == 3 and all(p["decision"] in ("malicious", "clean", "inconclusive") for p in lines)
    assert "by_group" in lines[0]["explanation"]


def test_run_directory_stores_data_root_placeholder(cfg_dict, tmp_path, monkeypatch):
    """Runs keep `${VAR}` instead of the expanded data path; bundles load without the variable set."""
    from silkscan.config import config_from_dict
    from silkscan.inference.bundle import ModelBundle
    from silkscan.workflow import evaluate, make_manifest, train

    monkeypatch.setenv("SILKSCAN_TEST_DATA", cfg_dict["data"]["root"])
    cfg_dict["data"]["root"] = "${SILKSCAN_TEST_DATA}"
    cfg = config_from_dict(cfg_dict)
    make_manifest(cfg)
    run = train(cfg)
    text = (run / "config.resolved.yaml").read_text()
    assert "root: ${SILKSCAN_TEST_DATA}" in text and str(tmp_path) not in text.split("root:")[1].splitlines()[0]

    monkeypatch.delenv("SILKSCAN_TEST_DATA")
    bundle = ModelBundle(run)                       # serving: no data path needed
    assert bundle.config.data.root == "${SILKSCAN_TEST_DATA}"
    import pytest
    from silkscan.errors import ConfigError
    with pytest.raises(ConfigError, match="environment variable"):
        evaluate(run, ["test"])
    monkeypatch.setenv("SILKSCAN_TEST_DATA", cfg_dict["data"]["root_template"] if "root_template" in cfg_dict["data"]
                       else str(tmp_path / "data"))
    assert evaluate(run, ["test"]).exists()
