"""Research commands, threshold policies, JSONL evaluation and reports on the synthetic fixture."""

import json
from pathlib import Path

import numpy as np
import pytest
import yaml

from silkscan.cli.main import main
from silkscan.errors import DataValidationError
from silkscan.evaluation.metrics import bootstrap_ci
from silkscan.evaluation.threshold import threshold_stability


def test_bootstrap_intervals_contain_point_estimates():
    rng = np.random.default_rng(0)
    y = (rng.random(2000) < 0.5).astype(int)
    s = rng.random(2000) + 0.5 * y
    ci = bootstrap_ci(y, s, 0.9, 100, 0)
    rec, fpr = (s[y == 1] >= 0.9).mean(), (s[y == 0] >= 0.9).mean()
    assert ci["recall"][0] <= rec <= ci["recall"][1]
    assert ci["fpr"][0] <= fpr <= ci["fpr"][1]
    only_malware = bootstrap_ci(np.ones(50, int), rng.random(50), 0.5, 20, 0)
    assert only_malware["fpr"] is None and only_malware["roc_auc"] is None
    st = threshold_stability(rng.random(5000), 0.01, 50, 0)
    assert st["p2.5"] <= st["p50"] <= st["p97.5"]


def test_experiment_commands(cfg_dict, tmp_path, capsys):
    cfg_path = tmp_path / "cfg.yaml"
    cfg_dict["evaluation"]["bootstrap"] = 20
    cfg_dict["evaluation"]["subgroup_flags"] = {"has_network": "import_semantics.network_count",
                                                "bogus": "no.such_column"}
    cfg_path.write_text(yaml.safe_dump(cfg_dict))
    c = ["-c", str(cfg_path)]

    assert main(["manifest", *c]) == 0
    capsys.readouterr()
    assert main(["train", *c]) == 0
    run = Path(json.loads(capsys.readouterr().out)["run_dir"])
    th = json.loads((run / "threshold.json").read_text())["lightgbm"]
    assert th["bootstrap_threshold"]["n_boot"] == 20

    assert main(["evaluate", "--run", str(run), "--splits", "test", "--json"]) == 0
    capsys.readouterr()
    ev = sorted((run / "evaluations").iterdir())[-1]
    test = json.loads((ev / "test.json").read_text())
    assert "ci95" in test and set(test["threshold_stability"]) == {"p2.5", "p50", "p97.5"}
    sg = test["subgroups"]
    assert set(sg["has_network"]) == {"has_network=yes", "has_network=no"} and "error" in sg["bogus"]
    assert sum(v["n"] for v in sg["has_network"].values()) == test["n"]

    assert main(["ablation", *c, "--variants", "section_summary", "section_summary,import_semantics",
                 "--seeds", "0", "1", "--test"]) == 0
    table = capsys.readouterr().out
    assert "section_summary+import_semantics" in table and "±" in table

    assert main(["explain-report", "--run", str(run), "--n", "100"]) == 0
    rep = json.loads(Path(capsys.readouterr().out.strip()).read_text())
    assert set(rep["splits"]) == {"test", "challenge"}
    assert "challenge_vs_test_malware" in rep
    assert "TP" in rep["splits"]["test"]["by_outcome"]


def test_unmatched_patterns_list_available_files(cfg_dict):
    from silkscan.config import config_from_dict
    from silkscan.data.manifest import build_manifest

    cfg_dict["data"]["splits"]["train"] = ["*does_not_exist*.jsonl"]
    with pytest.raises(DataValidationError, match="synthetic_Win64_train.jsonl"):
        build_manifest(config_from_dict(cfg_dict).data)


def test_threshold_policy_jsonl_evaluation_and_report(cfg_dict, tmp_path, capsys):
    cfg_dict["evaluation"]["bootstrap"] = 10
    cfg_path = tmp_path / "cfg.yaml"
    cfg_path.write_text(yaml.safe_dump(cfg_dict))
    c = ["-c", str(cfg_path)]
    assert main(["manifest", *c]) == 0 and main(["train", *c]) == 0
    capsys.readouterr()
    run = sorted(Path(cfg_dict["runs_dir"]).iterdir())[-1]

    flag = ["--flag-name", "net", "--flag-column", "import_semantics.network_count"]
    assert main(["threshold", "--run", str(run), "--policy", "per_group", *flag]) == 0
    res = json.loads(capsys.readouterr().out)
    comp = res["comparison_on_validation"]
    target = cfg_dict["evaluation"]["target_fpr"]
    for g in ("net=yes", "net=no"):  # per-group thresholds meet the target in each group on validation
        assert comp["per_group"][g]["fpr"] <= target + 1e-12
    strict = comp["strictest"]["thresholds"]
    assert strict["yes"] == strict["no"] == max(comp["per_group"]["thresholds"].values())
    assert main(["threshold", "--run", str(run), "--policy", "auto", *flag]) == 2  # needs --force
    assert main(["threshold", "--run", str(run), "--policy", "auto", "--force", *flag]) == 0
    capsys.readouterr()

    data = Path(cfg_dict["data"]["root"]) / "synthetic_Win64_test.jsonl"
    assert main(["evaluate", "--run", str(run), "--jsonl", str(data), "--name", "mine"]) == 0
    text = capsys.readouterr().out
    assert "SYNTHETIC DATA" in text and "## mine" in text and "Policy:" in text
    ev = sorted((run / "evaluations").iterdir())[-1]
    r = json.loads((ev / "mine.json").read_text())
    assert r["source"]["records_read"] == len(data.read_text().splitlines())
    t_yes, t_no = r["threshold_policy"]["thresholds"].values() if "thresholds" in r["threshold_policy"] else (0, 0)
    if t_yes != t_no:  # per_group with distinct thresholds
        assert r["at_threshold"]["threshold"] == "per-record (threshold policy)"
    else:              # global / strictest: one threshold for every record
        assert isinstance(r["at_threshold"]["threshold"], float)

    out = tmp_path / "rapor.md"
    assert main(["report", "--run", str(run), "--out", str(out)]) == 0
    assert "Actual malicious" in out.read_text()

    preds = [json.loads(x) for x in (main(["predict", "--run", str(run), "--jsonl", str(data), "--limit", "5"]) == 0
                                     and capsys.readouterr().out.splitlines())]
    assert all("threshold_policy" in p for p in preds)
