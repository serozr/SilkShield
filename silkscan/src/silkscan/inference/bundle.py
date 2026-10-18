"""Model bundle = a run directory. Loads without any training data."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import scipy.sparse as sp
import yaml

from silkscan.config import Config, config_from_dict
from silkscan.errors import SilkScanError, SchemaMismatchError
from silkscan.features.pipeline import FeaturePipeline
from silkscan.features.schema import FeatureSchema
from silkscan.inference.backends import ScoringBackend, make_backend
from silkscan.utils.io import read_json, write_json

MODEL_FILE = "model.txt"
SCHEMA_FILE = "feature_schema.json"
STATES_FILE = "extractor_states.json"
THRESHOLD_FILE = "threshold.json"
CONFIG_FILE = "config.resolved.yaml"


def column_flag(X: Any, j: int) -> np.ndarray:
    col = X[:, j].toarray().ravel() if sp.issparse(X) else np.asarray(X[:, j])
    return np.nan_to_num(col) > 0


class ModelBundle:
    def __init__(self, run_dir: Path):
        self.run_dir = Path(run_dir)
        for f in (MODEL_FILE, SCHEMA_FILE, STATES_FILE, THRESHOLD_FILE, CONFIG_FILE):
            if not (self.run_dir / f).exists():
                raise SilkScanError(f"{self.run_dir} is not a complete model bundle (missing {f}).")
        with open(self.run_dir / CONFIG_FILE, encoding="utf-8") as fh:
            self.config: Config = config_from_dict(yaml.safe_load(fh), expand_env=False)
        self.schema = FeatureSchema.from_dict(read_json(self.run_dir / SCHEMA_FILE))
        self.states: dict[str, Any] = read_json(self.run_dir / STATES_FILE)
        self.thresholds: dict[str, Any] = read_json(self.run_dir / THRESHOLD_FILE)

    @property
    def model_path(self) -> Path:
        return self.run_dir / MODEL_FILE

    def pipeline(self) -> FeaturePipeline:
        """Rebuild the training-time pipeline and refuse to continue on any schema difference."""
        pipe = FeaturePipeline(self.config.features.groups)
        pipe.set_states(self.states)
        self.schema.require_match(pipe.schema())
        return pipe

    def backend(self, name: str = "lightgbm", num_threads: int = 0) -> ScoringBackend:
        b = make_backend(name, self.model_path, num_threads)
        if name == "lightgbm":
            names = list(b.booster.feature_name())
            if names != self.schema.feature_names:
                raise SchemaMismatchError(f"model.txt has {len(names)} features that do not match feature_schema.json.")
        return b

    def threshold(self, backend: str) -> float:
        if backend not in self.thresholds:
            raise SilkScanError(
                f"No decision threshold for backend `{backend}` in this bundle. Scores of a different backend may "
                f"differ slightly; select one on validation data: silkscan threshold --run {self.run_dir} "
                f"--backend {backend}"
            )
        return float(self.thresholds[backend]["threshold"])

    def policy(self, backend: str) -> dict[str, Any] | None:
        return self.thresholds.get(backend, {}).get("policy")

    def row_thresholds(self, backend: str, feature_names: list[str], X: Any) -> np.ndarray:
        """Decision threshold for every row: the global one, or per file kind if a policy is active."""
        from silkscan.evaluation.threshold import row_thresholds

        policy = self.policy(backend)
        flags = None
        if policy and policy["mode"] != "global":
            if policy["column"] not in feature_names:
                raise SchemaMismatchError(f"Threshold policy needs column {policy['column']}, not in the features.")
            flags = column_flag(X, feature_names.index(policy["column"]))
        return row_thresholds(policy, self.threshold(backend), flags, X.shape[0])

    def review(self, backend: str) -> dict[str, Any] | None:
        return self.thresholds.get(backend, {}).get("review")

    def row_review_thresholds(self, backend: str, feature_names: list[str], X: Any) -> np.ndarray | None:
        """Lower (suspicious-zone) threshold per row, or None if no review zone is configured."""
        from silkscan.evaluation.threshold import row_thresholds

        rev = self.review(backend)
        if not rev:
            return None
        flags = None
        if rev["mode"] != "global":
            flags = column_flag(X, feature_names.index(rev["column"]))
        return row_thresholds(rev, None, flags, X.shape[0])

    def set_review(self, backend: str, review: dict[str, Any], force: bool) -> None:
        entry = self.thresholds.get(backend)
        if entry is None:
            raise SilkScanError(f"Select a threshold for `{backend}` first.")
        if entry.get("review") and not force:
            raise SilkScanError(f"Backend `{backend}` already has a review zone; use --force to replace it.")
        entry["review"] = review
        write_json(self.run_dir / THRESHOLD_FILE, self.thresholds)

    def set_policy(self, backend: str, policy: dict[str, Any], comparison: dict[str, Any], force: bool) -> None:
        entry = self.thresholds.get(backend)
        if entry is None:
            raise SilkScanError(f"Select a global threshold for `{backend}` first (silkscan threshold --backend {backend}).")
        if entry.get("policy") and not force:
            raise SilkScanError(f"Backend `{backend}` already has a threshold policy; use --force to replace it.")
        entry["policy"] = policy
        entry["policy_comparison_on_validation"] = comparison
        write_json(self.run_dir / THRESHOLD_FILE, self.thresholds)

    def add_threshold(self, backend: str, selection: dict[str, Any], force: bool = False) -> None:
        if backend in self.thresholds and not force:
            raise SilkScanError(f"Bundle already has a threshold for `{backend}`; use --force to replace it.")
        self.thresholds[backend] = selection
        write_json(self.run_dir / THRESHOLD_FILE, self.thresholds)
