"""LightGBM adapter.

`train_lightgbm` takes arrays and a param dict and returns a booster, so a
hyperparameter search (e.g. Optuna) can wrap it later without touching the
data or feature code.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

import numpy as np
import scipy.sparse as sp

log = logging.getLogger(__name__)

# EMBER2024 benchmark config (examples/lgbm_config.json), minus task/IO keys.
DEFAULT_PARAMS: dict[str, Any] = {
    "objective": "binary",
    "boosting": "gbdt",
    "learning_rate": 0.1,
    "num_leaves": 64,
    "max_depth": -1,
    "min_data_in_leaf": 100,
    "min_sum_hessian_in_leaf": 0.001,
    "bagging_fraction": 0.9,
    "bagging_freq": 1,
    "feature_fraction": 0.9,
    "feature_fraction_bynode": 0.9,
    "lambda_l1": 0.0,
    "lambda_l2": 1.0,
    "is_unbalance": True,
    "metric": ["auc", "binary_logloss"],
    "first_metric_only": True,
    "deterministic": True,
    "force_col_wise": True,
    "num_threads": 0,
    "verbosity": -1,
}


@dataclass
class TrainResult:
    booster: Any
    best_iteration: int
    num_trees: int
    train_seconds: float
    params: dict[str, Any]


def lightgbm():
    import lightgbm as lgb

    # Route LightGBM's console output through logging so stdout stays machine-readable JSON.
    lgb.register_logger(logging.getLogger("lightgbm"))
    return lgb


def resolve_params(params: dict[str, Any], seed: int) -> dict[str, Any]:
    p = {**DEFAULT_PARAMS, **params}
    for k in ("seed", "bagging_seed", "feature_fraction_seed", "data_random_seed"):
        p.setdefault(k, seed)
    return p


def train_lightgbm(
    X_train: np.ndarray | sp.csr_matrix,
    y_train: np.ndarray,
    X_val: np.ndarray | sp.csr_matrix | None,
    y_val: np.ndarray | None,
    *,
    feature_names: Sequence[str],
    categorical: Sequence[str],
    params: dict[str, Any],
    num_boost_round: int,
    early_stopping_rounds: int | None,
) -> TrainResult:
    lgb = lightgbm()
    cat = list(categorical) or "auto"
    dtrain = lgb.Dataset(X_train, label=y_train, feature_name=list(feature_names), categorical_feature=cat,
                         free_raw_data=True)
    valid_sets, callbacks = [], [lgb.log_evaluation(period=50)]
    if X_val is not None:
        valid_sets = [lgb.Dataset(X_val, label=y_val, reference=dtrain)]
        if early_stopping_rounds:
            callbacks.append(lgb.early_stopping(early_stopping_rounds, first_metric_only=True, verbose=True))
    t0 = time.perf_counter()
    booster = lgb.train(params, dtrain, num_boost_round=num_boost_round, valid_sets=valid_sets,
                        valid_names=["validation"] if valid_sets else None, callbacks=callbacks)
    seconds = time.perf_counter() - t0
    best = booster.best_iteration or booster.current_iteration()
    log.info("Trained %d rounds (best iteration %d) in %.1fs", booster.current_iteration(), best, seconds)
    return TrainResult(booster, int(best), int(booster.current_iteration()), seconds, params)


def save_model(booster: Any, path: Path, best_iteration: int) -> None:
    """Text format only: portable across byte orders, unlike pickle."""
    booster.save_model(str(path), num_iteration=best_iteration)


def load_model(path: Path) -> Any:
    return lightgbm().Booster(model_file=str(path))
