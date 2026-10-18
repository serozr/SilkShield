"""Scoring backends: LightGBM (default) and IBM Snap ML (optional).

The decision threshold belongs to a backend: if a backend's scores differ
from LightGBM's (e.g. reduced-precision arithmetic on the Z accelerator), its
threshold is selected separately on validation scores (`silkscan threshold`).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

import numpy as np
import scipy.sparse as sp

from silkscan.errors import DependencyError
from silkscan.utils.env import has_nnpa
from silkscan.utils.io import to_native

BACKENDS = ("lightgbm", "snapml", "snapml-nnpa")


class ScoringBackend(Protocol):
    name: str

    def predict(self, X: np.ndarray | sp.csr_matrix) -> np.ndarray: ...


class LightGBMBackend:
    name = "lightgbm"

    def __init__(self, model_path: Path, num_threads: int = 0):
        from silkscan.models.lgbm import load_model

        self.booster = load_model(model_path)
        self.num_threads = num_threads

    def predict(self, X: np.ndarray | sp.csr_matrix) -> np.ndarray:
        X = X if sp.issparse(X) else to_native(np.asarray(X, dtype=np.float32))
        return np.asarray(self.booster.predict(X, num_threads=self.num_threads), dtype=np.float64)

    def contributions(self, X: np.ndarray) -> np.ndarray:
        """Per-feature SHAP-style contributions (log-odds); last column is the bias."""
        X = X.toarray() if sp.issparse(X) else X
        return np.asarray(self.booster.predict(to_native(np.asarray(X, dtype=np.float32)), pred_contrib=True))


class SnapMLBackend:
    """IBM Snap ML tree-ensemble inference; `accelerator=True` targets the Telum
    on-chip AI accelerator (NNPA).

    Uses `import_model(path, input_type="lightgbm", tree_format="zdnn_tensors")`; confirm the
    signature against the installed Snap ML version.
    """

    def __init__(self, model_path: Path, accelerator: bool = False, n_jobs: int = 0):
        try:
            import snapml
        except ImportError:
            raise DependencyError("Backend `snapml` needs IBM Snap ML: pip install snapml.")
        if accelerator and not has_nnpa():
            raise DependencyError("Backend `snapml-nnpa` needs the NNPA facility (IBM z16 or later); not found "
                                  "in /proc/cpuinfo.")
        self.name = "snapml-nnpa" if accelerator else "snapml"
        self.model = snapml.BoostingMachineClassifier()
        kwargs: dict[str, Any] = {"input_type": "lightgbm"}
        if accelerator:
            kwargs["tree_format"] = "zdnn_tensors"
        try:
            self.model.import_model(str(model_path), **kwargs)
        except TypeError as e:
            raise DependencyError(f"This Snap ML version does not accept import_model({kwargs}): {e}") from None
        self.n_jobs = n_jobs or None

    def predict(self, X: np.ndarray | sp.csr_matrix) -> np.ndarray:
        X = X.toarray() if sp.issparse(X) else X
        X = np.ascontiguousarray(to_native(np.asarray(X, dtype=np.float32)))
        kwargs = {"n_jobs": self.n_jobs} if self.n_jobs else {}
        proba = self.model.predict_proba(X, **kwargs)
        return np.asarray(proba[:, 1], dtype=np.float64)


def make_backend(name: str, model_path: Path, num_threads: int = 0) -> ScoringBackend:
    if name == "lightgbm":
        return LightGBMBackend(model_path, num_threads)
    if name == "snapml":
        return SnapMLBackend(model_path, accelerator=False, n_jobs=num_threads)
    if name == "snapml-nnpa":
        return SnapMLBackend(model_path, accelerator=True, n_jobs=num_threads)
    raise DependencyError(f"Unknown backend `{name}`; choose one of {BACKENDS}.")
