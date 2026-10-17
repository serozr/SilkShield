"""Feature extractor contract and the FeatureBlock output type."""

from __future__ import annotations

import enum
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar, Iterable, Mapping, Sequence

import numpy as np
import scipy.sparse as sp

from silkscan.errors import ExtractionError
from silkscan.utils.hashing import sha256_json


class Status(enum.IntEnum):
    """Per-record extraction outcome. Never collapsed into a zero vector."""

    OK = 0              # analysis succeeded (finding nothing, e.g. no imports, is still OK)
    MISSING_INPUT = 1   # a required input field is absent from the record
    PARSE_ERROR = 2     # the field exists but could not be interpreted
    NOT_APPLICABLE = 3  # the feature does not apply to this file (e.g. not parseable as PE)


NON_OK_STATUSES = (Status.MISSING_INPUT, Status.PARSE_ERROR, Status.NOT_APPLICABLE)
MAX_MESSAGES = 20
_NAME_TOKEN = re.compile(r"[^A-Za-z0-9_.\-/]")


def sanitize_token(text: str) -> str:
    """Make a string safe inside a LightGBM feature name (no spaces, quotes, ':', brackets, commas)."""
    return _NAME_TOKEN.sub("_", text.strip())


@dataclass
class Extraction:
    values: Sequence[float] | np.ndarray | None
    status: Status = Status.OK
    message: str | None = None

    @classmethod
    def missing(cls, message: str) -> "Extraction":
        return cls(None, Status.MISSING_INPUT, message)

    @classmethod
    def parse_error(cls, message: str) -> "Extraction":
        return cls(None, Status.PARSE_ERROR, message)

    @classmethod
    def not_applicable(cls, message: str) -> "Extraction":
        return cls(None, Status.NOT_APPLICABLE, message)


@dataclass
class FeatureBlock:
    """Output of one feature group for a set of records.

    Rows whose status is not OK hold NaN; the pipeline applies the group's
    missing-data policy when blocks are assembled.
    """

    ids: np.ndarray                      # bytes ('S') record ids
    matrix: np.ndarray | sp.csr_matrix   # (n_records, n_features), float32
    feature_names: tuple[str, ...]
    group: str
    version: str
    status: np.ndarray                   # uint8 Status per record
    messages: list[tuple[str, str]] = field(default_factory=list)  # (id, message) samples

    def __post_init__(self) -> None:
        self.feature_names = tuple(self.feature_names)
        n = len(self.ids)
        if self.matrix.ndim != 2:
            raise ExtractionError(f"Group `{self.group}` produced a {self.matrix.ndim}-D matrix; expected 2-D.")
        if self.matrix.shape != (n, len(self.feature_names)):
            raise ExtractionError(
                f"Group `{self.group}`: matrix shape {self.matrix.shape} does not match "
                f"{n} ids x {len(self.feature_names)} feature names."
            )
        if len(self.status) != n:
            raise ExtractionError(f"Group `{self.group}`: {len(self.status)} statuses for {n} ids.")
        check_feature_names(self.group, self.feature_names)

    @property
    def is_sparse(self) -> bool:
        return sp.issparse(self.matrix)

    def status_counts(self) -> dict[str, int]:
        return {s.name: int((self.status == s).sum()) for s in Status if (self.status == s).any()}


def check_feature_names(group: str, names: Sequence[str]) -> None:
    prefix = f"{group}."
    bad = [n for n in names if not n.startswith(prefix)]
    if bad:
        raise ExtractionError(f"Group `{group}`: feature names must start with `{prefix}`, got {bad[:3]}.")
    seen: set[str] = set()
    dupes = sorted({n for n in names if n in seen or seen.add(n)})
    if dupes:
        raise ExtractionError(f"Group `{group}`: duplicated feature names {dupes[:5]}.")


class FeatureExtractor(ABC):
    """Contract every feature group implements.

    Subclasses set the class attributes, implement `get_feature_names` and
    `extract_one`, and (if stateful) `fit`, `get_state` and `set_state`.
    Register the class in `silkscan.features.groups` and enable it in YAML; the
    training and evaluation code needs no change.
    """

    name: ClassVar[str]
    version: ClassVar[str]
    required_inputs: ClassVar[tuple[str, ...]]
    is_stateful: ClassVar[bool] = False
    default_missing_policy: ClassVar[str] = "error"
    # Safe to run in worker processes (stateless, picklable params).
    parallel_safe: ClassVar[bool] = True

    def __init__(self, **params: Any) -> None:
        self.params = dict(params)
        self._fitted = not self.is_stateful

    # -- identity used in schemas and cache keys ---------------------------
    def config_dict(self) -> dict[str, Any]:
        return dict(self.params)

    def tool_versions(self) -> dict[str, str]:
        """Versions/hashes of external tools or data files the output depends on."""
        return {}

    def state_fingerprint(self) -> str:
        return sha256_json(self.get_state())

    def categorical_feature_names(self) -> list[str]:
        return []

    def display_names(self) -> dict[str, str]:
        """Optional human-readable labels for columns (explanations only; never part of the schema)."""
        return {}

    # -- learned state -----------------------------------------------------
    def fit(self, views: Iterable[Mapping[str, Any]]) -> None:
        """Learn vocabularies/statistics. Called only with training records."""
        self._fitted = True

    def get_state(self) -> dict[str, Any]:
        return {}

    def set_state(self, state: Mapping[str, Any]) -> None:
        self._fitted = True

    @property
    def fitted(self) -> bool:
        return self._fitted

    # -- extraction ----------------------------------------------------------
    @abstractmethod
    def get_feature_names(self) -> list[str]:
        """Ordered, group-prefixed names (e.g. `import_semantics.network_count`)."""

    @abstractmethod
    def extract_one(self, view: Mapping[str, Any]) -> Extraction:
        """Extract one record. `view` contains only `required_inputs` keys that exist."""

    def transform(self, ids: np.ndarray, views: Sequence[Mapping[str, Any]]) -> FeatureBlock:
        if not self._fitted:
            raise ExtractionError(f"Group `{self.name}` is stateful and must be fitted on train data first.")
        names = self.get_feature_names()
        X = np.full((len(views), len(names)), np.nan, dtype=np.float32)
        status = np.zeros(len(views), dtype=np.uint8)
        messages: list[tuple[str, str]] = []
        for i, view in enumerate(views):
            try:
                ex = self.extract_one(view)
            except (KeyError, TypeError, ValueError, AttributeError, IndexError, ZeroDivisionError) as e:
                ex = Extraction.parse_error(f"{type(e).__name__}: {e}")
            if ex.status == Status.OK:
                row = np.asarray(ex.values, dtype=np.float32)
                if row.shape != (len(names),):
                    raise ExtractionError(
                        f"Group `{self.name}` returned {row.shape} values for {len(names)} feature names."
                    )
                X[i] = row
            else:
                status[i] = ex.status
                if len(messages) < MAX_MESSAGES:
                    messages.append((_decode(ids[i]), ex.message or ex.status.name))
        return FeatureBlock(ids, X, tuple(names), self.name, self.version, status, messages)

    def prefixed(self, local_names: Iterable[str]) -> list[str]:
        return [f"{self.name}.{n}" for n in local_names]


def _decode(rid: Any) -> str:
    return rid.decode() if isinstance(rid, bytes) else str(rid)


def present(view: Mapping[str, Any], key: str) -> bool:
    return key in view and view[key] is not None
