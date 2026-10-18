"""Feature pipeline shared by training, evaluation and prediction.

- fits stateful groups on train records only;
- computes all cache-missing groups in a single streaming pass;
- aligns groups by record id (never by row number);
- applies each group's missing-data policy;
- assembles one native-byte-order float32 matrix with deterministic columns.
"""

from __future__ import annotations

import contextlib
import logging
import multiprocessing
from dataclasses import dataclass, field
from typing import Any, Iterator, Mapping, Protocol, Sequence

import numpy as np
import scipy.sparse as sp

from silkscan.config import GroupConfig
from silkscan.data.manifest import Manifest
from silkscan.data.records import Record, input_view
from silkscan.errors import ExtractionError
from silkscan.features.base import NON_OK_STATUSES, FeatureBlock, FeatureExtractor, Status
from silkscan.features.cache import FeatureCache, cache_key, state_key
from silkscan.features.registry import create_extractor
from silkscan.features.schema import FeatureSchema, GroupSchema
from silkscan.utils.hashing import sha256_json
from silkscan.utils.io import open_le_memmap, save_array, to_native

log = logging.getLogger(__name__)

_COPY_ROWS = 65536


# ---------------------------------------------------------------------------
# record sources
# ---------------------------------------------------------------------------
class RecordSource(Protocol):
    name: str
    ids: np.ndarray
    fingerprint: str

    def iter_chunks(self) -> Iterator[list[Record]]: ...


class ManifestSource:
    def __init__(self, manifest: Manifest, split: str, id_field: str, chunk_size: int):
        s = manifest.split(split)
        self.name = split
        self.ids = s.ids
        self.labels = s.labels
        self.dates = s.dates
        self.fingerprint = manifest.split_fingerprints[split]
        self._manifest, self._id_field, self._chunk = manifest, id_field, chunk_size

    def iter_chunks(self) -> Iterator[list[Record]]:
        return self._manifest.iter_records(self.name, self._id_field, self._chunk)


class MemorySource:
    def __init__(self, records: Sequence[Record], name: str = "memory", chunk_size: int = 2048):
        self.name = name
        self.records = list(records)
        self.ids = np.array([r.id.encode() for r in self.records], dtype="S") if self.records else np.array([], "S64")
        self.fingerprint = sha256_json([[r.id, dict(r.inputs)] for r in self.records])
        self._chunk = chunk_size

    def iter_chunks(self) -> Iterator[list[Record]]:
        for i in range(0, len(self.records), self._chunk):
            yield self.records[i:i + self._chunk]


# ---------------------------------------------------------------------------
# assembled output
# ---------------------------------------------------------------------------
@dataclass
class AssembledFeatures:
    ids: np.ndarray
    X: np.ndarray | sp.csr_matrix
    feature_names: list[str]
    categorical: list[str]
    status: dict[str, np.ndarray]
    group_slices: dict[str, slice]
    # Rows where a group with policy `error` failed (only possible with strict=False).
    failed: np.ndarray = field(default_factory=lambda: np.zeros(0, dtype=bool))

    def record_status(self, i: int) -> dict[str, str]:
        return {g: Status(int(s[i])).name for g, s in self.status.items()}


@dataclass
class GroupSpec:
    extractor: FeatureExtractor
    policy: str

    @property
    def name(self) -> str:
        return self.extractor.name

    def output_names(self) -> list[str]:
        names = list(self.extractor.get_feature_names())
        if self.policy == "impute_with_indicator":
            names += indicator_names(self.name)
        return names

    def categorical(self) -> list[str]:
        return self.extractor.categorical_feature_names()


def indicator_names(group: str) -> list[str]:
    return [f"{group}.__status_{s.name.lower()}" for s in NON_OK_STATUSES]


# ---------------------------------------------------------------------------
# alignment
# ---------------------------------------------------------------------------
def align_index(group: str, block_ids: np.ndarray, ref_ids: np.ndarray) -> np.ndarray | None:
    """Row index into the block for each reference id; None if already aligned."""
    if len(block_ids) == len(ref_ids) and np.array_equal(block_ids, ref_ids):
        return None
    uniq, counts = np.unique(block_ids, return_counts=True)
    if (counts > 1).any():
        raise ExtractionError(f"Group `{group}` has duplicated ids, e.g. {_ex(uniq[counts > 1])}.")
    if len(block_ids) == 0:
        raise ExtractionError(f"Group `{group}` produced no rows for {len(ref_ids)} records.")
    sorter = np.argsort(block_ids, kind="stable")
    pos = np.clip(np.searchsorted(block_ids, ref_ids, sorter=sorter), 0, len(block_ids) - 1)
    idx = sorter[pos]
    missing = block_ids[idx] != ref_ids
    if missing.any():
        raise ExtractionError(
            f"Group `{group}` is missing {int(missing.sum())} of {len(ref_ids)} ids, e.g. {_ex(ref_ids[missing])}."
        )
    if len(block_ids) != len(ref_ids):
        extra = np.setdiff1d(block_ids, ref_ids)
        raise ExtractionError(f"Group `{group}` has {len(extra)} ids not in the record set, e.g. {_ex(extra)}.")
    return idx


def _ex(ids: np.ndarray, k: int = 3) -> list[str]:
    return [i.decode() if isinstance(i, bytes) else str(i) for i in ids[:k]]


# ---------------------------------------------------------------------------
# multiprocessing helpers
# ---------------------------------------------------------------------------
_WORKER_EXTRACTORS: dict[str, FeatureExtractor] = {}


def _worker_transform(payload: tuple[str, dict, dict, np.ndarray, list[dict]]) -> FeatureBlock:
    name, params, state, ids, views = payload
    key = sha256_json([name, params, state])
    ex = _WORKER_EXTRACTORS.get(key)
    if ex is None:
        ex = create_extractor(name, params)
        if ex.is_stateful:
            ex.set_state(state)
        _WORKER_EXTRACTORS[key] = ex
    return ex.transform(ids, views)


def _concat_blocks(blocks: list[FeatureBlock]) -> FeatureBlock:
    first = blocks[0]
    if len(blocks) == 1:
        return first
    matrix = sp.vstack([b.matrix for b in blocks], format="csr") if first.is_sparse else np.vstack(
        [b.matrix for b in blocks])
    msgs = [m for b in blocks for m in b.messages][:20]
    return FeatureBlock(np.concatenate([b.ids for b in blocks]), matrix, first.feature_names, first.group,
                        first.version, np.concatenate([b.status for b in blocks]), msgs)


# ---------------------------------------------------------------------------
# pipeline
# ---------------------------------------------------------------------------
class FeaturePipeline:
    def __init__(self, groups: Sequence[GroupConfig]):
        enabled = [g for g in groups if g.enabled]
        if not enabled:
            raise ExtractionError("No feature group is enabled.")
        self.specs: list[GroupSpec] = []
        for g in enabled:
            ex = create_extractor(g.name, g.params)
            self.specs.append(GroupSpec(ex, g.missing_policy or ex.default_missing_policy))

    # -- learned state -------------------------------------------------------
    def fit(self, train: RecordSource, cache: FeatureCache | None = None) -> None:
        if train.name != "train" and not train.name.startswith("train"):
            raise ExtractionError(f"Stateful groups may only be fitted on the train split, not `{train.name}`.")
        for spec in self.specs:
            ex = spec.extractor
            if not ex.is_stateful:
                continue
            key = state_key(train.fingerprint, ex)
            state = cache.load_state(ex.name, key) if cache else None
            if state is not None:
                log.info("Loaded fitted state of `%s` from cache", ex.name)
                ex.set_state(state)
                continue
            log.info("Fitting `%s` on %d train records", ex.name, len(train.ids))
            ex.fit(input_view(r, ex.required_inputs) for chunk in train.iter_chunks() for r in chunk)
            if cache:
                cache.save_state(ex.name, key, ex.get_state())

    def display_names(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for s in self.specs:
            out.update(s.extractor.display_names())
        return out

    def get_states(self) -> dict[str, dict[str, Any]]:
        return {s.name: s.extractor.get_state() for s in self.specs if s.extractor.is_stateful}

    def set_states(self, states: Mapping[str, Mapping[str, Any]]) -> None:
        for s in self.specs:
            if s.extractor.is_stateful:
                if s.name not in states:
                    raise ExtractionError(f"No saved state for stateful group `{s.name}`.")
                s.extractor.set_state(states[s.name])

    def schema(self) -> FeatureSchema:
        groups = []
        for s in self.specs:
            ex = s.extractor
            if not ex.fitted:
                raise ExtractionError(f"Group `{ex.name}` is not fitted; the schema is undefined.")
            groups.append(GroupSchema(
                name=ex.name, version=ex.version, feature_names=s.output_names(), dtype="float32",
                missing_policy=s.policy, state_fingerprint=ex.state_fingerprint(),
                config=ex.config_dict(),
                tool_versions=ex.tool_versions(), categorical=s.categorical(),
            ))
        return FeatureSchema(groups)

    # -- extraction ------------------------------------------------------------
    def _transform_chunk(self, spec: GroupSpec, ids: np.ndarray, records: list[Record],
                         pool: Any, n_jobs: int) -> FeatureBlock:
        ex = spec.extractor
        if pool is None or not ex.parallel_safe or len(records) < 2 * n_jobs:
            return ex.transform(ids, [input_view(r, ex.required_inputs) for r in records])
        parts = np.array_split(np.arange(len(records)), n_jobs)
        payloads = [(ex.name, ex.params, ex.get_state(), ids[p],
                     [dict(input_view(records[i], ex.required_inputs)) for i in p]) for p in parts if len(p)]
        return _concat_blocks(pool.map(_worker_transform, payloads))

    def compute_blocks(self, source: RecordSource, n_jobs: int = 1) -> dict[str, FeatureBlock]:
        """Compute all groups in memory (prediction and small data)."""
        chunks: dict[str, list[FeatureBlock]] = {s.name: [] for s in self.specs}
        with _pool(n_jobs) as pool:
            for records in source.iter_chunks():
                ids = np.array([r.id.encode() for r in records], dtype="S")
                for spec in self.specs:
                    chunks[spec.name].append(self._transform_chunk(spec, ids, records, pool, n_jobs))
        out = {}
        for spec in self.specs:
            if chunks[spec.name]:
                out[spec.name] = _concat_blocks(chunks[spec.name])
            else:
                names = spec.extractor.get_feature_names()
                out[spec.name] = FeatureBlock(np.array([], "S64"), np.zeros((0, len(names)), np.float32), names,
                                              spec.name, spec.extractor.version, np.zeros(0, np.uint8))
        return out

    def materialize(self, source: RecordSource, cache: FeatureCache, n_jobs: int = 1) -> dict[str, FeatureBlock]:
        """Return cached blocks for `source`, computing missing groups in one pass."""
        keys = {s.name: cache_key(source.fingerprint, s.extractor) for s in self.specs}
        pending = [s for s in self.specs if not cache.has(s.name, keys[s.name])]
        if pending:
            log.info("Computing feature groups %s for split `%s` (%d records)",
                     [s.name for s in pending], source.name, len(source.ids))
            self._compute_into_cache(source, pending, keys, cache, n_jobs)
        else:
            log.info("All feature groups for `%s` loaded from cache", source.name)
        return {s.name: cache.load(s.name, keys[s.name]) for s in self.specs}

    def _compute_into_cache(self, source: RecordSource, pending: list[GroupSpec], keys: dict[str, str],
                            cache: FeatureCache, n_jobs: int) -> None:
        from silkscan.utils.io import atomic_directory

        n = len(source.ids)
        with contextlib.ExitStack() as stack, _pool(n_jobs) as pool:
            tmp = {s.name: stack.enter_context(atomic_directory(cache.entry_dir(s.name, keys[s.name])))
                   for s in pending}
            dense = {}
            sparse_parts: dict[str, list] = {}
            for s in pending:
                d = len(s.extractor.get_feature_names())
                if getattr(s.extractor, "produces_sparse", False):
                    sparse_parts[s.name] = []
                else:
                    dense[s.name] = open_le_memmap(tmp[s.name] / "matrix.npy", (n, d))
            status = {s.name: np.zeros(n, dtype=np.uint8) for s in pending}
            messages: dict[str, list] = {s.name: [] for s in pending}
            row = 0
            for records in source.iter_chunks():
                ids = np.array([r.id.encode() for r in records], dtype="S")
                for s in pending:
                    b = self._transform_chunk(s, ids, records, pool, n_jobs)
                    if s.name in dense:
                        dense[s.name][row:row + len(records)] = b.matrix
                    else:
                        sparse_parts[s.name].append(b.matrix)
                    status[s.name][row:row + len(records)] = b.status
                    messages[s.name].extend(b.messages[: max(0, 20 - len(messages[s.name]))])
                row += len(records)
                if row % 50000 < len(records):
                    log.info("  %d / %d records", row, n)
            if row != n:
                raise ExtractionError(f"Source `{source.name}` yielded {row} records, expected {n}.")
            for s in pending:
                if s.name in dense:
                    dense[s.name].flush()
                    matrix = dense[s.name]
                else:
                    matrix = (sp.vstack(sparse_parts[s.name], format="csr") if sparse_parts[s.name]
                              else sp.csr_matrix((0, len(s.extractor.get_feature_names())), dtype=np.float32))
                block = FeatureBlock(source.ids, matrix, s.extractor.get_feature_names(), s.name,
                                     s.extractor.version, status[s.name], messages[s.name])
                if block.is_sparse:
                    m = block.matrix
                    save_array(tmp[s.name] / "csr_data.npy", m.data.astype(np.float32))
                    save_array(tmp[s.name] / "csr_indices.npy", m.indices.astype(np.int64))
                    save_array(tmp[s.name] / "csr_indptr.npy", m.indptr.astype(np.int64))
                save_array(tmp[s.name] / "ids.npy", source.ids)
                save_array(tmp[s.name] / "status.npy", status[s.name])
                cache._write_meta(tmp[s.name], block, {"split": source.name, "split_fingerprint": source.fingerprint})
                if s.name in dense:
                    del dense[s.name]  # close the memmap before the directory is renamed

    # -- assembly ----------------------------------------------------------------
    def assemble(self, blocks: Mapping[str, FeatureBlock], ref_ids: np.ndarray, strict: bool = True
                 ) -> AssembledFeatures:
        n = len(ref_ids)
        if len(np.unique(ref_ids)) != n:
            raise ExtractionError("Record set contains duplicated ids.")
        plan = []
        names: list[str] = []
        slices: dict[str, slice] = {}
        statuses: dict[str, np.ndarray] = {}
        failed = np.zeros(n, dtype=bool)
        for spec in self.specs:
            block = blocks[spec.name]
            expected = spec.extractor.get_feature_names()
            if list(block.feature_names) != list(expected):
                raise ExtractionError(f"Group `{spec.name}` block columns do not match the extractor's names.")
            idx = align_index(spec.name, block.ids, ref_ids)
            st = np.asarray(block.status if idx is None else block.status[idx])
            bad = st != Status.OK
            if bad.any() and spec.policy == "error":
                if strict:
                    raise ExtractionError(_failure_summary(spec, block, st))
                failed |= bad
            out_names = spec.output_names()
            slices[spec.name] = slice(len(names), len(names) + len(out_names))
            names += out_names
            statuses[spec.name] = st
            plan.append((spec, block, idx, st, bad))

        if any(b.is_sparse for _, b, _, _, _ in plan):
            X = self._assemble_sparse(plan, n)
        else:
            X = np.empty((n, len(names)), dtype=np.float32)
            for spec, block, idx, st, bad in plan:
                c0 = slices[spec.name].start
                d = len(block.feature_names)
                for r0 in range(0, n, _COPY_ROWS):
                    r1 = min(n, r0 + _COPY_ROWS)
                    src = np.asarray(block.matrix[r0:r1] if idx is None else block.matrix[idx[r0:r1]])
                    X[r0:r1, c0:c0 + d] = to_native(src)
                X[bad, c0:c0 + d] = np.nan
                if spec.policy == "impute_with_indicator":
                    for k, s in enumerate(NON_OK_STATUSES):
                        X[:, c0 + d + k] = st == s
        categorical = [c for s in self.specs for c in s.categorical()]
        return AssembledFeatures(ref_ids, X, names, categorical, statuses, slices, failed)

    @staticmethod
    def _assemble_sparse(plan: list, n: int) -> sp.csr_matrix:
        mats = []
        for spec, block, idx, st, bad in plan:
            m = block.matrix
            if sp.issparse(m):
                # Sparse groups keep zeros on failed rows; the status columns carry the information.
                m = m.tocsr() if idx is None else m.tocsr()[idx]
            else:
                m = to_native(np.asarray(m if idx is None else m[idx], dtype=np.float32)).copy()
                m[bad] = np.nan
                m = sp.csr_matrix(m)
            mats.append(m)
            if spec.policy == "impute_with_indicator":
                mats.append(sp.csr_matrix(np.stack([st == s for s in NON_OK_STATUSES], axis=1).astype(np.float32)))
        return sp.hstack(mats, format="csr", dtype=np.float32)

    # -- convenience -----------------------------------------------------------------
    def build(self, source: RecordSource, cache: FeatureCache, n_jobs: int = 1, strict: bool = True
              ) -> AssembledFeatures:
        return self.assemble(self.materialize(source, cache, n_jobs), source.ids, strict)

    def transform_records(self, records: Sequence[Record], strict: bool = False, n_jobs: int = 1
                          ) -> AssembledFeatures:
        src = MemorySource(records)
        return self.assemble(self.compute_blocks(src, n_jobs), src.ids, strict)


def _failure_summary(spec: GroupSpec, block: FeatureBlock, st: np.ndarray) -> str:
    counts = {s.name: int((st == s).sum()) for s in NON_OK_STATUSES if (st == s).any()}
    examples = "; ".join(f"{i}: {m}" for i, m in block.messages[:3])
    return (
        f"Group `{spec.name}` (missing_policy=error) failed for {int((st != 0).sum())} of {len(st)} records "
        f"{counts}. Examples: {examples}. Fix the data, or set `missing_policy: impute_with_indicator` for this group."
    )


@contextlib.contextmanager
def _pool(n_jobs: int) -> Iterator[Any]:
    if n_jobs <= 1:
        yield None
        return
    # fork (Linux: x86_64 and s390x) does not re-import __main__, so it also works from notebooks and
    # unguarded scripts, and workers inherit groups registered at runtime. spawn elsewhere.
    method = "fork" if "fork" in multiprocessing.get_all_start_methods() else "spawn"
    with multiprocessing.get_context(method).Pool(n_jobs) as pool:
        yield pool
