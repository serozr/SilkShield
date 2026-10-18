"""Split manifest: which records belong to which split, with data fingerprints.

Built in one streaming pass over the JSONL files. Only ids, labels, dates and (file, line) positions are
stored; feature extraction reads records back by position, so the dataset never has to fit in memory.

Rules:
- official train/test/challenge files are kept as they are;
- validation is the temporal tail of train (`data.validation_start`);
- ids must be unique within a split and disjoint across splits;
- unlabeled records (label null/-1) are excluded and counted.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterator

import numpy as np

from silkscan.config import DataConfig
from silkscan.data.jsonl import iter_selected_records, parse_line
from silkscan.data.records import Record, parse_date, parse_label, validate_id
from silkscan.errors import DataValidationError, LeakageError
from silkscan.utils.hashing import array_fingerprint, sha256_json
from silkscan.utils.io import read_json, to_little_endian, write_json

log = logging.getLogger(__name__)

FORMAT_VERSION = 1
SPLIT_ORDER = ("train", "validation", "test", "challenge")

# Fields compared when two records share an id (static-analysis content plus label).
_DIGEST_FIELDS = ("general", "header", "section", "imports", "exports", "datadirectories", "richheader",
                  "authenticode", "label")


@dataclass
class SplitData:
    name: str
    ids: np.ndarray       # bytes ('S'), no byte order
    labels: np.ndarray    # int8: 0 benign, 1 malicious
    dates: np.ndarray     # int64 Unix seconds, -1 = unknown
    file_idx: np.ndarray  # int32 index into Manifest.files
    line_no: np.ndarray   # int64 0-based line in that file

    def __len__(self) -> int:
        return len(self.ids)

    def take(self, mask: np.ndarray, name: str | None = None) -> "SplitData":
        return SplitData(name or self.name, self.ids[mask], self.labels[mask], self.dates[mask],
                         self.file_idx[mask], self.line_no[mask])

    def summary(self) -> dict[str, Any]:
        known = self.dates[self.dates >= 0]
        return {
            "n": int(len(self)),
            "n_malicious": int((self.labels == 1).sum()),
            "n_benign": int((self.labels == 0).sum()),
            "date_min": int(known.min()) if len(known) else None,
            "date_max": int(known.max()) if len(known) else None,
        }


def _split_fingerprint(split: SplitData, file_hashes: list[str]) -> str:
    used = sorted({file_hashes[i] for i in np.unique(split.file_idx)})
    return sha256_json({
        "files": used,
        "ids": array_fingerprint(split.ids),
        "labels": array_fingerprint(split.labels),
        "file_idx": array_fingerprint(split.file_idx.astype(np.int64)),
        "line_no": array_fingerprint(split.line_no),
    })


class Manifest:
    def __init__(self, data_root: Path, files: list[dict[str, Any]], splits: dict[str, SplitData],
                 stats: dict[str, Any], data_config: dict[str, Any]):
        self.data_root = Path(data_root)
        self.files = files
        self.splits = splits
        self.stats = stats
        self.data_config = data_config
        hashes = [f["sha256"] for f in files]
        self.split_fingerprints = {name: _split_fingerprint(s, hashes) for name, s in splits.items()}
        self.fingerprint = sha256_json({"files": hashes, "splits": self.split_fingerprints})

    @property
    def paths(self) -> list[Path]:
        return [self.data_root / f["path"] for f in self.files]

    def split(self, name: str) -> SplitData:
        if name not in self.splits:
            raise DataValidationError(f"Split `{name}` is not in the manifest (available: {sorted(self.splits)}).")
        return self.splits[name]

    def iter_records(self, name: str, id_field: str, chunk_size: int) -> Iterator[list[Record]]:
        s = self.split(name)
        expected = iter(s.ids)
        for chunk in iter_selected_records(self.paths, s.file_idx, s.line_no, id_field, chunk_size):
            for rec in chunk:
                if rec.id.encode() != next(expected):
                    raise DataValidationError(
                        f"Record at manifest position has id {rec.id}, expected another; the data changed. "
                        "Rebuild the manifest with `silkscan manifest --force`."
                    )
            yield chunk

    def save(self, directory: Path, force: bool = False) -> None:
        directory = Path(directory)
        if (directory / "manifest.json").exists() and not force:
            raise DataValidationError(f"A manifest already exists in {directory}. Use --force to rebuild it.")
        directory.mkdir(parents=True, exist_ok=True)
        for name, s in self.splits.items():
            np.savez(directory / f"{name}.npz", ids=s.ids, labels=s.labels,
                     dates=to_little_endian(s.dates), file_idx=to_little_endian(s.file_idx),
                     line_no=to_little_endian(s.line_no))
        write_json(directory / "manifest.json", {
            "format_version": FORMAT_VERSION,
            "data_root": str(self.data_root.resolve()),
            "files": self.files,
            "splits": {n: {**s.summary(), "fingerprint": self.split_fingerprints[n]} for n, s in self.splits.items()},
            "stats": self.stats,
            "data_config": self.data_config,
            "fingerprint": self.fingerprint,
        })

    @classmethod
    def load(cls, directory: Path, verify_sizes: bool = True) -> "Manifest":
        directory = Path(directory)
        path = directory / "manifest.json"
        if not path.exists():
            raise DataValidationError(f"No manifest in {directory}. Run `silkscan manifest -c <config>` first.")
        meta = read_json(path)
        if meta.get("format_version") != FORMAT_VERSION:
            raise DataValidationError(f"Manifest format {meta.get('format_version')} is not supported; rebuild it.")
        splits = {}
        for name in meta["splits"]:
            with np.load(directory / f"{name}.npz", allow_pickle=False) as z:
                splits[name] = SplitData(name, z["ids"], z["labels"], z["dates"].astype(np.int64),
                                         z["file_idx"].astype(np.int32), z["line_no"].astype(np.int64))
        m = cls(Path(meta["data_root"]), meta["files"], splits, meta["stats"], meta["data_config"])
        if m.fingerprint != meta["fingerprint"]:
            raise DataValidationError(f"Manifest in {directory} is inconsistent (fingerprint mismatch); rebuild it.")
        if verify_sizes:
            for f, p in zip(m.files, m.paths):
                if not p.exists() or p.stat().st_size != f["size"]:
                    raise DataValidationError(f"Data file {p} is missing or changed since the manifest was built.")
        return m


def resolve_split_files(root: Path, patterns: list[str], split: str) -> list[Path]:
    root = Path(root)
    if not root.is_dir():
        raise DataValidationError(
            f"Data root {root} does not exist. Download EMBER2024 (thrember.download_dataset(root, "
            "file_type='Win64')) and set `data.root`."
        )
    matched = sorted({p for pat in patterns for p in root.glob(pat) if p.is_file()})
    if not matched:
        found = sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())
        listing = "\n    ".join(found[:30]) + (f"\n    ... ({len(found)} files)" if len(found) > 30 else "")
        raise DataValidationError(
            f"No files for split `{split}` match {patterns} under {root}. "
            f"Adjust `data.splits` in the config. Files found there:\n    {listing or '(none)'}"
        )
    return matched


def build_manifest(cfg: DataConfig) -> Manifest:
    root = Path(cfg.root)
    split_files = {name: resolve_split_files(root, pats, name) for name, pats in cfg.splits.items()}
    owner: dict[Path, str] = {}
    for name, paths in split_files.items():
        for p in paths:
            if p in owner:
                raise LeakageError(f"File {p} matches both `{owner[p]}` and `{name}` split patterns.")
            owner[p] = name

    files: list[dict[str, Any]] = []
    splits: dict[str, SplitData] = {}
    stats: dict[str, Any] = {}
    keep_first = cfg.duplicate_policy == "keep_first"
    for name, paths in split_files.items():
        cols: dict[str, list] = {"ids": [], "labels": [], "dates": [], "file_idx": [], "line_no": []}
        st = {"lines": 0, "unlabeled": 0, "other_file_type": 0, "unexpected_file_type": 0, "duplicates_dropped": 0}
        filter_type = name in cfg.filter_file_type_splits
        first_seen: dict[str, tuple[int, str, str]] = {}  # id -> (label, static digest, location)
        for p in paths:
            fidx = len(files)
            h = hashlib.sha256()
            log.info("Reading %s (%s split)", p, name)
            with open(p, "rb") as f:
                for line_no, line in enumerate(f):
                    h.update(line)
                    if not line.strip():
                        continue
                    st["lines"] += 1
                    obj = parse_line(line, p, line_no)
                    rid = validate_id(obj.get(cfg.id_field))
                    if str(obj.get(cfg.file_type_field, "")).lower() != cfg.file_type.lower():
                        if filter_type:
                            st["other_file_type"] += 1
                            continue
                        st["unexpected_file_type"] += 1
                    if cfg.label_field not in obj:
                        raise DataValidationError(f"{p}:{line_no + 1}: no label field `{cfg.label_field}`.")
                    label = parse_label(obj[cfg.label_field])
                    if label == -1:
                        st["unlabeled"] += 1
                        continue
                    if keep_first:
                        digest = _static_digest(obj, cfg.duplicate_ignore_fields)
                        prev = first_seen.get(rid)
                        if prev is not None:
                            if prev[:2] != (label, digest):
                                raise DataValidationError(
                                    f"Id {rid} appears at {prev[2]} and {p.name}:{line_no + 1} with a different "
                                    "label or different static features; refusing to drop either copy."
                                )
                            st["duplicates_dropped"] += 1
                            continue
                        first_seen[rid] = (label, digest, f"{p.name}:{line_no + 1}")
                    date = parse_date(obj.get(cfg.date_field))
                    cols["ids"].append(rid.encode())
                    cols["labels"].append(label)
                    cols["dates"].append(-1 if date is None else date)
                    cols["file_idx"].append(fidx)
                    cols["line_no"].append(line_no)
                    if st["lines"] % 50000 == 0:
                        log.info("  %d lines", st["lines"])
            files.append({"path": str(p.relative_to(root)), "sha256": h.hexdigest(), "size": p.stat().st_size})
        if st["unexpected_file_type"]:
            log.warning("Split %s: %d records have a file_type other than %s (kept).",
                        name, st["unexpected_file_type"], cfg.file_type)
        splits[name] = SplitData(
            name,
            np.array(cols["ids"], dtype="S") if cols["ids"] else np.array([], dtype="S64"),
            np.array(cols["labels"], dtype=np.int8),
            np.array(cols["dates"], dtype=np.int64),
            np.array(cols["file_idx"], dtype=np.int32),
            np.array(cols["line_no"], dtype=np.int64),
        )
        stats[name] = st

    if cfg.validation_start is not None:
        splits = _carve_validation(splits, cfg.validation_start)
    if cfg.train_fraction < 1:
        keep = id_hash_fraction(splits["train"].ids) < cfg.train_fraction
        stats["train"]["subsampled_out"] = int((~keep).sum())
        splits["train"] = splits["train"].take(keep)
    for s in splits.values():
        _check_unique(s)
    splits = _check_disjoint(splits, cfg.overlap_policy, stats)
    for name, s in splits.items():
        if len(s) == 0:
            raise DataValidationError(f"Split `{name}` is empty after filtering (stats: {stats.get(name)}).")
    ordered = {n: splits[n] for n in sorted(splits, key=_split_rank)}
    return Manifest(root, files, ordered, stats, asdict(cfg))


def id_hash_fraction(ids: np.ndarray) -> np.ndarray:
    """Map each id to [0, 1) by its SHA-256, independent of platform and record order."""
    return np.array([int.from_bytes(hashlib.sha256(bytes(i)).digest()[:8], "big") / 2**64 for i in ids])


def _split_rank(name: str) -> tuple[int, str]:
    return (SPLIT_ORDER.index(name) if name in SPLIT_ORDER else len(SPLIT_ORDER), name)


def _carve_validation(splits: dict[str, SplitData], start: str) -> dict[str, SplitData]:
    boundary = parse_date(start)
    train = splits["train"]
    if (train.dates < 0).any():
        raise DataValidationError(
            f"{int((train.dates < 0).sum())} train records have no date, so a temporal validation split "
            "is impossible. Check `data.date_field`."
        )
    is_val = train.dates >= boundary
    if not is_val.any() or is_val.all():
        s = train.summary()
        raise DataValidationError(
            f"validation_start={start} leaves an empty train or validation split "
            f"(train dates {s['date_min']}..{s['date_max']} Unix seconds)."
        )
    out = dict(splits)
    out["train"] = train.take(~is_val)
    out["validation"] = train.take(is_val, "validation")
    return out


def _static_digest(obj: dict[str, Any], ignore: list[str]) -> str:
    return sha256_json({k: obj.get(k) for k in _DIGEST_FIELDS if k not in ignore})


def _check_unique(s: SplitData) -> None:
    uniq, counts = np.unique(s.ids, return_counts=True)
    if len(uniq) != len(s.ids):
        dupes = [u.decode() for u in uniq[counts > 1][:5]]
        raise DataValidationError(
            f"Split `{s.name}` has {int((counts > 1).sum())} duplicated ids, e.g. {dupes}. If the copies are the "
            "same file (EMBER2024 weekly files hold every record twice), set `data.duplicate_policy: keep_first`."
        )


def _check_disjoint(splits: dict[str, SplitData], policy: str, stats: dict[str, Any]) -> dict[str, SplitData]:
    out: dict[str, SplitData] = {}
    seen = np.array([], dtype="S64")
    for name in sorted(splits, key=_split_rank):
        s = splits[name]
        overlap = np.isin(s.ids, seen)
        if overlap.any():
            examples = [i.decode() for i in s.ids[overlap][:5]]
            if policy == "error":
                raise LeakageError(
                    f"{int(overlap.sum())} ids of split `{name}` also appear in an earlier split, e.g. {examples}. "
                    "Set `data.overlap_policy: drop_from_later` to drop them from the later split."
                )
            log.warning("Dropping %d ids from `%s` that appear in an earlier split.", int(overlap.sum()), name)
            stats.setdefault(name, {})["dropped_overlap"] = int(overlap.sum())
            s = s.take(~overlap)
        out[name] = s
        seen = np.concatenate([seen, s.ids])
    return out
