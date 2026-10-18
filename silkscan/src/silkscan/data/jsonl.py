"""Streaming JSONL reading. Never loads a whole file into memory."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator, Sequence

import numpy as np

from silkscan.data.records import Record, split_record
from silkscan.errors import DataValidationError


def iter_raw(paths: Sequence[Path]) -> Iterator[tuple[int, int, dict[str, Any]]]:
    """Yield (file_index, line_number, parsed_object) for every non-empty line."""
    for file_idx, path in enumerate(paths):
        with open(path, "rb") as f:
            for line_no, line in enumerate(f):
                if not line.strip():
                    continue
                yield file_idx, line_no, parse_line(line, path, line_no)


def parse_line(line: bytes, path: Path, line_no: int) -> dict[str, Any]:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError as e:
        raise DataValidationError(f"{path}:{line_no + 1}: invalid JSON ({e.msg}).") from None
    if not isinstance(obj, dict):
        raise DataValidationError(f"{path}:{line_no + 1}: expected a JSON object.")
    return obj


def iter_selected_records(
    paths: Sequence[Path],
    file_idx: np.ndarray,
    line_no: np.ndarray,
    id_field: str,
    chunk_size: int,
) -> Iterator[list[Record]]:
    """Yield records at the given (file, line) positions, in that order, in chunks.

    Positions must be sorted by (file, line), which is how the manifest stores them.
    """
    order = np.lexsort((line_no, file_idx))
    if not np.array_equal(order, np.arange(len(order))):
        raise DataValidationError("Manifest positions are not sorted by (file, line); rebuild the manifest.")
    chunk: list[Record] = []
    for fi in np.unique(file_idx):
        wanted = line_no[file_idx == fi]
        k = 0
        with open(paths[int(fi)], "rb") as f:
            for ln, line in enumerate(f):
                if k == len(wanted):
                    break
                if ln != wanted[k]:
                    continue
                k += 1
                chunk.append(split_record(parse_line(line, paths[int(fi)], ln), id_field))
                if len(chunk) == chunk_size:
                    yield chunk
                    chunk = []
        if k != len(wanted):
            raise DataValidationError(
                f"{paths[int(fi)]} has fewer lines than the manifest expects; the data changed. Rebuild the manifest."
            )
    if chunk:
        yield chunk
