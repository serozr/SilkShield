"""Run directories: one per training run, never overwritten."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from silkscan.errors import RunExistsError


def create_run_dir(runs_dir: Path, config_fingerprint: str, prefix: str = "") -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")[:-3]
    path = Path(runs_dir) / f"{prefix}{stamp}-{config_fingerprint[:8]}"
    try:
        path.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        raise RunExistsError(f"Run directory {path} already exists; refusing to overwrite it.") from None
    return path


def create_subdir(parent: Path, name: str) -> Path:
    path = Path(parent) / name
    try:
        path.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        raise RunExistsError(f"{path} already exists; refusing to overwrite it.") from None
    return path
