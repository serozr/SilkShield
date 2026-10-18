"""Runtime provenance (software versions, architecture) and the IBM Z NNPA check."""

from __future__ import annotations

import importlib.metadata
import platform
import sys
from pathlib import Path
from typing import Any

PACKAGES = ("silkscan", "numpy", "scipy", "lightgbm", "PyYAML", "thrember", "signify", "snapml", "yara-python")


def has_nnpa() -> bool:
    """True if the CPU exposes the Neural Network Processing Assist facility (IBM z16 and later)."""
    try:
        text = Path("/proc/cpuinfo").read_text(errors="replace")
    except OSError:
        return False
    for line in text.splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() in ("flags", "features"):
            return "nnpa" in value.split()
    return False


def package_versions() -> dict[str, str | None]:
    versions: dict[str, str | None] = {}
    for name in PACKAGES:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    return versions


def runtime_info() -> dict[str, Any]:
    """Software provenance only; no host, CPU or memory details."""
    return {"python": platform.python_version(), "machine": platform.machine(), "byteorder": sys.byteorder,
            "packages": package_versions()}
