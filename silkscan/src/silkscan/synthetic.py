"""Synthetic EMBER2024-shaped fixture for tests.

The records only imitate the *shape* of EMBER raw features (section, imports,
general, capa) plus metadata; ids are explicit `synthetic:` ids. Scores on this
data say nothing about real malware detection performance.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import numpy as np

BANNER = ("SYNTHETIC DATA: these numbers only show that the pipeline runs end to end; "
          "they are NOT malware detection results.")

_BENIGN_APIS = {"KERNEL32.dll": ["GetModuleHandleW", "GetCommandLineW", "ExitProcess", "HeapAlloc", "CreateFileW",
                                 "ReadFile", "CloseHandle", "GetLastError"],
                "USER32.dll": ["MessageBoxW", "CreateWindowExW", "ShowWindow", "GetMessageW"]}
_SUSPICIOUS_APIS = {"KERNEL32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "OpenProcess",
                                     "IsDebuggerPresent", "LoadLibraryA", "GetProcAddress", "Sleep"],
                    "WS2_32.dll": ["socket", "connect", "send", "recv"],
                    "ADVAPI32.dll": ["RegSetValueExW", "CryptEncrypt", "CryptAcquireContextW"],
                    "WININET.dll": ["InternetOpenA", "InternetOpenUrlA"]}
_CAPA_NS = ["host-interaction/process/inject", "communication/http/client", "anti-analysis/anti-debugging",
            "data-manipulation/encryption", "host-interaction/file-system/write", "host-interaction/registry",
            "collection/keylog", "linking/runtime-linking", "executable/resource"]
_ATTACK = ["Process Injection [T1055]", "Obfuscated Files or Information [T1027]", "Process Discovery [T1057]",
           "File and Directory Discovery [T1083]"]
_MBC = ["Terminate Process [C0018]", "Move File [C0063]", "Console [C0033]"]


def _synthetic_type(imports: dict[str, list[str]], n_sec: int) -> tuple[str, str]:
    """Behaviour tag and family stem derived from already-drawn content (no extra random draws)."""
    if "WS2_32.dll" in imports or "WININET.dll" in imports:
        return "downloader", "synthdl"
    if "ADVAPI32.dll" in imports:
        return "ransom", "synthransom"
    return ("virus", "synthvir") if n_sec >= 5 else ("coinminer", "synthminer")


def _record(rng: np.random.Generator, rid: str, label: int, date: datetime, file_type: str = "Win64"
            ) -> dict[str, Any]:
    mal = label == 1
    signal = 0.9 if mal else 0.0
    n_sec = int(rng.integers(3, 8))
    sections = []
    for i in range(n_sec):
        nonstd = rng.random() < (0.45 if mal else 0.1)
        name = (["UPX0", "UPX1", ".xyz", ".packed", ""][int(rng.integers(0, 5))] if nonstd
                else [".text", ".rdata", ".data", ".rsrc", ".reloc", ".pdata"][i % 6])
        size = int(rng.integers(0, 200_000)) if i else int(rng.integers(1000, 200_000))
        ent = float(np.clip(rng.normal(5.6 + signal * 1.2, 1.0), 0, 8))
        props = ["MEM_READ"] + (["MEM_EXECUTE", "CNT_CODE"] if i == 0 or rng.random() < 0.15 else []) + \
                (["MEM_WRITE"] if rng.random() < (0.5 if mal else 0.25) else [])
        sections.append({"name": name, "size": size, "entropy": ent, "vsize": int(size * rng.uniform(0.5, 3)),
                         "size_ratio": size / 1_000_000, "vsize_ratio": float(rng.uniform(0.3, 2)), "props": props})
    imports: dict[str, list[str]] = {}
    for dll, funcs in _BENIGN_APIS.items():
        imports[dll] = [f for f in funcs if rng.random() < 0.7]
    for dll, funcs in _SUSPICIOUS_APIS.items():
        chosen = [f for f in funcs if rng.random() < (0.35 if mal else 0.08)]
        if chosen:
            imports[dll] = chosen
    caps = [{"Capability": ns.split("/")[-1], "Namespace": ns, "Addrs": []}
            for ns in _CAPA_NS if rng.random() < (0.45 if mal else 0.12)]
    rec: dict[str, Any] = {
        "sha256": rid,
        "tlsh": "T1" + "0" * 70,
        "first_submission_date": date.strftime("%Y-%m-%d %H:%M:%S"),
        "last_analysis_date": date.strftime("%Y-%m-%d %H:%M:%S"),
        "detection_ratio": [int(rng.integers(20, 60)) if mal else 0, 70],
        "label": label,
        "file_type": file_type,
        "family": (_synthetic_type(imports, n_sec)[1] + str(int(rng.integers(0, 2)))) if mal else None,
        "family_confidence": 0.9 if mal else None,
        "behavior": [_synthetic_type(imports, n_sec)[0]] if mal and n_sec > 3 else [],  # n_sec 3: unlabelled
        "file_property": [], "packer": ["upx"] if mal and rng.random() < 0.3 else [], "exploit": [], "group": [],
        "general": {"size": 1_000_000, "entropy": float(rng.uniform(4, 7.9)), "is_pe": 1, "start_bytes": [77, 90, 144, 0]},
        "section": {"entry": sections[0]["name"], "sections": sections,
                    "overlay": {"size": 0, "size_ratio": 0, "entropy": 0}},
        "imports": imports,
        # capa results as released in EMBER2024: top-level lists (populated for both classes here).
        "caps": caps,
        "ttps": [{"Tactic": "X", "Technique": t} for t in _ATTACK if rng.random() < (0.4 if mal else 0.1)],
        "mbc": [{"Objective": "X", "Behavior": b} for b in _MBC if rng.random() < 0.3],
    }
    u = rng.random()
    if u < 0.02:  # not parseable as PE
        rec["general"]["is_pe"] = 0
        rec["section"] = {}
    elif u < 0.04:  # field missing from the record
        del rec["imports"]
    elif u < 0.05:  # malformed field
        rec["section"]["sections"] = "corrupted"
    return rec


def write_fixture(out_dir: Path, n_train: int = 1600, n_test: int = 400, n_challenge: int = 60, seed: int = 0
                  ) -> dict[str, Path]:
    """Write train/test/challenge JSONL files shaped like EMBER2024's release."""
    rng = np.random.default_rng(seed)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    files = {}

    def write(name: str, rows: list[dict[str, Any]]) -> None:
        p = out_dir / name
        with open(p, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        files[name] = p

    train = [_record(rng, f"synthetic:train:{i:06d}", int(rng.random() < 0.5),
                     start + timedelta(days=int(180 * i / n_train))) for i in range(n_train)]
    train[5]["label"] = None  # unlabeled records are excluded from the manifest
    write("synthetic_Win64_train.jsonl", train)
    test = [_record(rng, f"synthetic:test:{i:06d}", int(rng.random() < 0.5),
                    start + timedelta(days=182 + int(60 * i / n_test))) for i in range(n_test)]
    write("synthetic_Win64_test.jsonl", test)
    chal = [_record(rng, f"synthetic:challenge:{i:06d}", 1, start + timedelta(days=200),
                    file_type="Win64" if i % 6 else "Win32") for i in range(n_challenge)]
    write("synthetic_challenge.jsonl", chal)
    return files


def make_records(n: int, seed: int = 0, label: int | None = None) -> list:
    """In-memory synthetic records (identity/inputs/target already split)."""
    from silkscan.data.records import split_record

    rng = np.random.default_rng(seed)
    when = datetime(2024, 3, 1, tzinfo=timezone.utc)
    return [split_record(_record(rng, f"synthetic:t{seed}:{i:05d}",
                                 label if label is not None else int(rng.random() < 0.5), when))
            for i in range(n)]
