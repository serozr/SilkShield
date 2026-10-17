"""Built-in checks: SHA-256 allow/deny lists and YARA rules."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import numpy as np

from silkscan.checks.base import Check, CheckContext, Effect, Outcome, Severity
from silkscan.errors import ConfigError, DependencyError


def _paths(value: Any) -> list[Path]:
    if not value:
        return []
    return [Path(v) for v in (value if isinstance(value, (list, tuple)) else [value])]


class HashSet:
    """Membership over SHA-256 digests from text lists and/or binary .npy lists.

    - `.npy`: sorted, unique 32-byte digests (dtype S32), written by `silkscan hashlist`. Opened with
      mmap: loads in milliseconds, 32 bytes per hash, and all worker processes share the same pages.
      Lookup is a binary search.
    - text: one hex SHA-256 per line, `#` comments; for small hand-written lists.
    """

    def __init__(self, paths: list[Path]):
        self.arrays: list[np.ndarray] = []
        self.small: set[bytes] = set()
        for p in paths:
            if not p.is_file():
                raise ConfigError(f"Hash list {p} not found.")
            if p.suffix == ".npy":
                a = np.load(p, mmap_mode="r", allow_pickle=False)
                if a.dtype != np.dtype("S32") or a.ndim != 1:
                    raise ConfigError(f"{p}: expected a 1-D S32 array of SHA-256 digests, got {a.dtype} {a.shape}.")
                if len(a) > 1 and not bool(np.all(a[1:] > a[:-1])):
                    raise ConfigError(f"{p}: digests must be sorted and unique (rebuild with `silkscan hashlist`).")
                self.arrays.append(a)
            else:
                self.small |= _read_text_hashes(p)

    def __contains__(self, digest: bytes) -> bool:
        if digest in self.small:
            return True
        # Go through an S32 array so the key gets numpy's fixed-width semantics: elements read back from
        # an S32 array lose trailing NUL bytes, so a raw `bytes` key ending in 0x00 would never compare equal.
        key = np.array(digest, dtype="S32")[()]
        for a in self.arrays:
            i = int(np.searchsorted(a, key))
            if i < len(a) and a[i] == key:
                return True
        return False

    def __len__(self) -> int:
        return len(self.small) + sum(len(a) for a in self.arrays)


def _read_text_hashes(p: Path) -> set[bytes]:
    out = set()
    for n, line in enumerate(p.read_text().splitlines(), 1):
        h = line.split("#", 1)[0].strip()
        if h:
            try:
                d = bytes.fromhex(h)
            except ValueError:
                d = b""
            if len(d) != 32:
                raise ConfigError(f"{p}:{n}: not a SHA-256: {h!r}")
            out.add(d)
    return out


def _digest(sha256_hex: str) -> bytes | None:
    try:
        d = bytes.fromhex(sha256_hex)
    except ValueError:
        return None
    return d if len(d) == 32 else None


class HashList(Check):
    """Exact SHA-256 deny/allow lists (each a file or a list of files). Deny wins over allow."""

    name = "hash_list"
    version = "1"
    needs_bytes = False

    def setup(self) -> None:
        self.deny = HashSet(_paths(self.params.get("deny")))
        self.allow = HashSet(_paths(self.params.get("allow")))

    def tool_versions(self) -> dict[str, str]:
        out = {}
        for k in ("deny", "allow"):
            h = hashlib.sha256()
            for p in _paths(self.params.get(k)):
                h.update(p.read_bytes())
            out[f"{k}_sha256"] = h.hexdigest()
            out[f"{k}_count"] = str(len(getattr(self, k, ())))
        return out

    def run(self, ctx: CheckContext) -> Any:
        d = _digest(ctx.sha256)
        if d is None:  # e.g. synthetic ids: nothing to look up
            return self.result(Outcome.SKIPPED, message="id is not a SHA-256")
        if d in self.deny:
            return self.result(Outcome.HIT, severity=Severity.CRITICAL, effect=Effect.FORCE_MALICIOUS,
                               tags=["denylist"], evidence=[ctx.sha256.lower()])
        if d in self.allow:
            return self.result(Outcome.HIT, severity=Severity.INFO, effect=Effect.FORCE_CLEAN,
                               tags=["allowlist"], evidence=[ctx.sha256.lower()])
        return self.result(Outcome.MISS)


class Yara(Check):
    """All *.yar / *.yara files under `rules_dir`, compiled once.

    Per-rule metadata understood (all optional):
      severity = "low" | "medium" | "high" | "critical"   (default: params.default_severity)
      effect   = "evidence" | "force_malicious"          (a rule may not force "clean")
      tags     = "ransomware,loader"                     (added to the result's tags)
    The check's severity is the highest among matched rules; its effect is force_malicious if any
    matched rule asks for it and the check config allows it (params.allow_force: true).
    """

    name = "yara"
    version = "1"
    needs_bytes = True

    def setup(self) -> None:
        try:
            import yara
        except ImportError:
            raise DependencyError("Check `yara` needs yara-python: pip install yara-python "
                                  "(on s390x it builds libyara from source: gcc, make, openssl headers).") from None
        rules_dir = Path(self.params.get("rules_dir", "rules/yara"))
        files = sorted([*rules_dir.rglob("*.yar"), *rules_dir.rglob("*.yara")])
        if not files:
            raise ConfigError(f"No .yar/.yara files under {rules_dir}.")
        self._files = files
        try:
            self._rules = yara.compile(filepaths={f"r{i}": str(f) for i, f in enumerate(files)})
        except yara.SyntaxError as e:
            raise ConfigError(f"YARA syntax error: {e}") from None
        self._timeout = int(self.params.get("timeout_s", 5))
        self._default_sev = Severity.parse(self.params.get("default_severity", "medium"), Severity.MEDIUM)
        self._allow_force = bool(self.params.get("allow_force", False))

    def tool_versions(self) -> dict[str, str]:
        h = hashlib.sha256()
        for f in getattr(self, "_files", []):
            h.update(f.name.encode() + b"\0" + f.read_bytes())
        return {"rules_sha256": h.hexdigest(), "n_rule_files": str(len(getattr(self, "_files", [])))}

    def run(self, ctx: CheckContext) -> Any:
        matches = self._rules.match(data=ctx.data, timeout=self._timeout)
        if not matches:
            return self.result(Outcome.MISS)
        sev, force, tags, evidence = Severity.INFO, False, [], []
        for m in matches:
            meta = m.meta or {}
            sev = max(sev, Severity.parse(meta.get("severity"), self._default_sev))
            force |= str(meta.get("effect", "")).lower() == "force_malicious"
            tags += [t.strip() for t in str(meta.get("tags", "")).split(",") if t.strip()] + list(m.tags)
            evidence.append(m.rule)
        effect = Effect.FORCE_MALICIOUS if (force and self._allow_force) else Effect.EVIDENCE
        return self.result(Outcome.HIT, severity=sev, effect=effect, tags=sorted(set(tags)), evidence=evidence)


MACHINES = {0x8664: "AMD64", 0xAA64: "ARM64", 0x014C: "I386", 0x0200: "IA64", 0x01C4: "ARMNT"}


class PEFormat(Check):
    """Input gate before any parsing: is this a PE file the model was trained for?

    Not a PE (no MZ header / no PE signature) or, if `allowed_machines` is set, a machine type the model
    never saw (e.g. a 32-bit file for the Win64 model) -> FORCE_REVIEW: sent to review, never "clean",
    and parsing/model are skipped. Header *scoring* is deliberately absent: EMBER v3 already models
    header fields.
    """

    name = "pe_format"
    version = "1"
    needs_bytes = True
    default_effect = Effect.FORCE_REVIEW

    def setup(self) -> None:
        allowed = self.params.get("allowed_machines")
        self.allowed = {str(m).upper() for m in allowed} if allowed else None

    def run(self, ctx: CheckContext) -> Any:
        d = ctx.data
        if len(d) < 64 or d[:2] != b"MZ":
            return self.result(Outcome.HIT, severity=Severity.LOW, message="not a PE file (no MZ header)",
                               tags=["unsupported-format"])
        off = int.from_bytes(d[0x3C:0x40], "little")
        if off + 6 > len(d) or d[off:off + 4] != b"PE\0\0":
            return self.result(Outcome.HIT, severity=Severity.LOW, message="MZ header without a PE signature",
                               tags=["unsupported-format"])
        machine = int.from_bytes(d[off + 4:off + 6], "little")
        name = MACHINES.get(machine, f"0x{machine:04x}")
        if self.allowed is not None and name not in self.allowed:
            return self.result(Outcome.HIT, severity=Severity.LOW, tags=["out-of-distribution"],
                               message=f"machine {name} not in {sorted(self.allowed)} (model not trained on it)")
        return self.result(Outcome.MISS, evidence=[name])
