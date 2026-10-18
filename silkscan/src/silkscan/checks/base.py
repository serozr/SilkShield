"""Contract for cheap, rule-based checks that run next to the model (YARA, hash lists, ...).

Checks are NOT model features: EMBER2024 ships no file bytes, so byte-level rules
cannot be learned from it. They run at prediction time, after the model, and a
documented decision policy (silkscan.checks.decision) combines their results with
the model's score. They never change the trained model, its schema or the cache.

Writing a check:
1. subclass `Check`: set `name`, `version`, `needs_bytes`, `needs_raw`; implement `run(ctx)`;
   optionally `setup()` (load rules once) and `tool_versions()` (rule file hashes);
2. register it in `silkscan/checks/__init__.py` with `register_check`;
3. enable it under `checks:` in the serving config (configs/serving.yaml).
"""

from __future__ import annotations

import enum
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from types import MappingProxyType
from typing import Any, ClassVar, Mapping


class Outcome(str, enum.Enum):
    HIT = "hit"            # the check found what it looks for
    MISS = "miss"          # ran successfully, nothing found
    SKIPPED = "skipped"    # could not run on this input (e.g. needs file bytes, only features given)
    ERROR = "error"        # failed; never treated as "clean"


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: Any, default: "Severity") -> "Severity":
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 4:
            return cls(value)
        if isinstance(value, str) and value.strip().upper() in cls.__members__:
            return cls[value.strip().upper()]
        return default


class Effect(str, enum.Enum):
    """What a HIT does to the final decision (see silkscan.checks.decision)."""

    EVIDENCE = "evidence"                # reported and raises priority; does not change the decision
    FORCE_MALICIOUS = "force_malicious"  # e.g. hash deny-list, high-confidence YARA family rule
    FORCE_CLEAN = "force_clean"          # e.g. hash allow-list of known-good builds
    FORCE_REVIEW = "force_review"        # e.g. unsupported/unparseable format: send to review (fail-closed)


@dataclass(frozen=True)
class CheckContext:
    """Everything a check may look at. Labels and dataset metadata are never included."""

    sha256: str
    data: bytes | None                    # file bytes; None when only EMBER raw features are available
    raw: Mapping[str, Any]                # EMBER v3 raw static features (read-only), may be empty
    size: int | None = None
    filename: str | None = None           # as submitted; untrusted, informational only

    @classmethod
    def from_record(cls, sha256: str, inputs: Mapping[str, Any], data: bytes | None = None,
                    filename: str | None = None) -> "CheckContext":
        general = inputs.get("general") or {}
        size = len(data) if data is not None else general.get("size")
        return cls(sha256, data, MappingProxyType(dict(inputs)), size, filename)


@dataclass
class CheckResult:
    check: str
    version: str
    outcome: Outcome
    severity: Severity = Severity.INFO
    effect: Effect = Effect.EVIDENCE
    tags: list[str] = field(default_factory=list)          # e.g. ["ransomware", "family:lockbit"]
    evidence: list[str] = field(default_factory=list)      # e.g. matched rule names; keep short
    message: str | None = None
    elapsed_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["outcome"] = self.outcome.value
        d["severity"] = self.severity.name.lower()
        d["effect"] = self.effect.value
        return d


class Check(ABC):
    name: ClassVar[str]
    version: ClassVar[str]
    needs_bytes: ClassVar[bool] = False
    # False: runs BEFORE static analysis (sees only hash/bytes; ctx.raw is empty unless features were
    # submitted). True: runs after parsing, with ctx.raw filled. Keep it False for anything cheap.
    needs_raw: ClassVar[bool] = False
    default_effect: ClassVar[Effect] = Effect.EVIDENCE
    max_evidence: ClassVar[int] = 20

    def __init__(self, effect: Effect | str | None = None, **params: Any) -> None:
        self.params = params
        self.effect = Effect(effect) if effect is not None else self.default_effect

    def setup(self) -> None:
        """Load rules/lists once, before the first `run`. Raise SilkScanError on bad config."""

    def tool_versions(self) -> dict[str, str]:
        """Versions/hashes of rule files; reported with every verdict for traceability."""
        return {}

    @abstractmethod
    def run(self, ctx: CheckContext) -> CheckResult:
        """Inspect one input. Must not execute the file or reach the network."""

    # helpers ---------------------------------------------------------------------
    def result(self, outcome: Outcome, **kw: Any) -> CheckResult:
        kw.setdefault("effect", self.effect)
        ev = kw.get("evidence")
        if ev and len(ev) > self.max_evidence:
            kw["evidence"] = list(ev[: self.max_evidence]) + [f"... {len(ev) - self.max_evidence} more"]
        return CheckResult(self.name, self.version, outcome, **kw)

    def __call__(self, ctx: CheckContext) -> CheckResult:
        if self.needs_bytes and ctx.data is None:
            return self.result(Outcome.SKIPPED, message="needs file bytes; only static features were given")
        t0 = time.perf_counter()
        try:
            r = self.run(ctx)
        except Exception as e:  # a broken rule or check must not break prediction
            r = self.result(Outcome.ERROR, message=f"{type(e).__name__}: {e}")
        r.elapsed_ms = round((time.perf_counter() - t0) * 1e3, 3)
        return r
