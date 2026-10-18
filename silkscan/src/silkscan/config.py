"""YAML configuration loaded into strict dataclasses.

Unknown keys are rejected so a typo cannot silently fall back to a default.
Relative paths are resolved against the current working directory and
`${VAR}` environment variables are expanded.
"""

from __future__ import annotations

import copy
import dataclasses
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from silkscan.errors import ConfigError
from silkscan.utils.hashing import sha256_json

MISSING_POLICIES = ("error", "impute_with_indicator")
OVERLAP_POLICIES = ("error", "drop_from_later")
DUPLICATE_POLICIES = ("error", "keep_first")
# LightGBM aliases for the number of rounds; we keep that in model.num_boost_round.
_ROUND_ALIASES = {"num_iterations", "num_iteration", "n_iter", "num_tree", "num_trees", "num_round",
                  "num_rounds", "nrounds", "num_boost_round", "n_estimators", "max_iter"}


@dataclass
class DataConfig:
    root: str
    splits: dict[str, list[str]]
    file_type: str = "Win64"
    id_field: str = "sha256"
    label_field: str = "label"
    date_field: str = "first_submission_date"
    file_type_field: str = "file_type"
    # Splits whose files mix file types (EMBER2024's challenge set) are filtered by file_type.
    filter_file_type_splits: list[str] = field(default_factory=lambda: ["challenge"])
    validation_start: str | None = None
    # Deterministic id-hash subsample of the train split (validation/test untouched); 1.0 = all.
    train_fraction: float = 1.0
    overlap_policy: str = "error"
    # Repeated ids inside one split: `error`, or `keep_first` after checking that the copies have the same
    # label and static features (fields in duplicate_ignore_fields may differ).
    duplicate_policy: str = "error"
    duplicate_ignore_fields: list[str] = field(default_factory=lambda: ["caps", "ttps", "mbc"])
    chunk_size: int = 2048
    # `root` before `${VAR}` expansion; run directories store this instead of a machine-specific path.
    root_template: str | None = None


@dataclass
class GroupConfig:
    name: str
    enabled: bool = True
    missing_policy: str | None = None  # None -> the extractor's default
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class FeaturesConfig:
    groups: list[GroupConfig]
    cache_dir: str = "work/cache"
    n_jobs: int = 1


@dataclass
class ModelConfig:
    params: dict[str, Any] = field(default_factory=dict)
    num_boost_round: int = 500
    early_stopping_rounds: int | None = 50


@dataclass
class EvaluationConfig:
    target_fpr: float = 0.001
    report_fprs: list[float] = field(default_factory=lambda: [0.001, 0.01])
    # A low score with a failed/missing feature group is reported as "inconclusive", not "clean".
    inconclusive_on_status: bool = True
    # Bootstrap resamples for confidence intervals and threshold stability (0 = off).
    bootstrap: int = 200
    # Subgroup reports keyed by a binary feature column, e.g. {"dll": "ember_v3.header_0043"}: metrics at the
    # global threshold for rows where the column is > 0 and where it is not.
    subgroup_flags: dict[str, str] = field(default_factory=dict)


@dataclass
class Config:
    data: DataConfig
    features: FeaturesConfig
    model: ModelConfig = field(default_factory=ModelConfig)
    evaluation: EvaluationConfig = field(default_factory=EvaluationConfig)
    work_dir: str = "work"
    runs_dir: str = "runs"
    seed: int = 0

    @property
    def manifest_dir(self) -> Path:
        return Path(self.work_dir) / "manifest"

    def enabled_groups(self) -> list[GroupConfig]:
        return [g for g in self.features.groups if g.enabled]

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    def fingerprint(self) -> str:
        return sha256_json(self.to_dict())


def _build(cls: type, raw: Any, where: str) -> Any:
    if not isinstance(raw, dict):
        raise ConfigError(f"`{where}` must be a mapping, got {type(raw).__name__}.")
    names = {f.name for f in dataclasses.fields(cls)}
    unknown = sorted(set(raw) - names)
    if unknown:
        raise ConfigError(f"Unknown key(s) in `{where}`: {unknown}. Valid keys: {sorted(names)}.")
    try:
        return cls(**raw)
    except TypeError as e:
        raise ConfigError(f"Invalid `{where}`: {e}") from None


def _expand(value: Any) -> Any:
    if isinstance(value, str):
        expanded = os.path.expandvars(value)
        if "${" in expanded:
            raise ConfigError(f"Unset environment variable in config value {value!r}.")
        return expanded
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


def config_from_dict(raw: dict[str, Any], expand_env: bool = True) -> Config:
    """Build a Config. With expand_env=False, `${VAR}` placeholders are kept (e.g. a model bundle's config,
    which must load on machines where the training data path is not set)."""
    raw = copy.deepcopy(raw)
    data = raw.get("data")
    template = data.get("root_template") or data.get("root") if isinstance(data, dict) else None
    if expand_env:
        raw = _expand(raw)
    if isinstance(raw.get("data"), dict) and template and "$" in str(template):
        raw["data"]["root_template"] = template  # set after expansion so the placeholder survives
    for key in ("data", "features"):
        if key not in raw:
            raise ConfigError(f"Config is missing the required `{key}` section.")
    top = dict(raw)
    top["data"] = _build(DataConfig, raw["data"], "data")
    feats = dict(raw["features"])
    groups_raw = feats.get("groups")
    if not isinstance(groups_raw, list) or not groups_raw:
        raise ConfigError("`features.groups` must be a non-empty list.")
    feats["groups"] = [_build(GroupConfig, g, f"features.groups[{i}]") for i, g in enumerate(groups_raw)]
    top["features"] = _build(FeaturesConfig, feats, "features")
    if "model" in raw:
        top["model"] = _build(ModelConfig, raw["model"], "model")
    if "evaluation" in raw:
        top["evaluation"] = _build(EvaluationConfig, raw["evaluation"], "evaluation")
    cfg = _build(Config, top, "<root>")
    _validate(cfg)
    return cfg


def _validate(cfg: Config) -> None:
    d = cfg.data
    if "train" not in d.splits:
        raise ConfigError("`data.splits` must define a `train` split.")
    if "validation" in d.splits:
        raise ConfigError("`validation` is carved out of train by `data.validation_start`; do not list its files.")
    if d.overlap_policy not in OVERLAP_POLICIES:
        raise ConfigError(f"`data.overlap_policy` must be one of {OVERLAP_POLICIES}.")
    if not 0 < d.train_fraction <= 1:
        raise ConfigError("`data.train_fraction` must be in (0, 1].")
    if d.duplicate_policy not in DUPLICATE_POLICIES:
        raise ConfigError(f"`data.duplicate_policy` must be one of {DUPLICATE_POLICIES}.")
    if d.chunk_size < 1:
        raise ConfigError("`data.chunk_size` must be >= 1.")
    names = [g.name for g in cfg.features.groups]
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        raise ConfigError(f"Feature group(s) listed more than once: {dupes}.")
    if not cfg.enabled_groups():
        raise ConfigError("At least one feature group must be enabled.")
    for g in cfg.features.groups:
        if g.missing_policy is not None and g.missing_policy not in MISSING_POLICIES:
            raise ConfigError(f"Group `{g.name}`: missing_policy must be one of {MISSING_POLICIES}.")
    clash = sorted(_ROUND_ALIASES & set(cfg.model.params))
    if clash:
        raise ConfigError(f"Set the number of rounds with `model.num_boost_round`, not model.params {clash}.")
    if not 0 < cfg.evaluation.target_fpr < 1:
        raise ConfigError("`evaluation.target_fpr` must be in (0, 1).")


def _deep_merge(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in over.items():
        out[k] = _deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def _load_raw(path: Path, seen: tuple[Path, ...] = ()) -> dict[str, Any]:
    if not path.is_file():
        raise ConfigError(f"Config file not found: {path}")
    if path.resolve() in seen:
        raise ConfigError(f"Circular `extends` in {path}.")
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    parent = raw.pop("extends", None)
    if parent is None:
        return raw
    # Mappings are merged key by key; lists (e.g. features.groups) are replaced as a whole.
    return _deep_merge(_load_raw(path.parent / parent, seen + (path.resolve(),)), raw)


def load_config(path: str | Path, overrides: dict[str, Any] | None = None) -> Config:
    raw = _load_raw(Path(path))
    for dotted, value in (overrides or {}).items():
        node = raw
        *parents, leaf = dotted.split(".")
        for p in parents:
            node = node.setdefault(p, {})
        node[leaf] = value
    return config_from_dict(raw)


# ---------------------------------------------------------------------------
# serving (prediction-time) configuration: model run, backend and checks
# ---------------------------------------------------------------------------
@dataclass
class CheckConfig:
    name: str
    enabled: bool = True
    effect: str | None = None          # evidence | force_malicious | force_clean | force_review; None -> default
    params: dict[str, Any] = field(default_factory=dict)
    required: bool = True              # false: if its dependency is missing (e.g. yara on s390x), skip with a warning


@dataclass
class ServingConfig:
    run: str                           # model bundle (run directory)
    backend: str = "lightgbm"
    checks: list[CheckConfig] = field(default_factory=list)
    explain_top: int = 5
    max_file_mb: int = 100             # larger submissions are rejected before parsing
    # A pre-check hit that forces the decision (deny/allow list, forcing YARA rule) skips static
    # analysis and the model. false = always run the model too (audit / shadow mode).
    short_circuit: bool = True
    stage2: str | None = None          # threat type/family model dir (`silkscan train-type`); None = off


def load_serving_config(path: str | Path) -> ServingConfig:
    raw = _expand(_load_raw(Path(path)))
    checks = [_build(CheckConfig, c, f"checks[{i}]") for i, c in enumerate(raw.pop("checks", None) or [])]
    cfg = _build(ServingConfig, {**raw, "checks": checks}, "<serving>")
    for c in cfg.checks:
        if c.effect not in (None, "evidence", "force_malicious", "force_clean", "force_review"):
            raise ConfigError(f"Check `{c.name}`: effect must be evidence, force_malicious, force_clean or "
                              "force_review.")
    return cfg


def resolve_data_root(cfg: Config) -> Config:
    """Expand environment variables in `data.root` at use time (bundles keep the `${VAR}` placeholder)."""
    root = os.path.expandvars(cfg.data.root)
    if "$" in root:
        raise ConfigError(f"Data root {cfg.data.root!r} needs an environment variable that is not set "
                          "(e.g. export EMBER2024_DIR=...), or pass -c <config>.")
    return dataclasses.replace(cfg, data=dataclasses.replace(cfg.data, root=root))
