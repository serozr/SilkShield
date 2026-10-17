"""Rule-based checks next to the model. Register new checks here and enable them in the serving config."""

from __future__ import annotations

import logging
from typing import Any

from silkscan.checks.base import Check, CheckContext, CheckResult, Effect, Outcome, Severity
from silkscan.checks.builtin import HashList, PEFormat, Yara
from silkscan.errors import ConfigError, DependencyError

log = logging.getLogger(__name__)

CHECKS: dict[str, type[Check]] = {}


def register_check(cls: type[Check]) -> type[Check]:
    for attr in ("name", "version"):
        if not hasattr(cls, attr):
            raise TypeError(f"{cls.__name__} must define `{attr}`.")
    if cls.name in CHECKS and CHECKS[cls.name] is not cls:
        raise TypeError(f"Check name `{cls.name}` is already registered.")
    CHECKS[cls.name] = cls
    return cls


def create_checks(configs: list[Any]) -> list[Check]:
    """Instantiate and set up enabled checks from serving-config entries (CheckConfig)."""
    out = []
    for c in configs:
        if not c.enabled:
            continue
        if c.name not in CHECKS:
            raise ConfigError(f"Unknown check `{c.name}`. Registered: {sorted(CHECKS)}.")
        try:
            chk = CHECKS[c.name](effect=c.effect, **c.params)
        except (TypeError, ValueError) as e:
            raise ConfigError(f"Invalid config for check `{c.name}`: {e}") from None
        try:
            chk.setup()
        except DependencyError as e:
            if getattr(c, "required", True):
                raise
            log.warning("Optional check `%s` disabled: %s", c.name, e)
            continue
        out.append(chk)
    return out


register_check(PEFormat)
register_check(HashList)
register_check(Yara)

__all__ = ["CHECKS", "Check", "CheckContext", "CheckResult", "Effect", "Outcome", "Severity", "create_checks",
           "register_check"]
