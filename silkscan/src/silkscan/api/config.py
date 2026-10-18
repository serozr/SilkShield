"""Strict service configuration; paths are relative to the launch directory."""
from __future__ import annotations

import math
import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from silkscan.errors import ConfigError


@dataclass
class SubscriberConfig:
    enabled: bool = False
    url: str = ""
    blob_base: str = ""
    token_env: str = "SILKSCAN_UPSTREAM_TOKEN"
    reconnect_max_s: float = 60
    max_event_bytes: int = 65536


@dataclass
class APIConfig:
    serving: str = "configs/serving.yaml"
    host: str = "127.0.0.1"
    port: int = 8090
    workers: int = max(1, (os.cpu_count() or 2) - 1)
    sync_timeout_s: float = 5
    parse_timeout_s: float = 10
    parse_memory_mb: int = 2048
    parse_recycle_after: int = 500
    max_batch: int = 1000
    batch_window_ms: float = 5
    queue_size: int = 1000
    max_pending_mb: int = 512
    quarantine_dir: str = "work/api/quarantine"
    quarantine_ttl_h: float = 72
    store_url: str = "sqlite:///work/api/verdicts.db"
    rate_limit_per_min: int = 600
    events_buffer: int = 10000
    events_client_queue: int = 256
    heartbeat_s: float = 15
    auth_required: bool = True
    health_auth_required: bool = True
    worker_start_timeout_s: float = 120
    worker_timeout_s: float = 900
    subscriber: SubscriberConfig = field(default_factory=SubscriberConfig)

    def validate(self):
        for name in ("port", "workers", "parse_memory_mb", "parse_recycle_after", "max_batch",
                     "queue_size", "rate_limit_per_min", "events_buffer", "events_client_queue", "max_pending_mb"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ConfigError(f"api.{name}: expected a positive integer")
        if self.port > 65535:
            raise ConfigError("api.port: must be <= 65535")
        for name in ("sync_timeout_s", "parse_timeout_s", "batch_window_ms", "quarantine_ttl_h",
                     "heartbeat_s", "worker_start_timeout_s", "worker_timeout_s"):
            value = getattr(self, name)
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise ConfigError(f"api.{name}: expected a finite nonnegative number")
            if name not in ("sync_timeout_s", "batch_window_ms") and value == 0:
                raise ConfigError(f"api.{name}: must be positive")
        for name in ("auth_required", "health_auth_required"):
            if type(getattr(self, name)) is not bool:
                raise ConfigError(f"api.{name}: expected a boolean")
        for name in ("serving", "host", "quarantine_dir", "store_url"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise ConfigError(f"api.{name}: expected a nonempty string")
        if not self.store_url.startswith("sqlite:///") or not self.store_url[10:]:
            raise ConfigError("api.store_url: only sqlite:///path is implemented")
        sub = self.subscriber
        if type(sub.enabled) is not bool:
            raise ConfigError("subscriber.enabled: expected a boolean")
        for name in ("url", "blob_base", "token_env"):
            if not isinstance(getattr(sub, name), str):
                raise ConfigError(f"subscriber.{name}: expected a string")
        if type(sub.max_event_bytes) is not int or sub.max_event_bytes <= 0:
            raise ConfigError("subscriber.max_event_bytes: expected a positive integer")
        if (type(sub.reconnect_max_s) not in (int, float)
                or not math.isfinite(sub.reconnect_max_s) or sub.reconnect_max_s < 1):
            raise ConfigError("subscriber.reconnect_max_s: expected a finite number >= 1")
        if sub.enabled:
            url = urlsplit(sub.url)
            if url.scheme not in ("http", "https") or not url.netloc or url.username:
                raise ConfigError("subscriber.url: expected an HTTP(S) URL without credentials")
            if not sub.blob_base:
                raise ConfigError("subscriber.blob_base: required when subscriber is enabled")
            base = urlsplit(sub.blob_base)
            if base.scheme and (base.scheme not in ("http", "https") or not base.netloc
                                or base.username or base.query or base.fragment):
                raise ConfigError("subscriber.blob_base: expected a local directory or an HTTP(S) base")
        return self


def _build(cls, raw, where):
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: expected a mapping")
    unknown = set(raw) - {f.name for f in fields(cls)}
    if unknown:
        raise ConfigError(f"{where}: unknown keys: {sorted(unknown)}")
    return cls(**raw)


def load_api_config(path: str | Path) -> APIConfig:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"Cannot read API configuration: {type(exc).__name__}") from None
    if not isinstance(raw, dict):
        raise ConfigError("api: expected a mapping")
    raw = dict(raw)
    raw["subscriber"] = _build(SubscriberConfig, raw.get("subscriber", {}), "subscriber")
    return _build(APIConfig, raw, "api").validate()
