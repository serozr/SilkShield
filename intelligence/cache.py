"""Cache — simple TTL cache for intelligence lookups to reduce API calls."""

from __future__ import annotations

from cachetools import TTLCache

from app.config import settings

_cache: TTLCache = TTLCache(maxsize=1024, ttl=settings.cache_ttl)


def cache_key(ioc: str, ioc_type: str) -> str:
    return f"{ioc_type}:{ioc}"


def get_cached(key: str):
    return _cache.get(key)


def set_cached(key: str, value):
    _cache[key] = value
