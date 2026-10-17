"""IOC Parser — detects and validates Indicator of Compromise types."""

from __future__ import annotations

import re

from app.schemas import IOCType


# ---------- Detection ---------- #

_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
_URL = re.compile(r"^https?://", re.IGNORECASE)
_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_IPV6 = re.compile(r"^[0-9a-fA-F:]{2,39}$")


def detect_ioc_type(ioc: str) -> IOCType:
    """Automatically detect the IOC type from its value."""
    ioc = ioc.strip()

    # Hash patterns (most specific first)
    if _SHA256.match(ioc):
        return IOCType.HASH
    if _SHA1.match(ioc):
        return IOCType.HASH
    if _MD5.match(ioc):
        return IOCType.HASH

    # URL
    if _URL.match(ioc):
        return IOCType.URL

    # IP address
    if _IPV4.match(ioc):
        # Validate octets
        parts = ioc.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return IOCType.IP

    # IPv6
    if ":" in ioc and _IPV6.match(ioc):
        return IOCType.IP

    # Default: treat as domain
    return IOCType.DOMAIN


# ---------- Validation ---------- #

def validate_ioc(ioc: str) -> bool:
    """Basic IOC validation — rejects empty/too-long inputs."""
    if not ioc or len(ioc.strip()) == 0:
        return False
    if len(ioc) > 2048:
        return False
    # Must contain at least one alphanumeric character
    if not any(c.isalnum() for c in ioc):
        return False
    return True
