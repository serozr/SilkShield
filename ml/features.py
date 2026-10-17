"""Feature Engineering — extracts ML features from normalized intelligence data."""

from __future__ import annotations

import time
from typing import Any, Dict

import numpy as np

# Ordered feature names used by the model
FEATURE_NAMES: list[str] = [
    "detection_count",
    "total_engines",
    "detection_ratio",
    "reputation",
    "related_count",
    "malicious_votes",
    "suspicious_votes",
    "domain_length",
    "subdomain_count",
    "has_ip_in_name",
    "suspicious_keywords",
    "url_length",
    "has_https",
    "path_depth",
    "has_query",
    "asn_reputation",
    "dns_record_count",
    "domain_age_days",
]

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "banking", "paypal", "microsoft", "apple", "google",
    "password", "credential", "suspend", "alert", "urgent",
    "wallet", "crypto", "prize", "winner", "free",
]


def get_feature_names() -> list[str]:
    return list(FEATURE_NAMES)


def features_to_array(features: Dict[str, Any]) -> np.ndarray:
    """Convert a feature dict to a 2-D numpy array in the correct order."""
    return np.array([[features.get(n, 0) for n in FEATURE_NAMES]])


def extract_features(
    intel_data: Dict[str, Any],
    ioc: str,
    ioc_type: str,
) -> Dict[str, Any]:
    """Extract a flat feature dict from normalized intelligence + IOC info."""

    f: Dict[str, Any] = {}
    meta = intel_data.get("metadata", {})

    # --- Threat-intelligence features ---
    f["detection_count"] = intel_data.get("detections", 0)
    f["total_engines"] = intel_data.get("total_engines", 0)
    f["detection_ratio"] = intel_data.get("detection_ratio", 0.0)
    f["reputation"] = intel_data.get("reputation", 0)
    f["related_count"] = len(intel_data.get("related_indicators", []))
    f["malicious_votes"] = meta.get("malicious_votes", 0)
    f["suspicious_votes"] = meta.get("suspicious_votes", 0)

    # --- IOC-type-specific features ---
    if ioc_type in ("domain", "url"):
        host = ioc if ioc_type == "domain" else ioc.split("//")[-1].split("/")[0]
        f["domain_length"] = len(host)
        f["subdomain_count"] = max(host.count(".") - 1, 0)
        f["has_ip_in_name"] = int(any(c.isdigit() for c in host.split(".")[0]))
        f["suspicious_keywords"] = _count_suspicious(ioc)

        if ioc_type == "url":
            f["url_length"] = len(ioc)
            f["has_https"] = int(ioc.lower().startswith("https"))
            f["path_depth"] = max(ioc.count("/") - 2, 0)
            f["has_query"] = int("?" in ioc)
        else:
            f["url_length"] = len(host)
            f["has_https"] = 0
            f["path_depth"] = 0
            f["has_query"] = 0
    elif ioc_type == "ip":
        f["domain_length"] = len(ioc)
        f["subdomain_count"] = 0
        f["has_ip_in_name"] = 1
        f["suspicious_keywords"] = 0
        f["url_length"] = len(ioc)
        f["has_https"] = 0
        f["path_depth"] = 0
        f["has_query"] = 0
    else:  # hash
        for key in ("domain_length", "subdomain_count", "has_ip_in_name",
                     "suspicious_keywords", "url_length", "has_https",
                     "path_depth", "has_query"):
            f[key] = 0

    # --- Infrastructure features ---
    f["asn_reputation"] = _asn_heuristic(meta)
    f["dns_record_count"] = meta.get("dns_record_count", 0)

    creation = meta.get("creation_date")
    if creation:
        f["domain_age_days"] = max(0, int((time.time() - creation) / 86400))
    else:
        f["domain_age_days"] = -1  # unknown

    return f


# ---------- helpers ---------- #

def _count_suspicious(ioc: str) -> int:
    low = ioc.lower()
    return sum(1 for w in SUSPICIOUS_WORDS if w in low)


_HIGH_RISK_COUNTRIES = {"RU", "CN", "KP", "IR"}


def _asn_heuristic(meta: dict) -> int:
    country = meta.get("country", "")
    return -1 if country in _HIGH_RISK_COUNTRIES else 0
