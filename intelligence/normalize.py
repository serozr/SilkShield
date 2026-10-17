"""Normalize — converts provider-specific responses into a common internal format."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List


@dataclass
class NormalizedIntelligence:
    """Provider-independent threat intelligence representation."""

    ioc: str
    type: str
    detections: int = 0
    total_engines: int = 0
    detection_ratio: float = 0.0
    reputation: int = 0
    related_indicators: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    source: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------- VirusTotal normalizer ---------- #

def normalize_virustotal(ioc: str, ioc_type: str, raw: dict) -> NormalizedIntelligence:
    """Convert a raw VirusTotal API v3 response into the internal schema."""
    data = raw.get("data", {})
    attrs = data.get("attributes", {})

    # Analysis stats
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    total = malicious + suspicious + harmless + undetected
    detections = malicious + suspicious
    ratio = round(detections / total, 4) if total > 0 else 0.0

    reputation = attrs.get("reputation", 0)

    meta: Dict[str, Any] = {
        "malicious_votes": malicious,
        "suspicious_votes": suspicious,
        "harmless_votes": harmless,
        "undetected_votes": undetected,
    }

    # Type-specific metadata
    if ioc_type == "domain":
        meta["creation_date"] = attrs.get("creation_date")
        meta["registrar"] = attrs.get("registrar")
        meta["whois"] = (attrs.get("whois") or "")[:500]
    elif ioc_type == "ip":
        meta["asn"] = attrs.get("asn")
        meta["as_owner"] = attrs.get("as_owner")
        meta["country"] = attrs.get("country")
    elif ioc_type == "hash":
        meta["type_description"] = attrs.get("type_description")
        meta["size"] = attrs.get("size")
        meta["names"] = (attrs.get("names") or [])[:5]

    return NormalizedIntelligence(
        ioc=ioc,
        type=ioc_type,
        detections=detections,
        total_engines=total,
        detection_ratio=ratio,
        reputation=reputation,
        metadata=meta,
        source="virustotal",
    )
