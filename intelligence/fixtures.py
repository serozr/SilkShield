"""Demo Fixtures — clearly labelled offline test data for demo reliability.

⚠ These are NOT live intelligence results. They are synthetic data crafted
  to exercise every branch of the analysis pipeline without requiring
  external API access.
"""

from __future__ import annotations

from intelligence.normalize import NormalizedIntelligence

# ---------- Fixture catalogue ---------- #

DEMO_FIXTURES: dict[str, NormalizedIntelligence] = {}


def _add(intel: NormalizedIntelligence) -> None:
    key = f"{intel.type}:{intel.ioc}"
    DEMO_FIXTURES[key] = intel


# Phishing domain — high risk
_add(NormalizedIntelligence(
    ioc="evil-phishing-site.com",
    type="domain",
    detections=17,
    total_engines=94,
    detection_ratio=0.1809,
    reputation=-72,
    related_indicators=["192.168.1.100", "malware-payload.exe"],
    metadata={
        "malicious_votes": 14,
        "suspicious_votes": 3,
        "harmless_votes": 68,
        "undetected_votes": 9,
        "creation_date": 1696000000,
        "registrar": "Suspect Registrar LLC",
    },
    source="demo_fixture",
))

# Malicious IP — critical risk
_add(NormalizedIntelligence(
    ioc="185.220.101.1",
    type="ip",
    detections=22,
    total_engines=94,
    detection_ratio=0.2340,
    reputation=-85,
    related_indicators=["evil-phishing-site.com"],
    metadata={
        "malicious_votes": 20,
        "suspicious_votes": 2,
        "harmless_votes": 60,
        "undetected_votes": 12,
        "asn": 12345,
        "as_owner": "Suspicious Hosting Inc",
        "country": "RU",
    },
    source="demo_fixture",
))

# Malware hash — critical risk
_add(NormalizedIntelligence(
    # SHA-256 of a harmless text label used only as a synthetic demo indicator.
    # Do not use the well-known empty-file hash here: a real empty file must not
    # appear malicious in the file reputation workflow.
    ioc="7b5bda1922a562be4cf5fc9203a83ed94323c462dc0e22fd8af440a0423079e6",
    type="hash",
    detections=45,
    total_engines=72,
    detection_ratio=0.625,
    reputation=-100,
    related_indicators=["evil-c2-server.net", "203.0.113.50"],
    metadata={
        "malicious_votes": 42,
        "suspicious_votes": 3,
        "harmless_votes": 15,
        "undetected_votes": 12,
        "type_description": "Win32 EXE",
        "size": 245760,
        "names": ["trojan.exe", "update.exe"],
    },
    source="demo_fixture",
))

# Phishing URL — high risk
_add(NormalizedIntelligence(
    ioc="http://malicious-login.com/signin",
    type="url",
    detections=12,
    total_engines=94,
    detection_ratio=0.1277,
    reputation=-55,
    related_indicators=["malicious-login.com"],
    metadata={
        "malicious_votes": 10,
        "suspicious_votes": 2,
        "harmless_votes": 70,
        "undetected_votes": 12,
    },
    source="demo_fixture",
))

# Benign domain — safe baseline
_add(NormalizedIntelligence(
    ioc="google.com",
    type="domain",
    detections=0,
    total_engines=94,
    detection_ratio=0.0,
    reputation=100,
    related_indicators=[],
    metadata={
        "malicious_votes": 0,
        "suspicious_votes": 0,
        "harmless_votes": 94,
        "undetected_votes": 0,
        "creation_date": 874296000,
        "registrar": "MarkMonitor Inc.",
    },
    source="demo_fixture",
))


# ---------- Public helpers ---------- #

def get_fixture(ioc: str, ioc_type: str) -> NormalizedIntelligence | None:
    return DEMO_FIXTURES.get(f"{ioc_type}:{ioc}")


def get_demo_iocs() -> list[dict]:
    """Return a catalogue of available demo IOCs for the frontend."""
    return [
        {"ioc": "evil-phishing-site.com", "type": "domain",
         "description": "Known phishing domain (HIGH risk)"},
        {"ioc": "185.220.101.1", "type": "ip",
         "description": "Suspicious IP address (CRITICAL risk)"},
        {"ioc": "7b5bda1922a562be4cf5fc9203a83ed94323c462dc0e22fd8af440a0423079e6",
         "type": "hash", "description": "Synthetic demo hash — SHA-256 (fixture only)"},
        {"ioc": "http://malicious-login.com/signin", "type": "url",
         "description": "Phishing URL (HIGH risk)"},
        {"ioc": "google.com", "type": "domain",
         "description": "Benign domain — safe baseline (LOW risk)"},
    ]
