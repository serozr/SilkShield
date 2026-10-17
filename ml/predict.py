"""ML Predict — runs inference using a trained XGBoost model or heuristic fallback."""

from __future__ import annotations

import os
from typing import Any, Dict, Tuple

import joblib
import numpy as np

from ml.features import extract_features, features_to_array

MODEL_DIR = os.path.join(os.path.dirname(__file__), "model")
MODEL_PATH = os.path.join(MODEL_DIR, "xgboost_model.joblib")

_model = None


# ---------- model loading ---------- #

def load_model() -> bool:
    global _model
    if os.path.exists(MODEL_PATH):
        _model = joblib.load(MODEL_PATH)
        return True
    return False


# ---------- risk helpers ---------- #

def get_risk_level(score: int) -> str:
    if score <= 24:
        return "LOW"
    if score <= 49:
        return "MEDIUM"
    if score <= 74:
        return "HIGH"
    return "CRITICAL"


def get_classification(score: int, intel_data: dict) -> str:
    if score <= 24:
        return "BENIGN"
    ratio = intel_data.get("detection_ratio", 0)
    if ratio > 0.5:
        return "MALWARE"
    if ratio > 0.1:
        return "PHISHING"
    return "SUSPICIOUS"


# ---------- prediction ---------- #

def predict(intel_data: dict, ioc: str, ioc_type: str) -> Dict[str, Any]:
    """Return risk score, level, classification, confidence, and evidence."""

    features = extract_features(intel_data, ioc, ioc_type)
    arr = features_to_array(features)

    if _model is not None:
        proba = _model.predict_proba(arr)[0]
        probability = float(proba[1])
        risk_score = int(probability * 100)
        confidence = float(max(proba))
    else:
        risk_score, confidence = _heuristic_score(features)

    return {
        "risk_score": risk_score,
        "risk_level": get_risk_level(risk_score),
        "classification": get_classification(risk_score, intel_data),
        "confidence": round(confidence, 2),
        "evidence": _build_evidence(features, intel_data),
        "features": features,
        "model_available": _model is not None,
    }


# ---------- heuristic fallback ---------- #

def _heuristic_score(features: dict) -> Tuple[int, float]:
    """Deterministic scoring when no trained model is available."""

    score = 0.0

    # Detection ratio → 0-40 pts
    score += features.get("detection_ratio", 0) * 40

    # Detection count → 0-20 pts
    score += min(features.get("detection_count", 0) / 10, 1.0) * 20

    # Reputation → 0-15 pts (negative reputation = higher risk)
    rep = features.get("reputation", 0)
    if rep < 0:
        score += min(abs(rep) / 100, 1.0) * 15

    # Suspicious keywords → 0-10 pts
    score += min(features.get("suspicious_keywords", 0) / 3, 1.0) * 10

    # Domain age → 0-10 pts
    age = features.get("domain_age_days", -1)
    if 0 <= age < 30:
        score += 10
    elif 0 <= age < 90:
        score += 5

    # ASN reputation → 0-5 pts
    if features.get("asn_reputation", 0) < 0:
        score += 5

    risk = min(int(score), 100)

    total = features.get("total_engines", 0)
    if total > 50:
        conf = 0.85 + min(features.get("detection_ratio", 0), 0.14)
    elif total > 20:
        conf = 0.70 + min(features.get("detection_ratio", 0), 0.14)
    else:
        conf = 0.50
    conf = min(round(conf, 2), 0.99)

    return risk, conf


# ---------- evidence builder ---------- #

def _build_evidence(features: dict, intel_data: dict) -> list[str]:
    ev: list[str] = []

    det = features.get("detection_count", 0)
    total = features.get("total_engines", 0)
    if det > 0:
        ev.append(f"{det}/{total} security engines flagged this indicator")
    elif total > 0:
        ev.append(f"No detections across {total} security engines")

    rep = features.get("reputation", 0)
    if rep < -50:
        ev.append(f"Very poor reputation score ({rep})")
    elif rep < -20:
        ev.append(f"Poor reputation score ({rep})")
    elif rep > 50:
        ev.append(f"Good reputation score ({rep})")

    age = features.get("domain_age_days", -1)
    if 0 <= age < 30:
        ev.append(f"Recently registered ({age} days ago)")
    elif 0 <= age < 90:
        ev.append(f"Relatively new registration ({age} days ago)")

    kw = features.get("suspicious_keywords", 0)
    if kw > 0:
        ev.append(f"Contains {kw} suspicious keyword(s)")

    meta = intel_data.get("metadata", {})
    country = meta.get("country")
    if country:
        ev.append(f"Infrastructure located in {country}")

    owner = meta.get("as_owner")
    if owner:
        ev.append(f"Hosted by {owner}")

    related = intel_data.get("related_indicators", [])
    if related:
        ev.append(f"{len(related)} related indicator(s) found")

    if intel_data.get("source") == "demo_fixture":
        ev.append("[!] Analysis based on demo fixture data (not live intelligence)")

    return ev


# Auto-load model at import time
load_model()
