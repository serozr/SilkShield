"""
SilkShield — AI-Powered Real-Time Threat Decision Engine
=========================================================
FastAPI backend that orchestrates:
  IOC parsing → Threat Intelligence → ML Risk Scoring → AI Analysis
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

from app.config import settings
from app.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    HealthResponse,
    Recommendation,
    RiskLevel,
)
from intelligence.ioc import detect_ioc_type, validate_ioc
from intelligence.virustotal import VirusTotalClient
from intelligence.normalize import normalize_virustotal
from intelligence.cache import cache_key, get_cached, set_cached
from intelligence.fixtures import get_demo_iocs, get_fixture
from ml.predict import predict
from ai.analyst import analyze_threat

# ─── App ────────────────────────────────────────────────────── #

app = FastAPI(
    title="SilkShield",
    description="AI-Powered Real-Time Threat Decision Engine",
    version=settings.analysis_version,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount frontend static files
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

vt = VirusTotalClient()


# ─── Routes ─────────────────────────────────────────────────── #

@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint."""
    return HealthResponse()


@app.get("/demo-iocs")
async def demo_iocs():
    """Return available demo IOCs for testing."""
    return {"demo_iocs": get_demo_iocs()}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest):
    """Main analysis endpoint — full pipeline from IOC to decision."""

    # 1 — validate
    if not validate_ioc(request.ioc):
        raise HTTPException(
            status_code=400,
            detail={
                "error": {
                    "code": "INVALID_IOC",
                    "message": "The supplied IOC could not be validated.",
                }
            },
        )

    ioc = request.ioc.strip()
    ioc_type = (
        request.type.value if request.type else detect_ioc_type(ioc).value
    )

    # 2 — intelligence (cache → live → fixture → empty)
    key = cache_key(ioc, ioc_type)
    intel_data = get_cached(key)

    if intel_data is None:
        # try live VirusTotal
        if vt.is_configured:
            try:
                raw = await vt.lookup(ioc, ioc_type)
                intel = normalize_virustotal(ioc, ioc_type, raw)
                intel_data = intel.to_dict()
                set_cached(key, intel_data)
            except Exception:
                pass

        # try demo fixture
        if intel_data is None:
            fixture = get_fixture(ioc, ioc_type)
            if fixture is not None:
                intel_data = fixture.to_dict()
                set_cached(key, intel_data)

        # last resort: empty intelligence
        if intel_data is None:
            intel_data = {
                "ioc": ioc,
                "type": ioc_type,
                "detections": 0,
                "total_engines": 0,
                "detection_ratio": 0.0,
                "reputation": 0,
                "related_indicators": [],
                "metadata": {},
                "source": "none",
            }

    # 3 — ML prediction
    ml = predict(intel_data, ioc, ioc_type)

    # 4 — AI analysis
    try:
        ai = await analyze_threat(
            risk_score=ml["risk_score"],
            risk_level=ml["risk_level"],
            classification=ml["classification"],
            confidence=ml["confidence"],
            evidence=ml["evidence"],
            intel_data=intel_data,
            ioc=ioc,
            ioc_type=ioc_type,
        )
    except Exception:
        ai = {
            "summary": "AI analysis temporarily unavailable.",
            "reasoning": [],
            "recommendation": "MONITOR",
            "mitre": [],
            "provider": "error",
        }

    # 5 — normalise recommendation
    rec = ai.get("recommendation", "MONITOR")
    if rec not in ("ALLOW", "MONITOR", "BLOCK"):
        rec = "MONITOR"

    return AnalyzeResponse(
        ioc=ioc,
        type=ioc_type,
        risk_score=ml["risk_score"],
        risk_level=RiskLevel(ml["risk_level"]),
        classification=ml["classification"],
        confidence=ml["confidence"],
        evidence=ml["evidence"],
        ai_analysis=ai.get("summary", ""),
        recommendation=Recommendation(rec),
        mitre=ai.get("mitre", []),
        metadata={
            "analysis_version": settings.analysis_version,
            "intelligence_source": intel_data.get("source", "unknown"),
            "model_available": ml.get("model_available", False),
            "ai_provider": ai.get("provider", "unknown"),
        },
    )


@app.get("/")
async def root():
    """Serve the frontend."""
    index = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index):
        return FileResponse(index)
    return {"message": "SilkShield API is running. Frontend not found."}
