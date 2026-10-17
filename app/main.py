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
from intelligence.virustotal import (
    VirusTotalClient,
    VTAuthError,
    VTNetworkError,
    VTNotFoundError,
    VTRateLimitError,
)
from intelligence.normalize import normalize_virustotal, normalize_unseen_vt
from intelligence.cache import cache_key, get_cached, set_cached
from intelligence.fixtures import get_demo_iocs, get_fixture
from ml.predict import predict
from ai.analyst import analyze_threat
from app.telemetry import get_system_telemetry

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
    """Health check endpoint with host platform telemetry."""
    return HealthResponse(telemetry=get_system_telemetry())


@app.get("/system/info")
async def system_info():
    """Detailed hardware and platform inspection (IBM LinuxONE / s390x verifier)."""
    return get_system_telemetry()


@app.get("/api/virustotal/health")
async def virustotal_health():
    """Diagnostic check for VirusTotal API key and connectivity."""
    client = VirusTotalClient()
    return await client.test_connection()


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
    vt_warning: str | None = None

    if intel_data is not None:
        intel_data = dict(intel_data)
        if intel_data.get("source") in ("virustotal", "virustotal_live"):
            intel_data["source"] = "virustotal_cached"
    else:
        # try live VirusTotal
        if vt.is_configured:
            try:
                raw = await vt.lookup(ioc, ioc_type)
                intel = normalize_virustotal(ioc, ioc_type, raw)
                intel_data = intel.to_dict()
                intel_data["source"] = "virustotal_live"
                set_cached(key, intel_data)
            except VTNotFoundError:
                intel = normalize_unseen_vt(ioc, ioc_type)
                intel_data = intel.to_dict()
                set_cached(key, intel_data)
            except VTRateLimitError:
                vt_warning = "[!] VirusTotal rate limit reached (4 req/min for free tier). Fallback intelligence activated."
            except VTAuthError:
                vt_warning = "[!] VirusTotal API key is unauthorized or invalid. Fallback intelligence activated."
            except VTNetworkError as net_err:
                vt_warning = f"[!] VirusTotal connection failed ({net_err}). Fallback intelligence activated."
            except Exception as exc:
                vt_warning = f"[!] Threat intelligence error ({exc}). Fallback intelligence activated."

        # try demo fixture
        if intel_data is None:
            fixture = get_fixture(ioc, ioc_type)
            if fixture is not None:
                intel_data = fixture.to_dict()
                set_cached(key, intel_data)

        # last resort: empty intelligence
        if intel_data is None:
            fallback_source = (
                "virustotal_rate_limited"
                if (vt_warning and "rate limit" in vt_warning)
                else "local_fallback"
            )
            intel_data = {
                "ioc": ioc,
                "type": ioc_type,
                "detections": 0,
                "total_engines": 0,
                "detection_ratio": 0.0,
                "reputation": 0,
                "related_indicators": [],
                "metadata": {},
                "source": fallback_source,
            }

    # 3 — ML prediction
    ml = predict(intel_data, ioc, ioc_type)
    if vt_warning:
        ml["evidence"].insert(0, vt_warning)
    if intel_data.get("source") == "virustotal_unseen":
        ml["evidence"].append("[!] Indicator not found in VirusTotal database (unseen/newly observed)")

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
            "host_platform": get_system_telemetry()["platform_name"],
            "is_linuxone": get_system_telemetry()["is_linuxone"],
        },
    )


@app.get("/")
async def root():
    """Serve the frontend."""
    index = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index):
        return FileResponse(index)
    return {"message": "SilkShield API is running. Frontend not found."}
