"""SilkShield API Schemas — Pydantic models matching the API contract."""

from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


# ---------- Enums ---------- #

class IOCType(str, Enum):
    DOMAIN = "domain"
    URL = "url"
    IP = "ip"
    HASH = "hash"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Recommendation(str, Enum):
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    BLOCK = "BLOCK"


# ---------- Request ---------- #

class AnalyzeRequest(BaseModel):
    ioc: str
    type: Optional[IOCType] = None


# ---------- Response ---------- #

class AnalyzeResponse(BaseModel):
    ioc: str
    type: str
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    classification: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: List[str]
    ai_analysis: str
    recommendation: Recommendation
    mitre: List[str] = []
    metadata: dict = {}


class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "silkshield"


# ---------- Error ---------- #

class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorDetail
