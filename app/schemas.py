"""SilkShield API Schemas — Pydantic models matching the API contract."""

from __future__ import annotations

from enum import Enum
from typing import Annotated, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


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


class ChatTurn(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=600)

    @field_validator("content")
    @classmethod
    def non_blank_content(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Chat turns cannot be blank")
        return value


class ChatAnalysisContext(BaseModel):
    """Bounded report context for explaining an existing analysis result."""

    ioc: str = Field(min_length=1, max_length=2048)
    type: str = Field(min_length=1, max_length=20)
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    classification: str = Field(min_length=1, max_length=50)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: List[Annotated[str, Field(max_length=500)]] = Field(max_length=20)
    ai_analysis: str = Field(max_length=1200)
    reasoning: List[Annotated[str, Field(max_length=500)]] = Field(default_factory=list, max_length=5)
    recommendation: Recommendation
    mitre: List[Annotated[str, Field(max_length=40)]] = Field(max_length=10)
    mitigations: List[Annotated[str, Field(max_length=500)]] = Field(max_length=10)
    intelligence_source: str = Field(min_length=1, max_length=50)


class AnalystChatRequest(BaseModel):
    analysis: ChatAnalysisContext
    question: str = Field(min_length=1, max_length=600)
    history: List[ChatTurn] = Field(default_factory=list, max_length=8)

    @field_validator("question")
    @classmethod
    def non_blank_question(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Question cannot be blank")
        return value


class AnalystChatResponse(BaseModel):
    answer: str
    provider: str


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
    reasoning: List[str] = Field(default_factory=list, max_length=5)
    recommendation: Recommendation
    mitre: List[str] = []
    mitigations: List[str] = []
    metadata: dict = {}


class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "silkshield"
    telemetry: Optional[dict] = None


# ---------- Error ---------- #

class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorDetail
