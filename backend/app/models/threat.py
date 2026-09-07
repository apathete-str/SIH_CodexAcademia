"""Threat detection schemas."""
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ThreatCategory(str, Enum):
    PHISHING = "phishing"
    MALWARE = "malware"
    SPAM = "spam"
    SOCIAL_ENGINEERING = "social_engineering"
    BEC = "business_email_compromise"
    SCAM = "scam"
    BENIGN = "benign"


class Verdict(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Signal(BaseModel):
    """A single explainable detection signal."""

    name: str
    weight: float
    score: float = Field(ge=0.0, le=1.0)
    description: str = ""


class ModelContribution(BaseModel):
    model_name: str
    score: float = Field(ge=0.0, le=1.0)
    weight: float = Field(ge=0.0, le=1.0)


class ThreatAssessment(BaseModel):
    email_id: str
    threat_score: float = Field(ge=0.0, le=100.0)
    verdict: Verdict
    category: ThreatCategory | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    signals: list[Signal] = Field(default_factory=list)
    model_contributions: list[ModelContribution] = Field(default_factory=list)
    explanation: str = ""
    shap_values: dict[str, float] = Field(default_factory=dict)
    assessed_at: datetime = Field(default_factory=datetime.utcnow)
    model_version: str = "0.1.0"
    metadata: dict[str, Any] = Field(default_factory=dict)
