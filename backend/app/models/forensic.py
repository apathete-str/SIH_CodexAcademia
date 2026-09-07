"""Forensic intelligence & case management schemas."""
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EvidenceType(str, Enum):
    RAW_EMAIL = "raw_email"
    PARSED_RECORD = "parsed_record"
    ENRICHMENT = "enrichment"
    THREAT_ASSESSMENT = "threat_assessment"
    GEO_INTEL = "geo_intel"
    REPORT = "report"
    NOTE = "note"


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    FILE_HASH = "file_hash"


class IOC(BaseModel):
    """Normalized indicator of compromise extracted from an email."""

    type: IOCType
    value: str
    source: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    context: str | None = None


class ForensicTimelineEvent(BaseModel):
    """Human-readable event emitted during the analysis lifecycle."""

    timestamp: datetime = Field(default_factory=datetime.utcnow)
    stage: str
    action: str
    status: str = "completed"
    details: dict[str, Any] = Field(default_factory=dict)


class CustodyEvent(BaseModel):
    """A single chain-of-custody event."""

    sequence: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    actor: str
    action: str
    entity_type: EvidenceType
    entity_id: str
    entity_hash: str
    prev_hash: str | None = None
    event_hash: str = Field(description="HMAC-SHA256 of this event + prev hash")


class CaseStatus(str, Enum):
    OPEN = "open"
    UNDER_INVESTIGATION = "under_investigation"
    RESOLVED = "resolved"
    CLOSED = "closed"


class CaseSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EvidenceItem(BaseModel):
    id: str
    type: EvidenceType
    description: str
    sha256: str
    storage_ref: str | None = None
    added_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ForensicCase(BaseModel):
    id: str
    title: str
    description: str = ""
    status: CaseStatus = CaseStatus.OPEN
    severity: CaseSeverity = CaseSeverity.MEDIUM
    email_ids: list[str] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    custody_chain: list[CustodyEvent] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    assigned_to: str | None = None
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
