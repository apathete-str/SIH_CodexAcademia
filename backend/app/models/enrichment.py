"""Enrichment result schemas."""
from __future__ import annotations
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class UrlReputation(BaseModel):
    url: str
    expanded_url: str | None = None
    safe_browsing: str | None = None  # "safe" | "malicious" | "unknown"
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_total: int = 0
    urlscan_score: int | None = None
    is_shortened: bool = False
    risk: float = Field(default=0.0, ge=0.0, le=1.0)


class DomainReputation(BaseModel):
    domain: str
    registered: datetime | None = None
    age_days: int | None = None
    registrar: str | None = None
    is_typosquat: bool = False
    typosquat_of: str | None = None
    has_valid_spf: bool | None = None
    has_valid_dkim: bool | None = None
    has_valid_dmarc: bool | None = None
    risk: float = Field(default=0.0, ge=0.0, le=1.0)


class IpReputation(BaseModel):
    ip: str
    asn: str | None = None
    org: str | None = None
    is_proxy: bool = False
    is_tor: bool = False
    is_vpn: bool = False
    is_datacenter: bool = False
    reputation_score: float = Field(default=0.0, ge=0.0, le=1.0)


class AttachmentReputation(BaseModel):
    sha256: str
    filename: str
    content_type: str
    vt_malicious: int = 0
    vt_total: int = 0
    is_executable: bool = False
    is_archive: bool = False
    is_macro: bool = False
    risk: float = Field(default=0.0, ge=0.0, le=1.0)


class EnrichmentResult(BaseModel):
    email_id: str
    urls: list[UrlReputation] = Field(default_factory=list)
    domains: list[DomainReputation] = Field(default_factory=list)
    ips: list[IpReputation] = Field(default_factory=list)
    attachments: list[AttachmentReputation] = Field(default_factory=list)
    enriched_at: datetime = Field(default_factory=datetime.utcnow)
    provider: str = "mock"  # "mock" | "live"
    raw: dict[str, Any] = Field(default_factory=dict)
