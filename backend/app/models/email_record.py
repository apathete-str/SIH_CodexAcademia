"""Canonical normalized email record schema."""
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EmailSource(str, Enum):
    MTA = "mta"
    IMAP = "imap"
    UPLOAD = "upload"
    API = "api"


class AuthResult(BaseModel):
    """SPF/DKIM/DMARC authentication results."""

    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None


class ReceivedHop(BaseModel):
    """One entry from the Received header chain."""

    from_host: str | None = None
    by_host: str | None = None
    ip: str | None = None
    timestamp: datetime | None = None
    helo: str | None = None


class Attachment(BaseModel):
    filename: str
    content_type: str
    size: int
    sha256: str
    storage_ref: str | None = None


class EmailRecord(BaseModel):
    """Normalized representation of a parsed email."""

    id: str = Field(description="Stable unique ID (hash of raw bytes)")
    source: EmailSource
    message_id: str | None = None
    subject: str = ""
    from_addr: str | None = None
    from_display: str | None = None
    to_addrs: list[str] = Field(default_factory=list)
    cc_addrs: list[str] = Field(default_factory=list)
    reply_to: str | None = None
    date: datetime | None = None
    received_at: datetime = Field(default_factory=datetime.utcnow)
    received_chain: list[ReceivedHop] = Field(default_factory=list)
    auth_results: AuthResult = Field(default_factory=AuthResult)
    body_text: str = ""
    body_html: str = ""
    urls: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    attachments: list[Attachment] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    raw_ref: str | None = Field(default=None, description="Storage ref to raw bytes")
    raw_sha256: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
