"""GeoLocation intelligence schemas."""
from __future__ import annotations
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class GeoPoint(BaseModel):
    ip: str
    country: str | None = None
    country_code: str | None = None
    region: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    asn: str | None = None
    org: str | None = None
    is_proxy: bool = False
    is_tor: bool = False
    is_vpn: bool = False
    is_datacenter: bool = False
    risk: float = Field(default=0.0, ge=0.0, le=1.0)


class InfraHop(BaseModel):
    """A hop in the email delivery path with geo info."""

    order: int
    host: str | None = None
    ip: str | None = None
    geo: GeoPoint | None = None
    timestamp: datetime | None = None


class GeoIntel(BaseModel):
    email_id: str
    sender_ip: str | None = None
    sender_geo: GeoPoint | None = None
    hops: list[InfraHop] = Field(default_factory=list)
    origin_country: str | None = None
    origin_country_code: str | None = None
    geo_risk: float = Field(default=0.0, ge=0.0, le=1.0)
    attribution: dict[str, Any] = Field(default_factory=dict)
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)
