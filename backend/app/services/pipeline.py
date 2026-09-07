"""Synchronous end-to-end analysis pipeline for the MVP."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from pydantic import BaseModel
from app.detect.ensemble import assess_threat
from app.enrich.mock_providers import MockEnrichmentProvider
from app.geo.geolocate import analyze_geo
from app.models.email_record import EmailRecord
from app.models.enrichment import EnrichmentResult
from app.models.geo import GeoIntel
from app.models.forensic import CustodyEvent, EvidenceType, ForensicTimelineEvent, IOC, IOCType
from app.models.threat import ThreatAssessment
from app.forensic.chain_of_custody import append_event


class AnalysisResult(BaseModel):
    email: EmailRecord
    enrichment: EnrichmentResult
    threat: ThreatAssessment
    geo: GeoIntel
    iocs: list[IOC]
    timeline: list[ForensicTimelineEvent]
    custody_chain: list[CustodyEvent]


def _hash_model(value: BaseModel) -> str:
    payload = value.model_dump_json().encode()
    return hashlib.sha256(payload).hexdigest()


def _extract_iocs(email: EmailRecord) -> list[IOC]:
    iocs = [IOC(type=IOCType.URL, value=url, source="email.body", context=email.subject) for url in email.urls]
    iocs.extend(IOC(type=IOCType.DOMAIN, value=domain, source="email.body") for domain in email.domains)
    iocs.extend(IOC(type=IOCType.IP, value=ip, source="email.headers", context="Received chain") for ip in email.ips)
    if email.from_addr:
        iocs.append(IOC(type=IOCType.EMAIL, value=email.from_addr, source="email.from", confidence=1.0))
    iocs.extend(IOC(type=IOCType.FILE_HASH, value=attachment.sha256, source="email.attachment", context=attachment.filename) for attachment in email.attachments)
    unique: dict[tuple[str, str], IOC] = {}
    for ioc in iocs:
        unique[(ioc.type.value, ioc.value)] = ioc
    return list(unique.values())


def analyze_email(email: EmailRecord) -> AnalysisResult:
    started = datetime.now(timezone.utc)
    enrichment = MockEnrichmentProvider().enrich(email)
    threat = assess_threat(email, enrichment)
    geo = analyze_geo(email, enrichment)
    iocs = _extract_iocs(email)
    timeline = [
        ForensicTimelineEvent(timestamp=started, stage="ingestion", action="raw_email_captured", details={"source": email.source.value, "sha256": email.raw_sha256}),
        ForensicTimelineEvent(stage="parsing", action="email_normalized", details={"ioc_count": len(iocs), "attachment_count": len(email.attachments)}),
        ForensicTimelineEvent(stage="enrichment", action="indicators_enriched", details={"provider": enrichment.provider}),
        ForensicTimelineEvent(stage="detection", action="threat_assessed", details={"verdict": threat.verdict.value, "score": threat.threat_score}),
        ForensicTimelineEvent(stage="geolocation", action="infrastructure_traced", details={"hop_count": len(geo.hops), "origin": geo.origin_country}),
    ]
    chain: list[CustodyEvent] = []
    append_event(chain, "system", "captured", EvidenceType.RAW_EMAIL, email.id, email.raw_sha256 or email.id)
    append_event(chain, "system", "parsed", EvidenceType.PARSED_RECORD, email.id, _hash_model(email))
    append_event(chain, "system", "enriched", EvidenceType.ENRICHMENT, email.id, _hash_model(enrichment))
    append_event(chain, "system", "assessed", EvidenceType.THREAT_ASSESSMENT, email.id, _hash_model(threat))
    append_event(chain, "system", "geolocated", EvidenceType.GEO_INTEL, email.id, _hash_model(geo))
    return AnalysisResult(email=email, enrichment=enrichment, threat=threat, geo=geo, iocs=iocs, timeline=timeline, custody_chain=chain)
