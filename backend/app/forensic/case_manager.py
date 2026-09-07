"""In-memory case repository for MVP; replace with PostgreSQL repository in production."""
from __future__ import annotations
from datetime import datetime, timezone
from app.ingest.ingest_service import generate_case_id
from app.models.forensic import CaseSeverity, CaseStatus, EvidenceItem, EvidenceType, ForensicCase
from app.forensic.chain_of_custody import append_event

_CASES: dict[str, ForensicCase] = {}


def create_case(title: str, description: str = "", severity: CaseSeverity = CaseSeverity.MEDIUM, actor: str = "system") -> ForensicCase:
    case = ForensicCase(id=generate_case_id(), title=title, description=description, severity=severity)
    append_event(case.custody_chain, actor, "case_created", EvidenceType.NOTE, case.id, case.id)
    _CASES[case.id] = case
    return case


def get_case(case_id: str) -> ForensicCase | None:
    return _CASES.get(case_id)


def list_cases() -> list[ForensicCase]:
    return list(_CASES.values())


def add_evidence(case: ForensicCase, evidence: EvidenceItem, actor: str = "system") -> ForensicCase:
    case.evidence.append(evidence)
    case.updated_at = datetime.now(timezone.utc)
    append_event(case.custody_chain, actor, "evidence_added", evidence.type, evidence.id, evidence.sha256)
    return case
